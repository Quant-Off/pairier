package node

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Quant-Off/pairier/host/internal/audit"
	"github.com/Quant-Off/pairier/host/internal/core"
	"github.com/Quant-Off/pairier/host/internal/exchange"
	"github.com/Quant-Off/pairier/host/internal/store"
	"github.com/Quant-Off/pairier/host/internal/wire"
)

func opts(t *testing.T, dir string) Options {
	t.Helper()
	bin := os.Getenv("KMS_CORE_BIN")
	if bin == "" {
		t.Skip("KMS_CORE_BIN not set")
	}
	return Options{Dir: dir, CoreBinary: bin, AllowUnlockedMemory: true, Timeout: 5 * time.Second, Now: func() time.Time { return time.Unix(1_700_000_000, 0) }}
}

func initNode(t *testing.T, id string, pqc bool) (*Node, Options) {
	t.Helper()
	o := opts(t, filepath.Join(t.TempDir(), id))
	n, err := Init(context.Background(), o, id, pqc)
	if err != nil {
		t.Fatalf("init %s: %v", id, err)
	}
	t.Cleanup(func() { _ = n.Close() })
	return n, o
}

func TestInitChecksCoreBeforeCreatingDir(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "node")
	notExec := filepath.Join(base, "kms-core")
	if err := os.WriteFile(notExec, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, bin := range []string{"", filepath.Join(base, "missing"), notExec, base} {
		o := Options{Dir: dir, CoreBinary: bin, AllowUnlockedMemory: true, Timeout: time.Second}
		if _, err := Init(context.Background(), o, "alice", false); err == nil {
			t.Fatalf("core %q accepted", bin)
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("core %q: node dir created: %v", bin, err)
		}
	}
}

func TestFailedInitLeavesNothingBehind(t *testing.T) {
	base := t.TempDir()
	existing := filepath.Join(base, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{filepath.Join(base, "fresh"), existing} {
		o := opts(t, dir)
		o.Timeout = time.Nanosecond
		if _, err := Init(context.Background(), o, "alice", false); err == nil {
			t.Fatal("init succeeded with an unusable core timeout")
		}
		entries, err := os.ReadDir(dir)
		if dir == existing {
			if err != nil || len(entries) != 0 {
				t.Fatalf("pre-existing dir not emptied: %v %d", err, len(entries))
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("created dir not removed: %v %d", err, len(entries))
		}
		o.Timeout = 5 * time.Second
		n, err := Init(context.Background(), o, "alice", false)
		if err != nil {
			t.Fatalf("re-init after failure: %v", err)
		}
		_ = n.Close()
	}
}

func TestRelativeCoreBinary(t *testing.T) {
	o := opts(t, filepath.Join(t.TempDir(), "alice"))
	abs, err := filepath.Abs(o.CoreBinary)
	if err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if o.CoreBinary, err = filepath.Rel(wd, abs); err != nil {
		t.Fatal(err)
	}
	n, err := Init(context.Background(), o, "alice", false)
	if err != nil {
		t.Fatalf("relative core %q: %v", o.CoreBinary, err)
	}
	_ = n.Close()
	n, err = Open(context.Background(), o)
	if err != nil {
		t.Fatalf("relative core %q: %v", o.CoreBinary, err)
	}
	_ = n.Close()
}

func pair(t *testing.T, a, b *Node) {
	t.Helper()
	ctx := context.Background()
	ca, rawA, err := a.Card(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cb, rawB, err := b.Card(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fpA, _ := ca.Fingerprint()
	fpB, _ := cb.Fingerprint()
	if _, err := a.AddMember(ctx, rawB, fpA); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("wrong fingerprint accepted: %v", err)
	}
	if _, err := a.AddMember(ctx, rawA, fpA); !errors.Is(err, ErrSelf) {
		t.Fatalf("own card accepted: %v", err)
	}
	if _, err := a.AddMember(ctx, rawB, fpB); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddMember(ctx, rawB, fpB); !errors.Is(err, store.ErrExists) {
		t.Fatalf("duplicate member accepted: %v", err)
	}
	if _, err := b.AddMember(ctx, rawA, fpA); err != nil {
		t.Fatal(err)
	}
}

func TestExchangeBetweenNodes(t *testing.T) {
	ctx := context.Background()
	alice, aliceOpts := initNode(t, "alice", false)
	bob, _ := initNode(t, "bob", false)
	if alice.MemberID() != "alice" || alice.PQC() {
		t.Fatalf("node info %s %v", alice.MemberID(), alice.PQC())
	}
	pair(t, alice, bob)
	members, err := alice.Members()
	if err != nil || len(members) != 1 || members[0].MemberID != "bob" {
		t.Fatalf("members %+v %v", members, err)
	}

	k, err := alice.GenerateKey(ctx, "project/db", wire.UsageEncrypt|wire.UsageDecrypt|wire.UsageExport)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.GenerateKey(ctx, "x", wire.UsageSign); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("sign usage accepted for symmetric key: %v", err)
	}
	ct, err := alice.Encrypt(ctx, k.KeyID, []byte("secret"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}

	env, err := alice.Send(ctx, k.KeyID, "bob", wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Send(ctx, k.KeyID, "carol", wire.UsageDecrypt); !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("unknown member accepted: %v", err)
	}
	var se *core.StatusError
	if _, err := alice.Send(ctx, k.KeyID, "bob", wire.UsageWrap); !errors.As(err, &se) || se.Status != wire.StatusUsageDenied {
		t.Fatalf("usage escalation accepted: %v", err)
	}
	if _, err := alice.Receive(ctx, env); !errors.Is(err, ErrNotRecipient) {
		t.Fatalf("sender accepted its own envelope: %v", err)
	}

	rec, err := bob.Receive(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if rec.KeyID != k.KeyID || rec.Usage != wire.UsageDecrypt || rec.Label != "project/db" || rec.Origin == nil || rec.Origin.Sender != "alice" {
		t.Fatalf("received %+v", rec)
	}
	pt, err := bob.Decrypt(ctx, rec.KeyID, ct, []byte("aad"))
	if err != nil || string(pt) != "secret" {
		t.Fatalf("decrypt %q %v", pt, err)
	}
	if _, err := bob.Encrypt(ctx, rec.KeyID, []byte("x"), nil); !errors.As(err, &se) || se.Status != wire.StatusUsageDenied {
		t.Fatalf("granted usage not enforced: %v", err)
	}
	if _, err := bob.Receive(ctx, env); !errors.Is(err, store.ErrExists) {
		t.Fatalf("replay accepted: %v", err)
	}
	tampered := append([]byte{}, env...)
	tampered[len(tampered)-1] ^= 1
	if _, err := bob.Receive(ctx, tampered); !errors.Is(err, exchange.ErrSignature) {
		t.Fatalf("tampered envelope accepted: %v", err)
	}

	carol, _ := initNode(t, "carol", false)
	pair(t, alice, carol)
	env2, err := alice.Send(ctx, k.KeyID, "carol", wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Receive(ctx, env2); !errors.Is(err, ErrNotRecipient) {
		t.Fatalf("misaddressed envelope accepted: %v", err)
	}
	if _, err := carol.Receive(ctx, env); !errors.Is(err, ErrNotRecipient) {
		t.Fatalf("misaddressed envelope accepted: %v", err)
	}

	if err := alice.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, aliceOpts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	keys, err := reopened.Keys()
	if err != nil || len(keys) != 5 {
		t.Fatalf("keys after reopen %d %v", len(keys), err)
	}
	if _, err := reopened.Key(ctx, k.KeyID); err != nil {
		t.Fatal(err)
	}
	env3, err := reopened.Send(ctx, k.KeyID, "bob", wire.UsageEncrypt|wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Receive(ctx, env3); !errors.Is(err, store.ErrExists) {
		t.Fatalf("expected duplicate key id, got %v", err)
	}

	entries, err := audit.Read(reopened.AuditLogPath())
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	for _, e := range entries {
		events = append(events, e.Event)
	}
	joined := strings.Join(events, ",")
	for _, want := range []string{"node.init", "member.add", "key.generate", "key.encrypt", "key.send", "node.open"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("audit log lacks %s: %s", want, joined)
		}
	}
	var failed bool
	for _, e := range entries {
		if e.Event == "key.send" && e.Fields["to"] == "carol" && e.Fields["error"] != "" {
			failed = true
		}
	}
	if !failed {
		t.Fatal("failed send to unknown member not audited")
	}
	if n, _, err := bob.VerifyAudit(nil); err != nil || n == 0 {
		t.Fatalf("bob audit %d %v", n, err)
	}
	if _, err := audit.Verify(bob.AuditLogPath(), checkpoints{n: reopened}); !errors.Is(err, audit.ErrSignature) {
		t.Fatalf("alice's audit key verified bob's log: %v", err)
	}
}

func TestAuditLogCannotBeRewrittenWithoutTheCore(t *testing.T) {
	ctx := context.Background()
	alice, o := initNode(t, "alice", false)
	if _, err := alice.GenerateKey(ctx, "k", wire.UsageEncrypt); err != nil {
		t.Fatal(err)
	}
	if n, _, err := alice.VerifyAudit(nil); err != nil || n != 2 {
		t.Fatalf("verify %d %v", n, err)
	}
	if err := alice.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(o.Dir, "audit.log")
	entries, err := audit.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	forged := filepath.Join(t.TempDir(), "forged.log")
	fl, err := audit.Open(forged, audit.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		f := e.Fields
		if e.Event == "key.generate" {
			f = map[string]string{"key": "0000", "label": "k", "usage": "1"}
		}
		if err := fl.Append(e.Event, f); err != nil {
			t.Fatal(err)
		}
	}
	_ = fl.Close()
	raw, _ := os.ReadFile(forged)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, o); !errors.Is(err, audit.ErrSignature) {
		t.Fatalf("node opened with a rewritten audit log: %v", err)
	}
}

func TestStoredMetadataIsVerifiedAgainstCore(t *testing.T) {
	ctx := context.Background()
	alice, o := initNode(t, "alice", false)
	k, err := alice.GenerateKey(ctx, "label", wire.UsageEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(o.Dir, "keys", k.KeyID+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rec store.KeyRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	rec.Usage = wire.UsageEncrypt | wire.UsageDecrypt | wire.UsageExport
	edited, _ := json.Marshal(&rec)
	if err := os.WriteFile(path, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Key(ctx, k.KeyID); !errors.Is(err, ErrMetadata) {
		t.Fatalf("metadata tamper not detected: %v", err)
	}
	kemPath := filepath.Join(o.Dir, "keys", alice.info.KemKeyID+".json")
	kraw, err := os.ReadFile(kemPath)
	if err != nil {
		t.Fatal(err)
	}
	var krec store.KeyRecord
	if err := json.Unmarshal(kraw, &krec); err != nil {
		t.Fatal(err)
	}
	krec.PublicKey[len(krec.PublicKey)-1] ^= 1
	kedit, _ := json.Marshal(&krec)
	if err := os.WriteFile(kemPath, kedit, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Key(ctx, krec.KeyID); !errors.Is(err, ErrMetadata) {
		t.Fatalf("swapped kem public key not detected: %v", err)
	}
	if _, err := Open(ctx, o); err == nil {
		t.Fatal("node opened with a swapped kem public key")
	}
	if _, err := alice.Encrypt(ctx, k.KeyID, []byte("x"), nil); !errors.Is(err, ErrMetadata) {
		t.Fatalf("tampered key usable: %v", err)
	}

	bob, bobOpts := initNode(t, "bob", false)
	_, rawA, _ := alice.Card(ctx)
	ca, _ := exchange.DecodeCard(rawA)
	fp, _ := ca.Fingerprint()
	if _, err := bob.AddMember(ctx, rawA, fp); err != nil {
		t.Fatal(err)
	}
	mpath := filepath.Join(bobOpts.Dir, "members", "alice.json")
	mraw, _ := os.ReadFile(mpath)
	var m store.MemberRecord
	_ = json.Unmarshal(mraw, &m)
	m.Fingerprint = "0000"
	medit, _ := json.Marshal(&m)
	if err := os.WriteFile(mpath, medit, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Member(ctx, "alice"); !errors.Is(err, ErrMetadata) {
		t.Fatalf("member tamper not detected: %v", err)
	}
}

func TestPQCNodes(t *testing.T) {
	ctx := context.Background()
	alice, _ := initNode(t, "alice", true)
	if !alice.Core().PQC() {
		t.Skip("core built without pqc")
	}
	bob, _ := initNode(t, "bob", true)
	pair(t, alice, bob)
	card, _, _ := alice.Card(ctx)
	if card.IdentityAlg != wire.AlgMLDSA65 || card.KemAlg != wire.AlgMLKEM768P256 {
		t.Fatalf("pqc algs %x %x", card.IdentityAlg, card.KemAlg)
	}
	k, err := alice.GenerateKey(ctx, "k", wire.UsageDecrypt|wire.UsageExport)
	if err != nil {
		t.Fatal(err)
	}
	env, err := alice.Send(ctx, k.KeyID, "bob", wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Receive(ctx, env); err != nil {
		t.Fatal(err)
	}
	carol, _ := initNode(t, "carol", true)
	legacy := &exchange.Card{
		MemberID:          "carol",
		IdentityAlg:       carol.identity.Alg,
		IdentityPublicKey: carol.identity.PublicKey,
		KemAlg:            wire.AlgHybridP256MLKEM768,
		KemPublicKey:      bytes.Repeat([]byte{4}, 1249),
		TLSPublicKey:      carol.TLSPublicKey(),
		CreatedAt:         uint64(carol.info.CreatedAt),
	}
	if err := exchange.SignCard(ctx, carol.core, carol.identity.Blob, legacy); err != nil {
		t.Fatal(err)
	}
	rawLegacy, _ := legacy.Encode()
	fpLegacy, _ := legacy.Fingerprint()
	if _, err := alice.AddMember(ctx, rawLegacy, fpLegacy); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.Send(ctx, k.KeyID, "carol", wire.UsageDecrypt); !errors.Is(err, ErrRetiredKEM) {
		t.Fatalf("send to a retired kem card: %v", err)
	}
	classic, _ := initNode(t, "dave", false)
	_, rawA, _ := alice.Card(ctx)
	fp, _ := card.Fingerprint()
	var se *core.StatusError
	if _, err := classic.AddMember(ctx, rawA, fp); !errors.As(err, &se) || se.Status != wire.StatusCapabilityDisabled {
		t.Fatalf("node without pqc must refuse a pqc card, got %v", err)
	}
}

func TestUnknownPeerNeedsNoCoreCall(t *testing.T) {
	ctx := context.Background()
	alice, _ := initNode(t, "alice", false)
	bob, _ := initNode(t, "bob", false)
	pair(t, alice, bob)
	if err := alice.core.Close(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		id   string
		spki []byte
	}{
		{"carol", bob.TLSPublicKey()},
		{"bob", alice.TLSPublicKey()},
		{"bob", []byte("stranger")},
	} {
		if _, err := alice.MemberByTLS(ctx, c.id, c.spki); !errors.Is(err, ErrUnknownMember) {
			t.Fatalf("%s: unknown peer reached the core: %v", c.id, err)
		}
	}
	if _, err := alice.MemberByTLS(ctx, "bob", bob.TLSPublicKey()); err == nil || errors.Is(err, ErrUnknownMember) {
		t.Fatalf("known peer must still be verified by the core: %v", err)
	}
}

func TestTLSMaterialAndPeerLookup(t *testing.T) {
	ctx := context.Background()
	alice, aliceOpts := initNode(t, "alice", false)
	bob, _ := initNode(t, "bob", false)
	if cert, err := alice.TLSCertificate(); err != nil || cert.Leaf == nil || len(alice.TLSPublicKey()) == 0 {
		t.Fatal("tls material missing after init")
	}
	card, _, err := alice.Card(ctx)
	if err != nil || !bytes.Equal(card.TLSPublicKey, alice.TLSPublicKey()) {
		t.Fatalf("card tls key mismatch: %v", err)
	}
	pair(t, alice, bob)
	found, err := alice.MemberByTLS(ctx, "bob", bob.TLSPublicKey())
	if err != nil || found.MemberID != "bob" {
		t.Fatalf("lookup: %+v %v", found, err)
	}
	for _, c := range []struct {
		id   string
		spki []byte
	}{
		{"alice", alice.TLSPublicKey()},
		{"bob", alice.TLSPublicKey()},
		{"carol", bob.TLSPublicKey()},
		{"../bob", bob.TLSPublicKey()},
		{"bob", nil},
	} {
		if _, err := alice.MemberByTLS(ctx, c.id, c.spki); !errors.Is(err, ErrUnknownMember) {
			t.Fatalf("%s resolved: %v", c.id, err)
		}
	}
	spki := alice.TLSPublicKey()
	if err := alice.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, aliceOpts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !bytes.Equal(reopened.TLSPublicKey(), spki) {
		t.Fatal("tls key changed after reopen")
	}
	if cert, err := reopened.TLSCertificate(); err != nil || cert.Leaf.Subject.CommonName != "alice" {
		t.Fatalf("certificate subject: %v", err)
	}
	keys, _ := reopened.Keys()
	if len(keys) != 4 {
		t.Fatalf("expected identity, kem, audit and tls keys, got %d", len(keys))
	}
}

func TestInboxPendingLimitPerSender(t *testing.T) {
	ctx := context.Background()
	alice, _ := initNode(t, "alice", false)
	bob, _ := initNode(t, "bob", false)
	pair(t, alice, bob)
	k, err := alice.GenerateKey(ctx, "k", wire.UsageDecrypt|wire.UsageExport)
	if err != nil {
		t.Fatal(err)
	}
	send := func() []byte {
		env, err := alice.Send(ctx, k.KeyID, "bob", wire.UsageDecrypt)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	var first string
	for i := 0; i < MaxPendingPerSender; i++ {
		rec, err := bob.StoreInbox(ctx, send(), "alice")
		if err != nil {
			t.Fatalf("envelope %d: %v", i, err)
		}
		if first == "" {
			first = rec.ID
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := bob.StoreInbox(ctx, send(), "alice"); !errors.Is(err, ErrInboxFull) {
			t.Fatalf("limit not enforced: %v", err)
		}
	}
	if heads, err := bob.Witnessed("alice"); err != nil || len(heads) != MaxPendingPerSender {
		t.Fatalf("rejected envelopes were witnessed: %d %v", len(heads), err)
	}
	if err := bob.Reject(ctx, first); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.StoreInbox(ctx, send(), "alice"); err != nil {
		t.Fatalf("slot not freed after reject: %v", err)
	}
}

func TestLabelsRejectControlCharacters(t *testing.T) {
	ctx := context.Background()
	alice, _ := initNode(t, "alice", false)
	for _, l := range []string{"a\nb", "\x1b[2J", "a‮b", "⁦x", "a\x7f", "a\u0085", "\xff"} {
		if _, err := alice.GenerateKey(ctx, l, wire.UsageEncrypt); !errors.Is(err, ErrLabel) {
			t.Fatalf("%q accepted: %v", l, err)
		}
	}
	if _, err := alice.GenerateKey(ctx, "프로젝트/db", wire.UsageEncrypt); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.core.GenerateKey(ctx, wire.AlgAES256GCM, wire.UsageEncrypt, "a\nb"); err == nil {
		t.Fatal("core accepted a control character in a label")
	}
}

func writeLegacyTLS(t *testing.T, n *Node, dir string) []byte {
	t.Helper()
	ctx := context.Background()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: n.info.MemberID},
		NotBefore:             time.Unix(1_600_000_000, 0),
		NotAfter:              time.Unix(2_000_000_000, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	label := "tls-wrap/" + n.info.MemberID
	wrap, err := n.core.GenerateKey(ctx, wire.AlgAES256GCM, wire.UsageEncrypt|wire.UsageDecrypt, label)
	if err != nil {
		t.Fatal(err)
	}
	wrapRec := &store.KeyRecord{KeyID: store.KeyIDString(wrap.KeyID), Alg: wire.AlgAES256GCM, Usage: wire.UsageEncrypt | wire.UsageDecrypt, Label: label, Blob: wrap.Blob, CreatedAt: 1}
	if err := n.st.PutKey(wrapRec); err != nil {
		t.Fatal(err)
	}
	ct, err := n.core.Encrypt(ctx, wrap.Blob, keyDER, certDER)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(&store.TLSRecord{Cert: certDER, WrapKeyID: wrapRec.KeyID, KeyCiphertext: ct, CreatedAt: 1})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "tls.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return leaf.RawSubjectPublicKeyInfo
}

func hasEvent(t *testing.T, path, event string) bool {
	t.Helper()
	entries, err := audit.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Event == event {
			return true
		}
	}
	return false
}

func TestTLSKeyStaysInCore(t *testing.T) {
	alice, o := initNode(t, "alice", false)
	cert, err := alice.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := cert.PrivateKey.(*coreSigner)
	if !ok {
		t.Fatalf("tls private key type %T", cert.PrivateKey)
	}
	raw, err := os.ReadFile(filepath.Join(o.Dir, "tls.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("key_ciphertext")) || bytes.Contains(raw, []byte("wrap_key_id")) || !bytes.Contains(raw, []byte("key_id")) {
		t.Fatalf("tls record holds key material: %s", raw)
	}
	if _, err := signer.Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err == nil {
		t.Fatal("pre-hashed signing accepted")
	}
	if _, err := signer.SignMessage(rand.Reader, []byte("m"), crypto.SHA384); err == nil {
		t.Fatal("sha-384 signing accepted")
	}
	sig, err := signer.SignMessage(rand.Reader, []byte("message"), crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("message"))
	if !ecdsa.VerifyASN1(cert.Leaf.PublicKey.(*ecdsa.PublicKey), digest[:], sig) {
		t.Fatal("core tls signature does not verify")
	}
	if err := cert.Leaf.CheckSignature(cert.Leaf.SignatureAlgorithm, cert.Leaf.RawTBSCertificate, cert.Leaf.Signature); err != nil {
		t.Fatalf("self-signed certificate: %v", err)
	}
}

func TestLegacyTLSNodeRenewsCard(t *testing.T) {
	ctx := context.Background()
	alice, aliceOpts := initNode(t, "alice", false)
	bob, _ := initNode(t, "bob", false)
	pair(t, alice, bob)
	legacySPKI := writeLegacyTLS(t, alice, aliceOpts.Dir)
	if err := alice.Close(); err != nil {
		t.Fatal(err)
	}
	legacy, err := Open(ctx, aliceOpts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.TLSCertificate(); !errors.Is(err, ErrLegacyTLS) {
		t.Fatalf("legacy tls key loaded: %v", err)
	}
	if !bytes.Equal(legacy.TLSPublicKey(), legacySPKI) {
		t.Fatal("legacy card must keep its tls key until renewal")
	}
	oldCard, _, err := legacy.Card(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldFP, _ := oldCard.Fingerprint()
	card, rawCard, err := legacy.RenewCard(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fp, _ := card.Fingerprint()
	if bytes.Equal(card.TLSPublicKey, legacySPKI) || fp == oldFP {
		t.Fatal("renewal kept the legacy tls key")
	}
	if !bytes.Equal(card.KemPublicKey, oldCard.KemPublicKey) || !bytes.Equal(card.IdentityPublicKey, oldCard.IdentityPublicKey) {
		t.Fatal("renewal changed keys that are not retired")
	}
	if _, err := legacy.TLSCertificate(); err != nil {
		t.Fatal(err)
	}
	if !hasEvent(t, legacy.AuditLogPath(), "card.renew") {
		t.Fatal("card renewal not audited")
	}

	if _, err := bob.MemberByTLS(ctx, "alice", card.TLSPublicKey); !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("renewed key trusted before the card was updated: %v", err)
	}
	if _, err := bob.AddMember(ctx, rawCard, oldFP); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("renewed card accepted with the old fingerprint: %v", err)
	}
	rec, err := bob.AddMember(ctx, rawCard, fp)
	if err != nil || rec.UpdatedAt == 0 || rec.AddedAt == 0 {
		t.Fatalf("member update: %+v %v", rec, err)
	}
	if _, err := bob.AddMember(ctx, rawCard, fp); !errors.Is(err, store.ErrExists) {
		t.Fatalf("same card added twice: %v", err)
	}
	if _, err := bob.MemberByTLS(ctx, "alice", card.TLSPublicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := bob.MemberByTLS(ctx, "alice", legacySPKI); !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("legacy tls key still trusted: %v", err)
	}
	if !hasEvent(t, bob.AuditLogPath(), "member.update") {
		t.Fatal("member update not audited")
	}
	impostor, _ := initNode(t, "alice", false)
	impCard, rawImp, _ := impostor.Card(ctx)
	impFP, _ := impCard.Fingerprint()
	if _, err := bob.AddMember(ctx, rawImp, impFP); !errors.Is(err, ErrIdentityChanged) {
		t.Fatalf("card with another identity replaced a member: %v", err)
	}

	k, err := bob.GenerateKey(ctx, "after-renew", wire.UsageDecrypt|wire.UsageExport)
	if err != nil {
		t.Fatal(err)
	}
	env, err := bob.Send(ctx, k.KeyID, "alice", wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Receive(ctx, env); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, aliceOpts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.TLSCertificate(); err != nil || !bytes.Equal(reopened.TLSPublicKey(), card.TLSPublicKey) {
		t.Fatalf("renewed tls key after reopen: %v", err)
	}
}

func TestRenewKEMReplacesTheNodeKem(t *testing.T) {
	ctx := context.Background()
	alice, o := initNode(t, "alice", true)
	if !alice.Core().PQC() {
		t.Skip("core built without pqc")
	}
	old := alice.kem.KeyID
	if err := alice.renewKEM(ctx); err != nil {
		t.Fatal(err)
	}
	if alice.kem.KeyID == old || alice.kem.Alg != wire.AlgMLKEM768P256 || alice.info.KemKeyID != alice.kem.KeyID {
		t.Fatalf("kem after renewal: %+v", alice.kem)
	}
	card, _, err := alice.Card(ctx)
	if err != nil || !bytes.Equal(card.KemPublicKey, alice.kem.PublicKey) {
		t.Fatalf("card kem: %v", err)
	}
	if err := alice.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, o)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.kem.KeyID != alice.kem.KeyID {
		t.Fatal("renewed kem not persisted")
	}
}

func TestAddWitnessHeadKeepsOrderAndCap(t *testing.T) {
	h := func(seq uint64, b byte) store.WitnessHead {
		return store.WitnessHead{Seq: seq, Hash: strings.Repeat(string("0123456789abcdef"[b%16]), 64)}
	}
	heads, changed, conflict := addWitnessHead(nil, h(5, 1))
	if !changed || conflict != "" || len(heads) != 1 {
		t.Fatal("first head")
	}
	heads, _, _ = addWitnessHead(heads, h(9, 2))
	heads, changed, _ = addWitnessHead(heads, h(2, 3))
	if !changed || heads[0].Seq != 2 || heads[1].Seq != 5 || heads[2].Seq != 9 {
		t.Fatalf("out of order delivery: %+v", heads)
	}
	if _, changed, conflict := addWitnessHead(heads, h(5, 1)); changed || conflict != "" {
		t.Fatal("repeated head changed the record")
	}
	if _, changed, conflict := addWitnessHead(heads, h(5, 7)); changed || conflict != h(5, 1).Hash {
		t.Fatalf("fork not reported: %q", conflict)
	}
	full := make([]store.WitnessHead, 0, store.MaxWitnessHeads)
	for i := 1; i <= store.MaxWitnessHeads; i++ {
		full = append(full, h(uint64(i)*2, 4))
	}
	full, changed, _ = addWitnessHead(full, h(uint64(store.MaxWitnessHeads)*2+1, 5))
	if !changed || len(full) != store.MaxWitnessHeads || full[0].Seq != 4 || full[len(full)-1].Seq != uint64(store.MaxWitnessHeads)*2+1 {
		t.Fatalf("cap kept %d heads from %d", len(full), full[0].Seq)
	}
}

func TestPeersWitnessAuditHeads(t *testing.T) {
	ctx := context.Background()
	alice, aliceOpts := initNode(t, "alice", false)
	bob, _ := initNode(t, "bob", false)
	pair(t, alice, bob)
	k, err := alice.GenerateKey(ctx, "witnessed", wire.UsageDecrypt|wire.UsageExport)
	if err != nil {
		t.Fatal(err)
	}
	seq, hash := alice.log.Head()
	env, err := alice.Send(ctx, k.KeyID, "bob", wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.Receive(ctx, env); err != nil {
		t.Fatal(err)
	}
	heads, err := bob.Witnessed("alice")
	if err != nil || len(heads) != 1 || heads[0] != (audit.Anchor{Seq: seq, Hash: hash}) {
		t.Fatalf("witnessed %v %v, want %d:%s", heads, err, seq, hash)
	}
	env2, err := alice.Send(ctx, k.KeyID, "bob", wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.StoreInbox(ctx, env2, "alice"); err != nil {
		t.Fatal(err)
	}
	if heads, _ = bob.Witnessed("alice"); len(heads) != 2 {
		t.Fatalf("inbox delivery not witnessed: %v", heads)
	}
	if none, err := alice.Witnessed("carol"); err != nil || len(none) != 0 {
		t.Fatalf("unknown member witness: %v %v", none, err)
	}
	if _, _, err := alice.VerifyAudit(heads); err != nil {
		t.Fatal(err)
	}

	rec, err := alice.Key(ctx, k.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	card, err := alice.Member(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	forged, err := exchange.NewContext("alice", "bob", alice.opts.now(), heads[0].Seq, bytes.Repeat([]byte{0x11}, exchange.AuditHashLen))
	if err != nil {
		t.Fatal(err)
	}
	cb, _ := forged.Encode()
	pkg, err := alice.core.ExportKey(ctx, rec.Blob, card.KemAlg, card.KemPublicKey, wire.UsageDecrypt, cb)
	if err != nil {
		t.Fatal(err)
	}
	fenv, err := exchange.Seal(ctx, alice.core, alice.identity.Blob, alice.identity.Alg, forged, pkg)
	if err != nil {
		t.Fatal(err)
	}
	rawForged, _ := fenv.Encode()
	if _, err := bob.Receive(ctx, rawForged); !errors.Is(err, ErrWitnessConflict) {
		t.Fatalf("forked audit head accepted: %v", err)
	}
	if !hasEvent(t, bob.AuditLogPath(), "witness.conflict") {
		t.Fatal("witness conflict not audited")
	}
	if after, _ := bob.Witnessed("alice"); len(after) != 2 || after[0] != heads[0] {
		t.Fatalf("conflict changed the witness record: %v", after)
	}

	if err := alice.Close(); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(aliceOpts.Dir, "audit.log")
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(raw), "\n")
	if err := os.WriteFile(logPath, []byte(strings.Join(lines[:int(heads[0].Seq)-1], "")), 0o600); err != nil {
		t.Fatal(err)
	}
	rolled, err := Open(ctx, aliceOpts)
	if err != nil {
		t.Fatal(err)
	}
	defer rolled.Close()
	for i := 0; i < 5; i++ {
		if _, err := rolled.GenerateKey(ctx, "refill", wire.UsageEncrypt); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := rolled.VerifyAudit(nil); err != nil {
		t.Fatalf("rolled back log is still a valid chain: %v", err)
	}
	if _, _, err := rolled.VerifyAudit(heads); !errors.Is(err, audit.ErrRollback) {
		t.Fatalf("rollback hidden from the witnessed heads: %v", err)
	}
}

func TestEnvelopeWithoutAuditHeadIsRejected(t *testing.T) {
	ctx := context.Background()
	alice, _ := initNode(t, "alice", false)
	bob, _ := initNode(t, "bob", false)
	pair(t, alice, bob)
	k, err := alice.GenerateKey(ctx, "headless", wire.UsageDecrypt|wire.UsageExport)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := alice.Key(ctx, k.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	card, err := alice.Member(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	var nonce [exchange.NonceLen]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	w := wire.NewWriter()
	w.U8(1)
	w.String("alice")
	w.String("bob")
	w.U64(uint64(alice.opts.now().Unix()))
	w.Bytes(nonce[:])
	cb, err := w.Finish()
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := alice.core.ExportKey(ctx, rec.Blob, card.KemAlg, card.KemPublicKey, wire.UsageDecrypt, cb)
	if err != nil {
		t.Fatal(err)
	}
	sw := wire.NewWriter()
	sw.Bytes(cb)
	sw.Bytes(pkg)
	sw.U16(alice.identity.Alg)
	body, err := sw.Finish()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := alice.core.Sign(ctx, alice.identity.Blob, append([]byte("KXP1"), body...))
	if err != nil {
		t.Fatal(err)
	}
	env := &exchange.Envelope{Context: cb, Package: pkg, SigAlg: alice.identity.Alg, Signature: sig}
	raw, err := env.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.StoreInbox(ctx, raw, "alice"); !errors.Is(err, exchange.ErrFormat) {
		t.Fatalf("envelope without audit head stored: %v", err)
	}
	if _, err := bob.Receive(ctx, raw); !errors.Is(err, exchange.ErrFormat) {
		t.Fatalf("envelope without audit head received: %v", err)
	}
	if heads, err := bob.Witnessed("alice"); err != nil || len(heads) != 0 {
		t.Fatalf("witness record changed: %v %v", heads, err)
	}
}
