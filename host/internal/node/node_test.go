package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	if alice.TLSCertificate().Leaf == nil || len(alice.TLSPublicKey()) == 0 {
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
	if reopened.TLSCertificate().Leaf.Subject.CommonName != "alice" {
		t.Fatal("certificate subject")
	}
	keys, _ := reopened.Keys()
	if len(keys) != 4 {
		t.Fatalf("expected identity, kem, audit and tls-wrap keys, got %d", len(keys))
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
	if _, err := bob.StoreInbox(ctx, send(), "alice"); !errors.Is(err, ErrInboxFull) {
		t.Fatalf("limit not enforced: %v", err)
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
