package exchange

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/Quant-Off/pairier/host/internal/core"
	"github.com/Quant-Off/pairier/host/internal/wire"
)

func TestContextRoundtripAndValidation(t *testing.T) {
	c, err := NewContext("alice", "bob", time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeContext(b)
	if err != nil {
		t.Fatal(err)
	}
	if d.Sender != "alice" || d.Recipient != "bob" || d.CreatedAt != 1_700_000_000 || d.Nonce != c.Nonce {
		t.Fatalf("mismatch %+v", d)
	}
	if _, err := DecodeContext(append(b, 0)); !errors.Is(err, ErrFormat) {
		t.Fatalf("trailing bytes accepted: %v", err)
	}
	if _, err := DecodeContext(b[:len(b)-1]); !errors.Is(err, ErrFormat) {
		t.Fatalf("truncated accepted: %v", err)
	}
	for _, bad := range []string{"", "Alice", "-a", "a b", "a/b", string(make([]byte, 65))} {
		if _, err := NewContext(bad, "bob", time.Now()); !errors.Is(err, ErrBadMemberID) {
			t.Fatalf("member id %q accepted: %v", bad, err)
		}
	}
	if _, err := NewContext("alice", "alice", time.Now()); !errors.Is(err, ErrBadMemberID) {
		t.Fatal("self exchange accepted")
	}
	c2, _ := NewContext("alice", "bob", time.Now())
	if c2.Nonce == c.Nonce {
		t.Fatal("nonce not fresh")
	}
}

func TestEnvelopeAndCardEncoding(t *testing.T) {
	cb, _ := (&Context{Sender: "a", Recipient: "b", CreatedAt: 1}).Encode()
	e := &Envelope{Context: cb, Package: []byte("pkg"), SigAlg: wire.AlgECDSAP256SHA256, Signature: []byte("sig")}
	b, err := e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeEnvelope(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(d.Context, cb) || string(d.Package) != "pkg" || d.SigAlg != e.SigAlg || string(d.Signature) != "sig" {
		t.Fatalf("mismatch %+v", d)
	}
	if _, err := DecodeEnvelope(append(b, 0)); !errors.Is(err, ErrFormat) {
		t.Fatal("trailing bytes accepted")
	}
	bad := append([]byte{}, b...)
	bad[0] = 'X'
	if _, err := DecodeEnvelope(bad); !errors.Is(err, ErrFormat) {
		t.Fatal("bad magic accepted")
	}
	e.SigAlg = wire.AlgAES256GCM
	b2, _ := e.Encode()
	if _, err := DecodeEnvelope(b2); !errors.Is(err, ErrAlgorithm) {
		t.Fatal("non-signature alg accepted")
	}

	card := &Card{MemberID: "bob", IdentityAlg: wire.AlgEd25519, IdentityPublicKey: make([]byte, 32), KemAlg: wire.AlgDHKEMP256, KemPublicKey: make([]byte, 65), CreatedAt: 7, Signature: []byte("s")}
	cb2, err := card.Encode()
	if err != nil {
		t.Fatal(err)
	}
	dc, err := DecodeCard(cb2)
	if err != nil {
		t.Fatal(err)
	}
	fp1, _ := card.Fingerprint()
	fp2, _ := dc.Fingerprint()
	if fp1 != fp2 || len(NormalizeFingerprint(fp1)) != 64 {
		t.Fatalf("fingerprint %q %q", fp1, fp2)
	}
	if !dc.MatchesFingerprint(" "+fp1+" ") || dc.MatchesFingerprint(fp1[:10]) {
		t.Fatal("fingerprint matching")
	}
	dc.KemPublicKey[0] ^= 1
	fp3, _ := dc.Fingerprint()
	if fp3 == fp1 {
		t.Fatal("fingerprint ignores kem key")
	}
	card.KemAlg = wire.AlgEd25519
	if _, err := card.Encode(); !errors.Is(err, ErrAlgorithm) {
		t.Fatal("kem alg not validated")
	}
	card.KemAlg = wire.AlgDHKEMP256
	card.MemberID = "Bob"
	if _, err := card.Encode(); !errors.Is(err, ErrBadMemberID) {
		t.Fatal("member id not validated")
	}
}

func realCore(t *testing.T) *core.Client {
	t.Helper()
	bin := os.Getenv("KMS_CORE_BIN")
	if bin == "" {
		t.Skip("KMS_CORE_BIN not set")
	}
	c, err := core.Spawn(context.Background(), core.Options{Binary: bin, EphemeralRoot: true, PQC: true, AllowUnlockedMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestSignedEnvelopeAndCardWithRealCore(t *testing.T) {
	a := realCore(t)
	b := realCore(t)
	ctx := context.Background()
	sigAlg, kemAlg := uint16(wire.AlgECDSAP256SHA256), uint16(wire.AlgDHKEMP256)
	if a.PQC() {
		sigAlg, kemAlg = wire.AlgMLDSA65, wire.AlgHybridP256MLKEM768
	}
	aid, err := a.GenerateKey(ctx, sigAlg, wire.UsageSign, "a/identity")
	if err != nil {
		t.Fatal(err)
	}
	bid, err := b.GenerateKey(ctx, sigAlg, wire.UsageSign, "b/identity")
	if err != nil {
		t.Fatal(err)
	}
	bkem, err := b.GenerateKey(ctx, kemAlg, wire.UsageDecapsulate, "b/kem")
	if err != nil {
		t.Fatal(err)
	}
	card := &Card{MemberID: "bob", IdentityAlg: sigAlg, IdentityPublicKey: bid.PublicKey, KemAlg: kemAlg, KemPublicKey: bkem.PublicKey, CreatedAt: 1}
	if err := SignCard(ctx, b, bid.Blob, card); err != nil {
		t.Fatal(err)
	}
	enc, _ := card.Encode()
	received, err := DecodeCard(enc)
	if err != nil {
		t.Fatal(err)
	}
	if err := received.Verify(ctx, a); err != nil {
		t.Fatalf("card verify: %v", err)
	}
	forged := *received
	forged.KemPublicKey = append([]byte{}, received.KemPublicKey...)
	forged.KemPublicKey[1] ^= 1
	if err := forged.Verify(ctx, a); !errors.Is(err, ErrSignature) {
		t.Fatalf("forged card accepted: %v", err)
	}

	k, err := a.GenerateKey(ctx, wire.AlgAES256GCM, wire.UsageEncrypt|wire.UsageDecrypt|wire.UsageExport, "shared")
	if err != nil {
		t.Fatal(err)
	}
	ectx, _ := NewContext("alice", "bob", time.Now())
	cb, _ := ectx.Encode()
	pkg, err := a.ExportKey(ctx, k.Blob, received.KemAlg, received.KemPublicKey, wire.UsageDecrypt, cb)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(ctx, a, aid.Blob, sigAlg, ectx, pkg)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := env.Encode()
	got, err := DecodeEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	gctx, err := got.Verify(ctx, b, aid.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if gctx.Sender != "alice" || gctx.Recipient != "bob" {
		t.Fatalf("context %+v", gctx)
	}
	if _, err := got.Verify(ctx, b, bid.PublicKey); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong signer accepted: %v", err)
	}
	tampered := *got
	tampered.Package = append([]byte{}, got.Package...)
	tampered.Package[len(tampered.Package)-1] ^= 1
	if _, err := tampered.Verify(ctx, b, aid.PublicKey); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered package accepted: %v", err)
	}
	imp, err := b.ImportKey(ctx, bkem.Blob, got.Package, got.Context)
	if err != nil {
		t.Fatal(err)
	}
	if imp.KeyID != k.KeyID || imp.Usage != wire.UsageDecrypt {
		t.Fatalf("imported %+v", imp)
	}
}
