package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Quant-Off/pairier/host/internal/exchange"
	"github.com/Quant-Off/pairier/host/internal/node"
	"github.com/Quant-Off/pairier/host/internal/wire"
)

func initNode(t *testing.T, id string) *node.Node {
	t.Helper()
	bin := os.Getenv("KMS_CORE_BIN")
	if bin == "" {
		t.Skip("KMS_CORE_BIN not set")
	}
	n, err := node.Init(context.Background(), node.Options{Dir: filepath.Join(t.TempDir(), id), CoreBinary: bin, AllowUnlockedMemory: true, Timeout: 5 * time.Second}, id, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.Close() })
	return n
}

func trust(t *testing.T, a, b *node.Node) {
	t.Helper()
	ctx := context.Background()
	ca, rawA, _ := a.Card(ctx)
	cb, rawB, _ := b.Card(ctx)
	fpA, _ := ca.Fingerprint()
	fpB, _ := cb.Fingerprint()
	if _, err := a.AddMember(ctx, rawB, fpB); err != nil {
		t.Fatal(err)
	}
	if _, err := b.AddMember(ctx, rawA, fpA); err != nil {
		t.Fatal(err)
	}
}

func serve(t *testing.T, n *node.Node) string {
	t.Helper()
	srv := New(n, nil)
	tlsConfig, err := srv.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
	})
	return "https://" + ln.Addr().String()
}

func TestPushInboxAndAccept(t *testing.T) {
	ctx := context.Background()
	alice := initNode(t, "alice")
	bob := initNode(t, "bob")
	carol := initNode(t, "carol")
	trust(t, alice, bob)
	trust(t, alice, carol)
	bobURL := serve(t, bob)

	if err := NewClient(alice, nil).Health(ctx, bobURL, "bob"); err != nil {
		t.Fatalf("health: %v", err)
	}
	if err := NewClient(carol, nil).Health(ctx, bobURL, "alice"); err == nil {
		t.Fatal("pinned to the wrong member yet connection succeeded")
	}
	if err := NewClient(carol, nil).Health(ctx, bobURL, "bob"); err == nil {
		t.Fatal("unknown client certificate accepted by bob")
	}

	k, err := alice.GenerateKey(ctx, "shared", wire.UsageEncrypt|wire.UsageDecrypt|wire.UsageExport)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := alice.Encrypt(ctx, k.KeyID, []byte("hello bob"), nil)
	if err != nil {
		t.Fatal(err)
	}
	env, err := alice.Send(ctx, k.KeyID, "bob", wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewClient(alice, nil).Push(ctx, bobURL, "bob", env)
	if err != nil {
		t.Fatalf("push: %v", err)
	}
	if _, err := NewClient(alice, nil).Push(ctx, bobURL, "bob", env); err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("duplicate push accepted: %v", err)
	}
	envCarol, err := alice.Send(ctx, k.KeyID, "carol", wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(alice, nil).Push(ctx, bobURL, "bob", envCarol); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("misaddressed envelope accepted: %v", err)
	}
	tampered := append([]byte{}, env...)
	tampered[len(tampered)-1] ^= 1
	if _, err := NewClient(alice, nil).Push(ctx, bobURL, "bob", tampered); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("tampered envelope accepted: %v", err)
	}

	items, err := bob.Inbox()
	if err != nil || len(items) != 1 || items[0].ID != id || items[0].Sender != "alice" {
		t.Fatalf("inbox %+v %v", items, err)
	}
	rec, err := bob.Accept(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if rec.KeyID != k.KeyID || rec.Origin.Sender != "alice" {
		t.Fatalf("accepted %+v", rec)
	}
	pt, err := bob.Decrypt(ctx, rec.KeyID, ct, nil)
	if err != nil || string(pt) != "hello bob" {
		t.Fatalf("decrypt %q %v", pt, err)
	}
	if items, _ := bob.Inbox(); len(items) != 0 {
		t.Fatal("inbox not cleared after accept")
	}
	if _, err := bob.Accept(ctx, id); err == nil {
		t.Fatal("accept of a missing item succeeded")
	}

	env2, _ := alice.Send(ctx, k.KeyID, "bob", wire.UsageDecrypt)
	id2, err := NewClient(alice, nil).Push(ctx, bobURL, "bob", env2)
	if err != nil {
		t.Fatal(err)
	}
	if err := bob.Reject(ctx, id2); err != nil {
		t.Fatal(err)
	}
	if items, _ := bob.Inbox(); len(items) != 0 {
		t.Fatal("inbox not cleared after reject")
	}
	if _, err := bob.StoreInbox(ctx, env2, "carol"); !errors.Is(err, node.ErrSenderMismatch) {
		t.Fatalf("sender mismatch accepted: %v", err)
	}
	trust(t, carol, bob)
	envFromCarol, err := carol.Send(ctx, mustKey(t, carol), "bob", wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(alice, nil).Push(ctx, bobURL, "bob", envFromCarol); err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("relayed envelope from another sender accepted: %v", err)
	}
	dave := initNode(t, "dave")
	trust(t, dave, carol)
	envFromDave, err := dave.Send(ctx, mustKey(t, dave), "carol", wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.StoreInbox(ctx, envFromDave, "dave"); !errors.Is(err, node.ErrNotRecipient) {
		t.Fatalf("envelope for another recipient accepted: %v", err)
	}
	cb, rawB, _ := bob.Card(ctx)
	fpB, _ := cb.Fingerprint()
	if _, err := dave.AddMember(ctx, rawB, fpB); err != nil {
		t.Fatal(err)
	}
	envToBob, err := dave.Send(ctx, mustKey(t, dave), "bob", wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.StoreInbox(ctx, envToBob, "dave"); !errors.Is(err, node.ErrUnknownMember) {
		t.Fatalf("envelope from an unknown member accepted: %v", err)
	}
	if _, err := bob.StoreInbox(ctx, []byte("junk"), "alice"); !errors.Is(err, exchange.ErrFormat) {
		t.Fatalf("junk accepted: %v", err)
	}
}

func mustKey(t *testing.T, n *node.Node) string {
	t.Helper()
	k, err := n.GenerateKey(context.Background(), "relay", wire.UsageDecrypt|wire.UsageExport)
	if err != nil {
		t.Fatal(err)
	}
	return k.KeyID
}

func TestWitnessedHeadsComeBackOnline(t *testing.T) {
	ctx := context.Background()
	alice := initNode(t, "alice")
	bob := initNode(t, "bob")
	carol := initNode(t, "carol")
	trust(t, alice, bob)
	trust(t, bob, carol)
	bobURL := serve(t, bob)

	heads, err := NewClient(alice, nil).Witness(ctx, bobURL, "bob")
	if err != nil || len(heads) != 0 {
		t.Fatalf("witness before any exchange: %v %v", heads, err)
	}
	k, err := alice.GenerateKey(ctx, "shared", wire.UsageDecrypt|wire.UsageExport)
	if err != nil {
		t.Fatal(err)
	}
	env, err := alice.Send(ctx, k.KeyID, "bob", wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewClient(alice, nil).Push(ctx, bobURL, "bob", env); err != nil {
		t.Fatal(err)
	}
	heads, err = NewClient(alice, nil).Witness(ctx, bobURL, "bob")
	if err != nil || len(heads) != 1 {
		t.Fatalf("witness after push: %v %v", heads, err)
	}
	if _, _, err := alice.VerifyAudit(heads); err != nil {
		t.Fatal(err)
	}
	if mine, err := NewClient(carol, nil).Witness(ctx, bobURL, "bob"); err != nil || len(mine) != 0 {
		t.Fatalf("carol saw heads witnessed for alice: %v %v", mine, err)
	}
	if _, err := NewClient(carol, nil).Witness(ctx, bobURL, "alice"); err == nil {
		t.Fatal("witness fetched from a server pinned to another member")
	}
}
