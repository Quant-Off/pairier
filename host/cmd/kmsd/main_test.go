package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Quant-Off/pairier/host/internal/api"
	"github.com/Quant-Off/pairier/host/internal/node"
	"github.com/Quant-Off/pairier/host/internal/wire"
)

func TestFlagsAndVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--version"}, &out, &errb, nil); code != 0 || !strings.HasPrefix(out.String(), "kmsd ") {
		t.Fatalf("%d %q", code, out.String())
	}
	if code := run(nil, &out, &errb, nil); code != 2 {
		t.Fatalf("missing dir accepted: %d", code)
	}
	if code := run([]string{"--dir", t.TempDir(), "--listen", "nope"}, &out, &errb, nil); code != 2 {
		t.Fatalf("bad listen accepted: %d", code)
	}
	cfg := filepath.Join(t.TempDir(), "c.json")
	_ = os.WriteFile(cfg, []byte(`{"dir":"/nonexistent/x","listen":"127.0.0.1:0"}`), 0o600)
	if code := run([]string{"--config", cfg}, &out, &errb, nil); code != 1 {
		t.Fatalf("unopenable node should fail at runtime, got %d: %s", code, errb.String())
	}
}

func TestEnvironmentDefaults(t *testing.T) {
	t.Setenv("KMS_DIR", "")
	t.Setenv("KMS_CORE", "")
	var out, errb bytes.Buffer
	if code := run([]string{"--listen", "127.0.0.1:0"}, &out, &errb, nil); code != 2 {
		t.Fatalf("missing dir accepted: %d", code)
	}
	envDir := filepath.Join(t.TempDir(), "env")
	envCore := filepath.Join(t.TempDir(), "env-core")
	t.Setenv("KMS_DIR", envDir)
	t.Setenv("KMS_CORE", envCore)
	errb.Reset()
	if code := run([]string{"--listen", "127.0.0.1:0"}, &out, &errb, nil); code != 1 || !strings.Contains(errb.String(), envCore) {
		t.Fatalf("env core not used: %d %s", code, errb.String())
	}
	flagCore := filepath.Join(t.TempDir(), "flag-core")
	errb.Reset()
	if code := run([]string{"--listen", "127.0.0.1:0", "--core", flagCore}, &out, &errb, nil); code != 1 || !strings.Contains(errb.String(), flagCore) {
		t.Fatalf("flag did not override env: %d %s", code, errb.String())
	}
	cfgCore := filepath.Join(t.TempDir(), "cfg-core")
	cfg := filepath.Join(t.TempDir(), "c.json")
	_ = os.WriteFile(cfg, []byte(`{"core":"`+cfgCore+`","listen":"127.0.0.1:0"}`), 0o600)
	errb.Reset()
	if code := run([]string{"--config", cfg}, &out, &errb, nil); code != 1 || !strings.Contains(errb.String(), cfgCore) {
		t.Fatalf("config did not override env: %d %s", code, errb.String())
	}
}

func TestServeAndShutdown(t *testing.T) {
	bin := os.Getenv("KMS_CORE_BIN")
	if bin == "" {
		t.Skip("KMS_CORE_BIN not set")
	}
	ctx := context.Background()
	mk := func(id string) (*node.Node, node.Options) {
		o := node.Options{Dir: filepath.Join(t.TempDir(), id), CoreBinary: bin, AllowUnlockedMemory: true, Timeout: 5 * time.Second}
		n, err := node.Init(ctx, o, id, false)
		if err != nil {
			t.Fatal(err)
		}
		return n, o
	}
	bob, bobOpts := mk("bob")
	alice, _ := mk("alice")
	defer alice.Close()
	ca, rawA, _ := alice.Card(ctx)
	cb, rawB, _ := bob.Card(ctx)
	fpA, _ := ca.Fingerprint()
	fpB, _ := cb.Fingerprint()
	if _, err := bob.AddMember(ctx, rawA, fpA); err != nil {
		t.Fatal(err)
	}
	if _, err := alice.AddMember(ctx, rawB, fpB); err != nil {
		t.Fatal(err)
	}
	if err := bob.Close(); err != nil {
		t.Fatal(err)
	}

	sctx, cancel := context.WithCancel(ctx)
	addr := make(chan string, 1)
	done := make(chan error, 1)
	var stderr bytes.Buffer
	go func() {
		done <- serve(sctx, settings{listen: "127.0.0.1:0", node: bobOpts}, &stderr, func(a string) { addr <- a })
	}()
	var bobAddr string
	select {
	case bobAddr = <-addr:
	case err := <-done:
		t.Fatalf("serve exited early: %v\n%s", err, stderr.String())
	case <-time.After(10 * time.Second):
		t.Fatal("server did not become ready")
	}
	k, err := alice.GenerateKey(ctx, "k", wire.UsageDecrypt|wire.UsageExport)
	if err != nil {
		t.Fatal(err)
	}
	env, err := alice.Send(ctx, k.KeyID, "bob", wire.UsageDecrypt)
	if err != nil {
		t.Fatal(err)
	}
	pushCtx, stopPush := context.WithTimeout(ctx, 10*time.Second)
	defer stopPush()
	if _, err := api.NewClient(alice, nil).Push(pushCtx, "https://"+bobAddr, "bob", env); err != nil {
		t.Fatalf("push: %v\n%s", err, stderr.String())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("server did not stop")
	}
	if !strings.Contains(stderr.String(), "stopped") {
		t.Fatalf("stderr %q", stderr.String())
	}
	reopened, err := node.Open(ctx, bobOpts)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	items, err := reopened.Inbox()
	if err != nil || len(items) != 1 || items[0].Sender != "alice" {
		t.Fatalf("inbox %+v %v", items, err)
	}
}

func TestLimitListener(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := limit(raw, 1)
	defer ln.Close()
	accepted := make(chan net.Conn, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()
	dial := func() net.Conn {
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	c1, c2 := dial(), dial()
	defer c1.Close()
	defer c2.Close()
	first := <-accepted
	select {
	case <-accepted:
		t.Fatal("second connection accepted beyond the limit")
	case <-time.After(200 * time.Millisecond):
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	_ = first.Close()
	select {
	case second := <-accepted:
		_ = second.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("slot was not released")
	}
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-accepted:
		if ok {
			t.Fatal("accept after close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("accept did not stop after close")
	}
}
