package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestParseAndFormatUsage(t *testing.T) {
	bits, err := parseUsage("Encrypt, decrypt,export")
	if err != nil || formatUsage(bits) != "encrypt,decrypt,export" {
		t.Fatalf("%v %v", bits, err)
	}
	if _, err := parseUsage("encrypt,bogus"); err == nil {
		t.Fatal("unknown usage accepted")
	}
	if _, err := parseUsage(""); err == nil {
		t.Fatal("empty usage accepted")
	}
}

func TestUsageAndVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, nil, &out, &errb); code != 2 {
		t.Fatalf("code %d", code)
	}
	if code := run([]string{"version"}, nil, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "kmsctl ") {
		t.Fatalf("version: %d %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"key", "list"}, nil, &out, &errb); code != 2 {
		t.Fatalf("missing dir should be a usage error, got %d", code)
	}
}

func TestEndToEndExchange(t *testing.T) {
	bin := os.Getenv("KMS_CORE_BIN")
	if bin == "" {
		t.Skip("KMS_CORE_BIN not set")
	}
	base := t.TempDir()
	alice := filepath.Join(base, "alice")
	bob := filepath.Join(base, "bob")
	exec := func(stdin []byte, args ...string) (string, string, int) {
		var out, errb syncBuffer
		code := run(append([]string{"--core", bin, "--allow-unlocked-memory"}, args...), bytes.NewReader(stdin), &out, &errb)
		return out.String(), errb.String(), code
	}
	must := func(stdin []byte, args ...string) string {
		t.Helper()
		out, errOut, code := exec(stdin, args...)
		if code != 0 {
			t.Fatalf("%v failed (%d): %s%s", args, code, out, errOut)
		}
		return out
	}
	field := func(s, key string) string {
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(line, key+"\t") {
				return strings.TrimPrefix(line, key+"\t")
			}
		}
		t.Fatalf("field %q missing in %q", key, s)
		return ""
	}

	initA := must(nil, "--dir", alice, "init", "--id", "alice")
	initB := must(nil, "--dir", bob, "init", "--id", "bob")
	if _, _, code := exec(nil, "--dir", alice, "init", "--id", "alice"); code == 0 {
		t.Fatal("re-init succeeded")
	}
	cardA := filepath.Join(base, "alice.card")
	cardB := filepath.Join(base, "bob.card")
	must(nil, "--dir", alice, "card", "--out", cardA)
	must(nil, "--dir", bob, "card", "--out", cardB)
	if _, _, code := exec(nil, "--dir", alice, "member", "add", "--card", cardB, "--fingerprint", field(initA, "fingerprint")); code == 0 {
		t.Fatal("wrong fingerprint accepted")
	}
	must(nil, "--dir", alice, "member", "add", "--card", cardB, "--fingerprint", field(initB, "fingerprint"))
	must(nil, "--dir", bob, "member", "add", "--card", cardA, "--fingerprint", strings.ToUpper(field(initA, "fingerprint")))
	if list := must(nil, "--dir", alice, "member", "list"); !strings.HasPrefix(list, "bob\t") {
		t.Fatalf("member list %q", list)
	}

	gen := must(nil, "--dir", alice, "key", "gen", "--label", "project/db")
	keyID := strings.SplitN(gen, "\t", 2)[0]
	ct := must([]byte("top secret"), "--dir", alice, "encrypt", "--id", keyID, "--aad", "ctx")
	env := filepath.Join(base, "db.kxp")
	must(nil, "--dir", alice, "key", "send", "--id", keyID, "--to", "bob", "--out", env)
	if _, _, code := exec(nil, "--dir", alice, "key", "send", "--id", keyID, "--to", "bob", "--out", env); code == 0 {
		t.Fatal("overwriting an existing output file succeeded")
	}
	recv := must(nil, "--dir", bob, "key", "receive", "--in", env)
	if !strings.HasPrefix(recv, keyID+"\t") || !strings.Contains(recv, "from alice") {
		t.Fatalf("receive %q", recv)
	}
	pt := must([]byte(ct), "--dir", bob, "decrypt", "--id", keyID, "--aad", "ctx")
	if pt != "top secret" {
		t.Fatalf("decrypt %q", pt)
	}
	if _, _, code := exec([]byte(ct), "--dir", bob, "decrypt", "--id", keyID, "--aad", "other"); code == 0 {
		t.Fatal("wrong aad accepted")
	}
	if _, _, code := exec([]byte("x"), "--dir", bob, "encrypt", "--id", keyID); code == 0 {
		t.Fatal("recipient could encrypt with decrypt-only grant")
	}
	info := must(nil, "--dir", bob, "key", "info", "--id", keyID)
	if !strings.Contains(info, "origin\talice") || !strings.Contains(info, "usage\tdecrypt\n") {
		t.Fatalf("info %q", info)
	}
	if list := must(nil, "--dir", bob, "key", "list"); strings.Count(list, "\n") != 3 {
		t.Fatalf("bob key list %q", list)
	}
}
