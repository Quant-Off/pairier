package audit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChainAppendVerifyAndTamper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	now := func() time.Time { return time.Unix(1_700_000_000, 0) }
	l, err := Open(path, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append("node.init", map[string]string{"member": "alice"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Append("key.generate", map[string]string{"key": "abc", "usage": "encrypt"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Append("", nil); !errors.Is(err, ErrField) {
		t.Fatal("empty event accepted")
	}
	if l.Seq() != 2 {
		t.Fatalf("seq %d", l.Seq())
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	n, err := Verify(path, nil)
	if err != nil || n != 2 {
		t.Fatalf("verify %d %v", n, err)
	}
	l2, err := Open(path, Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := l2.Append("key.send", nil); err != nil {
		t.Fatal(err)
	}
	_ = l2.Close()
	entries, err := Read(path)
	if err != nil || len(entries) != 3 || entries[2].Prev != entries[1].Hash || entries[0].Fields["member"] != "alice" {
		t.Fatalf("read %+v %v", entries, err)
	}

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	edited := strings.Replace(lines[1], `"usage":"encrypt"`, `"usage":"export"`, 1)
	if edited == lines[1] {
		t.Fatal("edit did not apply")
	}
	tampered := strings.Join([]string{lines[0], edited, lines[2]}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tamper not detected: %v", err)
	}
	if _, err := Open(path, Options{Now: now}); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("open on tampered log succeeded: %v", err)
	}
	truncated := strings.Join([]string{lines[0], lines[2]}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(truncated), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path, nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("deletion not detected: %v", err)
	}
	if err := os.WriteFile(path, []byte(lines[0]+"\n"+lines[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, Options{Now: now}); err != nil {
		t.Fatalf("prefix of a valid chain rejected: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, Options{Now: now}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("permissive mode accepted: %v", err)
	}
}

func TestConcurrentHandlesShareOneChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	for i := 0; i < 5; i++ {
		if err := a.Append("a", nil); err != nil {
			t.Fatal(err)
		}
		if err := b.Append("b", nil); err != nil {
			t.Fatal(err)
		}
	}
	if a.Seq() != 9 || b.Seq() != 10 {
		t.Fatalf("seq %d %d", a.Seq(), b.Seq())
	}
	if n, err := Verify(path, nil); err != nil || n != 10 {
		t.Fatalf("verify %d %v", n, err)
	}
	if err := os.Truncate(path, 10); err != nil {
		t.Fatal(err)
	}
	if err := a.Append("a", nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("shrunk log not detected: %v", err)
	}
}

type ecdsaCheckpoints struct {
	key   *ecdsa.PrivateKey
	calls int
}

func (k *ecdsaCheckpoints) SignCheckpoint(msg []byte) ([]byte, error) {
	k.calls++
	sum := sha256.Sum256(msg)
	return ecdsa.SignASN1(rand.Reader, k.key, sum[:])
}

func (k *ecdsaCheckpoints) VerifyCheckpoint(msg, sig []byte) (bool, error) {
	sum := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(&k.key.PublicKey, sum[:], sig), nil
}

func TestSignedCheckpoints(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k := &ecdsaCheckpoints{key: key}
	if _, err := Open(path, Options{Signer: k}); err == nil {
		t.Fatal("signer without verifier accepted")
	}
	l, err := Open(path, Options{Signer: k, Verifier: k})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{"a", "b", "c"} {
		if err := l.Append(ev, map[string]string{"k": ev}); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()
	if k.calls != 3 {
		t.Fatalf("expected one signature per entry, got %d", k.calls)
	}
	if n, err := Verify(path, k); err != nil || n != 3 {
		t.Fatalf("verify %d %v", n, err)
	}

	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	entries, _ := Read(path)

	forger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := &ecdsaCheckpoints{key: forger}
	if _, err := Verify(path, f); !errors.Is(err, ErrSignature) {
		t.Fatalf("foreign key verified the log: %v", err)
	}
	if _, err := Open(path, Options{Signer: f, Verifier: f}); !errors.Is(err, ErrSignature) {
		t.Fatalf("open with foreign verifier succeeded: %v", err)
	}

	rewritten := filepath.Join(t.TempDir(), "audit.log")
	rl, err := Open(rewritten, Options{Signer: f, Verifier: f})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := rl.Append(e.Event, e.Fields); err != nil {
			t.Fatal(err)
		}
	}
	_ = rl.Close()
	if _, err := Verify(rewritten, nil); err != nil {
		t.Fatalf("rewritten chain should be internally consistent: %v", err)
	}
	if _, err := Verify(rewritten, k); !errors.Is(err, ErrSignature) {
		t.Fatalf("recomputed chain accepted without the signing key: %v", err)
	}

	unsigned := filepath.Join(t.TempDir(), "audit.log")
	ul, _ := Open(unsigned, Options{})
	_ = ul.Append("x", nil)
	_ = ul.Close()
	if _, err := Open(unsigned, Options{Signer: k, Verifier: k}); !errors.Is(err, ErrSignature) {
		t.Fatalf("unsigned log accepted by a verifying open: %v", err)
	}

	stripped := strings.Replace(lines[2], `,"sig":"`+entries[2].Sig+`"`, "", 1)
	if stripped == lines[2] {
		t.Fatal("strip did not apply")
	}
	if err := os.WriteFile(path, []byte(lines[0]+"\n"+lines[1]+"\n"+stripped+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, Options{Signer: k, Verifier: k}); !errors.Is(err, ErrSignature) {
		t.Fatalf("stripped head signature accepted: %v", err)
	}

	if err := os.WriteFile(path, []byte(lines[0]+"\n"+lines[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l2, err := Open(path, Options{Signer: k, Verifier: k})
	if err != nil {
		t.Fatalf("truncated but signed prefix should open: %v", err)
	}
	if seq, _ := l2.Head(); seq != 2 {
		t.Fatalf("head seq %d", seq)
	}
	_ = l2.Close()
}
