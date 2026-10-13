package audit

import (
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
	l, err := Open(path, now)
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
	n, err := Verify(path)
	if err != nil || n != 2 {
		t.Fatalf("verify %d %v", n, err)
	}
	l2, err := Open(path, now)
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
	if _, err := Verify(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tamper not detected: %v", err)
	}
	if _, err := Open(path, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("open on tampered log succeeded: %v", err)
	}
	truncated := strings.Join([]string{lines[0], lines[2]}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(truncated), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(path); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("deletion not detected: %v", err)
	}
	if err := os.WriteFile(path, []byte(lines[0]+"\n"+lines[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, now); err != nil {
		t.Fatalf("prefix of a valid chain rejected: %v", err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, now); !errors.Is(err, ErrInsecure) {
		t.Fatalf("permissive mode accepted: %v", err)
	}
}

func TestConcurrentHandlesShareOneChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(path, nil)
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
	if n, err := Verify(path); err != nil || n != 10 {
		t.Fatalf("verify %d %v", n, err)
	}
	if err := os.Truncate(path, 10); err != nil {
		t.Fatal(err)
	}
	if err := a.Append("a", nil); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("shrunk log not detected: %v", err)
	}
}
