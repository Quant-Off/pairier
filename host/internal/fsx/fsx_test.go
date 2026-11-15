package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateDirectoriesAndFiles(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "node")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	if err := MkdirPrivate(dir); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second mkdir: %v", err)
	}
	if err := CheckPrivateDir(dir); err != nil {
		t.Fatalf("private dir rejected: %v", err)
	}
	file := filepath.Join(dir, "f.json")
	if err := os.WriteFile(file, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateFile(file); err != nil {
		t.Fatalf("private file rejected: %v", err)
	}
	if err := CheckNotWritableByOthers(file); err != nil {
		t.Fatalf("private file rejected by config policy: %v", err)
	}
	if err := CheckPrivateDir(file); !errors.Is(err, ErrInsecure) {
		t.Fatalf("file accepted as dir: %v", err)
	}
	if err := CheckPrivateFile(dir); !errors.Is(err, ErrInsecure) {
		t.Fatalf("dir accepted as file: %v", err)
	}
	if err := CheckPrivateFile(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
	plain := filepath.Join(base, "plain")
	if err := os.Mkdir(plain, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := MakePrivate(plain); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateDir(plain); err != nil {
		t.Fatalf("dir made private rejected: %v", err)
	}
}

func TestLockRenameAndExecutable(t *testing.T) {
	dir := t.TempDir()
	if err := MakePrivate(dir); err != nil {
		t.Fatal(err)
	}
	lock, err := OpenNoFollow(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := Lock(lock); err != nil {
		t.Fatal(err)
	}
	if err := Unlock(lock); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "a")
	dst := filepath.Join(dir, "b")
	if err := os.WriteFile(src, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Rename(src, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatal(err)
	}
	if err := SyncDir(dir); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(dir, "tool"+ExeSuffix)
	if err := os.WriteFile(tool, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(tool)
	if err != nil || !IsExecutable(fi, tool) {
		t.Fatalf("tool not executable: %v %v", fi, err)
	}
	data := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(data, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err = os.Stat(data)
	if err != nil || IsExecutable(fi, data) {
		t.Fatalf("data executable: %v %v", fi, err)
	}
}

func TestWriteNewIsPrivateAndExclusive(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.bin")
	if err := WriteNew(out, []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if err := CheckPrivateFile(out); err != nil {
		t.Fatalf("new file is not private: %v", err)
	}
	if err := WriteNew(out, []byte("other")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("existing file overwritten: %v", err)
	}
	got, err := ReadFileLimited(out, 6)
	if err != nil || string(got) != "secret" {
		t.Fatalf("read back %q %v", got, err)
	}
	if _, err := ReadFileLimited(out, 5); err == nil {
		t.Fatal("limit not enforced")
	}
	if _, err := ReadFileLimited(dir, 5); err == nil {
		t.Fatal("directory read as a file")
	}
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := WriteNew(link, []byte("x")); err == nil {
		t.Fatal("dangling symlink followed")
	}
	if _, err := os.Lstat(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("symlink target created: %v", err)
	}
}
