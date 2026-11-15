//go:build windows

package winsys

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestPipePairRoundTrip(t *testing.T) {
	p, err := NewPipePair()
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	pid, err := p.ClientProcessID()
	if err != nil || pid != syscall.Getpid() {
		t.Fatalf("client pid %d %v", pid, err)
	}
	server := os.NewFile(uintptr(p.Server), p.Name)
	p.Server = syscall.InvalidHandle
	defer server.Close()
	client := os.NewFile(uintptr(p.Client), "client")
	p.Client = syscall.InvalidHandle
	defer client.Close()

	go func() { _, _ = client.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(server, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("read %q %v", buf, err)
	}
	if err := server.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("deadline unsupported: %v", err)
	}
	if _, err := server.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected deadline error, got %v", err)
	}
	if err := server.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = server.Write([]byte("pong")) }()
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("read %q %v", buf, err)
	}
}

func createWithSDDL(t *testing.T, path, sddl string) {
	t.Helper()
	d, err := newDescriptor(sddl)
	if err != nil {
		t.Fatal(err)
	}
	defer d.free()
	sa := &syscall.SecurityAttributes{Length: uint32(unsafe.Sizeof(syscall.SecurityAttributes{})), SecurityDescriptor: d.sd}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_WRITE, 0, sa, syscall.CREATE_NEW, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	syscall.CloseHandle(h)
}

func TestCheckPathPolicies(t *testing.T) {
	me, err := CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := me.String()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	private := filepath.Join(dir, "private")
	if err := os.WriteFile(private, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetPrivate(private, "file"); err != nil {
		t.Fatal(err)
	}
	if err := CheckPath(private, Policy{}); err != nil {
		t.Fatalf("private file rejected: %v", err)
	}
	world := filepath.Join(dir, "world")
	createWithSDDL(t, world, "D:P(A;;FA;;;SY)(A;;FA;;;"+sid+")(A;;FR;;;WD)")
	if err := CheckPath(world, Policy{}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("world readable accepted: %v", err)
	}
	admins := filepath.Join(dir, "admins")
	createWithSDDL(t, admins, "D:P(A;;FA;;;SY)(A;;FA;;;"+sid+")(A;;FA;;;BA)")
	if err := CheckPath(admins, Policy{}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("administrators accepted by strict policy: %v", err)
	}
	if err := CheckPath(admins, Policy{AllowAdministrators: true}); err != nil {
		t.Fatalf("administrators rejected by config policy: %v", err)
	}
	denied := filepath.Join(dir, "denied")
	createWithSDDL(t, denied, "D:P(D;;FR;;;WD)(A;;FA;;;SY)(A;;FA;;;"+sid+")")
	if err := CheckPath(denied, Policy{}); !errors.Is(err, ErrInsecure) {
		t.Fatalf("deny entry accepted: %v", err)
	}
}

func TestLockBlocksSecondHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	a, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := Lock(syscall.Handle(a.Fd())); err != nil {
		t.Fatal(err)
	}
	acquired := make(chan struct{})
	go func() {
		_ = Lock(syscall.Handle(b.Fd()))
		close(acquired)
	}()
	select {
	case <-acquired:
		t.Fatal("second lock acquired while the first is held")
	case <-time.After(200 * time.Millisecond):
	}
	if err := Unlock(syscall.Handle(a.Fd())); err != nil {
		t.Fatal(err)
	}
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("second lock never acquired")
	}
	_ = Unlock(syscall.Handle(b.Fd()))
}

func TestIsRemotePath(t *testing.T) {
	local, err := IsRemotePath(t.TempDir())
	if err != nil || local {
		t.Fatalf("temp dir remote=%v err=%v", local, err)
	}
	remote, err := IsRemotePath(`\\server\share\node`)
	if err != nil || !remote {
		t.Fatalf("unc remote=%v err=%v", remote, err)
	}
}

func TestNewFilesAreOwnedByCurrentUser(t *testing.T) {
	if ownerErr != nil {
		t.Fatal(ownerErr)
	}
	me, err := CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner, free, err := pathOwner(path)
	if err != nil {
		t.Fatal(err)
	}
	defer free()
	if !equalSID(me, owner) {
		s, _ := owner.String()
		t.Fatalf("new file owned by %s", s)
	}
}
