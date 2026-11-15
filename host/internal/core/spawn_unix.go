//go:build unix

package core

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

const childFD = 3

type unixTransport struct {
	parent *net.UnixConn
	child  *os.File
}

func newTransport() (transport, error) {
	syscall.ForkLock.RLock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("core: socketpair: %w", err)
	}
	pf := os.NewFile(uintptr(fds[0]), "kms-core-parent")
	child := os.NewFile(uintptr(fds[1]), "kms-core-child")
	fc, err := net.FileConn(pf)
	_ = pf.Close()
	if err != nil {
		_ = child.Close()
		return nil, fmt.Errorf("core: fileconn: %w", err)
	}
	uc, ok := fc.(*net.UnixConn)
	if !ok {
		_ = fc.Close()
		_ = child.Close()
		return nil, fmt.Errorf("core: socketpair did not yield a unix conn")
	}
	return &unixTransport{parent: uc, child: child}, nil
}

func (t *unixTransport) args() []string {
	return []string{"--fd", strconv.Itoa(childFD)}
}

func (t *unixTransport) attach(cmd *exec.Cmd) {
	cmd.ExtraFiles = []*os.File{t.child}
}

func (t *unixTransport) started() (net.Conn, error) {
	_ = t.child.Close()
	return t.parent, nil
}

func (t *unixTransport) abort() {
	_ = t.child.Close()
	_ = t.parent.Close()
}

func childDir() string {
	return "/"
}
