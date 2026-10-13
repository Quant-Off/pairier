package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

type Options struct {
	Binary              string
	RootKeyFile         string
	EphemeralRoot       bool
	PQC                 bool
	AllowUnlockedMemory bool
	Timeout             time.Duration
	Stderr              io.Writer
}

const childFD = 3

func (o *Options) args() ([]string, error) {
	args := []string{"--fd", strconv.Itoa(childFD)}
	switch {
	case o.RootKeyFile != "" && o.EphemeralRoot:
		return nil, fmt.Errorf("core: RootKeyFile and EphemeralRoot are mutually exclusive")
	case o.RootKeyFile != "":
		args = append(args, "--root-key-file", o.RootKeyFile)
	case o.EphemeralRoot:
		args = append(args, "--ephemeral-root")
	default:
		return nil, fmt.Errorf("core: RootKeyFile or EphemeralRoot is required")
	}
	if o.PQC {
		args = append(args, "--pqc")
	}
	if o.AllowUnlockedMemory {
		args = append(args, "--allow-unlocked-memory")
	}
	return args, nil
}

func socketPair() (parent *net.UnixConn, child *os.File, err error) {
	syscall.ForkLock.RLock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, fmt.Errorf("core: socketpair: %w", err)
	}
	pf := os.NewFile(uintptr(fds[0]), "kms-core-parent")
	child = os.NewFile(uintptr(fds[1]), "kms-core-child")
	fc, err := net.FileConn(pf)
	_ = pf.Close()
	if err != nil {
		_ = child.Close()
		return nil, nil, fmt.Errorf("core: fileconn: %w", err)
	}
	uc, ok := fc.(*net.UnixConn)
	if !ok {
		_ = fc.Close()
		_ = child.Close()
		return nil, nil, fmt.Errorf("core: socketpair did not yield a unix conn")
	}
	return uc, child, nil
}

func Spawn(ctx context.Context, o Options) (*Client, error) {
	if o.Binary == "" {
		return nil, fmt.Errorf("core: Binary is required")
	}
	args, err := o.args()
	if err != nil {
		return nil, err
	}
	parent, child, err := socketPair()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(o.Binary, args...)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = o.Stderr
	cmd.ExtraFiles = []*os.File{child}
	if err := cmd.Start(); err != nil {
		_ = child.Close()
		_ = parent.Close()
		return nil, fmt.Errorf("core: start %q: %w", o.Binary, err)
	}
	_ = child.Close()
	return newClient(ctx, parent, cmd, o.Timeout)
}
