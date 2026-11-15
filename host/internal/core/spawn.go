package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"os/exec"
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

func (o *Options) args() ([]string, error) {
	var args []string
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

type transport interface {
	args() []string
	attach(cmd *exec.Cmd)
	started() (net.Conn, error)
	abort()
}

func Spawn(ctx context.Context, o Options) (*Client, error) {
	if o.Binary == "" {
		return nil, fmt.Errorf("core: Binary is required")
	}
	args, err := o.args()
	if err != nil {
		return nil, err
	}
	tr, err := newTransport()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(o.Binary, append(tr.args(), args...)...)
	cmd.Env = []string{}
	cmd.Dir = childDir()
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = o.Stderr
	tr.attach(cmd)
	if err := cmd.Start(); err != nil {
		tr.abort()
		return nil, fmt.Errorf("core: start %q: %w", o.Binary, err)
	}
	conn, err := tr.started()
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, err
	}
	return newClient(ctx, conn, cmd, o.Timeout)
}
