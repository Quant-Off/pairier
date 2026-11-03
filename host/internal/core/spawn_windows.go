//go:build windows

package core

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/Quant-Off/pairier/host/internal/winsys"
)

type pipeTransport struct {
	pair *winsys.PipePair
	file *os.File
}

func newTransport() (transport, error) {
	pair, err := winsys.NewPipePair()
	if err != nil {
		return nil, fmt.Errorf("core: %w", err)
	}
	file := os.NewFile(uintptr(pair.Server), pair.Name)
	if file == nil {
		pair.Close()
		return nil, fmt.Errorf("core: pipe server handle is invalid")
	}
	pair.Server = syscall.InvalidHandle
	return &pipeTransport{pair: pair, file: file}, nil
}

func (t *pipeTransport) args() []string {
	return []string{"--handle", strconv.FormatUint(uint64(t.pair.Client), 10)}
}

func (t *pipeTransport) attach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{AdditionalInheritedHandles: []syscall.Handle{t.pair.Client}}
}

func (t *pipeTransport) started() (net.Conn, error) {
	t.pair.CloseClient()
	return &pipeConn{f: t.file, name: t.pair.Name}, nil
}

func (t *pipeTransport) abort() {
	t.pair.Close()
	_ = t.file.Close()
}

func childDir() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return filepath.VolumeName(root) + `\`
	}
	return `C:\`
}

type pipeAddr string

func (a pipeAddr) Network() string { return "pipe" }
func (a pipeAddr) String() string  { return string(a) }

type pipeConn struct {
	f    *os.File
	name string
}

func (c *pipeConn) Read(b []byte) (int, error)         { return c.f.Read(b) }
func (c *pipeConn) Write(b []byte) (int, error)        { return c.f.Write(b) }
func (c *pipeConn) Close() error                       { return c.f.Close() }
func (c *pipeConn) LocalAddr() net.Addr                { return pipeAddr(c.name) }
func (c *pipeConn) RemoteAddr() net.Addr               { return pipeAddr(c.name) }
func (c *pipeConn) SetDeadline(t time.Time) error      { return c.f.SetDeadline(t) }
func (c *pipeConn) SetReadDeadline(t time.Time) error  { return c.f.SetReadDeadline(t) }
func (c *pipeConn) SetWriteDeadline(t time.Time) error { return c.f.SetWriteDeadline(t) }
