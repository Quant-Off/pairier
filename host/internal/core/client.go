package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"time"

	"github.com/Quant-Off/pairier/host/internal/wire"
)

const DefaultTimeout = 10 * time.Second

var (
	ErrBroken   = errors.New("core: session is broken")
	ErrClosed   = errors.New("core: client is closed")
	ErrProtocol = errors.New("core: protocol violation")
)

type StatusError struct {
	Op     wire.Op
	Status wire.Status
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("core: op 0x%04x failed: %s", uint16(e.Op), e.Status)
}

type GeneratedKey struct {
	KeyID     [wire.KeyIDLen]byte
	Blob      []byte
	PublicKey []byte
}

type KeyInfo struct {
	Alg       uint16
	Usage     uint32
	KeyID     [wire.KeyIDLen]byte
	Label     string
	PublicKey []byte
}

type ImportedKey struct {
	KeyID [wire.KeyIDLen]byte
	Blob  []byte
	Alg   uint16
	Usage uint32
	Label string
}

type Client struct {
	mu      sync.Mutex
	conn    net.Conn
	cmd     *exec.Cmd
	waitErr chan error
	timeout time.Duration
	nextID  uint32
	broken  error
	closed  bool
	hello   wire.HelloResponse
}

func newClient(ctx context.Context, conn net.Conn, cmd *exec.Cmd, timeout time.Duration) (*Client, error) {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	c := &Client{conn: conn, cmd: cmd, timeout: timeout}
	if cmd != nil {
		c.waitErr = make(chan error, 1)
		go func() { c.waitErr <- cmd.Wait() }()
	}
	var rsp wire.HelloResponse
	if err := c.call(ctx, &wire.HelloRequest{ProtocolVersion: wire.ProtocolVersion}, &rsp); err != nil {
		_ = c.Close()
		return nil, err
	}
	if rsp.ProtocolVersion != wire.ProtocolVersion {
		_ = c.Close()
		return nil, fmt.Errorf("%w: core speaks protocol %d", ErrProtocol, rsp.ProtocolVersion)
	}
	c.hello = rsp
	return c, nil
}

func Connect(ctx context.Context, path string, timeout time.Duration) (*Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("core: connect %q: %w", path, err)
	}
	return newClient(ctx, conn, nil, timeout)
}

func (c *Client) Capabilities() uint64 { return c.hello.Capabilities }
func (c *Client) FIPS() bool           { return c.hello.Capabilities&wire.CapFIPS != 0 }
func (c *Client) PQC() bool            { return c.hello.Capabilities&wire.CapPQC != 0 }
func (c *Client) EngineName() string   { return c.hello.EngineName }
func (c *Client) EngineVersion() string {
	return c.hello.EngineVersion
}

func (c *Client) Ping(ctx context.Context) error {
	return c.call(ctx, &wire.PingRequest{}, &wire.PingResponse{})
}

func (c *Client) GenerateKey(ctx context.Context, alg uint16, usage uint32, label string) (*GeneratedKey, error) {
	var rsp wire.KeyGenerateResponse
	if err := c.call(ctx, &wire.KeyGenerateRequest{Alg: alg, Usage: usage, Label: label}, &rsp); err != nil {
		return nil, err
	}
	return &GeneratedKey{KeyID: rsp.KeyID, Blob: rsp.KeyBlob, PublicKey: rsp.PublicKey}, nil
}

func (c *Client) Encrypt(ctx context.Context, blob, plaintext, aad []byte) ([]byte, error) {
	var rsp wire.AeadEncryptResponse
	if err := c.call(ctx, &wire.AeadEncryptRequest{KeyBlob: blob, Plaintext: plaintext, AAD: aad}, &rsp); err != nil {
		return nil, err
	}
	return rsp.Ciphertext, nil
}

func (c *Client) Decrypt(ctx context.Context, blob, ciphertext, aad []byte) ([]byte, error) {
	var rsp wire.AeadDecryptResponse
	if err := c.call(ctx, &wire.AeadDecryptRequest{KeyBlob: blob, Ciphertext: ciphertext, AAD: aad}, &rsp); err != nil {
		return nil, err
	}
	return rsp.Plaintext, nil
}

func (c *Client) Sign(ctx context.Context, blob, message []byte) ([]byte, error) {
	var rsp wire.SignResponse
	if err := c.call(ctx, &wire.SignRequest{KeyBlob: blob, Message: message}, &rsp); err != nil {
		return nil, err
	}
	return rsp.Signature, nil
}

func (c *Client) Verify(ctx context.Context, alg uint16, publicKey, message, signature []byte) (bool, error) {
	var rsp wire.VerifyResponse
	req := &wire.VerifyRequest{Alg: alg, PublicKey: publicKey, Message: message, Signature: signature}
	if err := c.call(ctx, req, &rsp); err != nil {
		return false, err
	}
	return rsp.Valid, nil
}

func (c *Client) Inspect(ctx context.Context, blob []byte) (*KeyInfo, error) {
	var rsp wire.KeyInspectResponse
	if err := c.call(ctx, &wire.KeyInspectRequest{KeyBlob: blob}, &rsp); err != nil {
		return nil, err
	}
	return &KeyInfo{Alg: rsp.Alg, Usage: rsp.Usage, KeyID: rsp.KeyID, Label: rsp.Label, PublicKey: rsp.PublicKey}, nil
}

func (c *Client) ExportKey(ctx context.Context, blob []byte, kemAlg uint16, recipientPublicKey []byte, usage uint32, context []byte) ([]byte, error) {
	if len(context) > wire.MaxContext {
		return nil, &StatusError{Op: wire.OpKeyExport, Status: wire.StatusLimitExceeded}
	}
	var rsp wire.KeyExportResponse
	req := &wire.KeyExportRequest{KeyBlob: blob, KemAlg: kemAlg, RecipientPublicKey: recipientPublicKey, Usage: usage, Context: context}
	if err := c.call(ctx, req, &rsp); err != nil {
		return nil, err
	}
	return rsp.Package, nil
}

func (c *Client) ImportKey(ctx context.Context, kemBlob, pkg, context []byte) (*ImportedKey, error) {
	if len(pkg) > wire.MaxPackage || len(context) > wire.MaxContext {
		return nil, &StatusError{Op: wire.OpKeyImport, Status: wire.StatusLimitExceeded}
	}
	var rsp wire.KeyImportResponse
	req := &wire.KeyImportRequest{KemKeyBlob: kemBlob, Package: pkg, Context: context}
	if err := c.call(ctx, req, &rsp); err != nil {
		return nil, err
	}
	return &ImportedKey{KeyID: rsp.KeyID, Blob: rsp.KeyBlob, Alg: rsp.Alg, Usage: rsp.Usage, Label: rsp.Label}, nil
}

func (c *Client) Random(ctx context.Context, n int) ([]byte, error) {
	if n < 0 || n > wire.MaxRandom {
		return nil, &StatusError{Op: wire.OpRandom, Status: wire.StatusLimitExceeded}
	}
	var rsp wire.RandomResponse
	if err := c.call(ctx, &wire.RandomRequest{Len: uint32(n)}, &rsp); err != nil {
		return nil, err
	}
	if len(rsp.Bytes) != n {
		return nil, c.failLocked(fmt.Errorf("%w: random returned %d bytes, want %d", ErrProtocol, len(rsp.Bytes), n))
	}
	return rsp.Bytes, nil
}

func (c *Client) call(ctx context.Context, req, rsp wire.Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return ErrClosed
	}
	if c.broken != nil {
		return c.broken
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	c.nextID++
	id := c.nextID
	body, err := wire.EncodeBody(req)
	if err != nil {
		return err
	}
	hdr, err := wire.NewRequest(req.Op(), id, uint32(len(body)))
	if err != nil {
		return err
	}
	hb, err := hdr.Encode()
	if err != nil {
		return err
	}

	if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return c.failLocked(err)
	}

	frame := make([]byte, 0, len(hb)+len(body))
	frame = append(frame, hb[:]...)
	frame = append(frame, body...)
	if _, err := c.conn.Write(frame); err != nil {
		return c.failLocked(err)
	}

	var rh [wire.HeaderLen]byte
	if _, err := io.ReadFull(c.conn, rh[:]); err != nil {
		return c.failLocked(err)
	}
	h, err := wire.DecodeHeader(rh[:])
	if err != nil {
		return c.failLocked(fmt.Errorf("%w: %v", ErrProtocol, err))
	}
	if h.Kind != wire.KindResponse || h.ID != id || h.Op != req.Op() {
		return c.failLocked(fmt.Errorf("%w: unexpected frame kind=%d id=%d op=0x%04x", ErrProtocol, h.Kind, h.ID, uint16(h.Op)))
	}
	if h.Status != wire.StatusOK {
		return &StatusError{Op: h.Op, Status: h.Status}
	}
	rb := make([]byte, h.Len)
	if _, err := io.ReadFull(c.conn, rb); err != nil {
		return c.failLocked(err)
	}
	if err := wire.DecodeBody(rsp, rb); err != nil {
		return c.failLocked(fmt.Errorf("%w: %v", ErrProtocol, err))
	}
	return nil
}

func (c *Client) failLocked(err error) error {
	if c.broken == nil {
		c.broken = fmt.Errorf("%w: %v", ErrBroken, err)
		_ = c.conn.Close()
	}
	return c.broken
}

func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	err := c.conn.Close()
	if c.cmd == nil {
		return err
	}
	select {
	case werr := <-c.waitErr:
		return errors.Join(err, exitError(werr))
	case <-time.After(c.timeout):
		_ = c.cmd.Process.Kill()
		werr := <-c.waitErr
		return errors.Join(err, fmt.Errorf("core: process killed after timeout: %w", werr))
	}
}

func exitError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("core: process exited with error: %w", err)
}
