package core

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Quant-Off/pairier/host/internal/wire"
)

type handler func(h wire.Header, body []byte) (wire.Header, []byte)

func fakeCore(t *testing.T, h handler) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	go func() {
		defer server.Close()
		for {
			var hb [wire.HeaderLen]byte
			if _, err := io.ReadFull(server, hb[:]); err != nil {
				return
			}
			hdr, err := wire.DecodeHeader(hb[:])
			if err != nil {
				return
			}
			body := make([]byte, hdr.Len)
			if _, err := io.ReadFull(server, body); err != nil {
				return
			}
			rh, rb := h(hdr, body)
			enc, err := rh.Encode()
			if err != nil {
				return
			}
			if _, err := server.Write(append(enc[:], rb...)); err != nil {
				return
			}
		}
	}()
	return client
}

func helloHandler(caps uint64) handler {
	return func(h wire.Header, body []byte) (wire.Header, []byte) {
		switch h.Op {
		case wire.OpHello:
			rb, _ := wire.EncodeBody(&wire.HelloResponse{ProtocolVersion: wire.ProtocolVersion, Capabilities: caps, EngineName: "fake", EngineVersion: "0"})
			rh, _ := wire.NewResponse(h.Op, h.ID, uint32(len(rb)))
			return rh, rb
		case wire.OpPing:
			rh, _ := wire.NewResponse(h.Op, h.ID, 0)
			return rh, nil
		case wire.OpRandom:
			var req wire.RandomRequest
			_ = wire.DecodeBody(&req, body)
			rb, _ := wire.EncodeBody(&wire.RandomResponse{Bytes: make([]byte, req.Len)})
			rh, _ := wire.NewResponse(h.Op, h.ID, uint32(len(rb)))
			return rh, rb
		default:
			return wire.NewError(h.Op, h.ID, wire.StatusUnsupportedOp), nil
		}
	}
}

func TestHelloAndCapabilities(t *testing.T) {
	conn := fakeCore(t, helloHandler(wire.CapFIPS|wire.CapPQC))
	c, err := newClient(context.Background(), conn, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.FIPS() || !c.PQC() || c.EngineName() != "fake" {
		t.Fatalf("hello not recorded: %+v", c.hello)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := c.Random(context.Background(), 8)
	if err != nil || len(b) != 8 {
		t.Fatalf("random: %v %d", err, len(b))
	}
	if _, err := c.Random(context.Background(), wire.MaxRandom+1); err == nil {
		t.Fatal("expected limit error")
	}
}

func TestStatusErrorsAreNotFatal(t *testing.T) {
	conn := fakeCore(t, helloHandler(0))
	c, err := newClient(context.Background(), conn, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Sign(context.Background(), []byte{1}, []byte{2})
	var se *StatusError
	if !errors.As(err, &se) || se.Status != wire.StatusUnsupportedOp || se.Op != wire.OpSign {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("session should survive status errors: %v", err)
	}
}

func TestProtocolViolationsBreakSession(t *testing.T) {
	cases := map[string]handler{
		"id mismatch": func(h wire.Header, _ []byte) (wire.Header, []byte) {
			if h.Op == wire.OpHello {
				return helloHandler(0)(h, nil)
			}
			rh, _ := wire.NewResponse(h.Op, h.ID+1, 0)
			return rh, nil
		},
		"op mismatch": func(h wire.Header, _ []byte) (wire.Header, []byte) {
			if h.Op == wire.OpHello {
				return helloHandler(0)(h, nil)
			}
			rh, _ := wire.NewResponse(wire.OpSign, h.ID, 0)
			return rh, nil
		},
		"trailing body bytes": func(h wire.Header, _ []byte) (wire.Header, []byte) {
			if h.Op == wire.OpHello {
				return helloHandler(0)(h, nil)
			}
			rh, _ := wire.NewResponse(h.Op, h.ID, 1)
			return rh, []byte{0}
		},
		"request kind echoed": func(h wire.Header, _ []byte) (wire.Header, []byte) {
			if h.Op == wire.OpHello {
				return helloHandler(0)(h, nil)
			}
			rh, _ := wire.NewRequest(h.Op, h.ID, 0)
			return rh, nil
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			conn := fakeCore(t, h)
			c, err := newClient(context.Background(), conn, nil, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := c.Ping(context.Background()); !errors.Is(err, ErrBroken) {
				t.Fatalf("expected ErrBroken, got %v", err)
			}
			if err := c.Ping(context.Background()); !errors.Is(err, ErrBroken) {
				t.Fatalf("session should stay broken, got %v", err)
			}
		})
	}
}

func TestBadHelloRejected(t *testing.T) {
	conn := fakeCore(t, func(h wire.Header, _ []byte) (wire.Header, []byte) {
		rb, _ := wire.EncodeBody(&wire.HelloResponse{ProtocolVersion: 2, EngineName: "x", EngineVersion: "y"})
		rh, _ := wire.NewResponse(h.Op, h.ID, uint32(len(rb)))
		return rh, rb
	})
	if _, err := newClient(context.Background(), conn, nil, time.Second); !errors.Is(err, ErrProtocol) {
		t.Fatalf("expected ErrProtocol, got %v", err)
	}
}

func TestContextCancelUnblocksAndBreaks(t *testing.T) {
	conn := fakeCore(t, func(h wire.Header, _ []byte) (wire.Header, []byte) {
		if h.Op == wire.OpHello {
			return helloHandler(0)(h, nil)
		}
		time.Sleep(2 * time.Second)
		rh, _ := wire.NewResponse(h.Op, h.ID, 0)
		return rh, nil
	})
	c, err := newClient(context.Background(), conn, nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = c.Ping(ctx)
	if !errors.Is(err, ErrBroken) {
		t.Fatalf("expected ErrBroken, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("cancel did not unblock the call promptly")
	}
}

func TestClosedClientRefusesCalls(t *testing.T) {
	conn := fakeCore(t, helloHandler(0))
	c, err := newClient(context.Background(), conn, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}

func TestOptionsArgs(t *testing.T) {
	if _, err := (&Options{}).args(); err == nil {
		t.Fatal("expected error without root source")
	}
	if _, err := (&Options{RootKeyFile: "/k", EphemeralRoot: true}).args(); err == nil {
		t.Fatal("expected error with both root sources")
	}
	args, err := (&Options{RootKeyFile: "/k", PQC: true, AllowUnlockedMemory: true}).args()
	if err != nil {
		t.Fatal(err)
	}
	want := "--fd 3 --root-key-file /k --pqc --allow-unlocked-memory"
	if got := strings.Join(args, " "); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func realBinary(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("KMS_CORE_BIN")
	if bin == "" {
		t.Skip("KMS_CORE_BIN not set")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("KMS_CORE_BIN %q not found: %v", bin, err)
	}
	return bin
}

func TestRealCoreSpawn(t *testing.T) {
	bin := realBinary(t)
	var stderr bytes.Buffer
	ctx := context.Background()
	c, err := Spawn(ctx, Options{Binary: bin, EphemeralRoot: true, PQC: true, AllowUnlockedMemory: true, Stderr: &stderr})
	if err != nil {
		t.Fatalf("spawn: %v\n%s", err, stderr.String())
	}
	if c.EngineName() != "kms-engine" {
		t.Fatalf("engine name %q", c.EngineName())
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	k, err := c.GenerateKey(ctx, wire.AlgAES256GCM, wire.UsageEncrypt|wire.UsageDecrypt, "go-test")
	if err != nil {
		t.Fatal(err)
	}
	ct, err := c.Encrypt(ctx, k.Blob, []byte("payload"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := c.Decrypt(ctx, k.Blob, ct, []byte("aad"))
	if err != nil || string(pt) != "payload" {
		t.Fatalf("decrypt: %q %v", pt, err)
	}
	_, err = c.Decrypt(ctx, k.Blob, ct, []byte("wrong"))
	var se *StatusError
	if !errors.As(err, &se) || se.Status != wire.StatusCryptoFailure {
		t.Fatalf("expected crypto failure, got %v", err)
	}
	sk, err := c.GenerateKey(ctx, wire.AlgEd25519, wire.UsageSign, "signer")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := c.Sign(ctx, sk.Blob, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	ok, err := c.Verify(ctx, wire.AlgEd25519, sk.PublicKey, []byte("m"), sig)
	if err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	ok, err = c.Verify(ctx, wire.AlgEd25519, sk.PublicKey, []byte("n"), sig)
	if err != nil || ok {
		t.Fatalf("verify tampered: %v %v", ok, err)
	}
	r, err := c.Random(ctx, 32)
	if err != nil || len(r) != 32 {
		t.Fatalf("random: %v", err)
	}
	if c.PQC() {
		pk, err := c.GenerateKey(ctx, wire.AlgMLDSA65, wire.UsageSign, "pq")
		if err != nil {
			t.Fatal(err)
		}
		if len(pk.PublicKey) != 1952 {
			t.Fatalf("ml-dsa-65 public key len %d", len(pk.PublicKey))
		}
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v\n%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "serving peer pid") {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
}

func TestRealCoreConnect(t *testing.T) {
	bin := realBinary(t)
	dir := t.TempDir()
	sock := dir + "/core.sock"
	cmd := exec.Command(bin, "--socket", sock, "--ephemeral-root", "--allow-unlocked-memory")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Wait() }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var c *Client
	var err error
	for {
		c, err = Connect(ctx, sock, time.Second)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("connect: %v\n%s", err, stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}
