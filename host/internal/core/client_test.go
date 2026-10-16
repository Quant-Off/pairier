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
		case wire.OpKeyInspect:
			var req wire.KeyInspectRequest
			if err := wire.DecodeBody(&req, body); err != nil {
				return wire.NewError(h.Op, h.ID, wire.StatusProtocol), nil
			}
			rsp := &wire.KeyInspectResponse{Alg: wire.AlgAES256GCM, Usage: wire.UsageDecrypt | wire.UsageExport, Label: "fake/" + string(req.KeyBlob)}
			copy(rsp.KeyID[:], req.KeyBlob)
			rb, _ := wire.EncodeBody(rsp)
			rh, _ := wire.NewResponse(h.Op, h.ID, uint32(len(rb)))
			return rh, rb
		case wire.OpKeyExport:
			var req wire.KeyExportRequest
			if err := wire.DecodeBody(&req, body); err != nil {
				return wire.NewError(h.Op, h.ID, wire.StatusProtocol), nil
			}
			rb, _ := wire.EncodeBody(&wire.KeyExportResponse{Package: append(append([]byte{}, req.Context...), req.RecipientPublicKey...)})
			rh, _ := wire.NewResponse(h.Op, h.ID, uint32(len(rb)))
			return rh, rb
		case wire.OpKeyImport:
			var req wire.KeyImportRequest
			if err := wire.DecodeBody(&req, body); err != nil {
				return wire.NewError(h.Op, h.ID, wire.StatusProtocol), nil
			}
			if !bytes.HasPrefix(req.Package, req.Context) {
				return wire.NewError(h.Op, h.ID, wire.StatusInvalidArgument), nil
			}
			rb, _ := wire.EncodeBody(&wire.KeyImportResponse{KeyBlob: req.KemKeyBlob, Alg: wire.AlgAES256GCM, Usage: wire.UsageDecrypt, Label: "imported"})
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

func TestExchangeCallsOverFakeCore(t *testing.T) {
	conn := fakeCore(t, helloHandler(0))
	c, err := newClient(context.Background(), conn, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx := context.Background()
	info, err := c.Inspect(ctx, []byte("blob"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Alg != wire.AlgAES256GCM || info.Usage != wire.UsageDecrypt|wire.UsageExport || info.Label != "fake/blob" || string(info.KeyID[:4]) != "blob" {
		t.Fatalf("unexpected info %+v", info)
	}
	pkg, err := c.ExportKey(ctx, []byte("blob"), wire.AlgDHKEMP256, []byte("pk"), wire.UsageDecrypt, []byte("ctx"))
	if err != nil || string(pkg) != "ctxpk" {
		t.Fatalf("export: %q %v", pkg, err)
	}
	imp, err := c.ImportKey(ctx, []byte("kem"), pkg, []byte("ctx"))
	if err != nil || string(imp.Blob) != "kem" || imp.Usage != wire.UsageDecrypt || imp.Label != "imported" {
		t.Fatalf("import: %+v %v", imp, err)
	}
	_, err = c.ImportKey(ctx, []byte("kem"), pkg, []byte("other"))
	var se *StatusError
	if !errors.As(err, &se) || se.Status != wire.StatusInvalidArgument {
		t.Fatalf("expected invalid argument, got %v", err)
	}
	if _, err := c.ExportKey(ctx, nil, 0, nil, 0, make([]byte, wire.MaxContext+1)); !errors.As(err, &se) || se.Status != wire.StatusLimitExceeded {
		t.Fatalf("expected limit error, got %v", err)
	}
	if _, err := c.ImportKey(ctx, nil, make([]byte, wire.MaxPackage+1), nil); !errors.As(err, &se) || se.Status != wire.StatusLimitExceeded {
		t.Fatalf("expected limit error, got %v", err)
	}
	if err := c.Ping(ctx); err != nil {
		t.Fatal(err)
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

func slowCore(t *testing.T, delay time.Duration) net.Conn {
	t.Helper()
	return fakeCore(t, func(h wire.Header, _ []byte) (wire.Header, []byte) {
		if h.Op == wire.OpHello {
			return helloHandler(0)(h, nil)
		}
		time.Sleep(delay)
		rh, _ := wire.NewResponse(h.Op, h.ID, 0)
		return rh, nil
	})
}

func TestCallerCancelDoesNotBreakSession(t *testing.T) {
	c, err := newClient(context.Background(), slowCore(t, 200*time.Millisecond), nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("call abandoned by its caller failed: %v", err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("session broken after an abandoned call: %v", err)
	}
	done, cancelDone := context.WithCancel(context.Background())
	cancelDone()
	if err := c.Ping(done); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled before sending, got %v", err)
	}
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("session broken after a cancelled caller: %v", err)
	}
}

func TestHungCoreBreaksSessionAfterTimeout(t *testing.T) {
	c, err := newClient(context.Background(), slowCore(t, 2*time.Second), nil, 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	if err := c.Ping(context.Background()); !errors.Is(err, ErrBroken) {
		t.Fatalf("expected ErrBroken, got %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout did not unblock the call promptly")
	}
	if err := c.Ping(context.Background()); !errors.Is(err, ErrBroken) {
		t.Fatalf("expected ErrBroken after timeout, got %v", err)
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

func TestRealCoreExchange(t *testing.T) {
	bin := realBinary(t)
	ctx := context.Background()
	spawn := func() *Client {
		var stderr bytes.Buffer
		c, err := Spawn(ctx, Options{Binary: bin, EphemeralRoot: true, PQC: true, AllowUnlockedMemory: true, Stderr: &stderr})
		if err != nil {
			t.Fatalf("spawn: %v\n%s", err, stderr.String())
		}
		return c
	}
	a := spawn()
	defer a.Close()
	b := spawn()
	defer b.Close()

	kemAlg := wire.AlgDHKEMP256
	if b.PQC() {
		kemAlg = wire.AlgMLKEM768P256
	}
	kem, err := b.GenerateKey(ctx, kemAlg, wire.UsageDecapsulate, "b/kem")
	if err != nil {
		t.Fatal(err)
	}
	k, err := a.GenerateKey(ctx, wire.AlgAES256GCM, wire.UsageEncrypt|wire.UsageDecrypt|wire.UsageExport, "a/shared")
	if err != nil {
		t.Fatal(err)
	}
	info, err := a.Inspect(ctx, k.Blob)
	if err != nil || info.KeyID != k.KeyID || info.Label != "a/shared" || info.Alg != wire.AlgAES256GCM || len(info.PublicKey) != 0 {
		t.Fatalf("inspect: %+v %v", info, err)
	}
	kinfo, err := b.Inspect(ctx, kem.Blob)
	if err != nil || !bytes.Equal(kinfo.PublicKey, kem.PublicKey) {
		t.Fatalf("kem inspect: %v", err)
	}
	_, err = b.Inspect(ctx, k.Blob)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != wire.StatusInvalidKeyBlob {
		t.Fatalf("foreign blob should be rejected, got %v", err)
	}
	ct, err := a.Encrypt(ctx, k.Blob, []byte("for b"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := a.ExportKey(ctx, k.Blob, kemAlg, kem.PublicKey, wire.UsageDecrypt, []byte("from=a;to=b"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ImportKey(ctx, kem.Blob, pkg, []byte("from=a;to=c")); !errors.As(err, &se) || se.Status != wire.StatusInvalidArgument {
		t.Fatalf("context mismatch should fail, got %v", err)
	}
	imp, err := b.ImportKey(ctx, kem.Blob, pkg, []byte("from=a;to=b"))
	if err != nil {
		t.Fatal(err)
	}
	if imp.KeyID != k.KeyID || imp.Usage != wire.UsageDecrypt || imp.Label != "a/shared" {
		t.Fatalf("imported: %+v", imp)
	}
	pt, err := b.Decrypt(ctx, imp.Blob, ct, nil)
	if err != nil || string(pt) != "for b" {
		t.Fatalf("decrypt: %q %v", pt, err)
	}
	if _, err := b.Encrypt(ctx, imp.Blob, []byte("x"), nil); !errors.As(err, &se) || se.Status != wire.StatusUsageDenied {
		t.Fatalf("granted usage should be enforced, got %v", err)
	}
	if _, err := a.ExportKey(ctx, k.Blob, kemAlg, kem.PublicKey, wire.UsageEncrypt|wire.UsageDecrypt|wire.UsageWrap, []byte("x")); !errors.As(err, &se) || se.Status != wire.StatusUsageDenied {
		t.Fatalf("usage escalation should fail, got %v", err)
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
