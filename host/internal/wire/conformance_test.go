package wire

import (
	"bytes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

const vectorPath = "../../../conformance/wire/v1.txt"

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func parseOp(t *testing.T, s string) Op {
	t.Helper()
	v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 16)
	if err != nil {
		t.Fatalf("bad op %q: %v", s, err)
	}
	return Op(v)
}

func parseKind(t *testing.T, s string) Kind {
	t.Helper()
	switch s {
	case "req":
		return KindRequest
	case "rsp":
		return KindResponse
	}
	t.Fatalf("bad kind %q", s)
	return 0
}

func roundtrip(op Op, kind Kind, body []byte) ([]byte, error) {
	m := NewMessage(op, kind)
	if m == nil {
		return nil, ErrUnknownOp
	}
	if err := DecodeBody(m, body); err != nil {
		return nil, err
	}
	return EncodeBody(m)
}

func field(fields []string, i int) string {
	if i < len(fields) {
		return fields[i]
	}
	return ""
}

func TestConformanceVectors(t *testing.T) {
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var frames, rejectHeaders, rejectBodies int
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		tag, name := f[0], f[1]
		switch tag {
		case "frame":
			b := unhex(t, field(f, 2))
			h, body := b[:HeaderLen], b[HeaderLen:]
			hdr, err := DecodeHeader(h)
			if err != nil {
				t.Fatalf("%s: header: %v", name, err)
			}
			if int(hdr.Len) != len(body) {
				t.Fatalf("%s: len %d != %d", name, hdr.Len, len(body))
			}
			enc, err := hdr.Encode()
			if err != nil || !bytes.Equal(enc[:], h) {
				t.Fatalf("%s: header re-encode mismatch (%v)", name, err)
			}
			if hdr.Status == StatusOK {
				re, err := roundtrip(hdr.Op, hdr.Kind, body)
				if err != nil {
					t.Fatalf("%s: body: %v", name, err)
				}
				if !bytes.Equal(re, body) {
					t.Fatalf("%s: body re-encode mismatch\n got %x\nwant %x", name, re, body)
				}
			} else if len(body) != 0 {
				t.Fatalf("%s: error response with body", name)
			}
			frames++
		case "reject_header":
			if _, err := DecodeHeader(unhex(t, field(f, 2))); err == nil {
				t.Fatalf("%s: header accepted", name)
			}
			rejectHeaders++
		case "reject_body":
			op := parseOp(t, field(f, 2))
			kind := parseKind(t, field(f, 3))
			if _, err := roundtrip(op, kind, unhex(t, field(f, 4))); err == nil {
				t.Fatalf("%s: body accepted", name)
			}
			rejectBodies++
		default:
			t.Fatalf("unknown tag %q", tag)
		}
	}
	if frames < 20 || rejectHeaders < 6 || rejectBodies < 10 {
		t.Fatalf("too few vectors: %d %d %d", frames, rejectHeaders, rejectBodies)
	}
}

func TestHeaderLayout(t *testing.T) {
	h, err := NewRequest(OpHello, 0x01020304, 4)
	if err != nil {
		t.Fatal(err)
	}
	got, err := h.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want := [HeaderLen]byte{'K', 'W', 'P', '1', 1, 0, 0, 1, 1, 2, 3, 4, 0, 0, 0, 4}
	if got != want {
		t.Fatalf("got %x want %x", got, want)
	}
	e := NewError(OpAeadEncrypt, 7, StatusCryptoFailure)
	got, err = e.Encode()
	if err != nil {
		t.Fatal(err)
	}
	want = [HeaderLen]byte{'K', 'W', 'P', '1', 2, 6, 0, 0x20, 0, 0, 0, 7, 0, 0, 0, 0}
	if got != want {
		t.Fatalf("got %x want %x", got, want)
	}
	back, err := DecodeHeader(got[:])
	if err != nil || back != e {
		t.Fatalf("decode mismatch: %+v %v", back, err)
	}
	if _, err := NewRequest(OpPing, 1, MaxBody+1); err != ErrBodyTooLarge {
		t.Fatalf("expected ErrBodyTooLarge, got %v", err)
	}
	if _, err := DecodeHeader(got[:15]); err != ErrTruncated {
		t.Fatalf("expected ErrTruncated, got %v", err)
	}
}

func TestWriterLimits(t *testing.T) {
	w := NewWriter()
	chunk := make([]byte, (1<<16)-4)
	for i := 0; i < 16; i++ {
		w.Bytes(chunk)
	}
	if w.Len() != MaxBody {
		t.Fatalf("len %d", w.Len())
	}
	w.U8(0)
	if _, err := w.Finish(); err != ErrBodyTooLarge {
		t.Fatalf("expected ErrBodyTooLarge, got %v", err)
	}
}

func TestReaderStrictness(t *testing.T) {
	r := NewReader([]byte{0, 0, 0, 5, 1, 2})
	if _, err := r.Bytes(4); err != ErrTooLarge {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
	r = NewReader([]byte{0, 0, 0, 5, 1, 2})
	if _, err := r.Bytes(5); err != ErrTruncated {
		t.Fatalf("expected ErrTruncated, got %v", err)
	}
	r = NewReader([]byte{0, 0, 0, 2, 1, 2, 9})
	s, err := r.Bytes(5)
	if err != nil || !bytes.Equal(s, []byte{1, 2}) {
		t.Fatalf("bytes: %x %v", s, err)
	}
	if cap(s) != 2 {
		t.Fatalf("subslice capacity leaks frame buffer: cap=%d", cap(s))
	}
	if err := r.Finish(); err != ErrTrailingBytes {
		t.Fatalf("expected ErrTrailingBytes, got %v", err)
	}
	r = NewReader([]byte{2})
	if _, err := r.Bool(); err != ErrBadBool {
		t.Fatalf("expected ErrBadBool, got %v", err)
	}
	r = NewReader([]byte{0, 0, 0, 1, 0xff})
	if _, err := r.String(8); err != ErrBadUTF8 {
		t.Fatalf("expected ErrBadUTF8, got %v", err)
	}
	r = NewReader([]byte{0, 0, 0, 1, 1})
	if _, err := r.Array(2); err != ErrBadLength {
		t.Fatalf("expected ErrBadLength, got %v", err)
	}
}
