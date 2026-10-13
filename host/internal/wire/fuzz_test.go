package wire

import (
	"bytes"
	"testing"
)

func FuzzDecodeHeader(f *testing.F) {
	for _, h := range []Header{
		{Kind: KindRequest, Op: OpHello, ID: 1, Len: 4},
		{Kind: KindResponse, Status: StatusCryptoFailure, Op: OpAeadEncrypt, ID: 7},
	} {
		b, _ := h.Encode()
		f.Add(b[:])
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := DecodeHeader(b)
		if err != nil {
			return
		}
		re, err := h.Encode()
		if err != nil || !bytes.Equal(re[:], b) {
			t.Fatalf("header %+v did not re-encode to its input", h)
		}
	})
}

func FuzzDecodeBody(f *testing.F) {
	f.Add(uint16(OpHello), uint8(KindRequest), []byte{0, 0, 0, 1})
	f.Add(uint16(OpKeyGenerate), uint8(KindRequest), []byte{0, 1, 0, 0, 0, 3, 0, 0, 0, 1, 'x'})
	f.Add(uint16(OpKeyExport), uint8(KindResponse), []byte{0, 0, 0, 2, 1, 2})
	f.Add(uint16(OpVerify), uint8(KindResponse), []byte{1})
	f.Fuzz(func(t *testing.T, op uint16, kind uint8, body []byte) {
		m := NewMessage(Op(op), Kind(kind))
		if m == nil {
			return
		}
		if err := DecodeBody(m, body); err != nil {
			return
		}
		re, err := EncodeBody(m)
		if err != nil || !bytes.Equal(re, body) {
			t.Fatalf("op 0x%04x kind %d: decoded body did not re-encode to its input", op, kind)
		}
	})
}
