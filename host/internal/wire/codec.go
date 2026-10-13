package wire

import (
	"encoding/binary"
	"math"
	"unicode/utf8"
)

type Reader struct {
	buf []byte
	pos int
}

func NewReader(b []byte) *Reader { return &Reader{buf: b} }

func (r *Reader) Remaining() int { return len(r.buf) - r.pos }

func (r *Reader) take(n int) ([]byte, error) {
	if n < 0 || n > len(r.buf)-r.pos {
		return nil, ErrTruncated
	}
	end := r.pos + n
	s := r.buf[r.pos:end:end]
	r.pos = end
	return s, nil
}

func (r *Reader) U8() (uint8, error) {
	s, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return s[0], nil
}

func (r *Reader) U16() (uint16, error) {
	s, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(s), nil
}

func (r *Reader) U32() (uint32, error) {
	s, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(s), nil
}

func (r *Reader) U64() (uint64, error) {
	s, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(s), nil
}

func (r *Reader) Bool() (bool, error) {
	v, err := r.U8()
	if err != nil {
		return false, err
	}
	switch v {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, ErrBadBool
	}
}

func (r *Reader) Bytes(max int) ([]byte, error) {
	n, err := r.U32()
	if err != nil {
		return nil, err
	}
	if max < 0 || uint64(n) > uint64(max) {
		return nil, ErrTooLarge
	}
	return r.take(int(n))
}

func (r *Reader) Array(n int) ([]byte, error) {
	s, err := r.Bytes(n)
	if err != nil {
		return nil, err
	}
	if len(s) != n {
		return nil, ErrBadLength
	}
	return s, nil
}

func (r *Reader) String(max int) (string, error) {
	s, err := r.Bytes(max)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(s) {
		return "", ErrBadUTF8
	}
	return string(s), nil
}

func (r *Reader) Finish() error {
	if r.pos != len(r.buf) {
		return ErrTrailingBytes
	}
	return nil
}

type Writer struct {
	buf []byte
	err error
}

func NewWriter() *Writer { return &Writer{} }

func (w *Writer) push(b []byte) {
	if w.err != nil {
		return
	}
	if len(b) > MaxBody-len(w.buf) {
		w.err = ErrBodyTooLarge
		return
	}
	w.buf = append(w.buf, b...)
}

func (w *Writer) U8(v uint8) { w.push([]byte{v}) }

func (w *Writer) U16(v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	w.push(b[:])
}

func (w *Writer) U32(v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	w.push(b[:])
}

func (w *Writer) U64(v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	w.push(b[:])
}

func (w *Writer) Bool(v bool) {
	if v {
		w.U8(1)
	} else {
		w.U8(0)
	}
}

func (w *Writer) Bytes(b []byte) {
	if w.err != nil {
		return
	}
	if uint64(len(b)) > math.MaxUint32 {
		w.err = ErrTooLarge
		return
	}
	w.U32(uint32(len(b)))
	w.push(b)
}

func (w *Writer) String(s string) { w.Bytes([]byte(s)) }

func (w *Writer) Len() int { return len(w.buf) }

func (w *Writer) Finish() ([]byte, error) {
	if w.err != nil {
		return nil, w.err
	}
	return w.buf, nil
}
