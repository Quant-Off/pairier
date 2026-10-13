package wire

import (
	"encoding/binary"
	"errors"
)

const (
	HeaderLen       = 16
	MaxBody         = 1 << 20
	ProtocolVersion = 1
)

var Magic = [4]byte{'K', 'W', 'P', '1'}

var (
	ErrTruncated     = errors.New("wire: truncated input")
	ErrTrailingBytes = errors.New("wire: trailing bytes after message")
	ErrBadMagic      = errors.New("wire: bad frame magic")
	ErrBadKind       = errors.New("wire: bad frame kind")
	ErrBadStatus     = errors.New("wire: bad frame status")
	ErrBadBool       = errors.New("wire: bad boolean encoding")
	ErrBadUTF8       = errors.New("wire: string is not valid utf-8")
	ErrBadLength     = errors.New("wire: field has wrong length")
	ErrTooLarge      = errors.New("wire: field exceeds its size limit")
	ErrBodyTooLarge  = errors.New("wire: body exceeds maximum frame size")
	ErrUnknownOp     = errors.New("wire: unknown operation code")
)

type Kind uint8

const (
	KindRequest  Kind = 1
	KindResponse Kind = 2
)

func (k Kind) valid() bool { return k == KindRequest || k == KindResponse }

type Status uint8

const (
	StatusOK                 Status = 0
	StatusProtocol           Status = 1
	StatusUnsupportedOp      Status = 2
	StatusInvalidArgument    Status = 3
	StatusInvalidKeyBlob     Status = 4
	StatusUsageDenied        Status = 5
	StatusCryptoFailure      Status = 6
	StatusCapabilityDisabled Status = 7
	StatusLimitExceeded      Status = 8
	StatusInternal           Status = 9
)

func (s Status) valid() bool { return s <= StatusInternal }

func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusProtocol:
		return "protocol error"
	case StatusUnsupportedOp:
		return "unsupported operation"
	case StatusInvalidArgument:
		return "invalid argument"
	case StatusInvalidKeyBlob:
		return "invalid key blob"
	case StatusUsageDenied:
		return "usage denied"
	case StatusCryptoFailure:
		return "cryptographic failure"
	case StatusCapabilityDisabled:
		return "capability disabled"
	case StatusLimitExceeded:
		return "limit exceeded"
	case StatusInternal:
		return "internal error"
	default:
		return "unknown status"
	}
}

type Op uint16

const (
	OpHello       Op = 0x0001
	OpPing        Op = 0x0002
	OpKeyGenerate Op = 0x0010
	OpAeadEncrypt Op = 0x0020
	OpAeadDecrypt Op = 0x0021
	OpSign        Op = 0x0022
	OpVerify      Op = 0x0023
	OpRandom      Op = 0x0040
)

func (o Op) Known() bool {
	switch o {
	case OpHello, OpPing, OpKeyGenerate, OpAeadEncrypt, OpAeadDecrypt, OpSign, OpVerify, OpRandom:
		return true
	default:
		return false
	}
}

type Header struct {
	Kind   Kind
	Status Status
	Op     Op
	ID     uint32
	Len    uint32
}

func NewRequest(op Op, id, n uint32) (Header, error) {
	h := Header{Kind: KindRequest, Status: StatusOK, Op: op, ID: id, Len: n}
	return h, h.Validate()
}

func NewResponse(op Op, id, n uint32) (Header, error) {
	h := Header{Kind: KindResponse, Status: StatusOK, Op: op, ID: id, Len: n}
	return h, h.Validate()
}

func NewError(op Op, id uint32, status Status) Header {
	return Header{Kind: KindResponse, Status: status, Op: op, ID: id, Len: 0}
}

func (h Header) Validate() error {
	if !h.Kind.valid() {
		return ErrBadKind
	}
	if !h.Status.valid() {
		return ErrBadStatus
	}
	if h.Len > MaxBody {
		return ErrBodyTooLarge
	}
	if h.Kind == KindRequest && h.Status != StatusOK {
		return ErrBadStatus
	}
	if h.Kind == KindResponse && h.Status != StatusOK && h.Len != 0 {
		return ErrBadStatus
	}
	return nil
}

func (h Header) Encode() ([HeaderLen]byte, error) {
	var out [HeaderLen]byte
	if err := h.Validate(); err != nil {
		return out, err
	}
	copy(out[0:4], Magic[:])
	out[4] = byte(h.Kind)
	out[5] = byte(h.Status)
	binary.BigEndian.PutUint16(out[6:8], uint16(h.Op))
	binary.BigEndian.PutUint32(out[8:12], h.ID)
	binary.BigEndian.PutUint32(out[12:16], h.Len)
	return out, nil
}

func DecodeHeader(b []byte) (Header, error) {
	if len(b) != HeaderLen {
		return Header{}, ErrTruncated
	}
	if [4]byte(b[0:4]) != Magic {
		return Header{}, ErrBadMagic
	}
	h := Header{
		Kind:   Kind(b[4]),
		Status: Status(b[5]),
		Op:     Op(binary.BigEndian.Uint16(b[6:8])),
		ID:     binary.BigEndian.Uint32(b[8:12]),
		Len:    binary.BigEndian.Uint32(b[12:16]),
	}
	if err := h.Validate(); err != nil {
		return Header{}, err
	}
	return h, nil
}
