package exchange

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/Quant-Off/pairier/host/internal/wire"
)

const (
	ContextVersion = 2
	contextV1      = 1
	MaxMemberID    = 64
	NonceLen       = 16
	AuditHashLen   = 32
)

var (
	ErrBadMemberID = errors.New("exchange: invalid member id")
	ErrFormat      = errors.New("exchange: malformed object")
	ErrSignature   = errors.New("exchange: signature verification failed")
	ErrAlgorithm   = errors.New("exchange: unsupported algorithm")
)

var memberIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func ValidMemberID(id string) bool {
	return len(id) <= MaxMemberID && memberIDPattern.MatchString(id)
}

type Signer interface {
	Sign(ctx context.Context, blob, message []byte) ([]byte, error)
}

type Verifier interface {
	Verify(ctx context.Context, alg uint16, publicKey, message, signature []byte) (bool, error)
}

type Context struct {
	Sender    string
	Recipient string
	CreatedAt uint64
	Nonce     [NonceLen]byte
	AuditSeq  uint64
	AuditHash [AuditHashLen]byte
}

func NewContext(sender, recipient string, now time.Time, auditSeq uint64, auditHash []byte) (*Context, error) {
	if !ValidMemberID(sender) || !ValidMemberID(recipient) {
		return nil, ErrBadMemberID
	}
	if sender == recipient {
		return nil, fmt.Errorf("%w: sender and recipient are the same", ErrBadMemberID)
	}
	if auditSeq == 0 || len(auditHash) != AuditHashLen {
		return nil, fmt.Errorf("%w: audit head is required", ErrFormat)
	}
	c := &Context{Sender: sender, Recipient: recipient, CreatedAt: uint64(now.Unix()), AuditSeq: auditSeq}
	copy(c.AuditHash[:], auditHash)
	if _, err := rand.Read(c.Nonce[:]); err != nil {
		return nil, fmt.Errorf("exchange: nonce: %w", err)
	}
	return c, nil
}

func (c *Context) HasAuditHead() bool { return c.AuditSeq != 0 }

func (c *Context) Encode() ([]byte, error) {
	if !ValidMemberID(c.Sender) || !ValidMemberID(c.Recipient) {
		return nil, ErrBadMemberID
	}
	if c.AuditSeq == 0 {
		return nil, fmt.Errorf("%w: audit head is required", ErrFormat)
	}
	w := wire.NewWriter()
	w.U8(ContextVersion)
	w.String(c.Sender)
	w.String(c.Recipient)
	w.U64(c.CreatedAt)
	w.Bytes(c.Nonce[:])
	w.U64(c.AuditSeq)
	w.Bytes(c.AuditHash[:])
	return w.Finish()
}

func DecodeContext(b []byte) (*Context, error) {
	if len(b) > wire.MaxContext {
		return nil, ErrFormat
	}
	r := wire.NewReader(b)
	v, err := r.U8()
	if err != nil || (v != contextV1 && v != ContextVersion) {
		return nil, ErrFormat
	}
	c := &Context{}
	if c.Sender, err = r.String(MaxMemberID); err != nil {
		return nil, ErrFormat
	}
	if c.Recipient, err = r.String(MaxMemberID); err != nil {
		return nil, ErrFormat
	}
	if c.CreatedAt, err = r.U64(); err != nil {
		return nil, ErrFormat
	}
	nonce, err := r.Array(NonceLen)
	if err != nil {
		return nil, ErrFormat
	}
	copy(c.Nonce[:], nonce)
	if v == ContextVersion {
		if c.AuditSeq, err = r.U64(); err != nil || c.AuditSeq == 0 {
			return nil, ErrFormat
		}
		hash, err := r.Array(AuditHashLen)
		if err != nil {
			return nil, ErrFormat
		}
		copy(c.AuditHash[:], hash)
	}
	if err := r.Finish(); err != nil {
		return nil, ErrFormat
	}
	if !ValidMemberID(c.Sender) || !ValidMemberID(c.Recipient) || c.Sender == c.Recipient {
		return nil, ErrBadMemberID
	}
	return c, nil
}
