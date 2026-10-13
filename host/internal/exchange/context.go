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
	ContextVersion = 1
	MaxMemberID    = 64
	NonceLen       = 16
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
}

func NewContext(sender, recipient string, now time.Time) (*Context, error) {
	if !ValidMemberID(sender) || !ValidMemberID(recipient) {
		return nil, ErrBadMemberID
	}
	if sender == recipient {
		return nil, fmt.Errorf("%w: sender and recipient are the same", ErrBadMemberID)
	}
	c := &Context{Sender: sender, Recipient: recipient, CreatedAt: uint64(now.Unix())}
	if _, err := rand.Read(c.Nonce[:]); err != nil {
		return nil, fmt.Errorf("exchange: nonce: %w", err)
	}
	return c, nil
}

func (c *Context) Encode() ([]byte, error) {
	if !ValidMemberID(c.Sender) || !ValidMemberID(c.Recipient) {
		return nil, ErrBadMemberID
	}
	w := wire.NewWriter()
	w.U8(ContextVersion)
	w.String(c.Sender)
	w.String(c.Recipient)
	w.U64(c.CreatedAt)
	w.Bytes(c.Nonce[:])
	return w.Finish()
}

func DecodeContext(b []byte) (*Context, error) {
	if len(b) > wire.MaxContext {
		return nil, ErrFormat
	}
	r := wire.NewReader(b)
	v, err := r.U8()
	if err != nil || v != ContextVersion {
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
	if err := r.Finish(); err != nil {
		return nil, ErrFormat
	}
	if !ValidMemberID(c.Sender) || !ValidMemberID(c.Recipient) || c.Sender == c.Recipient {
		return nil, ErrBadMemberID
	}
	return c, nil
}
