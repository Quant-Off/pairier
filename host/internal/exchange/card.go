package exchange

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/Quant-Off/pairier/host/internal/wire"
)

const (
	CardVersion = 1
	MaxCard     = 4 + 1 + 4 + MaxMemberID + 2 + 4 + wire.MaxPublicKey + 2 + 4 + wire.MaxPublicKey + 4 + wire.MaxPublicKey + 8 + 4 + wire.MaxSignature
)

var cardMagic = [4]byte{'K', 'I', 'D', '1'}

type Card struct {
	MemberID          string
	IdentityAlg       uint16
	IdentityPublicKey []byte
	KemAlg            uint16
	KemPublicKey      []byte
	TLSPublicKey      []byte
	CreatedAt         uint64
	Signature         []byte
}

func (c *Card) validate() error {
	if !ValidMemberID(c.MemberID) {
		return ErrBadMemberID
	}
	if !IsSignatureAlg(c.IdentityAlg) || !IsKemAlg(c.KemAlg) {
		return ErrAlgorithm
	}
	if len(c.IdentityPublicKey) == 0 || len(c.IdentityPublicKey) > wire.MaxPublicKey ||
		len(c.KemPublicKey) == 0 || len(c.KemPublicKey) > wire.MaxPublicKey ||
		len(c.TLSPublicKey) == 0 || len(c.TLSPublicKey) > wire.MaxPublicKey ||
		len(c.Signature) > wire.MaxSignature {
		return ErrFormat
	}
	return nil
}

func (c *Card) signedBytes() ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	w := wire.NewWriter()
	w.U8(CardVersion)
	w.String(c.MemberID)
	w.U16(c.IdentityAlg)
	w.Bytes(c.IdentityPublicKey)
	w.U16(c.KemAlg)
	w.Bytes(c.KemPublicKey)
	w.Bytes(c.TLSPublicKey)
	w.U64(c.CreatedAt)
	body, err := w.Finish()
	if err != nil {
		return nil, err
	}
	return append(cardMagic[:], body...), nil
}

func (c *Card) Encode() ([]byte, error) {
	head, err := c.signedBytes()
	if err != nil {
		return nil, err
	}
	w := wire.NewWriter()
	w.Bytes(c.Signature)
	tail, err := w.Finish()
	if err != nil {
		return nil, err
	}
	return append(head, tail...), nil
}

func DecodeCard(b []byte) (*Card, error) {
	if len(b) < 4 || len(b) > MaxCard || [4]byte(b[0:4]) != cardMagic {
		return nil, ErrFormat
	}
	r := wire.NewReader(b[4:])
	v, err := r.U8()
	if err != nil || v != CardVersion {
		return nil, ErrFormat
	}
	c := &Card{}
	if c.MemberID, err = r.String(MaxMemberID); err != nil {
		return nil, ErrFormat
	}
	if c.IdentityAlg, err = r.U16(); err != nil {
		return nil, ErrFormat
	}
	if c.IdentityPublicKey, err = r.Bytes(wire.MaxPublicKey); err != nil {
		return nil, ErrFormat
	}
	if c.KemAlg, err = r.U16(); err != nil {
		return nil, ErrFormat
	}
	if c.KemPublicKey, err = r.Bytes(wire.MaxPublicKey); err != nil {
		return nil, ErrFormat
	}
	if c.TLSPublicKey, err = r.Bytes(wire.MaxPublicKey); err != nil {
		return nil, ErrFormat
	}
	if c.CreatedAt, err = r.U64(); err != nil {
		return nil, ErrFormat
	}
	if c.Signature, err = r.Bytes(wire.MaxSignature); err != nil {
		return nil, ErrFormat
	}
	if err := r.Finish(); err != nil {
		return nil, ErrFormat
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Card) Fingerprint() (string, error) {
	msg, err := c.signedBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(msg)
	return FormatFingerprint(sum[:]), nil
}

func FormatFingerprint(sum []byte) string {
	h := hex.EncodeToString(sum)
	var b strings.Builder
	for i := 0; i < len(h); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		end := i + 4
		if end > len(h) {
			end = len(h)
		}
		b.WriteString(h[i:end])
	}
	return b.String()
}

func NormalizeFingerprint(s string) string {
	return strings.ToLower(strings.NewReplacer("-", "", " ", "", ":", "").Replace(strings.TrimSpace(s)))
}

func (c *Card) MatchesFingerprint(s string) bool {
	fp, err := c.Fingerprint()
	if err != nil {
		return false
	}
	want := NormalizeFingerprint(fp)
	got := NormalizeFingerprint(s)
	return len(got) == len(want) && got == want
}

func SignCard(ctx context.Context, s Signer, identityBlob []byte, c *Card) error {
	msg, err := c.signedBytes()
	if err != nil {
		return err
	}
	sig, err := s.Sign(ctx, identityBlob, msg)
	if err != nil {
		return fmt.Errorf("exchange: sign card: %w", err)
	}
	c.Signature = sig
	return nil
}

func (c *Card) Verify(ctx context.Context, v Verifier) error {
	msg, err := c.signedBytes()
	if err != nil {
		return err
	}
	ok, err := v.Verify(ctx, c.IdentityAlg, c.IdentityPublicKey, msg, c.Signature)
	if err != nil {
		return fmt.Errorf("exchange: verify card: %w", err)
	}
	if !ok {
		return ErrSignature
	}
	return nil
}
