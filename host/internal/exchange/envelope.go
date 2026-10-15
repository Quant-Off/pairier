package exchange

import (
	"context"
	"fmt"

	"github.com/Quant-Off/pairier/host/internal/wire"
)

const MaxEnvelope = 4 + 4 + wire.MaxContext + 4 + wire.MaxPackage + 2 + 4 + wire.MaxSignature

var envelopeMagic = [4]byte{'K', 'X', 'P', '1'}

type Envelope struct {
	Context   []byte
	Package   []byte
	SigAlg    uint16
	Signature []byte
}

func (e *Envelope) signedBytes() ([]byte, error) {
	if len(e.Context) > wire.MaxContext || len(e.Package) > wire.MaxPackage {
		return nil, ErrFormat
	}
	w := wire.NewWriter()
	w.Bytes(e.Context)
	w.Bytes(e.Package)
	w.U16(e.SigAlg)
	body, err := w.Finish()
	if err != nil {
		return nil, err
	}
	return append(envelopeMagic[:], body...), nil
}

func (e *Envelope) Encode() ([]byte, error) {
	if len(e.Signature) > wire.MaxSignature {
		return nil, ErrFormat
	}
	head, err := e.signedBytes()
	if err != nil {
		return nil, err
	}
	w := wire.NewWriter()
	w.Bytes(e.Signature)
	tail, err := w.Finish()
	if err != nil {
		return nil, err
	}
	return append(head, tail...), nil
}

func DecodeEnvelope(b []byte) (*Envelope, error) {
	if len(b) < 4 || len(b) > MaxEnvelope || [4]byte(b[0:4]) != envelopeMagic {
		return nil, ErrFormat
	}
	r := wire.NewReader(b[4:])
	e := &Envelope{}
	var err error
	if e.Context, err = r.Bytes(wire.MaxContext); err != nil {
		return nil, ErrFormat
	}
	if e.Package, err = r.Bytes(wire.MaxPackage); err != nil {
		return nil, ErrFormat
	}
	if e.SigAlg, err = r.U16(); err != nil {
		return nil, ErrFormat
	}
	if e.Signature, err = r.Bytes(wire.MaxSignature); err != nil {
		return nil, ErrFormat
	}
	if err := r.Finish(); err != nil {
		return nil, ErrFormat
	}
	if !IsSignatureAlg(e.SigAlg) {
		return nil, ErrAlgorithm
	}
	return e, nil
}

func Seal(ctx context.Context, s Signer, identityBlob []byte, sigAlg uint16, ectx *Context, pkg []byte) (*Envelope, error) {
	if !IsSignatureAlg(sigAlg) {
		return nil, ErrAlgorithm
	}
	cb, err := ectx.Encode()
	if err != nil {
		return nil, err
	}
	e := &Envelope{Context: cb, Package: pkg, SigAlg: sigAlg}
	msg, err := e.signedBytes()
	if err != nil {
		return nil, err
	}
	sig, err := s.Sign(ctx, identityBlob, msg)
	if err != nil {
		return nil, fmt.Errorf("exchange: sign: %w", err)
	}
	e.Signature = sig
	return e, nil
}

func (e *Envelope) Verify(ctx context.Context, v Verifier, senderPublicKey []byte) (*Context, error) {
	c, err := DecodeContext(e.Context)
	if err != nil {
		return nil, err
	}
	msg, err := e.signedBytes()
	if err != nil {
		return nil, err
	}
	ok, err := v.Verify(ctx, e.SigAlg, senderPublicKey, msg, e.Signature)
	if err != nil {
		return nil, fmt.Errorf("exchange: verify: %w", err)
	}
	if !ok {
		return nil, ErrSignature
	}
	return c, nil
}

func IsSignatureAlg(alg uint16) bool {
	switch alg {
	case wire.AlgECDSAP256SHA256, wire.AlgECDSAP384SHA384, wire.AlgEd25519, wire.AlgMLDSA65, wire.AlgMLDSA87:
		return true
	default:
		return false
	}
}

func IsKemAlg(alg uint16) bool {
	switch alg {
	case wire.AlgDHKEMP256, wire.AlgMLKEM768, wire.AlgMLKEM1024, wire.AlgHybridP256MLKEM768, wire.AlgMLKEM768P256:
		return true
	default:
		return false
	}
}

func IsPQCAlg(alg uint16) bool {
	switch alg {
	case wire.AlgMLDSA65, wire.AlgMLDSA87, wire.AlgMLKEM768, wire.AlgMLKEM1024, wire.AlgHybridP256MLKEM768, wire.AlgMLKEM768P256:
		return true
	default:
		return false
	}
}
