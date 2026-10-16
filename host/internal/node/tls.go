package node

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/Quant-Off/pairier/host/internal/exchange"
	"github.com/Quant-Off/pairier/host/internal/store"
	"github.com/Quant-Off/pairier/host/internal/wire"
)

const (
	tlsValidity    = 10 * 365 * 24 * time.Hour
	tlsSignTimeout = 10 * time.Second
	p256SigLen     = 64
)

var (
	ErrTLSMaterial = errors.New("node: tls material is inconsistent")
	ErrLegacyTLS   = errors.New("node: tls key is held outside the core, run kmsctl card renew and send the new card to members")
	errPrehashed   = errors.New("node: tls key signs only whole messages")
	errTLSHash     = errors.New("node: tls key signs only with sha-256")
)

type coreSigner struct {
	n    *Node
	blob []byte
	pub  *ecdsa.PublicKey
}

func (s *coreSigner) Public() crypto.PublicKey { return s.pub }

func (s *coreSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errPrehashed
}

func (s *coreSigner) SignMessage(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, errTLSHash
	}
	ctx, cancel := context.WithTimeout(context.Background(), tlsSignTimeout)
	defer cancel()
	sig, err := s.n.core.Sign(ctx, s.blob, msg)
	if err != nil {
		return nil, err
	}
	if len(sig) != p256SigLen {
		return nil, ErrTLSMaterial
	}
	return asn1.Marshal(struct{ R, S *big.Int }{
		new(big.Int).SetBytes(sig[:p256SigLen/2]),
		new(big.Int).SetBytes(sig[p256SigLen/2:]),
	})
}

func tlsLabel(memberID string) string { return "tls/" + memberID }

func (n *Node) issueTLS(ctx context.Context) (*store.TLSRecord, error) {
	label := tlsLabel(n.info.MemberID)
	k, err := n.core.GenerateKey(ctx, wire.AlgECDSAP256SHA256, wire.UsageSign, label)
	if err != nil {
		return nil, err
	}
	now := n.opts.now()
	rec := &store.KeyRecord{KeyID: store.KeyIDString(k.KeyID), Alg: wire.AlgECDSAP256SHA256, Usage: wire.UsageSign, Label: label, Blob: k.Blob, PublicKey: k.PublicKey, CreatedAt: now.Unix()}
	if err := n.st.PutKey(rec); err != nil {
		return nil, err
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), k.PublicKey)
	if err != nil {
		return nil, ErrTLSMaterial
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: n.info.MemberID},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(tlsValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, &coreSigner{n: n, blob: k.Blob, pub: pub})
	if err != nil {
		return nil, err
	}
	return &store.TLSRecord{Cert: certDER, KeyID: rec.KeyID, CreatedAt: now.Unix()}, nil
}

func (n *Node) createTLS(ctx context.Context) error {
	rec, err := n.issueTLS(ctx)
	if err != nil {
		return err
	}
	if err := n.st.PutTLS(rec); err != nil {
		return err
	}
	return n.loadTLS(ctx)
}

func (n *Node) loadTLS(ctx context.Context) error {
	rec, err := n.st.GetTLS()
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(rec.Cert)
	if err != nil {
		return ErrTLSMaterial
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() || leaf.Subject.CommonName != n.info.MemberID {
		return ErrTLSMaterial
	}
	if rec.Legacy() {
		n.tls = tls.Certificate{Certificate: [][]byte{rec.Cert}, Leaf: leaf}
		n.tlsLegacy = true
		return nil
	}
	key, err := n.Key(ctx, rec.KeyID)
	if err != nil {
		return fmt.Errorf("node: tls key: %w", err)
	}
	raw, err := pub.Bytes()
	if err != nil || key.Alg != wire.AlgECDSAP256SHA256 || key.Usage != wire.UsageSign ||
		key.Label != tlsLabel(n.info.MemberID) || !bytes.Equal(raw, key.PublicKey) {
		return ErrTLSMaterial
	}
	n.tls = tls.Certificate{Certificate: [][]byte{rec.Cert}, PrivateKey: &coreSigner{n: n, blob: key.Blob, pub: pub}, Leaf: leaf}
	n.tlsLegacy = false
	return nil
}

func (n *Node) TLSCertificate() (tls.Certificate, error) {
	if n.tlsLegacy {
		return tls.Certificate{}, ErrLegacyTLS
	}
	return n.tls, nil
}

func (n *Node) TLSPublicKey() []byte {
	if n.tls.Leaf == nil {
		return nil
	}
	return n.tls.Leaf.RawSubjectPublicKeyInfo
}

func (n *Node) MemberByTLS(ctx context.Context, memberID string, spki []byte) (*exchange.Card, error) {
	if len(spki) == 0 || !store.ValidMemberID(memberID) || memberID == n.info.MemberID {
		return nil, ErrUnknownMember
	}
	rec, err := n.st.GetMember(memberID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrBadID) {
			return nil, ErrUnknownMember
		}
		return nil, err
	}
	claimed, err := exchange.DecodeCard(rec.Card)
	if err != nil {
		return nil, err
	}
	if claimed.MemberID != memberID || !bytes.Equal(claimed.TLSPublicKey, spki) {
		return nil, ErrUnknownMember
	}
	card, err := n.Member(ctx, memberID)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(card.TLSPublicKey, spki) {
		return nil, ErrUnknownMember
	}
	return card, nil
}
