package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/Quant-Off/pairier/host/internal/exchange"
)

var (
	ErrNoCertificate = errors.New("auth: peer presented no certificate")
	ErrCertificate   = errors.New("auth: peer certificate rejected")
	ErrUnknownPeer   = errors.New("auth: peer is not a known member")
)

type Resolver interface {
	MemberByTLS(ctx context.Context, memberID string, spki []byte) (*exchange.Card, error)
}

func leaf(raw [][]byte, now time.Time) (*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, ErrNoCertificate
	}
	c, err := x509.ParseCertificate(raw[0])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCertificate, err)
	}
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return nil, fmt.Errorf("%w: outside validity period", ErrCertificate)
	}
	if c.PublicKeyAlgorithm != x509.ECDSA {
		return nil, fmt.Errorf("%w: unsupported key algorithm", ErrCertificate)
	}
	return c, nil
}

func Peer(ctx context.Context, r Resolver, cs *tls.ConnectionState, now time.Time) (*exchange.Card, error) {
	if cs == nil || len(cs.PeerCertificates) == 0 {
		return nil, ErrNoCertificate
	}
	c, err := leaf([][]byte{cs.PeerCertificates[0].Raw}, now)
	if err != nil {
		return nil, err
	}
	card, err := r.MemberByTLS(ctx, c.Subject.CommonName, c.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnknownPeer, err)
	}
	if c.Subject.CommonName != card.MemberID {
		return nil, fmt.Errorf("%w: subject does not match member", ErrCertificate)
	}
	return card, nil
}

func ServerTLSConfig(cert tls.Certificate, r Resolver, now func() time.Time) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			c, err := leaf(raw, now())
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			card, err := r.MemberByTLS(ctx, c.Subject.CommonName, c.RawSubjectPublicKeyInfo)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrUnknownPeer, err)
			}
			if c.Subject.CommonName != card.MemberID {
				return fmt.Errorf("%w: subject does not match member", ErrCertificate)
			}
			return nil
		},
	}
}

func ClientTLSConfig(cert tls.Certificate, peer *exchange.Card, now func() time.Time) *tls.Config {
	expected := append([]byte{}, peer.TLSPublicKey...)
	memberID := peer.MemberID
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			c, err := leaf(raw, now())
			if err != nil {
				return err
			}
			if !equalBytes(c.RawSubjectPublicKeyInfo, expected) {
				return fmt.Errorf("%w: server key is not the pinned member key", ErrCertificate)
			}
			if c.Subject.CommonName != memberID {
				return fmt.Errorf("%w: subject does not match member", ErrCertificate)
			}
			return nil
		},
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
