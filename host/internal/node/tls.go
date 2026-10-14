package node

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/Quant-Off/pairier/host/internal/exchange"
	"github.com/Quant-Off/pairier/host/internal/store"
	"github.com/Quant-Off/pairier/host/internal/wire"
)

const tlsValidity = 10 * 365 * 24 * time.Hour

var ErrTLSMaterial = errors.New("node: tls material is inconsistent")

func (n *Node) createTLS(ctx context.Context) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return err
	}
	now := n.opts.now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: n.info.MemberID},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(tlsValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	wrap, err := n.core.GenerateKey(ctx, wire.AlgAES256GCM, wire.UsageEncrypt|wire.UsageDecrypt, "tls-wrap/"+n.info.MemberID)
	if err != nil {
		return err
	}
	wrapRec := &store.KeyRecord{KeyID: store.KeyIDString(wrap.KeyID), Alg: wire.AlgAES256GCM, Usage: wire.UsageEncrypt | wire.UsageDecrypt, Label: "tls-wrap/" + n.info.MemberID, Blob: wrap.Blob, CreatedAt: now.Unix()}
	if err := n.st.PutKey(wrapRec); err != nil {
		return err
	}
	ct, err := n.core.Encrypt(ctx, wrap.Blob, keyDER, certDER)
	if err != nil {
		return err
	}
	if err := n.st.PutTLS(&store.TLSRecord{Cert: certDER, WrapKeyID: wrapRec.KeyID, KeyCiphertext: ct, CreatedAt: now.Unix()}); err != nil {
		return err
	}
	return n.loadTLS(ctx)
}

func (n *Node) loadTLS(ctx context.Context) error {
	rec, err := n.st.GetTLS()
	if err != nil {
		return err
	}
	wrap, err := n.Key(ctx, rec.WrapKeyID)
	if err != nil {
		return fmt.Errorf("node: tls wrap key: %w", err)
	}
	keyDER, err := n.core.Decrypt(ctx, wrap.Blob, rec.KeyCiphertext, rec.Cert)
	if err != nil {
		return fmt.Errorf("node: tls key: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return ErrTLSMaterial
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return ErrTLSMaterial
	}
	leaf, err := x509.ParseCertificate(rec.Cert)
	if err != nil {
		return ErrTLSMaterial
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&priv.PublicKey) || leaf.Subject.CommonName != n.info.MemberID {
		return ErrTLSMaterial
	}
	n.tls = tls.Certificate{Certificate: [][]byte{rec.Cert}, PrivateKey: priv, Leaf: leaf}
	return nil
}

func (n *Node) TLSCertificate() tls.Certificate { return n.tls }

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
