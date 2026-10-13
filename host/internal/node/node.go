package node

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/Quant-Off/pairier/host/internal/audit"
	"github.com/Quant-Off/pairier/host/internal/core"
	"github.com/Quant-Off/pairier/host/internal/exchange"
	"github.com/Quant-Off/pairier/host/internal/store"
	"github.com/Quant-Off/pairier/host/internal/wire"
)

var (
	ErrBadMemberID     = errors.New("node: invalid member id")
	ErrPQCUnavailable  = errors.New("node: core does not provide pqc")
	ErrFingerprint     = errors.New("node: fingerprint does not match the card")
	ErrSelf            = errors.New("node: card belongs to this node")
	ErrUnknownMember   = errors.New("node: unknown member")
	ErrNotRecipient    = errors.New("node: envelope is addressed to another member")
	ErrMetadata        = errors.New("node: stored metadata does not match the core")
	ErrNotSymmetric    = errors.New("node: only symmetric keys can be generated or exchanged")
	ErrSignatureAlg    = errors.New("node: envelope signature algorithm differs from the member card")
	ErrUsageNotAllowed = errors.New("node: usage not allowed for this key kind")
)

const SymmetricUsage = wire.UsageEncrypt | wire.UsageDecrypt | wire.UsageWrap | wire.UsageUnwrap | wire.UsageDerive | wire.UsageExport

type Options struct {
	Dir                 string
	CoreBinary          string
	AllowUnlockedMemory bool
	Timeout             time.Duration
	Stderr              io.Writer
	Now                 func() time.Time
}

type Node struct {
	opts     Options
	st       *store.Store
	core     *core.Client
	log      *audit.Log
	info     *store.Node
	identity *store.KeyRecord
	kem      *store.KeyRecord
	tls      tls.Certificate
}

func (n *Node) audit(event string, fields map[string]string, err error) error {
	if err != nil {
		if fields == nil {
			fields = map[string]string{}
		}
		fields["error"] = err.Error()
	}
	if aerr := n.log.Append(event, fields); aerr != nil {
		return fmt.Errorf("node: audit: %w", aerr)
	}
	return err
}

func (o *Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *Options) spawn(ctx context.Context, rootKey string, pqc bool) (*core.Client, error) {
	if o.CoreBinary == "" {
		return nil, errors.New("node: core binary path is required")
	}
	return core.Spawn(ctx, core.Options{
		Binary:              o.CoreBinary,
		RootKeyFile:         rootKey,
		PQC:                 pqc,
		AllowUnlockedMemory: o.AllowUnlockedMemory,
		Timeout:             o.Timeout,
		Stderr:              o.Stderr,
	})
}

func Init(ctx context.Context, o Options, memberID string, pqc bool) (*Node, error) {
	if !exchange.ValidMemberID(memberID) {
		return nil, ErrBadMemberID
	}
	if o.CoreBinary == "" {
		return nil, errors.New("node: core binary path is required")
	}
	st, err := store.Init(o.Dir)
	if err != nil {
		return nil, err
	}
	if err := generateRootKey(ctx, o, st.RootKeyPath()); err != nil {
		return nil, err
	}
	c, err := o.spawn(ctx, st.RootKeyPath(), pqc)
	if err != nil {
		return nil, err
	}
	log, err := audit.Open(st.AuditLogPath(), o.Now)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	n := &Node{opts: o, st: st, core: c, log: log}
	if err := n.createIdentity(ctx, memberID, pqc); err != nil {
		_ = n.Close()
		return nil, err
	}
	if err := n.createTLS(ctx); err != nil {
		_ = n.Close()
		return nil, err
	}
	if err := n.audit("node.init", map[string]string{"member": memberID, "identity": n.identity.KeyID, "kem": n.kem.KeyID, "pqc": fmt.Sprint(pqc), "fips": fmt.Sprint(c.FIPS())}, nil); err != nil {
		_ = n.Close()
		return nil, err
	}
	return n, nil
}

func generateRootKey(ctx context.Context, o Options, path string) error {
	cmd := exec.CommandContext(ctx, o.CoreBinary, "--generate-root-key", path)
	cmd.Env = []string{}
	cmd.Dir = "/"
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("node: generate root key: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func (n *Node) createIdentity(ctx context.Context, memberID string, pqc bool) error {
	if pqc && !n.core.PQC() {
		return ErrPQCUnavailable
	}
	sigAlg, kemAlg := uint16(wire.AlgECDSAP256SHA256), uint16(wire.AlgDHKEMP256)
	if pqc {
		sigAlg, kemAlg = wire.AlgMLDSA65, wire.AlgHybridP256MLKEM768
	}
	now := n.opts.now().Unix()
	id, err := n.core.GenerateKey(ctx, sigAlg, wire.UsageSign, "identity/"+memberID)
	if err != nil {
		return err
	}
	kem, err := n.core.GenerateKey(ctx, kemAlg, wire.UsageDecapsulate, "kem/"+memberID)
	if err != nil {
		return err
	}
	n.identity = &store.KeyRecord{KeyID: store.KeyIDString(id.KeyID), Alg: sigAlg, Usage: wire.UsageSign, Label: "identity/" + memberID, Blob: id.Blob, PublicKey: id.PublicKey, CreatedAt: now}
	n.kem = &store.KeyRecord{KeyID: store.KeyIDString(kem.KeyID), Alg: kemAlg, Usage: wire.UsageDecapsulate, Label: "kem/" + memberID, Blob: kem.Blob, PublicKey: kem.PublicKey, CreatedAt: now}
	if err := n.st.PutKey(n.identity); err != nil {
		return err
	}
	if err := n.st.PutKey(n.kem); err != nil {
		return err
	}
	n.info = &store.Node{MemberID: memberID, IdentityKeyID: n.identity.KeyID, KemKeyID: n.kem.KeyID, PQC: pqc, CreatedAt: now}
	return n.st.PutNode(n.info)
}

func Open(ctx context.Context, o Options) (*Node, error) {
	st, err := store.Open(o.Dir)
	if err != nil {
		return nil, err
	}
	info, err := st.GetNode()
	if err != nil {
		return nil, err
	}
	c, err := o.spawn(ctx, st.RootKeyPath(), info.PQC)
	if err != nil {
		return nil, err
	}
	log, err := audit.Open(st.AuditLogPath(), o.Now)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	n := &Node{opts: o, st: st, core: c, log: log, info: info}
	if info.PQC && !c.PQC() {
		_ = n.Close()
		return nil, ErrPQCUnavailable
	}
	if n.identity, err = n.Key(ctx, info.IdentityKeyID); err != nil {
		_ = n.Close()
		return nil, fmt.Errorf("node: identity key: %w", err)
	}
	if n.kem, err = n.Key(ctx, info.KemKeyID); err != nil {
		_ = n.Close()
		return nil, fmt.Errorf("node: kem key: %w", err)
	}
	if n.identity.Usage != wire.UsageSign || !exchange.IsSignatureAlg(n.identity.Alg) ||
		n.kem.Usage != wire.UsageDecapsulate || !exchange.IsKemAlg(n.kem.Alg) ||
		len(n.identity.PublicKey) == 0 || len(n.kem.PublicKey) == 0 {
		_ = n.Close()
		return nil, ErrMetadata
	}
	if err := n.loadTLS(ctx); err != nil {
		_ = n.Close()
		return nil, err
	}
	if err := n.audit("node.open", map[string]string{"member": info.MemberID, "fips": fmt.Sprint(c.FIPS()), "pqc": fmt.Sprint(c.PQC())}, nil); err != nil {
		_ = n.Close()
		return nil, err
	}
	return n, nil
}

func (n *Node) Close() error {
	cerr := n.core.Close()
	lerr := n.log.Close()
	return errors.Join(cerr, lerr)
}

func (n *Node) AuditLogPath() string { return n.st.AuditLogPath() }
func (n *Node) MemberID() string     { return n.info.MemberID }
func (n *Node) PQC() bool            { return n.info.PQC }
func (n *Node) FIPS() bool           { return n.core.FIPS() }
func (n *Node) Core() *core.Client {
	return n.core
}

func (n *Node) Key(ctx context.Context, id string) (*store.KeyRecord, error) {
	rec, err := n.st.GetKey(id)
	if err != nil {
		return nil, err
	}
	info, err := n.core.Inspect(ctx, rec.Blob)
	if err != nil {
		return nil, err
	}
	if store.KeyIDString(info.KeyID) != rec.KeyID || info.Alg != rec.Alg || info.Usage != rec.Usage || info.Label != rec.Label {
		return nil, ErrMetadata
	}
	return rec, nil
}

func (n *Node) Keys() ([]*store.KeyRecord, error) { return n.st.ListKeys() }

func (n *Node) GenerateKey(ctx context.Context, label string, usage uint32) (*store.KeyRecord, error) {
	if usage == 0 || usage&^SymmetricUsage != 0 {
		return nil, ErrUsageNotAllowed
	}
	if len(label) > wire.MaxLabel {
		return nil, fmt.Errorf("node: label exceeds %d bytes", wire.MaxLabel)
	}
	k, err := n.core.GenerateKey(ctx, wire.AlgAES256GCM, usage, label)
	if err != nil {
		return nil, n.audit("key.generate", map[string]string{"label": label}, err)
	}
	rec := &store.KeyRecord{KeyID: store.KeyIDString(k.KeyID), Alg: wire.AlgAES256GCM, Usage: usage, Label: label, Blob: k.Blob, CreatedAt: n.opts.now().Unix()}
	if err := n.st.PutKey(rec); err != nil {
		return nil, n.audit("key.generate", map[string]string{"key": rec.KeyID, "label": label}, err)
	}
	if err := n.audit("key.generate", map[string]string{"key": rec.KeyID, "label": label, "usage": fmt.Sprint(usage)}, nil); err != nil {
		return nil, err
	}
	return rec, nil
}

func (n *Node) Encrypt(ctx context.Context, keyID string, plaintext, aad []byte) ([]byte, error) {
	rec, err := n.Key(ctx, keyID)
	if err != nil {
		return nil, n.audit("key.encrypt", map[string]string{"key": keyID}, err)
	}
	ct, err := n.core.Encrypt(ctx, rec.Blob, plaintext, aad)
	if err := n.audit("key.encrypt", map[string]string{"key": keyID, "bytes": fmt.Sprint(len(plaintext))}, err); err != nil {
		return nil, err
	}
	return ct, nil
}

func (n *Node) Decrypt(ctx context.Context, keyID string, ciphertext, aad []byte) ([]byte, error) {
	rec, err := n.Key(ctx, keyID)
	if err != nil {
		return nil, n.audit("key.decrypt", map[string]string{"key": keyID}, err)
	}
	pt, err := n.core.Decrypt(ctx, rec.Blob, ciphertext, aad)
	if err := n.audit("key.decrypt", map[string]string{"key": keyID, "bytes": fmt.Sprint(len(ciphertext))}, err); err != nil {
		return nil, err
	}
	return pt, nil
}

func (n *Node) Card(ctx context.Context) (*exchange.Card, []byte, error) {
	card := &exchange.Card{
		MemberID:          n.info.MemberID,
		IdentityAlg:       n.identity.Alg,
		IdentityPublicKey: n.identity.PublicKey,
		KemAlg:            n.kem.Alg,
		KemPublicKey:      n.kem.PublicKey,
		TLSPublicKey:      n.TLSPublicKey(),
		CreatedAt:         uint64(n.info.CreatedAt),
	}
	if err := exchange.SignCard(ctx, n.core, n.identity.Blob, card); err != nil {
		return nil, nil, err
	}
	raw, err := card.Encode()
	if err != nil {
		return nil, nil, err
	}
	return card, raw, nil
}

func (n *Node) AddMember(ctx context.Context, raw []byte, fingerprint string) (*store.MemberRecord, error) {
	rec, err := n.addMember(ctx, raw, fingerprint)
	fields := map[string]string{}
	if rec != nil {
		fields["member"] = rec.MemberID
		fields["fingerprint"] = rec.Fingerprint
	}
	if err := n.audit("member.add", fields, err); err != nil {
		return nil, err
	}
	return rec, nil
}

func (n *Node) addMember(ctx context.Context, raw []byte, fingerprint string) (*store.MemberRecord, error) {
	card, err := exchange.DecodeCard(raw)
	if err != nil {
		return nil, err
	}
	if card.MemberID == n.info.MemberID {
		return nil, ErrSelf
	}
	if err := card.Verify(ctx, n.core); err != nil {
		return nil, err
	}
	if !card.MatchesFingerprint(fingerprint) {
		return nil, ErrFingerprint
	}
	fp, err := card.Fingerprint()
	if err != nil {
		return nil, err
	}
	rec := &store.MemberRecord{MemberID: card.MemberID, Card: raw, Fingerprint: fp, AddedAt: n.opts.now().Unix()}
	if err := n.st.PutMember(rec); err != nil {
		return nil, err
	}
	return rec, nil
}

func (n *Node) Members() ([]*store.MemberRecord, error) { return n.st.ListMembers() }

func (n *Node) Member(ctx context.Context, id string) (*exchange.Card, error) {
	rec, err := n.st.GetMember(id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) || errors.Is(err, store.ErrBadID) {
			return nil, fmt.Errorf("%w: %s", ErrUnknownMember, id)
		}
		return nil, err
	}
	card, err := exchange.DecodeCard(rec.Card)
	if err != nil {
		return nil, err
	}
	if card.MemberID != id || !card.MatchesFingerprint(rec.Fingerprint) {
		return nil, ErrMetadata
	}
	if err := card.Verify(ctx, n.core); err != nil {
		return nil, err
	}
	return card, nil
}

func (n *Node) Send(ctx context.Context, keyID, to string, usage uint32) ([]byte, error) {
	env, err := n.send(ctx, keyID, to, usage)
	if err := n.audit("key.send", map[string]string{"key": keyID, "to": to, "usage": fmt.Sprint(usage)}, err); err != nil {
		return nil, err
	}
	return env, nil
}

func (n *Node) send(ctx context.Context, keyID, to string, usage uint32) ([]byte, error) {
	rec, err := n.Key(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if rec.Alg != wire.AlgAES256GCM {
		return nil, ErrNotSymmetric
	}
	card, err := n.Member(ctx, to)
	if err != nil {
		return nil, err
	}
	ectx, err := exchange.NewContext(n.info.MemberID, to, n.opts.now())
	if err != nil {
		return nil, err
	}
	cb, err := ectx.Encode()
	if err != nil {
		return nil, err
	}
	pkg, err := n.core.ExportKey(ctx, rec.Blob, card.KemAlg, card.KemPublicKey, usage, cb)
	if err != nil {
		return nil, err
	}
	env, err := exchange.Seal(ctx, n.core, n.identity.Blob, n.identity.Alg, ectx, pkg)
	if err != nil {
		return nil, err
	}
	return env.Encode()
}

func (n *Node) Receive(ctx context.Context, raw []byte) (*store.KeyRecord, error) {
	rec, err := n.receive(ctx, raw)
	fields := map[string]string{"envelope": store.InboxID(raw)}
	if rec != nil {
		fields["key"] = rec.KeyID
		fields["from"] = rec.Origin.Sender
		fields["usage"] = fmt.Sprint(rec.Usage)
	}
	if err := n.audit("key.receive", fields, err); err != nil {
		return nil, err
	}
	return rec, nil
}

func (n *Node) receive(ctx context.Context, raw []byte) (*store.KeyRecord, error) {
	env, err := exchange.DecodeEnvelope(raw)
	if err != nil {
		return nil, err
	}
	peek, err := exchange.DecodeContext(env.Context)
	if err != nil {
		return nil, err
	}
	if peek.Recipient != n.info.MemberID {
		return nil, ErrNotRecipient
	}
	card, err := n.Member(ctx, peek.Sender)
	if err != nil {
		return nil, err
	}
	if env.SigAlg != card.IdentityAlg {
		return nil, ErrSignatureAlg
	}
	ectx, err := env.Verify(ctx, n.core, card.IdentityPublicKey)
	if err != nil {
		return nil, err
	}
	imp, err := n.core.ImportKey(ctx, n.kem.Blob, env.Package, env.Context)
	if err != nil {
		return nil, err
	}
	rec := &store.KeyRecord{
		KeyID:     store.KeyIDString(imp.KeyID),
		Alg:       imp.Alg,
		Usage:     imp.Usage,
		Label:     imp.Label,
		Blob:      imp.Blob,
		CreatedAt: n.opts.now().Unix(),
		Origin:    &store.Origin{Sender: ectx.Sender, SentAt: int64(ectx.CreatedAt)},
	}
	if err := n.st.PutKey(rec); err != nil {
		return nil, err
	}
	return rec, nil
}
