package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

const (
	dirMode  = 0o700
	fileMode = 0o600

	keysDir    = "keys"
	membersDir = "members"
	inboxDir   = "inbox"
	witnessDir = "witness"
	lockFile   = ".lock"
	nodeFile   = "node.json"
	tlsFile    = "tls.json"
	rootFile   = "root.key"
	auditFile  = "audit.log"
)

var (
	ErrExists    = errors.New("store: object already exists")
	ErrNotFound  = errors.New("store: object not found")
	ErrCorrupt   = errors.New("store: corrupt object")
	ErrInsecure  = errors.New("store: insecure directory")
	ErrBadID     = errors.New("store: invalid identifier")
	ErrNotInited = errors.New("store: directory is not initialized")
)

const MaxWitnessHeads = 4096

var (
	hashPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hexIDPattern    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	memberIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

type Store struct {
	dir     string
	created bool
}

type Origin struct {
	Sender string `json:"sender"`
	SentAt int64  `json:"sent_at"`
}

type KeyRecord struct {
	KeyID     string  `json:"key_id"`
	Alg       uint16  `json:"alg"`
	Usage     uint32  `json:"usage"`
	Label     string  `json:"label"`
	Blob      []byte  `json:"blob"`
	PublicKey []byte  `json:"public_key,omitempty"`
	CreatedAt int64   `json:"created_at"`
	Origin    *Origin `json:"origin,omitempty"`
}

type MemberRecord struct {
	MemberID    string `json:"member_id"`
	Card        []byte `json:"card"`
	Fingerprint string `json:"fingerprint"`
	AddedAt     int64  `json:"added_at"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
}

type Node struct {
	MemberID      string `json:"member_id"`
	IdentityKeyID string `json:"identity_key_id"`
	KemKeyID      string `json:"kem_key_id"`
	AuditKeyID    string `json:"audit_key_id"`
	PQC           bool   `json:"pqc"`
	CreatedAt     int64  `json:"created_at"`
}

func (n *Node) valid() bool {
	return ValidMemberID(n.MemberID) && ValidKeyID(n.IdentityKeyID) && ValidKeyID(n.KemKeyID) && ValidKeyID(n.AuditKeyID) &&
		n.IdentityKeyID != n.KemKeyID && n.IdentityKeyID != n.AuditKeyID && n.KemKeyID != n.AuditKeyID
}

type TLSRecord struct {
	Cert          []byte `json:"cert"`
	KeyID         string `json:"key_id,omitempty"`
	WrapKeyID     string `json:"wrap_key_id,omitempty"`
	KeyCiphertext []byte `json:"key_ciphertext,omitempty"`
	CreatedAt     int64  `json:"created_at"`
}

func (r *TLSRecord) Legacy() bool { return r.KeyID == "" }

func (r *TLSRecord) valid() bool {
	if len(r.Cert) == 0 {
		return false
	}
	if !r.Legacy() {
		return ValidKeyID(r.KeyID) && r.WrapKeyID == "" && len(r.KeyCiphertext) == 0
	}
	return ValidKeyID(r.WrapKeyID) && len(r.KeyCiphertext) != 0
}

type WitnessHead struct {
	Seq    uint64 `json:"seq"`
	Hash   string `json:"hash"`
	SeenAt int64  `json:"seen_at"`
}

type WitnessRecord struct {
	MemberID string        `json:"member_id"`
	Heads    []WitnessHead `json:"heads"`
}

func (r *WitnessRecord) valid() bool {
	if !ValidMemberID(r.MemberID) || len(r.Heads) == 0 || len(r.Heads) > MaxWitnessHeads {
		return false
	}
	var last uint64
	for _, h := range r.Heads {
		if h.Seq <= last || !hashPattern.MatchString(h.Hash) {
			return false
		}
		last = h.Seq
	}
	return true
}

type InboxRecord struct {
	ID         string `json:"id"`
	Envelope   []byte `json:"envelope"`
	ReceivedAt int64  `json:"received_at"`
}

func Init(dir string) (*Store, error) {
	created := true
	if err := os.Mkdir(dir, dirMode); err != nil {
		if errors.Is(err, fs.ErrExist) {
			created = false
			entries, rerr := os.ReadDir(dir)
			if rerr != nil || len(entries) != 0 {
				return nil, fmt.Errorf("%w: %s is not empty", ErrExists, dir)
			}
			if err := os.Chmod(dir, dirMode); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	for _, sub := range []string{keysDir, membersDir, inboxDir} {
		if err := os.Mkdir(filepath.Join(dir, sub), dirMode); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	if err := syncDir(dir); err != nil {
		return nil, err
	}
	st, err := Open(dir)
	if err != nil {
		return nil, err
	}
	st.created = created
	return st, nil
}

func (s *Store) Discard() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		path := filepath.Join(s.dir, e.Name())
		if e.Name() == rootFile {
			errs = append(errs, wipeFile(path))
		}
		errs = append(errs, os.RemoveAll(path))
	}
	if s.created {
		errs = append(errs, os.Remove(s.dir))
	} else {
		errs = append(errs, syncDir(s.dir))
	}
	return errors.Join(errs...)
}

func wipeFile(path string) error {
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(make([]byte, fi.Size())); err != nil {
		return err
	}
	return f.Sync()
}

func Open(dir string) (*Store, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err := checkDir(abs); err != nil {
		return nil, err
	}
	for _, sub := range []string{keysDir, membersDir, inboxDir} {
		if err := checkDir(filepath.Join(abs, sub)); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrNotInited, sub)
		}
	}
	return &Store{dir: abs}, nil
}

func checkDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s is a symlink", ErrInsecure, path)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrInsecure, path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s is accessible by group or others", ErrInsecure, path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%w: %s is not owned by the current user", ErrInsecure, path)
	}
	return nil
}

func (s *Store) Dir() string          { return s.dir }
func (s *Store) RootKeyPath() string  { return filepath.Join(s.dir, rootFile) }
func (s *Store) AuditLogPath() string { return filepath.Join(s.dir, auditFile) }

func ValidKeyID(id string) bool    { return hexIDPattern.MatchString(id) }
func ValidMemberID(id string) bool { return memberIDPattern.MatchString(id) }

func KeyIDString(id [16]byte) string { return hex.EncodeToString(id[:]) }

func InboxID(envelope []byte) string {
	sum := sha256.Sum256(envelope)
	return hex.EncodeToString(sum[:16])
}

func (s *Store) PutKey(r *KeyRecord) error {
	if !ValidKeyID(r.KeyID) {
		return ErrBadID
	}
	return s.writeNew(filepath.Join(keysDir, r.KeyID+".json"), r)
}

func (s *Store) GetKey(id string) (*KeyRecord, error) {
	if !ValidKeyID(id) {
		return nil, ErrBadID
	}
	var r KeyRecord
	if err := s.read(filepath.Join(keysDir, id+".json"), &r); err != nil {
		return nil, err
	}
	if r.KeyID != id || len(r.Blob) == 0 {
		return nil, ErrCorrupt
	}
	return &r, nil
}

func (s *Store) ListKeys() ([]*KeyRecord, error) {
	ids, err := s.listIDs(keysDir, ".json", ValidKeyID)
	if err != nil {
		return nil, err
	}
	out := make([]*KeyRecord, 0, len(ids))
	for _, id := range ids {
		r, err := s.GetKey(id)
		if err != nil {
			return nil, fmt.Errorf("%w: key %s: %v", ErrCorrupt, id, err)
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].KeyID < out[j].KeyID
	})
	return out, nil
}

func (s *Store) PutMember(m *MemberRecord) error {
	if !ValidMemberID(m.MemberID) {
		return ErrBadID
	}
	return s.writeNew(filepath.Join(membersDir, m.MemberID+".json"), m)
}

func (s *Store) ReplaceMember(m *MemberRecord) error {
	if !ValidMemberID(m.MemberID) {
		return ErrBadID
	}
	return s.replace(filepath.Join(membersDir, m.MemberID+".json"), m)
}

func (s *Store) GetMember(id string) (*MemberRecord, error) {
	if !ValidMemberID(id) {
		return nil, ErrBadID
	}
	var m MemberRecord
	if err := s.read(filepath.Join(membersDir, id+".json"), &m); err != nil {
		return nil, err
	}
	if m.MemberID != id || len(m.Card) == 0 {
		return nil, ErrCorrupt
	}
	return &m, nil
}

func (s *Store) ListMembers() ([]*MemberRecord, error) {
	ids, err := s.listIDs(membersDir, ".json", ValidMemberID)
	if err != nil {
		return nil, err
	}
	out := make([]*MemberRecord, 0, len(ids))
	for _, id := range ids {
		m, err := s.GetMember(id)
		if err != nil {
			return nil, fmt.Errorf("%w: member %s: %v", ErrCorrupt, id, err)
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MemberID < out[j].MemberID })
	return out, nil
}

func (s *Store) PutNode(n *Node) error {
	if !n.valid() {
		return ErrBadID
	}
	return s.writeNew(nodeFile, n)
}

func (s *Store) ReplaceNode(n *Node) error {
	if !n.valid() {
		return ErrBadID
	}
	return s.replace(nodeFile, n)
}

func (s *Store) GetNode() (*Node, error) {
	var n Node
	if err := s.read(nodeFile, &n); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotInited
		}
		return nil, err
	}
	if !n.valid() {
		return nil, ErrCorrupt
	}
	return &n, nil
}

func (s *Store) PutTLS(r *TLSRecord) error {
	if r.Legacy() || !r.valid() {
		return ErrBadID
	}
	return s.writeNew(tlsFile, r)
}

func (s *Store) ReplaceTLS(r *TLSRecord) error {
	if r.Legacy() || !r.valid() {
		return ErrBadID
	}
	return s.replace(tlsFile, r)
}

func (s *Store) GetTLS() (*TLSRecord, error) {
	var r TLSRecord
	if err := s.read(tlsFile, &r); err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrNotInited
		}
		return nil, err
	}
	if !r.valid() {
		return nil, ErrCorrupt
	}
	return &r, nil
}

func (s *Store) PutInbox(r *InboxRecord) error {
	if !ValidKeyID(r.ID) || r.ID != InboxID(r.Envelope) {
		return ErrBadID
	}
	return s.writeNew(filepath.Join(inboxDir, r.ID+".json"), r)
}

func (s *Store) GetInbox(id string) (*InboxRecord, error) {
	if !ValidKeyID(id) {
		return nil, ErrBadID
	}
	var r InboxRecord
	if err := s.read(filepath.Join(inboxDir, id+".json"), &r); err != nil {
		return nil, err
	}
	if r.ID != id || InboxID(r.Envelope) != id {
		return nil, ErrCorrupt
	}
	return &r, nil
}

func (s *Store) ListInbox() ([]*InboxRecord, error) {
	ids, err := s.listIDs(inboxDir, ".json", ValidKeyID)
	if err != nil {
		return nil, err
	}
	out := make([]*InboxRecord, 0, len(ids))
	for _, id := range ids {
		r, err := s.GetInbox(id)
		if err != nil {
			return nil, fmt.Errorf("%w: inbox %s: %v", ErrCorrupt, id, err)
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ReceivedAt != out[j].ReceivedAt {
			return out[i].ReceivedAt < out[j].ReceivedAt
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (s *Store) DeleteInbox(id string) error {
	if !ValidKeyID(id) {
		return ErrBadID
	}
	path := filepath.Join(s.dir, inboxDir, id+".json")
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	return syncDir(filepath.Dir(path))
}

func (s *Store) GetWitness(member string) (*WitnessRecord, error) {
	if !ValidMemberID(member) {
		return nil, ErrBadID
	}
	var r WitnessRecord
	if err := s.read(filepath.Join(witnessDir, member+".json"), &r); err != nil {
		return nil, err
	}
	if r.MemberID != member || !r.valid() {
		return nil, fmt.Errorf("%w: witness record for %s", ErrCorrupt, member)
	}
	return &r, nil
}

func (s *Store) UpdateWitness(member string, update func(*WitnessRecord) (bool, error)) error {
	if !ValidMemberID(member) {
		return ErrBadID
	}
	dir := filepath.Join(s.dir, witnessDir)
	if err := os.Mkdir(dir, dirMode); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := checkDir(dir); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(dir, lockFile), os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, fileMode)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("store: lock witness: %w", err)
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()
	rec, err := s.GetWitness(member)
	exists := err == nil
	if errors.Is(err, ErrNotFound) {
		rec = &WitnessRecord{MemberID: member}
	} else if err != nil {
		return err
	}
	changed, err := update(rec)
	if err != nil || !changed {
		return err
	}
	if rec.MemberID != member || !rec.valid() {
		return fmt.Errorf("%w: witness record for %s", ErrCorrupt, member)
	}
	rel := filepath.Join(witnessDir, member+".json")
	if exists {
		return s.replace(rel, rec)
	}
	return s.writeNew(rel, rec)
}

func (s *Store) listIDs(sub, ext string, valid func(string) bool) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(s.dir, sub))
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.Type()&fs.ModeType != 0 || !strings.HasSuffix(name, ext) || strings.HasPrefix(name, ".") {
			continue
		}
		id := strings.TrimSuffix(name, ext)
		if !valid(id) {
			return nil, fmt.Errorf("%w: unexpected file %s/%s", ErrCorrupt, sub, name)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (s *Store) read(rel string, v any) error {
	path := filepath.Join(s.dir, rel)
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInsecure, rel)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: %s is accessible by group or others", ErrInsecure, rel)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %s: %v", ErrCorrupt, rel, err)
	}
	if dec.More() {
		return fmt.Errorf("%w: %s: trailing data", ErrCorrupt, rel)
	}
	return nil
}

func writeTemp(path string, v any) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	if err := f.Chmod(fileMode); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

func (s *Store) replace(rel string, v any) error {
	path := filepath.Join(s.dir, rel)
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNotFound
		}
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrInsecure, rel)
	}
	tmp, err := writeTemp(path, v)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

func (s *Store) writeNew(rel string, v any) error {
	path := filepath.Join(s.dir, rel)
	if _, err := os.Lstat(path); err == nil {
		return ErrExists
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	tmp, err := writeTemp(path, v)
	if err != nil {
		return err
	}
	if err := os.Link(tmp, path); err != nil {
		_ = os.Remove(tmp)
		if errors.Is(err, fs.ErrExist) {
			return ErrExists
		}
		return err
	}
	if err := os.Remove(tmp); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
