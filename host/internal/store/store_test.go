package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Init(filepath.Join(t.TempDir(), "node"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestInitAndOpenEnforceLayoutAndPermissions(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "node")
	s, err := Init(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Init(dir); err == nil {
		t.Fatal("init over an initialized directory must fail")
	}
	if _, err := Open(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(base, "missing")); err == nil {
		t.Fatal("open of missing dir succeeded")
	}
	plain := filepath.Join(base, "plain")
	if err := os.Mkdir(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(plain); !errors.Is(err, ErrNotInited) {
		t.Fatalf("expected ErrNotInited, got %v", err)
	}
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrInsecure) {
		t.Fatalf("expected ErrInsecure, got %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); !errors.Is(err, ErrInsecure) {
		t.Fatalf("expected ErrInsecure for symlink, got %v", err)
	}
	if _, err := s.GetNode(); !errors.Is(err, ErrNotInited) {
		t.Fatalf("expected ErrNotInited, got %v", err)
	}
}

func TestKeyRecords(t *testing.T) {
	s := newStore(t)
	id := KeyIDString([16]byte{1, 2, 3})
	r := &KeyRecord{KeyID: id, Alg: 1, Usage: 3, Label: "l", Blob: []byte("blob"), CreatedAt: 10}
	if err := s.PutKey(r); err != nil {
		t.Fatal(err)
	}
	if err := s.PutKey(r); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
	got, err := s.GetKey(id)
	if err != nil || got.Label != "l" || string(got.Blob) != "blob" || got.Origin != nil {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := s.GetKey("nope"); !errors.Is(err, ErrBadID) {
		t.Fatalf("expected ErrBadID, got %v", err)
	}
	if _, err := s.GetKey(KeyIDString([16]byte{9})); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	r2 := &KeyRecord{KeyID: KeyIDString([16]byte{0}), Alg: 1, Usage: 2, Blob: []byte("b"), CreatedAt: 5, Origin: &Origin{Sender: "bob", SentAt: 4}}
	if err := s.PutKey(r2); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListKeys()
	if err != nil || len(list) != 2 || list[0].KeyID != r2.KeyID || list[1].Origin != nil || list[0].Origin.Sender != "bob" {
		t.Fatalf("list: %+v %v", list, err)
	}
	fi, err := os.Stat(filepath.Join(s.Dir(), "keys", id+".json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v %v", fi.Mode(), err)
	}
	if err := os.Chmod(filepath.Join(s.Dir(), "keys", id+".json"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetKey(id); !errors.Is(err, ErrInsecure) {
		t.Fatalf("expected ErrInsecure, got %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir(), "keys", "junk.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListKeys(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected ErrCorrupt for junk file, got %v", err)
	}
}

func TestCorruptAndUnknownFieldsRejected(t *testing.T) {
	s := newStore(t)
	id := KeyIDString([16]byte{7})
	path := filepath.Join(s.Dir(), "keys", id+".json")
	if err := os.WriteFile(path, []byte(`{"key_id":"`+id+`","alg":1,"usage":1,"blob":"YQ==","created_at":1,"extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetKey(id); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("unknown field accepted: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"key_id":"`+KeyIDString([16]byte{8})+`","alg":1,"usage":1,"blob":"YQ==","created_at":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetKey(id); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("id mismatch accepted: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"key_id":"`+id+`","alg":1,"usage":1,"blob":"YQ==","created_at":1}{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetKey(id); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("trailing data accepted: %v", err)
	}
}

func TestMembersNodeAndInbox(t *testing.T) {
	s := newStore(t)
	m := &MemberRecord{MemberID: "bob", Card: []byte("card"), Fingerprint: "fp", AddedAt: 1}
	if err := s.PutMember(m); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMember(&MemberRecord{MemberID: "Bob", Card: []byte("c")}); !errors.Is(err, ErrBadID) {
		t.Fatalf("expected ErrBadID, got %v", err)
	}
	if err := s.PutMember(&MemberRecord{MemberID: "alice", Card: []byte("c"), AddedAt: 2}); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListMembers()
	if err != nil || len(list) != 2 || list[0].MemberID != "alice" || list[1].Fingerprint != "fp" {
		t.Fatalf("members: %+v %v", list, err)
	}
	n := &Node{MemberID: "alice", IdentityKeyID: KeyIDString([16]byte{1}), KemKeyID: KeyIDString([16]byte{2}), PQC: true, CreatedAt: 3}
	if err := s.PutNode(n); err != nil {
		t.Fatal(err)
	}
	if err := s.PutNode(n); !errors.Is(err, ErrExists) {
		t.Fatalf("expected ErrExists, got %v", err)
	}
	got, err := s.GetNode()
	if err != nil || got.MemberID != "alice" || !got.PQC || got.KemKeyID != n.KemKeyID {
		t.Fatalf("node: %+v %v", got, err)
	}
	if _, err := s.GetTLS(); !errors.Is(err, ErrNotInited) {
		t.Fatalf("expected ErrNotInited, got %v", err)
	}
	tr := &TLSRecord{Cert: []byte("cert"), WrapKeyID: KeyIDString([16]byte{4}), KeyCiphertext: []byte("ct"), CreatedAt: 1}
	if err := s.PutTLS(tr); err != nil {
		t.Fatal(err)
	}
	if got, err := s.GetTLS(); err != nil || string(got.Cert) != "cert" || got.WrapKeyID != tr.WrapKeyID {
		t.Fatalf("tls: %+v %v", got, err)
	}
	env := []byte("envelope")
	rec := &InboxRecord{ID: InboxID(env), Envelope: env, ReceivedAt: 9}
	if err := s.PutInbox(rec); err != nil {
		t.Fatal(err)
	}
	if err := s.PutInbox(rec); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate envelope accepted: %v", err)
	}
	if err := s.PutInbox(&InboxRecord{ID: KeyIDString([16]byte{3}), Envelope: env}); !errors.Is(err, ErrBadID) {
		t.Fatalf("mismatched inbox id accepted: %v", err)
	}
	inbox, err := s.ListInbox()
	if err != nil || len(inbox) != 1 || string(inbox[0].Envelope) != "envelope" {
		t.Fatalf("inbox: %+v %v", inbox, err)
	}
	if err := s.DeleteInbox(rec.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteInbox(rec.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if _, err := os.Lstat(filepath.Join(s.Dir(), "inbox", rec.ID+".json.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("temp file left behind")
	}
}
