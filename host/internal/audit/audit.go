package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	fileMode  = 0o600
	maxLine   = 64 * 1024
	hashLen   = sha256.Size
	genesis   = "0000000000000000000000000000000000000000000000000000000000000000"
	MaxFields = 32
)

var (
	ErrCorrupt   = errors.New("audit: log chain is corrupt")
	ErrInsecure  = errors.New("audit: insecure log file")
	ErrField     = errors.New("audit: invalid event or field")
	ErrSignature = errors.New("audit: checkpoint signature is invalid")
	ErrAnchor    = errors.New("audit: invalid anchor")
	ErrRollback  = errors.New("audit: log does not contain the anchored entry")
)

type Anchor struct {
	Seq  uint64
	Hash string
}

func (a Anchor) String() string { return strconv.FormatUint(a.Seq, 10) + ":" + a.Hash }

func ParseAnchor(s string) (Anchor, error) {
	seqText, hash, ok := strings.Cut(s, ":")
	if !ok {
		return Anchor{}, ErrAnchor
	}
	seq, err := strconv.ParseUint(seqText, 10, 64)
	if err != nil || seq == 0 || seqText != strconv.FormatUint(seq, 10) {
		return Anchor{}, ErrAnchor
	}
	if h, err := hex.DecodeString(hash); err != nil || len(h) != hashLen || hash != hex.EncodeToString(h) {
		return Anchor{}, ErrAnchor
	}
	return Anchor{Seq: seq, Hash: hash}, nil
}

const checkpointDomain = "pairier/audit/checkpoint/v1"

type Signer interface {
	SignCheckpoint(msg []byte) ([]byte, error)
}

type Verifier interface {
	VerifyCheckpoint(msg, sig []byte) (bool, error)
}

func CheckpointMessage(seq uint64, hash string) ([]byte, error) {
	h, err := hex.DecodeString(hash)
	if err != nil || len(h) != hashLen {
		return nil, ErrCorrupt
	}
	msg := make([]byte, 0, len(checkpointDomain)+1+8+hashLen)
	msg = append(msg, checkpointDomain...)
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint64(msg, seq)
	return append(msg, h...), nil
}

func verifyEntry(v Verifier, e *Entry) error {
	if e.Sig == "" {
		return fmt.Errorf("%w: entry %d is unsigned", ErrSignature, e.Seq)
	}
	sig, err := hex.DecodeString(e.Sig)
	if err != nil {
		return fmt.Errorf("%w: entry %d", ErrSignature, e.Seq)
	}
	msg, err := CheckpointMessage(e.Seq, e.Hash)
	if err != nil {
		return err
	}
	ok, err := v.VerifyCheckpoint(msg, sig)
	if err != nil {
		return fmt.Errorf("%w: entry %d: %v", ErrSignature, e.Seq, err)
	}
	if !ok {
		return fmt.Errorf("%w: entry %d", ErrSignature, e.Seq)
	}
	return nil
}

type Entry struct {
	Seq    uint64            `json:"seq"`
	Time   int64             `json:"time"`
	Event  string            `json:"event"`
	Fields map[string]string `json:"fields,omitempty"`
	Prev   string            `json:"prev"`
	Hash   string            `json:"hash"`
	Sig    string            `json:"sig,omitempty"`
}

type Log struct {
	mu       sync.Mutex
	f        *os.File
	seq      uint64
	prev     string
	head     *Entry
	offset   int64
	now      func() time.Time
	signer   Signer
	verifier Verifier
}

type Options struct {
	Now      func() time.Time
	Signer   Signer
	Verifier Verifier
}

func Open(path string, o Options) (*Log, error) {
	now := o.Now
	if now == nil {
		now = time.Now
	}
	if (o.Signer == nil) != (o.Verifier == nil) {
		return nil, errors.New("audit: signer and verifier must be set together")
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, fileMode)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s", ErrInsecure, path)
	}
	if lfi, err := os.Lstat(path); err != nil || lfi.Mode()&fs.ModeSymlink != 0 {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %s is a symlink", ErrInsecure, path)
	}
	l := &Log{f: f, prev: genesis, now: now, signer: o.Signer, verifier: o.Verifier}
	if err := l.lock(); err != nil {
		_ = f.Close()
		return nil, err
	}
	err = l.catchUp()
	l.unlock()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return l, nil
}

func (l *Log) lock() error {
	if err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("audit: lock: %w", err)
	}
	return nil
}

func (l *Log) unlock() {
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
}

func (l *Log) catchUp() error {
	fi, err := l.f.Stat()
	if err != nil {
		return err
	}
	size := fi.Size()
	if size < l.offset {
		return fmt.Errorf("%w: log shrank from %d to %d bytes", ErrCorrupt, l.offset, size)
	}
	if size == l.offset {
		return nil
	}
	section := io.NewSectionReader(l.f, l.offset, size-l.offset)
	seq, prev, head, err := replayFrom(section, l.seq, l.prev, l.verifier != nil)
	if err != nil {
		return err
	}
	if l.verifier != nil && head != nil {
		if err := verifyEntry(l.verifier, head); err != nil {
			return err
		}
	}
	l.seq, l.prev, l.offset = seq, prev, size
	if head != nil {
		l.head = head
	}
	return nil
}

func (l *Log) Head() (uint64, string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq, l.prev
}

func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

func (l *Log) Seq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq
}

func (l *Log) Append(event string, fields map[string]string) error {
	if event == "" || len(event) > 64 || len(fields) > MaxFields {
		return ErrField
	}
	for k, v := range fields {
		if k == "" || len(k) > 64 || len(v) > 1024 {
			return ErrField
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.lock(); err != nil {
		return err
	}
	defer l.unlock()
	if err := l.catchUp(); err != nil {
		return err
	}
	e := &Entry{Seq: l.seq + 1, Time: l.now().Unix(), Event: event, Fields: fields, Prev: l.prev}
	h, err := digest(e)
	if err != nil {
		return err
	}
	e.Hash = h
	if l.signer != nil {
		msg, err := CheckpointMessage(e.Seq, e.Hash)
		if err != nil {
			return err
		}
		sig, err := l.signer.SignCheckpoint(msg)
		if err != nil {
			return fmt.Errorf("audit: sign checkpoint: %w", err)
		}
		e.Sig = hex.EncodeToString(sig)
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	n, err := l.f.Write(line)
	if err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	l.seq = e.Seq
	l.prev = e.Hash
	l.head = e
	l.offset += int64(n)
	return nil
}

func digest(e *Entry) (string, error) {
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	prev, err := hex.DecodeString(e.Prev)
	if err != nil || len(prev) != hashLen {
		return "", ErrCorrupt
	}
	h := sha256.New()
	h.Write(prev)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, v := range []any{e.Seq, e.Time, e.Event} {
		if err := enc.Encode(v); err != nil {
			return "", err
		}
	}
	for _, k := range keys {
		if err := enc.Encode(k); err != nil {
			return "", err
		}
		if err := enc.Encode(e.Fields[k]); err != nil {
			return "", err
		}
	}
	h.Write(buf.Bytes())
	return hex.EncodeToString(h.Sum(nil)), nil
}

func replayFrom(r io.Reader, seq uint64, prev string, requireSig bool) (uint64, string, *Entry, error) {
	var head *Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, maxLine), maxLine)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return 0, "", nil, fmt.Errorf("%w: blank line after entry %d", ErrCorrupt, seq)
		}
		var e Entry
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil || dec.More() {
			return 0, "", nil, fmt.Errorf("%w: entry %d is not valid json", ErrCorrupt, seq+1)
		}
		if e.Seq != seq+1 || e.Prev != prev {
			return 0, "", nil, fmt.Errorf("%w: entry %d breaks the chain", ErrCorrupt, e.Seq)
		}
		h, err := digest(&e)
		if err != nil || h != e.Hash {
			return 0, "", nil, fmt.Errorf("%w: entry %d hash mismatch", ErrCorrupt, e.Seq)
		}
		if requireSig && e.Sig == "" {
			return 0, "", nil, fmt.Errorf("%w: entry %d is unsigned", ErrSignature, e.Seq)
		}
		seq = e.Seq
		prev = e.Hash
		entry := e
		head = &entry
	}
	if err := sc.Err(); err != nil {
		return 0, "", nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return seq, prev, head, nil
}

func Verify(path string, v Verifier) (uint64, error) {
	n, _, err := VerifyAnchored(path, v, nil)
	return n, err
}

func VerifyAnchored(path string, v Verifier, anchors []Anchor) (uint64, Anchor, error) {
	entries, err := Read(path)
	if err != nil {
		return 0, Anchor{}, err
	}
	if v != nil {
		for i := range entries {
			if err := verifyEntry(v, &entries[i]); err != nil {
				return 0, Anchor{}, err
			}
		}
	}
	head := Anchor{Seq: 0, Hash: genesis}
	if len(entries) > 0 {
		last := entries[len(entries)-1]
		head = Anchor{Seq: last.Seq, Hash: last.Hash}
	}
	for _, anchor := range anchors {
		if anchor.Seq == 0 || anchor.Seq > uint64(len(entries)) {
			return 0, Anchor{}, fmt.Errorf("%w: log ends at entry %d before anchored entry %d", ErrRollback, head.Seq, anchor.Seq)
		}
		if e := entries[anchor.Seq-1]; e.Seq != anchor.Seq || e.Hash != anchor.Hash {
			return 0, Anchor{}, fmt.Errorf("%w: entry %d differs from the anchor", ErrRollback, anchor.Seq)
		}
	}
	return uint64(len(entries)), head, nil
}

func Read(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	seq, prev := uint64(0), genesis
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, maxLine), maxLine)
	for sc.Scan() {
		s, p, head, err := replayFrom(bytes.NewReader(append(sc.Bytes(), '\n')), seq, prev, false)
		if err != nil {
			return nil, err
		}
		if head == nil {
			return nil, fmt.Errorf("%w: blank line after entry %d", ErrCorrupt, seq)
		}
		seq, prev = s, p
		out = append(out, *head)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return out, nil
}
