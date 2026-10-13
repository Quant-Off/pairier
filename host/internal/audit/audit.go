package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"sync"
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
	ErrCorrupt  = errors.New("audit: log chain is corrupt")
	ErrInsecure = errors.New("audit: insecure log file")
	ErrField    = errors.New("audit: invalid event or field")
)

type Entry struct {
	Seq    uint64            `json:"seq"`
	Time   int64             `json:"time"`
	Event  string            `json:"event"`
	Fields map[string]string `json:"fields,omitempty"`
	Prev   string            `json:"prev"`
	Hash   string            `json:"hash"`
}

type Log struct {
	mu   sync.Mutex
	f    *os.File
	seq  uint64
	prev string
	now  func() time.Time
}

func Open(path string, now func() time.Time) (*Log, error) {
	if now == nil {
		now = time.Now
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
	seq, prev, err := replay(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Log{f: f, seq: seq, prev: prev, now: now}, nil
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
	e := &Entry{Seq: l.seq + 1, Time: l.now().Unix(), Event: event, Fields: fields, Prev: l.prev}
	h, err := digest(e)
	if err != nil {
		return err
	}
	e.Hash = h
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := l.f.Write(line); err != nil {
		return err
	}
	if err := l.f.Sync(); err != nil {
		return err
	}
	l.seq = e.Seq
	l.prev = e.Hash
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

func replay(r io.Reader) (uint64, string, error) {
	var seq uint64
	prev := genesis
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, maxLine), maxLine)
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			return 0, "", fmt.Errorf("%w: blank line after entry %d", ErrCorrupt, seq)
		}
		var e Entry
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil || dec.More() {
			return 0, "", fmt.Errorf("%w: entry %d is not valid json", ErrCorrupt, seq+1)
		}
		if e.Seq != seq+1 || e.Prev != prev {
			return 0, "", fmt.Errorf("%w: entry %d breaks the chain", ErrCorrupt, e.Seq)
		}
		h, err := digest(&e)
		if err != nil || h != e.Hash {
			return 0, "", fmt.Errorf("%w: entry %d hash mismatch", ErrCorrupt, e.Seq)
		}
		seq = e.Seq
		prev = e.Hash
	}
	if err := sc.Err(); err != nil {
		return 0, "", fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return seq, prev, nil
}

func Verify(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	seq, _, err := replay(f)
	return seq, err
}

func Read(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, _, err := replay(f); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, maxLine), maxLine)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, ErrCorrupt
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
