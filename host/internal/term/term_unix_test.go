//go:build linux || darwin

package term

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/Quant-Off/pairier/host/internal/tui"
)

func TestOpenRefusesNonTerminal(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "plain"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := Open(f, f); !errors.Is(err, ErrNotTerminal) {
		t.Fatalf("regular file accepted as a terminal: %v", err)
	}
}

func TestRawModeOnPTY(t *testing.T) {
	master, slave, err := openPTY()
	if err != nil {
		t.Skipf("pty: %v", err)
	}
	defer master.Close()
	defer slave.Close()
	ws := winsize{Row: 30, Col: 100}
	if err := ioctl(master.Fd(), syscall.TIOCSWINSZ, unsafe.Pointer(&ws)); err != nil {
		t.Fatal(err)
	}
	before, err := getTermios(slave.Fd())
	if err != nil {
		t.Fatal(err)
	}
	tty, err := Open(slave, slave)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := getTermios(slave.Fd())
	if err != nil {
		t.Fatal(err)
	}
	if raw.Lflag&(syscall.ICANON|syscall.ECHO|syscall.ISIG) != 0 || raw.Iflag&(syscall.IXON|syscall.ICRNL) != 0 || raw.Oflag&syscall.OPOST != 0 {
		t.Fatalf("not raw: %+v", raw)
	}
	if w, h, err := tty.Size(); err != nil || w != 100 || h != 30 {
		t.Fatalf("size %d %d %v", w, h, err)
	}
	if _, err := master.Write([]byte("a\x1b[A\x03")); err != nil {
		t.Fatal(err)
	}
	want := []tui.Event{tui.RuneEvent('a'), tui.KeyEvent(tui.KeyUp), tui.CtrlEvent('c')}
	for _, w := range want {
		select {
		case ev := <-tty.Events():
			if ev != w {
				t.Fatalf("got %v want %v", ev, w)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("no event, want %v", w)
		}
	}
	if err := tty.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := getTermios(slave.Fd())
	if err != nil {
		t.Fatal(err)
	}
	if *after != *before {
		t.Fatalf("terminal not restored\nbefore %+v\nafter  %+v", before, after)
	}
	if err := tty.Close(); err != nil {
		t.Fatal(err)
	}
}
