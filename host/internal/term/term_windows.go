//go:build windows

package term

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/Quant-Off/pairier/host/internal/tui"
	"github.com/Quant-Off/pairier/host/internal/winsys"
)

const pollInterval = 500 * time.Millisecond

func Open(in, out *os.File) (*TTY, error) {
	ih, oh := syscall.Handle(in.Fd()), syscall.Handle(out.Fd())
	inMode, err := winsys.GetConsoleMode(ih)
	if err != nil {
		return nil, ErrNotTerminal
	}
	outMode, err := winsys.GetConsoleMode(oh)
	if err != nil {
		return nil, ErrNotTerminal
	}
	vt := outMode | winsys.ConsoleProcessedOutput | winsys.ConsoleVirtualTerminalProcessing
	if err := winsys.SetConsoleMode(oh, vt|winsys.ConsoleDisableNewlineAutoReturn); err != nil {
		if err := winsys.SetConsoleMode(oh, vt); err != nil {
			return nil, ErrNoVT
		}
	}
	if err := winsys.SetConsoleMode(ih, winsys.ConsoleWindowInput); err != nil {
		return nil, errors.Join(fmt.Errorf("term: console input mode: %w", err), winsys.SetConsoleMode(oh, outMode))
	}
	t := newTTY(in, out)
	t.restore = func() error {
		return errors.Join(winsys.SetConsoleMode(ih, inMode), winsys.SetConsoleMode(oh, outMode))
	}
	go t.read(ih)
	go t.poll()
	return t, nil
}

func (t *TTY) read(h syscall.Handle) {
	var d tui.ConsoleDecoder
	recs := make([]winsys.InputRecord, 16)
	for {
		n, err := winsys.ReadConsoleInput(h, recs)
		if err != nil {
			return
		}
		for i := range recs[:n] {
			if recs[i].EventType != winsys.KeyEventType {
				continue
			}
			k := recs[i].Key()
			for _, ev := range d.Key(k.Down, k.Repeat, k.VirtualKey, k.Char, k.ControlState) {
				if !t.send(ev) {
					return
				}
			}
		}
	}
}

func (t *TTY) poll() {
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	lw, lh, _ := t.Size()
	for {
		select {
		case <-tick.C:
			w, h, err := t.Size()
			if err != nil || (w == lw && h == lh) {
				continue
			}
			lw, lh = w, h
			if !t.send(tui.ResizeEvent(w, h)) {
				return
			}
		case <-t.done:
			return
		}
	}
}

func (t *TTY) Size() (int, int, error) {
	return winsys.ConsoleWindowSize(syscall.Handle(t.out.Fd()))
}
