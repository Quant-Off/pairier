package term

import (
	"errors"
	"os"
	"sync"

	"github.com/Quant-Off/pairier/host/internal/tui"
)

var (
	ErrNotTerminal = errors.New("term: standard input and output must be an interactive terminal")
	ErrNoVT        = errors.New("term: the console does not support virtual terminal sequences")
)

type TTY struct {
	in      *os.File
	out     *os.File
	events  chan tui.Event
	done    chan struct{}
	once    sync.Once
	restore func() error
	stop    func()
}

func newTTY(in, out *os.File) *TTY {
	return &TTY{in: in, out: out, events: make(chan tui.Event, 64), done: make(chan struct{})}
}

func (t *TTY) Events() <-chan tui.Event { return t.events }

func (t *TTY) Write(p []byte) (int, error) { return t.out.Write(p) }

func (t *TTY) send(ev tui.Event) bool {
	select {
	case t.events <- ev:
		return true
	case <-t.done:
		return false
	}
}

func (t *TTY) Close() error {
	var err error
	t.once.Do(func() {
		close(t.done)
		if t.stop != nil {
			t.stop()
		}
		if t.restore != nil {
			err = t.restore()
		}
	})
	return err
}
