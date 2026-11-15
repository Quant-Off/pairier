package console

import (
	"bytes"
	"strings"
	"sync"
	"time"

	"github.com/Quant-Off/pairier/host/internal/tui"
)

const maxPartial = 4096

type logBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
	part  []byte
}

func newLogBuffer(max int) *logBuffer { return &logBuffer{max: max} }

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.part = append(l.part, p...)
	for {
		i := bytes.IndexByte(l.part, '\n')
		if i < 0 {
			break
		}
		l.push("core: " + string(l.part[:i]))
		l.part = l.part[i+1:]
	}
	if len(l.part) > maxPartial {
		l.push("core: " + string(l.part))
		l.part = nil
	}
	return len(p), nil
}

func (l *logBuffer) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.push(s)
}

func (l *logBuffer) push(s string) {
	s = tui.Clean(strings.TrimRight(s, "\r"))
	l.lines = append(l.lines, time.Now().Format("15:04:05 ")+s)
	if len(l.lines) > l.max {
		l.lines = append(l.lines[:0], l.lines[len(l.lines)-l.max:]...)
	}
}

func (l *logBuffer) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}
