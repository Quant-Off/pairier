package tui

import (
	"bytes"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxPaste    = 4096
	maxSequence = 32
	EscDelay    = 30 * time.Millisecond
	PasteDelay  = 2 * time.Second
)

var pasteEnd = []byte("\x1b[201~")

type Decoder struct {
	buf   []byte
	paste bool
	text  []byte
}

func (d *Decoder) Feed(p []byte) []Event {
	d.buf = append(d.buf, p...)
	var out []Event
	for len(d.buf) > 0 {
		if d.paste {
			ev, ok := d.feedPaste()
			if !ok {
				break
			}
			out = append(out, ev)
			continue
		}
		ev, n, ok := d.next()
		if !ok {
			break
		}
		d.buf = d.buf[n:]
		if ev.Kind == EventKey && ev.Key == KeyNone {
			continue
		}
		out = append(out, ev)
	}
	if len(d.buf) == 0 {
		d.buf = nil
	}
	return out
}

func (d *Decoder) Pending() time.Duration {
	switch {
	case d.paste:
		return PasteDelay
	case len(d.buf) > 0:
		return EscDelay
	}
	return 0
}

func (d *Decoder) Flush() []Event {
	if d.paste {
		d.paste = false
		d.buf = nil
		return []Event{d.takePaste()}
	}
	if len(d.buf) == 0 {
		return nil
	}
	rest := d.buf
	d.buf = nil
	if rest[0] != 0x1b {
		return nil
	}
	out := []Event{KeyEvent(KeyEsc)}
	out = append(out, d.Feed(rest[1:])...)
	d.buf = nil
	d.paste = false
	return out
}

func (d *Decoder) feedPaste() (Event, bool) {
	if i := bytes.Index(d.buf, pasteEnd); i >= 0 {
		d.addPaste(d.buf[:i])
		d.buf = d.buf[i+len(pasteEnd):]
		d.paste = false
		return d.takePaste(), true
	}
	keep := 0
	for k := len(pasteEnd) - 1; k > 0; k-- {
		if bytes.HasSuffix(d.buf, pasteEnd[:k]) {
			keep = k
			break
		}
	}
	d.addPaste(d.buf[:len(d.buf)-keep])
	d.buf = append([]byte(nil), d.buf[len(d.buf)-keep:]...)
	return Event{}, false
}

func (d *Decoder) addPaste(b []byte) {
	room := MaxPaste - len(d.text)
	if room <= 0 {
		return
	}
	if len(b) > room {
		b = b[:room]
	}
	d.text = append(d.text, b...)
}

func (d *Decoder) takePaste() Event {
	s := CleanPaste(string(d.text))
	d.text = d.text[:0]
	return PasteEvent(s)
}

func CleanPaste(s string) string {
	s = strings.ToValidUTF8(s, "?")
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\r', '\n', '\t':
			b.WriteByte(' ')
		default:
			b.WriteRune(cleanRune(r))
		}
	}
	return b.String()
}

func (d *Decoder) next() (Event, int, bool) {
	b := d.buf
	c := b[0]
	switch {
	case c == 0x1b:
		if len(b) == 1 {
			return Event{}, 0, false
		}
		switch b[1] {
		case '[':
			return d.csi(b)
		case 'O':
			if len(b) < 3 {
				return Event{}, 0, false
			}
			return ss3(b[2]), 3, true
		}
		return KeyEvent(KeyEsc), 1, true
	case c == '\r' || c == '\n':
		return KeyEvent(KeyEnter), 1, true
	case c == '\t':
		return KeyEvent(KeyTab), 1, true
	case c == 0x7f || c == 0x08:
		return KeyEvent(KeyBackspace), 1, true
	case c == 0:
		return Event{}, 1, true
	case c < 0x20:
		return CtrlEvent(rune('a' + c - 1)), 1, true
	case c < 0x80:
		return RuneEvent(rune(c)), 1, true
	}
	if !utf8.FullRune(b) {
		return Event{}, 0, false
	}
	r, n := utf8.DecodeRune(b)
	if r == utf8.RuneError || cleanRune(r) != r {
		return Event{}, n, true
	}
	return RuneEvent(r), n, true
}

func (d *Decoder) csi(b []byte) (Event, int, bool) {
	i := 2
	for i < len(b) && b[i] >= 0x30 && b[i] <= 0x3f {
		i++
	}
	for i < len(b) && b[i] >= 0x20 && b[i] <= 0x2f {
		i++
	}
	if i >= len(b) {
		if len(b) >= maxSequence {
			return Event{}, len(b), true
		}
		return Event{}, 0, false
	}
	final := b[i]
	if final < 0x40 || final > 0x7e {
		return Event{}, i, true
	}
	params := string(b[2:i])
	n := i + 1
	switch final {
	case 'A':
		return KeyEvent(KeyUp), n, true
	case 'B':
		return KeyEvent(KeyDown), n, true
	case 'C':
		return KeyEvent(KeyRight), n, true
	case 'D':
		return KeyEvent(KeyLeft), n, true
	case 'H':
		return KeyEvent(KeyHome), n, true
	case 'F':
		return KeyEvent(KeyEnd), n, true
	case 'Z':
		return KeyEvent(KeyBacktab), n, true
	case '~':
		if j := strings.IndexByte(params, ';'); j >= 0 {
			params = params[:j]
		}
		switch params {
		case "1", "7":
			return KeyEvent(KeyHome), n, true
		case "4", "8":
			return KeyEvent(KeyEnd), n, true
		case "3":
			return KeyEvent(KeyDelete), n, true
		case "5":
			return KeyEvent(KeyPgUp), n, true
		case "6":
			return KeyEvent(KeyPgDn), n, true
		case "200":
			d.paste = true
			d.text = d.text[:0]
		}
	}
	return Event{}, n, true
}

func ss3(c byte) Event {
	switch c {
	case 'A':
		return KeyEvent(KeyUp)
	case 'B':
		return KeyEvent(KeyDown)
	case 'C':
		return KeyEvent(KeyRight)
	case 'D':
		return KeyEvent(KeyLeft)
	case 'H':
		return KeyEvent(KeyHome)
	case 'F':
		return KeyEvent(KeyEnd)
	}
	return Event{}
}

func Pump(chunks <-chan []byte, send func(Event) bool) {
	var d Decoder
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	for {
		select {
		case b, ok := <-chunks:
			if !ok {
				timer.Stop()
				return
			}
			timer.Stop()
			for _, ev := range d.Feed(b) {
				if !send(ev) {
					return
				}
			}
			if wait := d.Pending(); wait > 0 {
				timer.Reset(wait)
			}
		case <-timer.C:
			for _, ev := range d.Flush() {
				if !send(ev) {
					return
				}
			}
		}
	}
}
