package tui

import (
	"bytes"
	"io"
	"strconv"
)

const (
	enterSeq = "\x1b[?1049h\x1b[?7l\x1b[?2004h\x1b[?25l\x1b[0m\x1b[2J\x1b[H"
	leaveSeq = "\x1b[0m\x1b[2J\x1b[H\x1b[?2004l\x1b[?7h\x1b[?25h\x1b[?1049l"
)

type Renderer struct {
	out    io.Writer
	color  bool
	prev   []string
	width  int
	buf    bytes.Buffer
	active bool
}

func NewRenderer(out io.Writer, color bool) *Renderer {
	return &Renderer{out: out, color: color}
}

func (r *Renderer) Begin() error {
	r.active = true
	r.prev = nil
	_, err := io.WriteString(r.out, enterSeq)
	return err
}

func (r *Renderer) End() error {
	if !r.active {
		return nil
	}
	r.active = false
	r.prev = nil
	_, err := io.WriteString(r.out, leaveSeq)
	return err
}

func (r *Renderer) Invalidate() { r.prev = nil }

func (r *Renderer) Draw(s *Screen) error {
	r.buf.Reset()
	if len(r.prev) != s.H || r.width != s.W {
		r.prev = make([]string, s.H)
		r.width = s.W
		r.buf.WriteString("\x1b[0m\x1b[2J")
	}
	r.buf.WriteString("\x1b[?25l")
	for y := 0; y < s.H; y++ {
		line := r.row(s, y)
		if line == r.prev[y] {
			continue
		}
		r.buf.WriteString("\x1b[")
		r.buf.WriteString(strconv.Itoa(y + 1))
		r.buf.WriteString(";1H")
		r.buf.WriteString(line)
		r.prev[y] = line
	}
	if s.CursorOn {
		r.buf.WriteString("\x1b[")
		r.buf.WriteString(strconv.Itoa(s.CursorY + 1))
		r.buf.WriteByte(';')
		r.buf.WriteString(strconv.Itoa(s.CursorX + 1))
		r.buf.WriteString("H\x1b[?25h")
	}
	_, err := r.out.Write(r.buf.Bytes())
	return err
}

func (r *Renderer) row(s *Screen, y int) string {
	var b bytes.Buffer
	cur := Style{}
	b.WriteString("\x1b[0m")
	for x := 0; x < s.W; x++ {
		c := s.at(x, y)
		if c.cont {
			continue
		}
		if c.st != cur {
			b.WriteString(r.sgr(c.st))
			cur = c.st
		}
		if c.s == "" {
			b.WriteByte(' ')
		} else {
			b.WriteString(c.s)
		}
	}
	b.WriteString("\x1b[0m")
	return b.String()
}

func (r *Renderer) sgr(st Style) string {
	b := []byte("\x1b[0")
	if st.Bold {
		b = append(b, ";1"...)
	}
	if st.Dim {
		b = append(b, ";2"...)
	}
	if st.Underline {
		b = append(b, ";4"...)
	}
	if st.Reverse {
		b = append(b, ";7"...)
	}
	if r.color {
		if st.Fg != Default {
			b = append(b, ';')
			b = strconv.AppendInt(b, int64(29+int(st.Fg)), 10)
		}
		if st.Bg != Default {
			b = append(b, ';')
			b = strconv.AppendInt(b, int64(39+int(st.Bg)), 10)
		}
	}
	return string(append(b, 'm'))
}
