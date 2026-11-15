package tui

import "strings"

type Color uint8

const (
	Default Color = iota
	Black
	Red
	Green
	Yellow
	Blue
	Magenta
	Cyan
	White
)

type Style struct {
	Fg        Color
	Bg        Color
	Bold      bool
	Dim       bool
	Reverse   bool
	Underline bool
}

type cell struct {
	s    string
	st   Style
	cont bool
}

type Screen struct {
	W, H     int
	cells    []cell
	CursorX  int
	CursorY  int
	CursorOn bool
}

func NewScreen(w, h int) *Screen {
	s := &Screen{}
	s.Resize(w, h)
	return s
}

func (s *Screen) Resize(w, h int) {
	if w < 0 {
		w = 0
	}
	if h < 0 {
		h = 0
	}
	s.W, s.H = w, h
	s.cells = make([]cell, w*h)
	s.CursorOn = false
}

func (s *Screen) Clear() {
	for i := range s.cells {
		s.cells[i] = cell{}
	}
	s.CursorOn = false
}

func (s *Screen) at(x, y int) *cell { return &s.cells[y*s.W+x] }

func (s *Screen) set(x, y int, text string, st Style, w int) {
	c := s.at(x, y)
	if c.cont && x > 0 {
		*s.at(x-1, y) = cell{st: s.at(x-1, y).st}
	}
	if !c.cont && x+1 < s.W && s.at(x+1, y).cont && w == 1 {
		*s.at(x+1, y) = cell{st: st}
	}
	*c = cell{s: text, st: st}
	if w == 2 {
		n := s.at(x+1, y)
		if !n.cont && x+2 < s.W && s.at(x+2, y).cont {
			*s.at(x+2, y) = cell{st: st}
		}
		*n = cell{st: st, cont: true}
	}
}

func (s *Screen) Put(x, y int, text string, st Style) int {
	if y < 0 || y >= s.H || x >= s.W {
		return 0
	}
	col := x
	last := -1
	for _, r := range Clean(text) {
		w := RuneWidth(r)
		if w == 0 {
			if last >= 0 {
				c := s.at(last, y)
				if len(c.s) < 32 {
					c.s += string(r)
				}
			}
			continue
		}
		if col+w > s.W {
			break
		}
		if col >= 0 {
			s.set(col, y, string(r), st, w)
			last = col
		} else {
			last = -1
		}
		col += w
	}
	if col < x {
		return 0
	}
	return col - x
}

func (s *Screen) Field(x, y, w int, text string, st Style) {
	if x+w > s.W {
		w = s.W - x
	}
	s.Put(x, y, Fit(text, w), st)
}

func (s *Screen) Fill(x, y, w, h int, st Style) {
	for row := y; row < y+h; row++ {
		if row < 0 || row >= s.H {
			continue
		}
		for col := x; col < x+w; col++ {
			if col < 0 || col >= s.W {
				continue
			}
			s.set(col, row, "", st, 1)
		}
	}
}

func (s *Screen) Box(x, y, w, h int, title string, st Style) {
	if w < 2 || h < 2 {
		return
	}
	s.Fill(x, y, w, h, st)
	edge := "+" + strings.Repeat("-", w-2) + "+"
	s.Put(x, y, edge, st)
	s.Put(x, y+h-1, edge, st)
	for row := y + 1; row < y+h-1; row++ {
		s.Put(x, row, "|", st)
		s.Put(x+w-1, row, "|", st)
	}
	if title != "" {
		t := st
		t.Bold = true
		s.Put(x+2, y, " "+Fit(title, min(StringWidth(title), w-6))+" ", t)
	}
}

func (s *Screen) Cursor(x, y int) {
	if x < 0 || y < 0 || x >= s.W || y >= s.H {
		s.CursorOn = false
		return
	}
	s.CursorX, s.CursorY, s.CursorOn = x, y, true
}

func (s *Screen) Lines() []string {
	out := make([]string, s.H)
	for y := 0; y < s.H; y++ {
		var b strings.Builder
		for x := 0; x < s.W; x++ {
			c := s.at(x, y)
			switch {
			case c.cont:
			case c.s == "":
				b.WriteByte(' ')
			default:
				b.WriteString(c.s)
			}
		}
		out[y] = strings.TrimRight(b.String(), " ")
	}
	return out
}

func (s *Screen) Text() string { return strings.Join(s.Lines(), "\n") }
