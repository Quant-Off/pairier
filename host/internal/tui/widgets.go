package tui

import (
	"strings"
	"unicode/utf8"
)

type Input struct {
	runes []rune
	pos   int
	off   int
	Max   int
}

func (in *Input) Value() string { return string(in.runes) }

func (in *Input) SetValue(s string) {
	in.runes = in.runes[:0]
	in.pos, in.off = 0, 0
	in.insert(CleanPaste(s))
}

func (in *Input) insert(s string) {
	for _, r := range s {
		if in.Max > 0 && len(string(in.runes))+utf8.RuneLen(r) > in.Max {
			return
		}
		in.runes = append(in.runes, 0)
		copy(in.runes[in.pos+1:], in.runes[in.pos:])
		in.runes[in.pos] = r
		in.pos++
	}
}

func (in *Input) Handle(ev Event) bool {
	if ev.Kind == EventPaste {
		in.insert(ev.Text)
		return true
	}
	if ev.Kind != EventKey {
		return false
	}
	switch ev.Key {
	case KeyRune:
		in.insert(string(cleanRune(ev.Rune)))
	case KeyBackspace:
		if in.pos > 0 {
			in.runes = append(in.runes[:in.pos-1], in.runes[in.pos:]...)
			in.pos--
		}
	case KeyDelete:
		if in.pos < len(in.runes) {
			in.runes = append(in.runes[:in.pos], in.runes[in.pos+1:]...)
		}
	case KeyLeft:
		if in.pos > 0 {
			in.pos--
		}
	case KeyRight:
		if in.pos < len(in.runes) {
			in.pos++
		}
	case KeyHome:
		in.pos = 0
	case KeyEnd:
		in.pos = len(in.runes)
	case KeyCtrl:
		switch ev.Rune {
		case 'a':
			in.pos = 0
		case 'e':
			in.pos = len(in.runes)
		case 'u':
			in.runes = append(in.runes[:0], in.runes[in.pos:]...)
			in.pos = 0
		case 'k':
			in.runes = in.runes[:in.pos]
		case 'w':
			i := in.pos
			for i > 0 && in.runes[i-1] == ' ' {
				i--
			}
			for i > 0 && in.runes[i-1] != ' ' {
				i--
			}
			in.runes = append(in.runes[:i], in.runes[in.pos:]...)
			in.pos = i
		default:
			return false
		}
	default:
		return false
	}
	return true
}

func (in *Input) Draw(s *Screen, x, y, w int, st Style, focus bool) {
	if w <= 1 {
		return
	}
	if in.off > in.pos {
		in.off = in.pos
	}
	for runesWidth(in.runes[in.off:in.pos]) > w-1 {
		in.off++
	}
	var b strings.Builder
	used := 0
	for _, r := range in.runes[in.off:] {
		rw := RuneWidth(r)
		if used+rw > w {
			break
		}
		b.WriteRune(r)
		used += rw
	}
	s.Field(x, y, w, b.String(), st)
	if focus {
		s.Cursor(x+runesWidth(in.runes[in.off:in.pos]), y)
	}
}

func runesWidth(rs []rune) int {
	w := 0
	for _, r := range rs {
		w += RuneWidth(r)
	}
	return w
}

type List struct {
	Sel int
	Off int
}

func (l *List) Clamp(n, h int) {
	if l.Sel >= n {
		l.Sel = n - 1
	}
	if l.Sel < 0 {
		l.Sel = 0
	}
	if h < 1 {
		h = 1
	}
	if l.Off > l.Sel {
		l.Off = l.Sel
	}
	if l.Sel >= l.Off+h {
		l.Off = l.Sel - h + 1
	}
	if l.Off > n-h {
		l.Off = max(n-h, 0)
	}
	if l.Off < 0 {
		l.Off = 0
	}
}

func (l *List) Handle(ev Event, n, h int) bool {
	switch {
	case ev.Is(KeyUp), ev.IsRune('k'):
		l.Sel--
	case ev.Is(KeyDown), ev.IsRune('j'):
		l.Sel++
	case ev.Is(KeyPgUp):
		l.Sel -= max(h-1, 1)
	case ev.Is(KeyPgDn):
		l.Sel += max(h-1, 1)
	case ev.Is(KeyHome), ev.IsRune('g'):
		l.Sel = 0
	case ev.Is(KeyEnd), ev.IsRune('G'):
		l.Sel = n - 1
	default:
		return false
	}
	l.Clamp(n, h)
	return true
}

type FieldKind uint8

const (
	FieldText FieldKind = iota
	FieldToggle
	FieldChoice
	FieldFlags
)

type Field struct {
	Label   string
	Kind    FieldKind
	Input   Input
	On      bool
	Options []string
	Index   int
	Checked []bool
	Hint    string
}

func TextField(label, value string, max int) *Field {
	f := &Field{Label: label, Kind: FieldText}
	f.Input.Max = max
	f.Input.SetValue(value)
	return f
}

func ToggleField(label string, on bool) *Field {
	return &Field{Label: label, Kind: FieldToggle, On: on}
}

func ChoiceField(label string, options []string, index int) *Field {
	return &Field{Label: label, Kind: FieldChoice, Options: options, Index: index}
}

func FlagsField(label string, options []string, checked []bool) *Field {
	return &Field{Label: label, Kind: FieldFlags, Options: options, Checked: checked}
}

func (f *Field) Value() string {
	switch f.Kind {
	case FieldText:
		return f.Input.Value()
	case FieldChoice:
		if f.Index >= 0 && f.Index < len(f.Options) {
			return f.Options[f.Index]
		}
	}
	return ""
}

func (f *Field) Selected() []string {
	var out []string
	for i, on := range f.Checked {
		if on {
			out = append(out, f.Options[i])
		}
	}
	return out
}

func (f *Field) handle(ev Event) bool {
	switch f.Kind {
	case FieldText:
		return f.Input.Handle(ev)
	case FieldToggle:
		if ev.IsRune(' ') || ev.Is(KeyLeft) || ev.Is(KeyRight) {
			f.On = !f.On
			return true
		}
	case FieldChoice:
		if len(f.Options) == 0 {
			return false
		}
		switch {
		case ev.Is(KeyLeft):
			f.Index = (f.Index + len(f.Options) - 1) % len(f.Options)
		case ev.Is(KeyRight), ev.IsRune(' '):
			f.Index = (f.Index + 1) % len(f.Options)
		default:
			return false
		}
		return true
	case FieldFlags:
		switch {
		case ev.Is(KeyLeft):
			if f.Index > 0 {
				f.Index--
			}
		case ev.Is(KeyRight):
			if f.Index < len(f.Options)-1 {
				f.Index++
			}
		case ev.IsRune(' '):
			if f.Index < len(f.Checked) {
				f.Checked[f.Index] = !f.Checked[f.Index]
			}
		default:
			return false
		}
		return true
	}
	return false
}

type Result uint8

const (
	None Result = iota
	Submit
	Cancel
)

type Form struct {
	Title  string
	Note   []string
	Fields []*Field
	Focus  int
	Err    string
}

func (f *Form) Handle(ev Event) Result {
	switch {
	case ev.Is(KeyEsc):
		return Cancel
	case ev.Is(KeyTab), ev.Is(KeyDown):
		f.Focus = (f.Focus + 1) % len(f.Fields)
		return None
	case ev.Is(KeyBacktab), ev.Is(KeyUp):
		f.Focus = (f.Focus + len(f.Fields) - 1) % len(f.Fields)
		return None
	case ev.Is(KeyEnter):
		if f.Focus == len(f.Fields)-1 {
			return Submit
		}
		f.Focus++
		return None
	}
	if f.Focus < len(f.Fields) {
		f.Fields[f.Focus].handle(ev)
	}
	return None
}

func (f *Form) Draw(s *Screen, base Style) {
	w := min(s.W-4, 78)
	labelW := 0
	for _, fl := range f.Fields {
		labelW = max(labelW, StringWidth(fl.Label))
	}
	labelW = min(labelW, w/3)
	var notes []string
	for _, n := range f.Note {
		notes = append(notes, Wrap(n, w-4)...)
	}
	errs := Wrap(f.Err, w-4)
	h := 4 + len(notes) + len(f.Fields)*2 + 1
	if len(errs) > 0 {
		h += len(errs) + 1
	}
	h = min(h, s.H)
	x := (s.W - w) / 2
	y := max((s.H-h)/2, 0)
	s.Box(x, y, w, h, f.Title, base)
	row := y + 2
	for _, line := range notes {
		s.Field(x+2, row, w-4, line, base)
		row++
	}
	if len(notes) > 0 {
		row++
	}
	valueX := x + 2 + labelW + 2
	valueW := w - (valueX - x) - 2
	focus := Style{Reverse: true}
	for i, fl := range f.Fields {
		if row >= y+h-1 {
			break
		}
		wrapped := false
		lst := base
		if i == f.Focus {
			lst.Bold = true
		}
		s.Field(x+2, row, labelW, fl.Label, lst)
		vst := Style{Underline: true}
		if i == f.Focus {
			vst = focus
		}
		switch fl.Kind {
		case FieldText:
			fl.Input.Draw(s, valueX, row, valueW, vst, i == f.Focus)
		case FieldToggle:
			mark := "[ ] no"
			if fl.On {
				mark = "[x] yes"
			}
			s.Field(valueX, row, valueW, mark, vst)
		case FieldChoice:
			v := "(none)"
			if len(fl.Options) > 0 {
				v = "< " + fl.Value() + " >"
			}
			s.Field(valueX, row, valueW, v, vst)
		case FieldFlags:
			col, line := valueX, row
			for j, opt := range fl.Options {
				mark := "[ ]"
				if fl.Checked[j] {
					mark = "[x]"
				}
				item := mark + " " + opt
				ost := base
				if i == f.Focus && j == fl.Index {
					ost = focus
				}
				if col > valueX && col+StringWidth(item) > valueX+valueW {
					if line+1 >= y+h-1 || line > row {
						break
					}
					col, line = valueX, line+1
					wrapped = true
				}
				col += s.Put(col, line, item, ost) + 1
			}
		}
		if fl.Hint != "" && !wrapped && row+1 < y+h-1 {
			s.Field(valueX, row+1, valueW, fl.Hint, Style{Dim: true})
		}
		row += 2
	}
	for _, line := range errs {
		if row >= y+h-1 {
			break
		}
		s.Field(x+2, row, w-4, line, Style{Fg: Red, Bold: true})
		row++
	}
	s.Field(x+2, y+h-1, w-4, " Tab move  Space toggle  Left/Right choose  Enter next  Esc cancel ", base)
}

type Dialog struct {
	Title   string
	Lines   []string
	Ask     bool
	Confirm string
	Input   Input
	Err     string
	Danger  bool
}

func (d *Dialog) Handle(ev Event) Result {
	if !d.Ask {
		if ev.Is(KeyEnter) || ev.Is(KeyEsc) || ev.IsRune('q') || ev.IsRune(' ') {
			return Cancel
		}
		return None
	}
	if ev.Is(KeyEsc) {
		return Cancel
	}
	if d.Confirm != "" {
		if ev.Is(KeyEnter) {
			if d.Input.Value() == d.Confirm {
				return Submit
			}
			d.Err = "the text does not match"
			return None
		}
		d.Input.Handle(ev)
		return None
	}
	switch {
	case ev.IsRune('y'), ev.IsRune('Y'):
		return Submit
	case ev.IsRune('n'), ev.IsRune('N'):
		return Cancel
	}
	return None
}

func (d *Dialog) Draw(s *Screen, base Style) {
	w := min(s.W-4, 78)
	var lines []string
	for _, l := range d.Lines {
		lines = append(lines, Wrap(l, w-4)...)
	}
	h := 4 + len(lines)
	if d.Ask && d.Confirm != "" {
		h += 2
	}
	if d.Err != "" {
		h++
	}
	h = min(h, s.H)
	x := (s.W - w) / 2
	y := max((s.H-h)/2, 0)
	st := base
	if d.Danger {
		st.Fg = Red
	}
	s.Box(x, y, w, h, d.Title, st)
	row := y + 2
	for _, line := range lines {
		if row >= y+h-1 {
			break
		}
		s.Field(x+2, row, w-4, line, base)
		row++
	}
	if d.Ask && d.Confirm != "" && row+1 < y+h-1 {
		row++
		label := "type " + d.Confirm + ": "
		n := s.Put(x+2, row, label, Style{Bold: true})
		d.Input.Draw(s, x+2+n, row, w-4-n, Style{Reverse: true}, true)
		row++
	}
	if d.Err != "" && row < y+h-1 {
		s.Field(x+2, row, w-4, d.Err, Style{Fg: Red, Bold: true})
	}
	hint := " Enter/Esc close "
	if d.Ask {
		hint = " y confirm  n/Esc cancel "
		if d.Confirm != "" {
			hint = " Enter confirm  Esc cancel "
		}
	}
	s.Field(x+2, y+h-1, w-4, hint, st)
}
