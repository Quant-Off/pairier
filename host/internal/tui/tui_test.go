package tui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func feedAll(chunks ...string) []Event {
	var d Decoder
	var out []Event
	for _, c := range chunks {
		out = append(out, d.Feed([]byte(c))...)
	}
	return append(out, d.Flush()...)
}

func TestDecoderKeys(t *testing.T) {
	cases := []struct {
		in   string
		want []Event
	}{
		{"a", []Event{RuneEvent('a')}},
		{"\r", []Event{KeyEvent(KeyEnter)}},
		{"\x7f", []Event{KeyEvent(KeyBackspace)}},
		{"\x03", []Event{CtrlEvent('c')}},
		{"\x1b[A\x1b[B\x1b[C\x1b[D", []Event{KeyEvent(KeyUp), KeyEvent(KeyDown), KeyEvent(KeyRight), KeyEvent(KeyLeft)}},
		{"\x1bOA\x1bOH", []Event{KeyEvent(KeyUp), KeyEvent(KeyHome)}},
		{"\x1b[1;5A", []Event{KeyEvent(KeyUp)}},
		{"\x1b[3~\x1b[5~\x1b[6~\x1b[Z", []Event{KeyEvent(KeyDelete), KeyEvent(KeyPgUp), KeyEvent(KeyPgDn), KeyEvent(KeyBacktab)}},
		{"\x1b", []Event{KeyEvent(KeyEsc)}},
		{"\x1bq", []Event{KeyEvent(KeyEsc), RuneEvent('q')}},
		{"가", []Event{RuneEvent('가')}},
		{"\xc2\x9b", nil},
		{"\xff", nil},
		{"\x1b[99x", nil},
	}
	for _, c := range cases {
		got := feedAll(c.in)
		if len(got) != len(c.want) {
			t.Fatalf("%q: got %v want %v", c.in, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%q: event %d got %v want %v", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestDecoderSplitInput(t *testing.T) {
	got := feedAll("\x1b", "[", "A", "\xea\xb0", "\x80")
	if len(got) != 2 || got[0] != KeyEvent(KeyUp) || got[1] != RuneEvent('가') {
		t.Fatalf("%v", got)
	}
	var d Decoder
	if ev := d.Feed([]byte("\x1b")); len(ev) != 0 || d.Pending() != EscDelay {
		t.Fatalf("lone escape not held: %v %v", ev, d.Pending())
	}
	if ev := d.Flush(); len(ev) != 1 || ev[0] != KeyEvent(KeyEsc) {
		t.Fatalf("flush %v", ev)
	}
	if d.Pending() != 0 {
		t.Fatal("still pending")
	}
}

func TestDecoderPaste(t *testing.T) {
	got := feedAll("x\x1b[200~ab\r\ncd\x1b]52;c;ZXZpbA==\x07\x1b[20", "1~y")
	if len(got) != 3 || got[0] != RuneEvent('x') || got[2] != RuneEvent('y') {
		t.Fatalf("%v", got)
	}
	if got[1].Kind != EventPaste || got[1].Text != "ab  cd?]52;c;ZXZpbA==?" {
		t.Fatalf("paste %q", got[1].Text)
	}
	var d Decoder
	d.Feed([]byte("\x1b[200~" + strings.Repeat("z", MaxPaste*2)))
	if d.Pending() != PasteDelay {
		t.Fatal("unterminated paste not pending")
	}
	ev := d.Flush()
	if len(ev) != 1 || len(ev[0].Text) != MaxPaste {
		t.Fatalf("paste not bounded: %d", len(ev[0].Text))
	}
	if ev := d.Feed([]byte("q")); len(ev) != 1 || ev[0] != RuneEvent('q') {
		t.Fatalf("decoder stuck in paste mode: %v", ev)
	}
}

func TestDecoderBoundsGarbage(t *testing.T) {
	var d Decoder
	d.Feed([]byte("\x1b[" + strings.Repeat("1", maxSequence*4)))
	if len(d.buf) > maxSequence {
		t.Fatalf("unbounded sequence buffer %d", len(d.buf))
	}
}

func TestPump(t *testing.T) {
	chunks := make(chan []byte)
	events := make(chan Event, 8)
	done := make(chan struct{})
	go func() {
		Pump(chunks, func(ev Event) bool { events <- ev; return true })
		close(done)
	}()
	chunks <- []byte("\x1b")
	select {
	case ev := <-events:
		if ev != KeyEvent(KeyEsc) {
			t.Fatalf("%v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("escape not flushed")
	}
	chunks <- []byte("ok")
	if a, b := <-events, <-events; a != RuneEvent('o') || b != RuneEvent('k') {
		t.Fatalf("%v %v", a, b)
	}
	close(chunks)
	<-done
}

func FuzzDecoder(f *testing.F) {
	f.Add([]byte("\x1b[200~a\x1b[201~\x1b[A\x1bO"))
	f.Add([]byte("\xea\xb0\x80\x1b\x1b[1;2~"))
	f.Fuzz(func(t *testing.T, b []byte) {
		var d Decoder
		for i := 0; i < len(b); i += 3 {
			evs := d.Feed(b[i:min(i+3, len(b))])
			for _, ev := range evs {
				if ev.Kind == EventKey && ev.Key == KeyRune && cleanRune(ev.Rune) != ev.Rune {
					t.Fatalf("unsafe rune %U", ev.Rune)
				}
				if strings.ContainsAny(ev.Text, "\x1b\x07\r\n") {
					t.Fatalf("control in paste %q", ev.Text)
				}
			}
			if len(d.buf) > maxSequence+len(pasteEnd)+4 && !d.paste {
				t.Fatalf("buffer grew to %d", len(d.buf))
			}
		}
		d.Flush()
	})
}

func TestCleanAndWidth(t *testing.T) {
	cases := map[string]string{
		"plain":        "plain",
		"a\x1b[2Jb":    "a?[2Jb",
		"\x9b31m":      "?31m",
		"evil‮gnp.exe": "evil?gnp.exe",
		"x⁦y‏z؜":       "x?y?z?",
		"tab\there":    "tab here",
		"bad\xffutf8":  "bad?utf8",
		"line sep":     "line?sep",
		"한글 라벨":        "한글 라벨",
		"　wide":        " wide",
	}
	for in, want := range cases {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q want %q", in, got, want)
		}
	}
	if StringWidth("한글ab") != 6 || StringWidth("é") != 1 || StringWidth("\x1b") != 1 {
		t.Fatalf("widths %d %d %d", StringWidth("한글ab"), StringWidth("é"), StringWidth("\x1b"))
	}
	for _, c := range []struct {
		in   string
		w    int
		want string
	}{
		{"abc", 5, "abc  "},
		{"abcdef", 4, "abc~"},
		{"한글라벨", 5, "한글~"},
		{"한글라벨", 4, "한~ "},
		{"x", 0, ""},
	} {
		if got := Fit(c.in, c.w); got != c.want || StringWidth(got) != c.w {
			t.Errorf("Fit(%q, %d) = %q want %q", c.in, c.w, got, c.want)
		}
	}
}

func TestScreenWideCellsAndRender(t *testing.T) {
	s := NewScreen(10, 2)
	s.Put(0, 0, "가나다라마바", Style{})
	if got := s.Lines()[0]; got != "가나다라마" {
		t.Fatalf("%q", got)
	}
	s.Put(1, 0, "x", Style{})
	if got := s.Lines()[0]; got != " x나다라마" {
		t.Fatalf("overwrite right half %q", got)
	}
	s.Put(2, 0, "yz", Style{})
	if got := s.Lines()[0]; got != " xyz다라마" {
		t.Fatalf("overwrite left half %q", got)
	}
	s.Put(9, 1, "가", Style{})
	if got := s.Lines()[1]; got != "" {
		t.Fatalf("wide rune at the edge %q", got)
	}
	s.Put(0, 1, "\x1b]0;pwned\x07", Style{})
	var out bytes.Buffer
	r := NewRenderer(&out, true)
	if err := r.Draw(s); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte("\x1b]")) || bytes.Contains(out.Bytes(), []byte{0x07}) {
		t.Fatalf("control sequence reached the terminal: %q", out.String())
	}
	out.Reset()
	if err := r.Draw(s); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte(";1H")) {
		t.Fatalf("unchanged frame redrawn: %q", out.String())
	}
	s.Put(0, 1, "Z", Style{Fg: Red, Bold: true})
	out.Reset()
	_ = r.Draw(s)
	if !bytes.Contains(out.Bytes(), []byte("\x1b[2;1H")) || bytes.Contains(out.Bytes(), []byte("\x1b[1;1H")) || !bytes.Contains(out.Bytes(), []byte("\x1b[0;1;31m")) {
		t.Fatalf("diff render %q", out.String())
	}
	plain := NewRenderer(&out, false)
	out.Reset()
	_ = plain.Draw(s)
	if bytes.Contains(out.Bytes(), []byte(";31")) {
		t.Fatal("color emitted with color off")
	}
}

func TestInputEditing(t *testing.T) {
	var in Input
	in.Max = 8
	for _, ev := range []Event{RuneEvent('a'), RuneEvent('한'), RuneEvent('b'), KeyEvent(KeyLeft), KeyEvent(KeyBackspace), RuneEvent('c')} {
		in.Handle(ev)
	}
	if in.Value() != "acb" {
		t.Fatalf("%q", in.Value())
	}
	in.Handle(PasteEvent("123456789"))
	if len(in.Value()) > 8 {
		t.Fatalf("max not enforced %q", in.Value())
	}
	in.SetValue("one two")
	in.Handle(CtrlEvent('w'))
	if in.Value() != "one " {
		t.Fatalf("ctrl-w %q", in.Value())
	}
	in.Handle(CtrlEvent('u'))
	if in.Value() != "" {
		t.Fatalf("ctrl-u %q", in.Value())
	}
	in.SetValue("a\x1bb")
	if in.Value() != "a?b" {
		t.Fatalf("SetValue kept a control %q", in.Value())
	}
	s := NewScreen(6, 1)
	in.SetValue("가나다라마")
	in.Draw(s, 0, 0, 6, Style{}, true)
	if !s.CursorOn || s.CursorX > 5 {
		t.Fatalf("cursor %v %d", s.CursorOn, s.CursorX)
	}
}

func TestFormAndDialog(t *testing.T) {
	f := &Form{Title: "t", Fields: []*Field{
		TextField("Label", "", 0),
		FlagsField("Usage", []string{"a", "b"}, []bool{true, false}),
		ChoiceField("To", []string{"x", "y"}, 0),
	}}
	for _, ev := range []Event{RuneEvent('k'), KeyEvent(KeyTab), KeyEvent(KeyRight), RuneEvent(' '), KeyEvent(KeyEnter), KeyEvent(KeyRight)} {
		if r := f.Handle(ev); r != None {
			t.Fatalf("early result %v", r)
		}
	}
	if f.Handle(KeyEvent(KeyEnter)) != Submit {
		t.Fatal("no submit on the last field")
	}
	if f.Fields[0].Value() != "k" || strings.Join(f.Fields[1].Selected(), ",") != "a,b" || f.Fields[2].Value() != "y" {
		t.Fatalf("%q %v %q", f.Fields[0].Value(), f.Fields[1].Selected(), f.Fields[2].Value())
	}
	if f.Handle(KeyEvent(KeyEsc)) != Cancel {
		t.Fatal("esc")
	}
	s := NewScreen(80, 24)
	f.Draw(s, Style{})
	if !strings.Contains(s.Text(), "[x] a") {
		t.Fatalf("form render\n%s", s.Text())
	}
	d := &Dialog{Title: "renew", Ask: true, Confirm: "alice"}
	if d.Handle(RuneEvent('y')) != None || d.Handle(KeyEvent(KeyEnter)) != None || d.Err == "" {
		t.Fatal("typed confirmation bypassed")
	}
	d.Input.SetValue("alice")
	if d.Handle(KeyEvent(KeyEnter)) != Submit {
		t.Fatal("typed confirmation refused")
	}
	yn := &Dialog{Ask: true}
	if yn.Handle(KeyEvent(KeyEnter)) != None || yn.Handle(RuneEvent('y')) != Submit {
		t.Fatal("y/n dialog")
	}
}

func TestListClamp(t *testing.T) {
	var l List
	l.Handle(KeyEvent(KeyEnd), 10, 4)
	if l.Sel != 9 || l.Off != 6 {
		t.Fatalf("%+v", l)
	}
	l.Clamp(3, 4)
	if l.Sel != 2 || l.Off != 0 {
		t.Fatalf("%+v", l)
	}
	l.Clamp(0, 4)
	if l.Sel != 0 || l.Off != 0 {
		t.Fatalf("%+v", l)
	}
}

func TestConsoleDecoder(t *testing.T) {
	var d ConsoleDecoder
	if ev := d.Key(true, 1, vkTab, 9, shiftPressed); len(ev) != 1 || ev[0] != KeyEvent(KeyBacktab) {
		t.Fatalf("%v", ev)
	}
	if ev := d.Key(true, 3, 'A', 'a', 0); len(ev) != 3 || ev[2] != RuneEvent('a') {
		t.Fatalf("%v", ev)
	}
	if ev := d.Key(false, 1, 'A', 'a', 0); ev != nil {
		t.Fatal("key up produced input")
	}
	if ev := d.Key(true, 1, 'C', 3, 0x08); len(ev) != 1 || ev[0] != CtrlEvent('c') {
		t.Fatalf("%v", ev)
	}
	if ev := d.Key(true, 1, 0xe7, 0xd83d, 0); ev != nil {
		t.Fatal("high surrogate emitted")
	}
	if ev := d.Key(true, 1, 0xe7, 0xde00, 0); len(ev) != 1 || ev[0] != RuneEvent(0x1f600) {
		t.Fatalf("%v", ev)
	}
	if ev := d.Key(true, 1, 0xe7, 0x202e, 0); ev != nil {
		t.Fatal("bidi override accepted")
	}
	if ev := d.Key(true, 1000, 'A', 'a', 0); len(ev) != maxRepeat {
		t.Fatalf("repeat not bounded %d", len(ev))
	}
}

func TestWrap(t *testing.T) {
	got := Wrap("node: fingerprint does not match the card abcdefghijklmnop", 12)
	for _, l := range got {
		if StringWidth(l) > 12 {
			t.Fatalf("line too wide %q", l)
		}
	}
	if strings.Join(got, " ") != "node: fingerprint does not match the card abcdefghijkl mnop" {
		t.Fatalf("%q", got)
	}
	if got := Wrap("짧은 한글", 20); len(got) != 1 {
		t.Fatalf("%q", got)
	}
	f := &Form{Fields: []*Field{FlagsField("Recipient usage", []string{"encrypt", "decrypt", "wrap", "unwrap", "derive", "export"}, make([]bool, 6))}}
	s := NewScreen(80, 24)
	f.Draw(s, Style{})
	if !strings.Contains(s.Text(), "[ ] export") {
		t.Fatalf("flags not wrapped\n%s", s.Text())
	}
}
