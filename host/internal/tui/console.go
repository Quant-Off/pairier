package tui

import "unicode/utf16"

const (
	vkBack   = 0x08
	vkTab    = 0x09
	vkReturn = 0x0d
	vkEscape = 0x1b
	vkPrior  = 0x21
	vkNext   = 0x22
	vkEnd    = 0x23
	vkHome   = 0x24
	vkLeft   = 0x25
	vkUp     = 0x26
	vkRight  = 0x27
	vkDown   = 0x28
	vkDelete = 0x2e

	shiftPressed = 0x10
	maxRepeat    = 64
)

type ConsoleDecoder struct {
	high rune
}

func (d *ConsoleDecoder) Key(down bool, repeat, vk, ch uint16, state uint32) []Event {
	if !down {
		return nil
	}
	ev, ok := d.key(vk, ch, state)
	if !ok {
		return nil
	}
	n := min(max(int(repeat), 1), maxRepeat)
	out := make([]Event, n)
	for i := range out {
		out[i] = ev
	}
	return out
}

func (d *ConsoleDecoder) key(vk, ch uint16, state uint32) (Event, bool) {
	switch vk {
	case vkBack:
		return KeyEvent(KeyBackspace), true
	case vkTab:
		if state&shiftPressed != 0 {
			return KeyEvent(KeyBacktab), true
		}
		return KeyEvent(KeyTab), true
	case vkReturn:
		return KeyEvent(KeyEnter), true
	case vkEscape:
		return KeyEvent(KeyEsc), true
	case vkPrior:
		return KeyEvent(KeyPgUp), true
	case vkNext:
		return KeyEvent(KeyPgDn), true
	case vkEnd:
		return KeyEvent(KeyEnd), true
	case vkHome:
		return KeyEvent(KeyHome), true
	case vkLeft:
		return KeyEvent(KeyLeft), true
	case vkUp:
		return KeyEvent(KeyUp), true
	case vkRight:
		return KeyEvent(KeyRight), true
	case vkDown:
		return KeyEvent(KeyDown), true
	case vkDelete:
		return KeyEvent(KeyDelete), true
	}
	if ch == 0 {
		return Event{}, false
	}
	r := rune(ch)
	if utf16.IsSurrogate(r) {
		if r < 0xdc00 {
			d.high = r
			return Event{}, false
		}
		if d.high == 0 {
			return Event{}, false
		}
		r = utf16.DecodeRune(d.high, r)
	}
	d.high = 0
	switch {
	case r == 0x1b:
		return KeyEvent(KeyEsc), true
	case r == 0x7f:
		return KeyEvent(KeyBackspace), true
	case r < 0x20:
		return CtrlEvent('a' + r - 1), true
	case cleanRune(r) != r:
		return Event{}, false
	}
	return RuneEvent(r), true
}
