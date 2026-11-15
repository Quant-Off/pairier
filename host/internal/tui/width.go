package tui

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

var wide = [][2]rune{
	{0x1100, 0x115f}, {0x231a, 0x231b}, {0x2329, 0x232a}, {0x23e9, 0x23ec}, {0x23f0, 0x23f0},
	{0x23f3, 0x23f3}, {0x25fd, 0x25fe}, {0x2614, 0x2615}, {0x2648, 0x2653}, {0x267f, 0x267f},
	{0x2693, 0x2693}, {0x26a1, 0x26a1}, {0x26aa, 0x26ab}, {0x26bd, 0x26be}, {0x26c4, 0x26c5},
	{0x26ce, 0x26ce}, {0x26d4, 0x26d4}, {0x26ea, 0x26ea}, {0x26f2, 0x26f3}, {0x26f5, 0x26f5},
	{0x26fa, 0x26fa}, {0x26fd, 0x26fd}, {0x2705, 0x2705}, {0x270a, 0x270b}, {0x2728, 0x2728},
	{0x274c, 0x274c}, {0x274e, 0x274e}, {0x2753, 0x2755}, {0x2757, 0x2757}, {0x2795, 0x2797},
	{0x27b0, 0x27b0}, {0x27bf, 0x27bf}, {0x2b1b, 0x2b1c}, {0x2b50, 0x2b50}, {0x2b55, 0x2b55},
	{0x2e80, 0x303e}, {0x3041, 0x33ff}, {0x3400, 0x4dbf}, {0x4e00, 0x9fff}, {0xa000, 0xa4cf},
	{0xa960, 0xa97f}, {0xac00, 0xd7a3}, {0xf900, 0xfaff}, {0xfe10, 0xfe19}, {0xfe30, 0xfe6f},
	{0xff00, 0xff60}, {0xffe0, 0xffe6}, {0x16fe0, 0x16fe4}, {0x17000, 0x18aff}, {0x1b000, 0x1b2ff},
	{0x1f004, 0x1f004}, {0x1f0cf, 0x1f0cf}, {0x1f18e, 0x1f18e}, {0x1f191, 0x1f19a}, {0x1f200, 0x1f251},
	{0x1f300, 0x1f64f}, {0x1f680, 0x1f6ff}, {0x1f900, 0x1f9ff}, {0x1fa70, 0x1faff}, {0x20000, 0x2fffd},
	{0x30000, 0x3fffd},
}

func isWide(r rune) bool {
	lo, hi := 0, len(wide)
	for lo < hi {
		m := (lo + hi) / 2
		switch {
		case r < wide[m][0]:
			hi = m
		case r > wide[m][1]:
			lo = m + 1
		default:
			return true
		}
	}
	return false
}

func RuneWidth(r rune) int {
	switch {
	case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
		return 0
	case r < 0x300:
		return 1
	case unicode.In(r, unicode.Mn, unicode.Me):
		return 0
	case r >= 0x1160 && r <= 0x11ff, r >= 0xd7b0 && r <= 0xd7ff:
		return 0
	case isWide(r):
		return 2
	}
	return 1
}

func StringWidth(s string) int {
	w := 0
	for _, r := range Clean(s) {
		w += RuneWidth(r)
	}
	return w
}

func cleanRune(r rune) rune {
	switch {
	case r == '\t':
		return ' '
	case r == utf8.RuneError, r < 0x20, r == 0x7f, r >= 0x80 && r < 0xa0:
		return '?'
	case r < 0x7f:
		return r
	case unicode.In(r, unicode.Cf, unicode.Co, unicode.Cs, unicode.Zl, unicode.Zp):
		return '?'
	case unicode.Is(unicode.Zs, r):
		return ' '
	case !unicode.IsPrint(r) && !unicode.In(r, unicode.Mn, unicode.Me):
		return '?'
	}
	return r
}

func Clean(s string) string {
	plain := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x7f {
			plain = false
			break
		}
	}
	if plain {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(cleanRune(r))
	}
	return b.String()
}

func Fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	s = Clean(s)
	var b strings.Builder
	used := 0
	cut := false
	for _, r := range s {
		rw := RuneWidth(r)
		if used+rw > w {
			cut = true
			break
		}
		b.WriteRune(r)
		used += rw
	}
	if !cut {
		return b.String() + strings.Repeat(" ", w-used)
	}
	out := []rune(b.String())
	for len(out) > 0 && used > w-1 {
		used -= RuneWidth(out[len(out)-1])
		out = out[:len(out)-1]
	}
	return string(out) + "~" + strings.Repeat(" ", w-1-used)
}

func Wrap(s string, w int) []string {
	s = Clean(s)
	if w <= 0 {
		return nil
	}
	if StringWidth(s) <= w {
		return []string{s}
	}
	var out []string
	var line []rune
	used := 0
	flush := func() {
		out = append(out, strings.TrimRight(string(line), " "))
		line, used = line[:0], 0
	}
	for _, word := range strings.SplitAfter(s, " ") {
		ww := StringWidth(word)
		if used > 0 && used+StringWidth(strings.TrimRight(word, " ")) > w {
			flush()
		}
		if ww > w {
			for _, r := range word {
				rw := RuneWidth(r)
				if used+rw > w {
					flush()
				}
				line = append(line, r)
				used += rw
			}
			continue
		}
		line = append(line, []rune(word)...)
		used += ww
	}
	if used > 0 {
		flush()
	}
	return out
}
