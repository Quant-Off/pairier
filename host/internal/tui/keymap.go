package tui

var dubeolsik = map[rune]rune{
	'ㅂ': 'q', 'ㅈ': 'w', 'ㄷ': 'e', 'ㄱ': 'r', 'ㅅ': 't', 'ㅛ': 'y', 'ㅕ': 'u', 'ㅑ': 'i', 'ㅐ': 'o', 'ㅔ': 'p',
	'ㅁ': 'a', 'ㄴ': 's', 'ㅇ': 'd', 'ㄹ': 'f', 'ㅎ': 'g', 'ㅗ': 'h', 'ㅓ': 'j', 'ㅏ': 'k', 'ㅣ': 'l',
	'ㅋ': 'z', 'ㅌ': 'x', 'ㅊ': 'c', 'ㅍ': 'v', 'ㅠ': 'b', 'ㅜ': 'n', 'ㅡ': 'm',
	'ㅃ': 'Q', 'ㅉ': 'W', 'ㄸ': 'E', 'ㄲ': 'R', 'ㅆ': 'T', 'ㅒ': 'O', 'ㅖ': 'P',
}

func Latin(r rune) rune {
	if l, ok := dubeolsik[r]; ok {
		return l
	}
	return r
}

func Shortcut(ev Event) Event {
	if ev.Kind == EventKey && ev.Key == KeyRune {
		ev.Rune = Latin(ev.Rune)
	}
	return ev
}

type Texts struct {
	FormHint     string
	Close        string
	Confirm      string
	ConfirmTyped string
	More         string
	Yes          string
	No           string
	None         string
	Mismatch     string
	Type         string
}

var English = Texts{
	FormHint:     " Tab move  Space toggle  Enter next  Esc cancel ",
	Close:        " Enter/Esc close ",
	Confirm:      " y confirm  n/Esc cancel ",
	ConfirmTyped: " Enter confirm  Esc cancel ",
	More:         " Up/Down more ",
	Yes:          "[x] yes",
	No:           "[ ] no",
	None:         "(none)",
	Mismatch:     "the text does not match",
	Type:         "type %s: ",
}

func textsOr(t *Texts) *Texts {
	if t == nil {
		return &English
	}
	return t
}
