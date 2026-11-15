package tui

type Key uint8

const (
	KeyNone Key = iota
	KeyRune
	KeyCtrl
	KeyEnter
	KeyTab
	KeyBacktab
	KeyBackspace
	KeyDelete
	KeyEsc
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyHome
	KeyEnd
	KeyPgUp
	KeyPgDn
)

type Kind uint8

const (
	EventKey Kind = iota
	EventPaste
	EventResize
)

type Event struct {
	Kind   Kind
	Key    Key
	Rune   rune
	Text   string
	Width  int
	Height int
}

func KeyEvent(k Key) Event { return Event{Kind: EventKey, Key: k} }

func RuneEvent(r rune) Event { return Event{Kind: EventKey, Key: KeyRune, Rune: r} }

func CtrlEvent(r rune) Event { return Event{Kind: EventKey, Key: KeyCtrl, Rune: r} }

func PasteEvent(s string) Event { return Event{Kind: EventPaste, Text: s} }

func ResizeEvent(w, h int) Event { return Event{Kind: EventResize, Width: w, Height: h} }

func (e Event) Is(k Key) bool { return e.Kind == EventKey && e.Key == k }

func (e Event) IsRune(r rune) bool { return e.Kind == EventKey && e.Key == KeyRune && e.Rune == r }

func (e Event) IsCtrl(r rune) bool { return e.Kind == EventKey && e.Key == KeyCtrl && e.Rune == r }
