package console

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Quant-Off/pairier/host/internal/api"
	"github.com/Quant-Off/pairier/host/internal/exchange"
	"github.com/Quant-Off/pairier/host/internal/node"
	"github.com/Quant-Off/pairier/host/internal/tui"
)

type fakeTerm struct {
	events chan tui.Event
	mu     sync.Mutex
	out    bytes.Buffer
	w, h   int
}

func (f *fakeTerm) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.out.Write(p)
}

func (f *fakeTerm) Size() (int, int, error) { return f.w, f.h, nil }

func (f *fakeTerm) Events() <-chan tui.Event { return f.events }

func (f *fakeTerm) output() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.out.Bytes()...)
}

type harness struct {
	t       *testing.T
	term    *fakeTerm
	mu      sync.Mutex
	screen  string
	handled int
	sent    int
	seen    []string
	frames  chan struct{}
	done    chan error
	cancel  context.CancelFunc
}

func coreBin(t *testing.T) string {
	t.Helper()
	bin := os.Getenv("KMS_CORE_BIN")
	if bin == "" {
		t.Skip("KMS_CORE_BIN not set")
	}
	return bin
}

func launch(t *testing.T, o Options, watch ...string) *harness {
	t.Helper()
	h := &harness{t: t, term: &fakeTerm{events: make(chan tui.Event), w: 110, h: 32}, frames: make(chan struct{}, 1), done: make(chan error, 1)}
	if o.Version == "" {
		o.Version = "test"
	}
	o.afterDraw = func(s *tui.Screen, handled int) {
		text := s.Text()
		h.mu.Lock()
		h.screen = text
		h.handled = handled
		for _, w := range watch {
			if strings.Contains(text, w) {
				h.seen = append(h.seen, w)
			}
		}
		h.mu.Unlock()
		select {
		case h.frames <- struct{}{}:
		default:
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() { h.done <- Run(ctx, h.term, o) }()
	t.Cleanup(h.stop)
	return h
}

func (h *harness) stop() {
	h.cancel()
	select {
	case err := <-h.done:
		if err != nil {
			h.t.Errorf("run: %v", err)
		}
		h.done <- nil
	case <-time.After(10 * time.Second):
		h.t.Error("ui did not stop")
	}
}

func (h *harness) caughtUp() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.handled >= h.sent
}

func (h *harness) send(evs ...tui.Event) {
	for _, ev := range evs {
		select {
		case h.term.events <- ev:
		case <-time.After(10 * time.Second):
			h.t.Fatalf("ui stopped reading input\n%s", h.text())
		}
		h.mu.Lock()
		h.sent++
		h.mu.Unlock()
		deadline := time.Now().Add(10 * time.Second)
		for !h.caughtUp() {
			if time.Now().After(deadline) {
				h.t.Fatalf("no frame after input\n%s", h.text())
			}
			select {
			case <-h.frames:
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
}

func (h *harness) typ(s string) {
	for _, r := range s {
		h.send(tui.RuneEvent(r))
	}
}

func (h *harness) enter()   { h.send(tui.KeyEvent(tui.KeyEnter)) }
func (h *harness) clearIn() { h.send(tui.CtrlEvent('u')) }
func (h *harness) replace(s string) {
	h.clearIn()
	h.typ(s)
}

func (h *harness) text() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.screen
}

func (h *harness) wait(want string) string {
	h.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		s := h.text()
		if strings.Contains(s, want) {
			return s
		}
		if time.Now().After(deadline) {
			h.t.Fatalf("timed out waiting for %q\n%s", want, s)
		}
		select {
		case <-h.frames:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (h *harness) idle() {
	h.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for strings.Contains(h.text(), "(Esc cancels)") {
		if time.Now().After(deadline) {
			h.t.Fatalf("job did not finish\n%s", h.text())
		}
		select {
		case <-h.frames:
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (h *harness) closeDialog(title string) {
	h.t.Helper()
	h.wait(title)
	h.enter()
	h.idle()
}

func cardFingerprint(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	card, err := exchange.DecodeCard(raw)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := card.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func nodeOpts(bin string) node.Options {
	return node.Options{CoreBinary: bin, AllowUnlockedMemory: true, Timeout: 10 * time.Second}
}

func initNode(t *testing.T, h *harness, id, card string) {
	t.Helper()
	h.wait("Initialize node")
	h.enter()
	h.typ(id)
	h.enter()
	h.enter()
	h.closeDialog("Node initialized")
	h.wait("member " + id)
	h.send(tui.RuneEvent('c'))
	h.wait("Export card")
	h.replace(card)
	h.enter()
	h.closeDialog("Card exported")
}

func addMember(t *testing.T, h *harness, card, fp string) {
	t.Helper()
	h.send(tui.RuneEvent('3'), tui.RuneEvent('a'))
	h.wait("Add member")
	h.typ(card)
	h.enter()
	h.send(tui.PasteEvent(strings.ToUpper(fp) + "\n"))
	h.enter()
	h.closeDialog("Member added")
}

func serve(t *testing.T, n *node.Node) string {
	t.Helper()
	srv := api.New(n, nil)
	cfg, err := srv.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: srv.Handler(), TLSConfig: cfg, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = hs.ServeTLS(ln, "", "") }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = hs.Shutdown(ctx)
	})
	return "https://" + ln.Addr().String()
}

func TestConsoleCoversTheKMS(t *testing.T) {
	bin := coreBin(t)
	base := t.TempDir()
	aliceDir, bobDir := filepath.Join(base, "alice"), filepath.Join(base, "bob")
	aliceCard, bobCard := filepath.Join(base, "alice.card"), filepath.Join(base, "bob.card")
	secret := "top secret plaintext"

	alice := launch(t, Options{Node: nodeOpts(bin), Dir: aliceDir}, secret)
	initNode(t, alice, "alice", aliceCard)
	bob := launch(t, Options{Node: nodeOpts(bin), Dir: bobDir}, secret)
	initNode(t, bob, "bob", bobCard)
	aliceFP, bobFP := cardFingerprint(t, aliceCard), cardFingerprint(t, bobCard)

	alice.send(tui.RuneEvent('3'), tui.RuneEvent('a'))
	alice.wait("Add member")
	alice.typ(bobCard)
	alice.enter()
	alice.typ(aliceFP)
	alice.enter()
	alice.closeDialog("add member failed")
	if !strings.Contains(alice.text(), "(empty)") {
		t.Fatalf("member added with the wrong fingerprint\n%s", alice.text())
	}
	addMember(t, alice, bobCard, bobFP)
	addMember(t, bob, aliceCard, aliceFP)
	alice.wait("dhkem-p256")

	alice.send(tui.RuneEvent('2'), tui.RuneEvent('n'))
	alice.wait("Generate key")
	alice.typ("project/db 데이터")
	alice.enter()
	alice.enter()
	alice.wait("project/db 데이터")
	alice.idle()

	envFile := filepath.Join(base, "db.kxp")
	alice.send(tui.RuneEvent('s'))
	alice.wait("Send key to file")
	alice.enter()
	alice.enter()
	alice.replace(envFile)
	alice.enter()
	alice.wait("fingerprint  " + splitFingerprint(bobFP)[0])
	alice.send(tui.RuneEvent('y'))
	alice.closeDialog("Envelope written")

	plain := filepath.Join(base, "plain.txt")
	if err := os.WriteFile(plain, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	alice.send(tui.RuneEvent('e'))
	alice.wait("Encrypt file")
	alice.typ(plain)
	alice.enter()
	alice.enter()
	alice.typ("ctx")
	alice.enter()
	alice.closeDialog("wrote")
	if _, err := os.Stat(plain + ".enc"); err != nil {
		t.Fatal(err)
	}

	bob.send(tui.RuneEvent('2'), tui.RuneEvent('r'))
	bob.wait("Receive key")
	bob.typ(envFile)
	bob.enter()
	bob.closeDialog("Key received")
	bob.wait("project/db 데이터")
	bob.idle()
	out := filepath.Join(base, "plain.out")
	bob.send(tui.RuneEvent('d'))
	bob.wait("Decrypt file")
	bob.typ(plain + ".enc")
	bob.enter()
	bob.typ(out)
	bob.enter()
	bob.typ("wrong")
	bob.enter()
	bob.closeDialog("decrypt failed")
	bob.send(tui.RuneEvent('d'))
	bob.wait("Decrypt file")
	bob.typ(plain + ".enc")
	bob.enter()
	bob.typ(out)
	bob.enter()
	bob.typ("ctx")
	bob.enter()
	bob.closeDialog("wrote")
	if got, err := os.ReadFile(out); err != nil || string(got) != secret {
		t.Fatalf("decrypted %q %v", got, err)
	}
	bob.send(tui.RuneEvent('d'))
	bob.wait("Decrypt file")
	bob.typ(plain + ".enc")
	bob.enter()
	bob.typ(out)
	bob.enter()
	bob.enter()
	bob.wait("already exists")
	bob.send(tui.KeyEvent(tui.KeyEsc))

	bobNode, err := node.Open(context.Background(), node.Options{Dir: bobDir, CoreBinary: bin, AllowUnlockedMemory: true, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer bobNode.Close()
	bobURL := serve(t, bobNode)

	alice.send(tui.RuneEvent('3'), tui.RuneEvent('h'))
	alice.wait("Health of bob")
	alice.replace(bobURL)
	alice.enter()
	alice.wait("health ok bob")

	for _, label := range []string{"push/one", "push/two"} {
		alice.send(tui.RuneEvent('2'), tui.RuneEvent('n'))
		alice.wait("Generate key")
		alice.typ(label)
		alice.enter()
		alice.enter()
		alice.wait(label)
		alice.idle()
		alice.send(tui.RuneEvent('p'))
		alice.wait("Push key")
		alice.enter()
		alice.enter()
		alice.wait(bobURL)
		alice.enter()
		alice.wait("kmsd         " + bobURL)
		alice.send(tui.RuneEvent('y'))
		alice.closeDialog("Key pushed")
	}

	bob.send(tui.RuneEvent('4'), tui.CtrlEvent('r'))
	bob.wait("Inbox (2)")
	bob.idle()
	bob.send(tui.KeyEvent(tui.KeyEnter))
	bob.wait("Accept envelope")
	bob.send(tui.RuneEvent('y'))
	bob.closeDialog("Key imported")
	bob.wait("Inbox (1)")
	bob.send(tui.RuneEvent('x'))
	bob.wait("Reject envelope")
	bob.send(tui.RuneEvent('y'))
	bob.idle()
	bob.wait("rejected")
	bob.send(tui.RuneEvent('2'))
	bob.wait("push/")
	if one, two := strings.Contains(bob.text(), "push/one"), strings.Contains(bob.text(), "push/two"); one == two {
		t.Fatalf("want exactly one pushed key imported\n%s", bob.text())
	}

	witness := filepath.Join(base, "alice.witness")
	bob.send(tui.RuneEvent('3'), tui.RuneEvent('w'))
	bob.wait("Export witnessed heads of alice")
	bob.replace(witness)
	bob.enter()
	bob.closeDialog("Witnessed heads")

	alice.send(tui.RuneEvent('5'))
	alice.wait("key.send")
	alice.idle()
	alice.send(tui.RuneEvent('v'))
	alice.wait("Verify audit log")
	alice.enter()
	alice.typ(witness)
	alice.enter()
	alice.send(tui.KeyEvent(tui.KeyRight))
	alice.enter()
	alice.replace(bobURL)
	alice.enter()
	alice.closeDialog("Audit log verified")
	alice.wait("heads witnessed by bob")

	alice.send(tui.RuneEvent('1'), tui.RuneEvent('R'))
	alice.wait("Renew card")
	alice.typ("alic")
	alice.enter()
	alice.wait("the text does not match")
	alice.typ("e")
	alice.enter()
	alice.wait("New fingerprint")
	renewed := filepath.Join(base, "alice.renewed")
	alice.replace(renewed)
	alice.enter()
	alice.closeDialog("Card exported")
	if fp := cardFingerprint(t, renewed); fp == aliceFP || !strings.Contains(alice.text(), splitFingerprint(fp)[0]) {
		t.Fatalf("renewed fingerprint %s not shown\n%s", fp, alice.text())
	}

	alice.send(tui.RuneEvent('6'))
	alice.wait("renewed")

	for _, h := range []*harness{alice, bob} {
		h.mu.Lock()
		leaked := len(h.seen) > 0
		h.mu.Unlock()
		if leaked {
			t.Fatal("plaintext was drawn on the screen")
		}
		raw := h.term.output()
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("plaintext reached the terminal")
		}
		if bytes.Contains(raw, []byte("\x1b]")) || bytes.Contains(raw, []byte{0x07}) || bytes.Contains(raw, []byte{0xc2, 0x9b}) {
			t.Fatal("terminal control sequence emitted")
		}
	}
}

func TestOfflineModeHidesNetworkActions(t *testing.T) {
	bin := coreBin(t)
	base := t.TempDir()
	h := launch(t, Options{Node: nodeOpts(bin), Dir: filepath.Join(base, "carol"), Offline: true})
	initNode(t, h, "carol", filepath.Join(base, "carol.card"))
	if !strings.Contains(h.text(), "[offline]") {
		t.Fatalf("offline not shown\n%s", h.text())
	}
	h.send(tui.RuneEvent('2'), tui.RuneEvent('n'))
	h.wait("Generate key")
	h.typ("k")
	h.enter()
	h.enter()
	h.idle()
	h.wait(" k ")
	s := h.text()
	if strings.Contains(s, "p push") {
		t.Fatalf("push offered offline\n%s", s)
	}
	h.send(tui.RuneEvent('p'))
	time.Sleep(100 * time.Millisecond)
	if strings.Contains(h.text(), "Push key") {
		t.Fatal("push form opened offline")
	}
	h.send(tui.RuneEvent('5'), tui.RuneEvent('v'))
	h.wait("Verify audit log")
	if strings.Contains(h.text(), "Peer kmsd URL") {
		t.Fatal("peer audit offered offline")
	}
	h.enter()
	h.enter()
	h.closeDialog("Audit log verified")
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestIdleClosesTheNode(t *testing.T) {
	bin := coreBin(t)
	base := t.TempDir()
	clk := &clock{t: time.Now()}
	h := launch(t, Options{Node: nodeOpts(bin), Dir: filepath.Join(base, "dave"), Idle: time.Minute, now: clk.now})
	h.wait("Initialize node")
	h.enter()
	h.typ("dave")
	h.enter()
	h.enter()
	h.closeDialog("Node initialized")
	time.Sleep(1500 * time.Millisecond)
	if strings.Contains(h.text(), "without input") {
		t.Fatal("node closed before the idle time passed")
	}
	clk.add(2 * time.Minute)
	h.wait("without input")
	if strings.Contains(h.text(), "member dave") {
		t.Fatalf("node details still shown after idle close\n%s", h.text())
	}
	h.enter()
	h.wait("member dave")
}

func TestStartScreenAndErrors(t *testing.T) {
	base := t.TempDir()
	h := launch(t, Options{Node: node.Options{CoreBinary: filepath.Join(base, "missing-core")}})
	h.wait("Open node")
	h.replace(filepath.Join(base, "new"))
	h.enter()
	h.wait("Initialize node")
	h.enter()
	h.typ("Bad ID")
	h.enter()
	h.enter()
	h.wait("invalid member id")
	h.send(tui.KeyEvent(tui.KeyEsc))
	h.wait("o open a node directory")
	h.send(tui.RuneEvent('n'))
	h.wait("Initialize node")
	h.enter()
	h.typ("erin")
	h.enter()
	h.enter()
	h.closeDialog("initialize node failed")
	h.wait("No node is open")
	if _, err := os.Stat(filepath.Join(base, "new")); !os.IsNotExist(err) {
		t.Fatalf("failed init left a directory behind: %v", err)
	}
	h.send(tui.ResizeEvent(40, 10))
	h.wait("terminal too small")
	h.send(tui.ResizeEvent(100, 30))
	h.wait("No node is open")
}

func TestHelpersRejectBadInput(t *testing.T) {
	if _, err := checkURL("http://host:1"); err == nil {
		t.Fatal("http url accepted")
	}
	if _, err := checkURL("https://user@host:1"); err == nil {
		t.Fatal("url with credentials accepted")
	}
	if u, err := checkURL(" https://host:7443/ "); err != nil || u != "https://host:7443" {
		t.Fatalf("%q %v", u, err)
	}
	if _, err := parseAnchors("1:zz"); err == nil {
		t.Fatal("malformed anchor accepted")
	}
	if got := expandPath(` "C:\Users\a b\x.card" `); got != `C:\Users\a b\x.card` {
		t.Fatalf("%q", got)
	}
	dir := t.TempDir()
	if _, err := inPath(dir); err == nil {
		t.Fatal("directory accepted as input")
	}
	if _, err := outPath(dir); err == nil {
		t.Fatal("existing path accepted as output")
	}
	var l logBuffer
	l.max = 3
	_, _ = l.Write([]byte("a\x1b]0;x\x07b\npartial"))
	if got := l.snapshot(); len(got) != 1 || !strings.HasSuffix(got[0], "core: a?]0;x?b") {
		t.Fatalf("%q", got)
	}
}

func TestSmallTerminals(t *testing.T) {
	bin := coreBin(t)
	base := t.TempDir()
	h := launch(t, Options{Node: nodeOpts(bin), Dir: filepath.Join(base, "frank")})
	initNode(t, h, "frank", filepath.Join(base, "frank.card"))
	for _, size := range [][2]int{{80, 24}, {64, 18}} {
		h.send(tui.ResizeEvent(size[0], size[1]))
		for tab := '1'; tab <= '6'; tab++ {
			h.send(tui.RuneEvent(tab))
			lines := strings.Split(h.text(), "\n")
			if len(lines) != size[1] || !strings.Contains(lines[1], "6 Log") || !strings.HasSuffix(lines[size[1]-2], "? help  q quit") {
				t.Fatalf("%dx%d tab %c\n%s", size[0], size[1], tab, h.text())
			}
		}
		h.send(tui.RuneEvent('?'))
		h.wait("Help")
		for i := 0; i < 40; i++ {
			h.send(tui.KeyEvent(tui.KeyDown))
		}
		h.wait("clipboard")
		h.enter()
		h.send(tui.RuneEvent('5'), tui.RuneEvent('v'))
		s := h.wait("Verify audit log")
		for _, label := range []string{"Anchors", "Anchor file", "Peer", "Peer kmsd URL", "Esc cancel"} {
			if !strings.Contains(s, label) {
				t.Fatalf("%dx%d verify form lost %q\n%s", size[0], size[1], label, s)
			}
		}
		h.send(tui.KeyEvent(tui.KeyEsc), tui.RuneEvent('2'), tui.RuneEvent('n'))
		s = h.wait("Generate key")
		if !strings.Contains(s, "[x] export") {
			t.Fatalf("%dx%d usage flags cut\n%s", size[0], size[1], s)
		}
		h.send(tui.KeyEvent(tui.KeyEsc))
	}
}
