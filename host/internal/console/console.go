package console

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Quant-Off/pairier/host/internal/node"
	"github.com/Quant-Off/pairier/host/internal/tui"
)

const (
	minWidth     = 64
	minHeight    = 18
	jobTimeout   = 2 * time.Minute
	refreshEvery = 15 * time.Second
	maxInput     = 1 << 20
	spinner      = `|/-\`
)

type Terminal interface {
	io.Writer
	Size() (int, int, error)
	Events() <-chan tui.Event
}

type Options struct {
	Node    node.Options
	Dir     string
	Offline bool
	Idle    time.Duration
	Version string
	Color   bool
	Paste   bool
	Lang    string

	afterDraw func(s *tui.Screen, handled int)
	now       func() time.Time
}

type phase uint8

const (
	phaseStart phase = iota
	phaseOpening
	phaseMain
	phaseLocked
)

const (
	tabNode = iota
	tabKeys
	tabMembers
	tabInbox
	tabAudit
	tabLog
	tabCount
)

var tabNames = [tabCount]string{"Node", "Keys", "Members", "Inbox", "Audit", "Log"}

type modal interface {
	handle(a *app, ev tui.Event)
	draw(s *tui.Screen)
}

type work func(ctx context.Context, n *node.Node) (func(*app), error)

type job struct {
	title  string
	quiet  bool
	cancel context.CancelFunc
}

type pending struct {
	title string
	body  func(ctx context.Context, res *result)
}

type result struct {
	title   string
	quiet   bool
	apply   func(*app)
	cleanup func()
	err     error
	panic   any
}

type app struct {
	ctx       context.Context
	term      Terminal
	opts      Options
	screen    *tui.Screen
	rend      *tui.Renderer
	logs      *logBuffer
	node      *node.Node
	dir       string
	phase     phase
	tab       int
	lists     [tabCount]tui.List
	selID     [tabCount]string
	filter    [tabCount]string
	info      nodeInfo
	data      snapshot
	verify    *verifyResult
	urls      map[string]string
	modal     modal
	job       *job
	next      *pending
	again     bool
	results   chan result
	status    string
	statusErr bool
	lastInput time.Time
	refreshed time.Time
	frame     int
	handled   int
	quit      bool
	catalog   map[string]string
	texts     *tui.Texts
}

func Run(ctx context.Context, t Terminal, o Options) (err error) {
	if o.now == nil {
		o.now = time.Now
	}
	a := &app{
		ctx:     ctx,
		term:    t,
		opts:    o,
		rend:    tui.NewRenderer(t, o.Color),
		logs:    newLogBuffer(500),
		urls:    map[string]string{},
		results: make(chan result, 1),
	}
	w, h, serr := t.Size()
	if serr != nil || w <= 0 || h <= 0 {
		w, h = 80, 24
	}
	a.screen = tui.NewScreen(w, h)
	a.rend.Paste = o.Paste
	if o.Lang == LangKorean {
		a.catalog, a.texts = korean, &koreanTexts
	}
	if err := a.rend.Begin(); err != nil {
		return err
	}
	defer func() {
		a.shutdown()
		if eerr := a.rend.End(); err == nil {
			err = eerr
		}
	}()
	a.lastInput = o.now()
	a.begin()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for !a.quit {
		a.draw()
		select {
		case <-ctx.Done():
			return nil
		case ev := <-t.Events():
			a.lastInput = a.opts.now()
			a.handle(ev)
			a.handled++
		case res := <-a.results:
			a.finish(res)
		case <-tick.C:
			a.tick()
		}
	}
	return nil
}

func (a *app) shutdown() {
	if a.job != nil {
		a.job.cancel()
		select {
		case res := <-a.results:
			if res.cleanup != nil {
				res.cleanup()
			}
		case <-time.After(5 * time.Second):
		}
		a.job = nil
	}
	a.closeNode()
}

func (a *app) closeNode() {
	if a.node != nil {
		if err := a.node.Close(); err != nil {
			a.logs.add("close node: " + err.Error())
		}
		a.node = nil
	}
}

func (a *app) run(title string, w work) bool {
	n := a.node
	return a.spawn(title, false, func(ctx context.Context, res *result) {
		res.apply, res.err = w(ctx, n)
	})
}

func (a *app) spawn(title string, quiet bool, body func(ctx context.Context, res *result)) bool {
	if a.job != nil {
		switch {
		case quiet:
			a.again = true
			return true
		case a.job.quiet && a.next == nil:
			a.next = &pending{title: title, body: body}
			return true
		}
		a.flash(a.tf("busy with %s", a.job.title), true)
		return false
	}
	ctx, cancel := context.WithTimeout(a.ctx, jobTimeout)
	a.job = &job{title: title, quiet: quiet, cancel: cancel}
	go func() {
		defer cancel()
		res := result{title: title, quiet: quiet}
		func() {
			defer func() {
				if r := recover(); r != nil {
					res.panic = r
				}
			}()
			body(ctx, &res)
		}()
		a.results <- res
	}()
	return true
}

func (a *app) finish(res result) {
	a.job = nil
	if res.panic != nil {
		panic(res.panic)
	}
	defer a.afterJob()
	if res.err != nil {
		if errors.Is(res.err, context.Canceled) {
			a.flash(a.tf("%s cancelled", res.title), true)
			a.logs.add(a.tf("%s cancelled", res.title))
			if a.phase == phaseOpening {
				a.phase = phaseStart
			}
			return
		}
		a.logs.add(res.title + ": " + res.err.Error())
		if a.phase == phaseOpening {
			a.phase = phaseStart
		}
		a.flash(a.tf("%s failed: %s", res.title, res.err.Error()), true)
		if !res.quiet {
			a.notify(a.tf("%s failed", res.title), []string{res.err.Error()}, true)
		}
		return
	}
	if res.apply != nil {
		res.apply(a)
	}
}

func (a *app) afterJob() {
	if a.job != nil {
		return
	}
	if p := a.next; p != nil {
		a.next = nil
		a.spawn(p.title, false, p.body)
		return
	}
	if a.again {
		a.again = false
		a.refresh()
	}
}

func (a *app) flash(msg string, isErr bool) {
	a.status, a.statusErr = msg, isErr
}

func (a *app) done(msg string) {
	a.flash(msg, false)
	a.logs.add(msg)
}

func (a *app) tick() {
	a.frame++
	now := a.opts.now()
	if a.phase != phaseMain || a.job != nil {
		return
	}
	if a.opts.Idle > 0 && now.Sub(a.lastInput) >= a.opts.Idle {
		a.lock()
		return
	}
	if a.modal == nil && now.Sub(a.refreshed) >= refreshEvery {
		a.refresh()
	}
}

func (a *app) lock() {
	a.closeNode()
	a.data = snapshot{}
	a.info = nodeInfo{}
	a.verify = nil
	a.modal = nil
	a.phase = phaseLocked
	a.rend.Invalidate()
	a.logs.add(a.tf("node closed after %s without input", a.opts.Idle))
	a.flash(a.t("node closed after inactivity"), false)
}

func (a *app) handle(ev tui.Event) {
	if ev.Kind == tui.EventResize {
		if ev.Width > 0 && ev.Height > 0 && (ev.Width != a.screen.W || ev.Height != a.screen.H) {
			a.screen.Resize(ev.Width, ev.Height)
			a.rend.Invalidate()
		}
		return
	}
	switch {
	case ev.IsCtrl('c'):
		a.quit = true
		return
	case ev.IsCtrl('l'):
		a.rend.Invalidate()
		return
	}
	if a.modal != nil {
		a.modal.handle(a, ev)
		return
	}
	ev = tui.Shortcut(ev)
	if ev.Is(tui.KeyEsc) && a.job != nil {
		a.job.cancel()
		return
	}
	switch a.phase {
	case phaseStart:
		a.handleStart(ev)
	case phaseOpening:
		if ev.IsRune('q') {
			a.quit = true
		}
	case phaseLocked:
		switch {
		case ev.Is(tui.KeyEnter):
			a.openNode(a.dir)
		case ev.IsRune('q'):
			a.quit = true
		}
	case phaseMain:
		a.handleMain(ev)
	}
}

func (a *app) handleStart(ev tui.Event) {
	switch {
	case ev.IsRune('o'):
		a.dirForm(a.startDir())
	case ev.IsRune('n'):
		a.initForm(a.startDir())
	case ev.IsRune('q'):
		a.quit = true
	}
}

func (a *app) startDir() string {
	if a.dir != "" {
		return a.dir
	}
	if a.opts.Dir != "" {
		return a.opts.Dir
	}
	return defaultDir()
}

func defaultDir() string {
	if runtime.GOOS == "windows" {
		if base := os.Getenv("LOCALAPPDATA"); base != "" {
			return filepath.Join(base, "pairier")
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".pairier")
	}
	return ""
}

func (a *app) begin() {
	dir := a.opts.Dir
	if dir == "" {
		a.dirForm(defaultDir())
		return
	}
	dir = expandPath(dir)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		a.initForm(dir)
		return
	}
	a.openNode(dir)
}

func (a *app) nodeOptions(dir string) node.Options {
	o := a.opts.Node
	o.Dir = dir
	o.Stderr = a.logs
	return o
}

var (
	plain    = tui.Style{}
	bold     = tui.Style{Bold: true}
	dim      = tui.Style{Dim: true}
	reverse  = tui.Style{Reverse: true}
	selected = tui.Style{Reverse: true, Bold: true}
	warn     = tui.Style{Fg: tui.Yellow, Bold: true}
	bad      = tui.Style{Fg: tui.Red, Bold: true}
	good     = tui.Style{Fg: tui.Green}
	heading  = tui.Style{Fg: tui.Cyan, Bold: true}
)

func (a *app) draw() {
	s := a.screen
	s.Clear()
	if s.W < minWidth || s.H < minHeight {
		s.Put(0, 0, a.tf("terminal too small (%dx%d), need %dx%d", s.W, s.H, minWidth, minHeight), bad)
		s.Put(0, 1, a.t("resize the window or press Ctrl+C to quit"), plain)
		_ = a.rend.Draw(s)
		a.afterDraw()
		return
	}
	a.drawHeader()
	body := tui.Style{}
	switch a.phase {
	case phaseStart:
		a.drawStart()
	case phaseOpening:
		s.Put(2, 3, a.tf("opening %s ...", a.dir), body)
	case phaseLocked:
		s.Put(2, 3, a.tf("The node was closed after %s without input.", a.opts.Idle), bold)
		s.Put(2, 4, a.t("The core process has exited and its key material is gone from memory."), plain)
		s.Put(2, 6, a.t("Enter reopen   q quit"), plain)
	case phaseMain:
		a.drawTabs()
		a.drawTab()
	}
	a.drawFooter()
	if a.modal != nil {
		a.modal.draw(s)
	}
	_ = a.rend.Draw(s)
	a.afterDraw()
}

func (a *app) afterDraw() {
	if a.opts.afterDraw != nil {
		a.opts.afterDraw(a.screen, a.handled)
	}
}

func (a *app) drawHeader() {
	s := a.screen
	s.Fill(0, 0, s.W, 1, reverse)
	left := " pairier"
	if a.info.member != "" {
		left += "  " + a.t("member") + " " + a.info.member
	}
	if a.dir != "" {
		left += "  " + a.dir
	}
	right := "kmsctl " + a.opts.Version + " "
	if a.opts.Offline {
		right = a.t("[offline]") + "  " + right
	}
	rw := tui.StringWidth(right)
	s.Field(0, 0, s.W-rw, left, reverse)
	s.Put(s.W-rw, 0, right, reverse)
}

func (a *app) drawTabs() {
	s := a.screen
	x := 0
	for i, name := range tabNames {
		label := fmt.Sprintf(" %d %s ", i+1, a.t(name))
		if i == tabInbox && len(a.data.inbox) > 0 {
			label = fmt.Sprintf(" %d %s (%d) ", i+1, a.t(name), len(a.data.inbox))
		}
		st := plain
		if i == a.tab {
			st = selected
		}
		x += s.Put(x, 1, label, st) + 1
	}
}

func (a *app) drawFooter() {
	s := a.screen
	right := a.t("? help  q quit ")
	if a.phase != phaseMain {
		right = ""
	}
	left := a.hints()
	if a.phase == phaseMain {
		if more := a.t("  Tab/1-6 tabs  / filter  Ctrl+R refresh"); tui.StringWidth(left+more+"  "+right) <= s.W {
			left += more
		}
	}
	rw := tui.StringWidth(right)
	s.Field(0, s.H-2, s.W-rw, left, dim)
	s.Put(s.W-rw, s.H-2, right, dim)
	switch {
	case a.job != nil:
		s.Field(0, s.H-1, s.W, fmt.Sprintf(" %c %s", spinner[a.frame%len(spinner)], a.job.title)+a.t(" ... (Esc cancels)"), warn)
	case a.status != "":
		st := good
		if a.statusErr {
			st = bad
		}
		s.Field(0, s.H-1, s.W, " "+a.status, st)
	}
}

func (a *app) hints() string {
	switch a.phase {
	case phaseStart:
		return a.t(" o open a node directory   n initialize a new node   q quit")
	case phaseLocked:
		return a.t(" Enter reopen   q quit")
	case phaseOpening:
		return a.t(" Esc cancel   q quit")
	}
	net := !a.opts.Offline
	switch a.tab {
	case tabNode:
		return a.t(" c export card  R renew card")
	case tabKeys:
		h := a.t(" n new  s send")
		if net {
			h += a.t("  p push")
		}
		return h + a.t("  r receive  e/d encrypt/decrypt  Enter info")
	case tabMembers:
		h := a.t(" a add  w witness heads")
		if net {
			h += a.t("  h health")
		}
		return h
	case tabInbox:
		return a.t(" Enter accept  x reject  i import file")
	case tabAudit:
		return a.t(" v verify")
	}
	return a.t(" Up/Down scroll")
}

func (a *app) drawStart() {
	s := a.screen
	lines := []string{
		a.t("No node is open."),
		"",
		a.t("o  open an existing node directory"),
		a.t("n  initialize a new node"),
		a.t("q  quit"),
		"",
		a.t("Every action runs through the same node code as the kmsctl commands"),
		a.t("and is written to the node audit log."),
	}
	for i, l := range lines {
		s.Put(2, 3+i, l, plain)
	}
}

func expandPath(p string) string {
	p = strings.TrimSpace(p)
	if len(p) >= 2 && (p[0] == '"' && p[len(p)-1] == '"' || p[0] == '\'' && p[len(p)-1] == '\'') {
		p = strings.TrimSpace(p[1 : len(p)-1])
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[1:])
		}
	}
	return p
}
