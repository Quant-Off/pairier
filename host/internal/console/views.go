package console

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"crypto/fips140"

	"github.com/Quant-Off/pairier/host/internal/audit"
	"github.com/Quant-Off/pairier/host/internal/exchange"
	"github.com/Quant-Off/pairier/host/internal/node"
	"github.com/Quant-Off/pairier/host/internal/store"
	"github.com/Quant-Off/pairier/host/internal/tui"
	"github.com/Quant-Off/pairier/host/internal/wire"
)

const (
	maxEntries  = 1000
	detailLines = 4
	auditTop    = 6
)

type nodeInfo struct {
	member      string
	fingerprint string
	identityAlg uint16
	kemAlg      uint16
	retiredKEM  bool
	legacyTLS   bool
	coreFIPS    bool
	pqc         bool
	engine      string
	auditPath   string
}

type memberRow struct {
	id          string
	fingerprint string
	identityAlg uint16
	kemAlg      uint16
	retired     bool
	heads       []audit.Anchor
	err         string
}

type snapshot struct {
	keys     []*store.KeyRecord
	members  []memberRow
	inbox    []node.InboxItem
	entries  []audit.Entry
	auditErr string
	audited  bool
}

type verifyResult struct {
	err     string
	count   uint64
	head    audit.Anchor
	anchors int
	peer    string
	at      time.Time
}

type column struct {
	name  string
	width int
}

type row struct {
	id   string
	cols []string
	st   tui.Style
}

func loadInfo(ctx context.Context, n *node.Node) (nodeInfo, error) {
	card, _, err := n.Card(ctx)
	if err != nil {
		return nodeInfo{}, err
	}
	fp, err := card.Fingerprint()
	if err != nil {
		return nodeInfo{}, err
	}
	_, terr := n.TLSCertificate()
	c := n.Core()
	return nodeInfo{
		member:      n.MemberID(),
		fingerprint: fp,
		identityAlg: card.IdentityAlg,
		kemAlg:      card.KemAlg,
		retiredKEM:  exchange.IsRetiredKemAlg(card.KemAlg),
		legacyTLS:   errors.Is(terr, node.ErrLegacyTLS),
		coreFIPS:    n.FIPS(),
		pqc:         n.PQC(),
		engine:      strings.TrimSpace(c.EngineName() + " " + c.EngineVersion()),
		auditPath:   n.AuditLogPath(),
	}, nil
}

func loadSnapshot(ctx context.Context, n *node.Node, withAudit bool) (snapshot, error) {
	var s snapshot
	var err error
	if s.keys, err = n.Keys(); err != nil {
		return s, err
	}
	recs, err := n.Members()
	if err != nil {
		return s, err
	}
	for _, m := range recs {
		r := memberRow{id: m.MemberID, fingerprint: m.Fingerprint}
		if card, err := n.Member(ctx, m.MemberID); err != nil {
			r.err = err.Error()
		} else {
			r.identityAlg, r.kemAlg = card.IdentityAlg, card.KemAlg
			r.retired = exchange.IsRetiredKemAlg(card.KemAlg)
		}
		if heads, err := n.Witnessed(m.MemberID); err == nil {
			r.heads = heads
		}
		s.members = append(s.members, r)
	}
	if s.inbox, err = n.Inbox(); err != nil {
		return s, err
	}
	sort.SliceStable(s.inbox, func(i, j int) bool { return s.inbox[i].ReceivedAt < s.inbox[j].ReceivedAt })
	if withAudit {
		s.audited = true
		entries, err := audit.Read(n.AuditLogPath())
		if err != nil {
			s.auditErr = err.Error()
		} else {
			if len(entries) > maxEntries {
				entries = entries[len(entries)-maxEntries:]
			}
			s.entries = entries
		}
	}
	return s, nil
}

func (a *app) refresh() {
	withAudit := a.tab == tabAudit || a.data.audited
	a.refreshed = a.opts.now()
	n := a.node
	if n == nil {
		return
	}
	a.spawn("refresh", true, func(ctx context.Context, res *result) {
		snap, err := loadSnapshot(ctx, n, withAudit)
		if err != nil {
			res.err = err
			return
		}
		res.apply = func(a *app) { a.data = snap }
	})
}

func stamp(sec int64) string {
	if sec == 0 {
		return "-"
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

func internalKey(k *store.KeyRecord) bool {
	for _, p := range []string{"identity/", "kem/", "audit/", "tls/"} {
		if strings.HasPrefix(k.Label, p) && k.Origin == nil {
			return true
		}
	}
	return false
}

func (a *app) memberRecord(id string) *memberRow {
	for i := range a.data.members {
		if a.data.members[i].id == id {
			return &a.data.members[i]
		}
	}
	return nil
}

func (a *app) memberIDs() []string {
	var out []string
	for _, m := range a.data.members {
		out = append(out, m.id)
	}
	return out
}

func (a *app) table(tab int) ([]column, []row) {
	var cols []column
	var rows []row
	switch tab {
	case tabKeys:
		cols = []column{{"KEY ID", 16}, {"ALG", 17}, {"USAGE", 0}, {"LABEL", 0}, {"FROM", 12}}
		keys := slices.Clone(a.data.keys)
		slices.SortStableFunc(keys, func(x, y *store.KeyRecord) int {
			switch ix, iy := internalKey(x), internalKey(y); {
			case ix == iy:
				return 0
			case iy:
				return -1
			}
			return 1
		})
		for _, k := range keys {
			origin := "local"
			if k.Origin != nil {
				origin = k.Origin.Sender
			}
			st := plain
			if internalKey(k) {
				st = dim
			}
			rows = append(rows, row{id: k.KeyID, cols: []string{k.KeyID[:min(16, len(k.KeyID))], wire.AlgName(k.Alg), wire.FormatUsage(k.Usage), k.Label, origin}, st: st})
		}
	case tabMembers:
		cols = []column{{"MEMBER", 16}, {"IDENTITY", 17}, {"KEM", 22}, {"FINGERPRINT", 0}}
		for _, m := range a.data.members {
			st := plain
			ident, kem := wire.AlgName(m.identityAlg), wire.AlgName(m.kemAlg)
			if m.err != "" {
				st, ident, kem = bad, "error", "error"
			} else if m.retired {
				st = warn
			}
			rows = append(rows, row{id: m.id, cols: []string{m.id, ident, kem, m.fingerprint}, st: st})
		}
	case tabInbox:
		cols = []column{{"ENVELOPE", 16}, {"FROM", 16}, {"SENT", 20}, {"RECEIVED", 0}}
		for _, it := range a.data.inbox {
			st := plain
			if a.memberRecord(it.Sender) == nil {
				st = warn
			}
			rows = append(rows, row{id: it.ID, cols: []string{it.ID[:min(16, len(it.ID))], it.Sender, stamp(it.SentAt), stamp(it.ReceivedAt)}, st: st})
		}
	case tabAudit:
		cols = []column{{"SEQ", 7}, {"TIME", 20}, {"EVENT", 18}, {"FIELDS", 0}}
		for i := len(a.data.entries) - 1; i >= 0; i-- {
			e := a.data.entries[i]
			st := plain
			if _, failed := e.Fields["error"]; failed || strings.HasSuffix(e.Event, ".conflict") {
				st = warn
			}
			rows = append(rows, row{id: fmt.Sprint(e.Seq), cols: []string{fmt.Sprint(e.Seq), stamp(e.Time), e.Event, fieldText(e.Fields)}, st: st})
		}
	case tabLog:
		cols = []column{{"SESSION LOG (memory only)", 0}}
		lines := a.logs.snapshot()
		for i, l := range lines {
			rows = append(rows, row{id: fmt.Sprint(i), cols: []string{l}, st: plain})
		}
	}
	if f := strings.ToLower(a.filter[tab]); f != "" {
		kept := rows[:0]
		for _, r := range rows {
			if strings.Contains(strings.ToLower(strings.Join(r.cols, " ")), f) {
				kept = append(kept, r)
			}
		}
		rows = kept
	}
	return cols, rows
}

func fieldText(fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+fields[k])
	}
	return strings.Join(parts, " ")
}

func (a *app) listTop(tab int) int {
	if tab == tabAudit {
		return auditTop
	}
	return 2
}

func (a *app) listRows(tab int) int {
	bottom := a.screen.H - 3 - detailLines - 1
	if tab == tabLog {
		bottom = a.screen.H - 3
	}
	return max(bottom-a.listTop(tab), 1)
}

func (a *app) selection(tab int, rows []row) int {
	l := &a.lists[tab]
	if id := a.selID[tab]; id != "" {
		for i, r := range rows {
			if r.id == id {
				l.Sel = i
				break
			}
		}
	}
	l.Clamp(len(rows), a.listRows(tab))
	if len(rows) == 0 {
		return -1
	}
	return l.Sel
}

func layout(cols []column, total int) []int {
	widths := make([]int, len(cols))
	fixed, flex := 0, 0
	for i, c := range cols {
		widths[i] = c.width
		fixed += c.width + 1
		if c.width == 0 {
			flex++
		}
	}
	if flex > 0 {
		each := max((total-fixed)/flex, 6)
		for i := range widths {
			if widths[i] == 0 {
				widths[i] = each
			}
		}
	}
	return widths
}

func (a *app) drawTable(tab int) int {
	s := a.screen
	cols, rows := a.table(tab)
	top := a.listTop(tab)
	height := a.listRows(tab)
	widths := layout(cols, s.W-1)
	x := 1
	for i, c := range cols {
		s.Field(x, top, widths[i], c.name, heading)
		x += widths[i] + 1
	}
	sel := a.selection(tab, rows)
	l := a.lists[tab]
	for i := 0; i < height && l.Off+i < len(rows); i++ {
		r := rows[l.Off+i]
		st := r.st
		y := top + 1 + i
		if l.Off+i == sel {
			st = selected
			s.Fill(0, y, s.W, 1, selected)
			s.Put(0, y, ">", selected)
		}
		x := 1
		for j := range cols {
			s.Field(x, y, widths[j], r.cols[j], st)
			x += widths[j] + 1
		}
	}
	if len(rows) == 0 {
		msg := "(empty)"
		if a.filter[tab] != "" {
			msg = "(nothing matches the filter " + a.filter[tab] + ", Esc clears it)"
		}
		s.Put(2, top+1, msg, dim)
	} else if a.filter[tab] != "" {
		s.Field(s.W-30, top, 29, "filter: "+a.filter[tab], warn)
	}
	return sel
}

func (a *app) detail(lines ...string) {
	s := a.screen
	y := s.H - 3 - detailLines
	s.Put(0, y, strings.Repeat("-", s.W), dim)
	for i, l := range lines {
		if i >= detailLines {
			break
		}
		s.Field(1, y+1+i, s.W-2, l, plain)
	}
}

func splitFingerprint(fp string) []string {
	groups := strings.Split(fp, "-")
	if len(groups) <= 8 {
		return []string{fp}
	}
	half := (len(groups) + 1) / 2
	return []string{strings.Join(groups[:half], "-"), strings.Join(groups[half:], "-")}
}

func (a *app) drawTab() {
	switch a.tab {
	case tabNode:
		a.drawNode()
	case tabKeys:
		if sel := a.drawTable(tabKeys); sel >= 0 {
			_, rows := a.table(tabKeys)
			k := a.keyByID(rows[sel].id)
			if k != nil {
				origin := "generated on this node"
				if k.Origin != nil {
					origin = "from " + k.Origin.Sender + " sent " + stamp(k.Origin.SentAt)
				}
				a.detail("id      "+k.KeyID+"   "+wire.AlgName(k.Alg), "label   "+k.Label, "usage   "+wire.FormatUsage(k.Usage)+"   created "+stamp(k.CreatedAt), "origin  "+origin)
			}
		}
	case tabMembers:
		if sel := a.drawTable(tabMembers); sel >= 0 {
			_, rows := a.table(tabMembers)
			if m := a.memberRecord(rows[sel].id); m != nil {
				fp := splitFingerprint(m.fingerprint)
				lines := []string{"member  " + m.id + "   fingerprint " + fp[0]}
				if len(fp) > 1 {
					lines = append(lines, "        "+strings.Repeat(" ", len(m.id)+15)+fp[1])
				}
				heads := fmt.Sprintf("witnessed audit heads %d", len(m.heads))
				if len(m.heads) > 0 {
					heads += ", latest " + m.heads[len(m.heads)-1].String()
				}
				lines = append(lines, heads)
				switch {
				case m.err != "":
					lines = append(lines, "error   "+m.err)
				case m.retired:
					lines = append(lines, "warning the card uses a retired kem, ask the member to run card renew")
				}
				a.detail(lines...)
			}
		}
	case tabInbox:
		if sel := a.drawTable(tabInbox); sel >= 0 {
			_, rows := a.table(tabInbox)
			if it := a.inboxByID(rows[sel].id); it != nil {
				from := "from    " + it.Sender
				if m := a.memberRecord(it.Sender); m != nil {
					from += "   fingerprint " + m.fingerprint
				} else {
					from += "   not a registered member"
				}
				a.detail("envelope "+it.ID, from, "sent    "+stamp(it.SentAt)+"   received "+stamp(it.ReceivedAt), "Enter verifies and imports the key, x deletes the envelope")
			}
		}
	case tabAudit:
		a.drawAudit()
	case tabLog:
		a.drawTable(tabLog)
	}
}

func (a *app) drawNode() {
	s := a.screen
	i := a.info
	y := 3
	put := func(label, value string, st tui.Style) {
		s.Field(2, y, 14, label, bold)
		s.Field(16, y, s.W-18, value, st)
		y++
	}
	put("Member", i.member, plain)
	put("Directory", a.dir, plain)
	for n, part := range splitFingerprint(i.fingerprint) {
		label := ""
		if n == 0 {
			label = "Fingerprint"
		}
		put(label, part, heading)
	}
	put("Identity", wire.AlgName(i.identityAlg), plain)
	kem := wire.AlgName(i.kemAlg)
	kemStyle := plain
	if i.retiredKEM {
		kem += "  retired, press R to renew the card"
		kemStyle = warn
	}
	put("KEM", kem, kemStyle)
	tlsText, tlsStyle := "held in the core", plain
	if i.legacyTLS {
		tlsText, tlsStyle = "stored outside the core, press R to renew the card", warn
	}
	put("TLS key", tlsText, tlsStyle)
	put("Core", fmt.Sprintf("%s   fips=%v   pqc=%v", i.engine, i.coreFIPS, i.pqc), plain)
	put("Host", fmt.Sprintf("kmsctl %s   %s   go_fips=%v", a.opts.Version, runtime.Version(), fips140.Enabled()), plain)
	put("Audit log", i.auditPath, plain)
	put("Store", fmt.Sprintf("%d keys, %d members, %d pending envelopes", len(a.data.keys), len(a.data.members), len(a.data.inbox)), plain)
	net := "network actions enabled (push, health, peer audit), each needs an https URL"
	if a.opts.Offline {
		net = "offline, actions that contact other nodes are hidden"
	}
	put("Mode", net, plain)
	if a.opts.Idle > 0 {
		put("Idle close", a.opts.Idle.String(), plain)
	}
}

func (a *app) drawAudit() {
	s := a.screen
	v := a.verify
	switch {
	case v == nil:
		s.Field(1, 3, s.W-2, "Not verified in this session. Press v to verify the chain, anchors and witnessed heads.", plain)
	case v.err != "":
		s.Field(1, 3, s.W-2, "Verification FAILED at "+v.at.UTC().Format(time.RFC3339), bad)
		s.Field(1, 4, s.W-2, v.err, bad)
	default:
		peer := ""
		if v.peer != "" {
			peer = ", heads witnessed by " + v.peer
		}
		s.Field(1, 3, s.W-2, fmt.Sprintf("Verified %d entries against %d anchors%s at %s", v.count, v.anchors, peer, v.at.UTC().Format(time.RFC3339)), good)
		s.Field(1, 4, s.W-2, "head "+v.head.String(), heading)
	}
	if a.data.auditErr != "" {
		s.Field(1, auditTop-1, s.W-2, "reading the log failed: "+a.data.auditErr, bad)
	}
	if sel := a.drawTable(tabAudit); sel >= 0 {
		_, rows := a.table(tabAudit)
		for _, e := range a.data.entries {
			if fmt.Sprint(e.Seq) == rows[sel].id {
				lines := []string{fmt.Sprintf("seq %d   %s   %s", e.Seq, stamp(e.Time), e.Event)}
				lines = append(lines, tui.Wrap(fieldText(e.Fields), s.W-2)...)
				a.detail(lines...)
				break
			}
		}
	}
}

func (a *app) keyByID(id string) *store.KeyRecord {
	for _, k := range a.data.keys {
		if k.KeyID == id {
			return k
		}
	}
	return nil
}

func (a *app) inboxByID(id string) *node.InboxItem {
	for i := range a.data.inbox {
		if a.data.inbox[i].ID == id {
			return &a.data.inbox[i]
		}
	}
	return nil
}

func (a *app) selected(tab int) string {
	_, rows := a.table(tab)
	if sel := a.selection(tab, rows); sel >= 0 {
		return rows[sel].id
	}
	return ""
}

func (a *app) switchTab(tab int) {
	a.tab = tab
	if tab == tabAudit && !a.data.audited && a.job == nil {
		a.refresh()
	}
}

func (a *app) handleMain(ev tui.Event) {
	switch {
	case ev.IsRune('q'):
		a.askQuit()
		return
	case ev.IsRune('?'):
		a.help()
		return
	case ev.Is(tui.KeyTab):
		a.switchTab((a.tab + 1) % tabCount)
		return
	case ev.Is(tui.KeyBacktab):
		a.switchTab((a.tab + tabCount - 1) % tabCount)
		return
	case ev.Kind == tui.EventKey && ev.Key == tui.KeyRune && ev.Rune >= '1' && ev.Rune < '1'+tabCount:
		a.switchTab(int(ev.Rune - '1'))
		return
	case ev.IsCtrl('r'):
		a.refresh()
		return
	case ev.IsRune('/') && a.tab != tabNode:
		a.filterForm()
		return
	case ev.Is(tui.KeyEsc):
		a.filter[a.tab] = ""
		return
	}
	if a.tab != tabNode {
		_, rows := a.table(a.tab)
		a.selection(a.tab, rows)
		if a.lists[a.tab].Handle(ev, len(rows), a.listRows(a.tab)) {
			if len(rows) > 0 {
				a.selID[a.tab] = rows[a.lists[a.tab].Sel].id
			}
			return
		}
	}
	switch a.tab {
	case tabNode:
		a.nodeKey(ev)
	case tabKeys:
		a.keysKey(ev)
	case tabMembers:
		a.membersKey(ev)
	case tabInbox:
		a.inboxKey(ev)
	case tabAudit:
		if ev.IsRune('v') {
			a.verifyForm()
		}
	}
}

func (a *app) askQuit() {
	if a.job == nil {
		a.quit = true
		return
	}
	a.confirm("Quit", []string{a.job.title + " is still running. Quit anyway? The operation is cancelled."}, "", false, func(a *app) { a.quit = true })
}

func (a *app) help() {
	lines := []string{
		"Tab, Shift+Tab or 1-6 switch tabs. Up/Down or j/k move, PgUp/PgDn and Home/End jump.",
		"/ filters the list, Esc clears the filter or cancels a running action, Ctrl+R refreshes, Ctrl+L redraws, q or Ctrl+C quits.",
		"",
		"Node     c export card (card)   R renew card (card renew)",
		"Keys     Enter info (key info)   n new (key gen)   s send to file (key send)   r receive file (key receive)",
		"         e encrypt file (encrypt)   d decrypt file (decrypt)   p push to kmsd (key push)",
		"Members  a add card (member add)   w export witnessed heads (member witness)   h health (peer health)",
		"Inbox    Enter accept (inbox accept)   x reject (inbox reject)   i import envelope file (key receive)",
		"Audit    v verify with anchors, an anchor file or a peer (audit verify)",
		"",
		"Fingerprints are never filled in for you, type them from the other channel.",
		"Decrypted data only goes to new files created for your user. Nothing is copied to the clipboard.",
	}
	if a.opts.Offline {
		lines = append(lines, "Offline mode hides push, health and peer audit.")
	}
	a.message("Help", lines, false)
}
