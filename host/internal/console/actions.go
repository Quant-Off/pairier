package console

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/Quant-Off/pairier/host/internal/api"
	"github.com/Quant-Off/pairier/host/internal/audit"
	"github.com/Quant-Off/pairier/host/internal/exchange"
	"github.com/Quant-Off/pairier/host/internal/fsx"
	"github.com/Quant-Off/pairier/host/internal/node"
	"github.com/Quant-Off/pairier/host/internal/store"
	"github.com/Quant-Off/pairier/host/internal/tui"
	"github.com/Quant-Off/pairier/host/internal/wire"
)

const (
	maxPath  = 4096
	maxURL   = 2048
	maxAAD   = 4096
	noPeer   = "(none)"
	symUsage = node.SymmetricUsage
)

type formModal struct {
	f      *tui.Form
	submit func(a *app, f *tui.Form) error
}

func (m *formModal) handle(a *app, ev tui.Event) {
	switch m.f.Handle(ev) {
	case tui.Cancel:
		a.modal = nil
	case tui.Submit:
		a.modal = nil
		m.f.Err = ""
		if err := m.submit(a, m.f); err != nil {
			m.f.Err = err.Error()
			a.modal = m
		}
	}
}

func (m *formModal) draw(s *tui.Screen) { m.f.Draw(s, plain) }

type dialogModal struct {
	d   *tui.Dialog
	yes func(a *app)
}

func (m *dialogModal) handle(a *app, ev tui.Event) {
	switch m.d.Handle(ev) {
	case tui.Cancel:
		a.modal = nil
	case tui.Submit:
		a.modal = nil
		if m.yes != nil {
			m.yes(a)
		}
	}
}

func (m *dialogModal) draw(s *tui.Screen) { m.d.Draw(s, plain) }

func (a *app) form(title string, note []string, fields []*tui.Field, submit func(a *app, f *tui.Form) error) {
	a.modal = &formModal{f: &tui.Form{Title: title, Note: note, Fields: fields}, submit: submit}
}

func (a *app) message(title string, lines []string, isErr bool) {
	a.modal = &dialogModal{d: &tui.Dialog{Title: title, Lines: lines, Danger: isErr}}
}

func (a *app) notify(title string, lines []string, isErr bool) {
	if a.modal == nil {
		a.message(title, lines, isErr)
	}
}

func (a *app) confirm(title string, lines []string, typed string, danger bool, yes func(a *app)) {
	a.modal = &dialogModal{d: &tui.Dialog{Title: title, Lines: lines, Ask: true, Confirm: typed, Danger: danger}, yes: yes}
}

func inPath(v string) (string, error) {
	p := expandPath(v)
	if p == "" {
		return "", errors.New("an input file is required")
	}
	fi, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", p)
	}
	if fi.Size() > maxInput {
		return "", fmt.Errorf("%s exceeds %d bytes", p, maxInput)
	}
	return p, nil
}

func outPath(v string) (string, error) {
	p := expandPath(v)
	if p == "" {
		return "", errors.New("an output file is required")
	}
	if _, err := os.Lstat(p); err == nil {
		return "", fmt.Errorf("%s already exists, choose another name", p)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return p, nil
}

func checkURL(v string) (string, error) {
	v = strings.TrimRight(strings.TrimSpace(v), "/")
	if !strings.HasPrefix(v, "https://") {
		return "", errors.New("the url must use https")
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("the url must look like https://HOST:PORT")
	}
	return v, nil
}

func usageField(label string, allowed, defaults uint32) *tui.Field {
	var names []string
	var checked []bool
	for _, u := range wire.Usages {
		if allowed&u.Bit != 0 {
			names = append(names, u.Name)
			checked = append(checked, defaults&u.Bit != 0)
		}
	}
	return tui.FlagsField(label, names, checked)
}

func usageBits(f *tui.Field) (uint32, error) {
	sel := f.Selected()
	if len(sel) == 0 {
		return 0, errors.New("choose at least one usage")
	}
	return wire.ParseUsage(strings.Join(sel, ","))
}

func fpLines(label, fp string) []string {
	pad := strings.Repeat(" ", len(label))
	var out []string
	for i, part := range splitFingerprint(fp) {
		if i == 0 {
			out = append(out, label+part)
		} else {
			out = append(out, pad+part)
		}
	}
	return out
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func (a *app) runOpen(title string, open func(ctx context.Context) (*node.Node, error), after func(a *app, info nodeInfo)) {
	a.phase = phaseOpening
	if !a.spawn(title, false, func(ctx context.Context, res *result) {
		n, err := open(ctx)
		if err != nil {
			res.err = err
			return
		}
		info, err := loadInfo(ctx, n)
		if err != nil {
			_ = n.Close()
			res.err = err
			return
		}
		res.cleanup = func() { _ = n.Close() }
		res.apply = func(a *app) {
			a.node, a.info, a.phase = n, info, phaseMain
			a.data, a.verify = snapshot{}, nil
			a.done("opened " + a.dir + " as " + info.member)
			a.refresh()
			if after != nil {
				after(a, info)
			}
		}
	}) {
		a.phase = phaseStart
	}
}

func (a *app) openNode(dir string) {
	opts := a.nodeOptions(dir)
	a.dir = dir
	a.runOpen("open node", func(ctx context.Context) (*node.Node, error) { return node.Open(ctx, opts) }, nil)
}

func (a *app) dirForm(dir string) {
	a.form("Open node", []string{"Enter the node directory. If it does not exist yet you can initialize it next."},
		[]*tui.Field{tui.TextField("Directory", dir, maxPath)},
		func(a *app, f *tui.Form) error {
			d := expandPath(f.Fields[0].Value())
			if d == "" {
				return errors.New("a directory is required")
			}
			if _, err := os.Stat(d); errors.Is(err, os.ErrNotExist) {
				a.initForm(d)
				return nil
			} else if err != nil {
				return err
			}
			a.openNode(d)
			return nil
		})
}

func (a *app) initForm(dir string) {
	fields := []*tui.Field{
		tui.TextField("Directory", dir, maxPath),
		tui.TextField("Member ID", "", exchange.MaxMemberID),
		tui.ToggleField("Post-quantum", false),
	}
	fields[1].Hint = "lowercase letters, digits, . _ -, the name members know you by"
	fields[2].Hint = "ML-DSA identity and ML-KEM exchange, needs a core built with pqc"
	note := []string{"Creates the directory for your user only, a root key and the node identity (kmsctl init)."}
	a.form("Initialize node", note, fields, func(a *app, f *tui.Form) error {
		d := expandPath(f.Fields[0].Value())
		id := strings.TrimSpace(f.Fields[1].Value())
		pqc := f.Fields[2].On
		if d == "" {
			return errors.New("a directory is required")
		}
		if !exchange.ValidMemberID(id) {
			return errors.New("invalid member id")
		}
		opts := a.nodeOptions(d)
		a.dir = d
		a.runOpen("initialize node", func(ctx context.Context) (*node.Node, error) {
			return node.Init(ctx, opts, id, pqc)
		}, func(a *app, info nodeInfo) {
			lines := []string{
				"member       " + info.member,
				"identity     " + wire.AlgName(info.identityAlg),
				"kem          " + wire.AlgName(info.kemAlg),
				fmt.Sprintf("core_fips    %v   pqc %v", info.coreFIPS, info.pqc),
			}
			lines = append(lines, fpLines("fingerprint  ", info.fingerprint)...)
			lines = append(lines, "", "Export your card with c and give the card and this fingerprint to each member over separate channels.")
			a.message("Node initialized", lines, false)
		})
		return nil
	})
}

func (a *app) filterForm() {
	tab := a.tab
	a.form("Filter "+tabNames[tab], nil, []*tui.Field{tui.TextField("Contains", a.filter[tab], 128)}, func(a *app, f *tui.Form) error {
		a.filter[tab] = strings.TrimSpace(f.Fields[0].Value())
		a.lists[tab] = tui.List{}
		a.selID[tab] = ""
		return nil
	})
}

func (a *app) nodeKey(ev tui.Event) {
	switch {
	case ev.IsRune('c'):
		a.cardForm(nil, a.info.member+".card", nil)
	case ev.IsRune('R'):
		a.renewDialog()
	}
}

func (a *app) cardForm(raw []byte, name string, note []string) {
	a.form("Export card", note, []*tui.Field{tui.TextField("Output file", name, maxPath)}, func(a *app, f *tui.Form) error {
		out, err := outPath(f.Fields[0].Value())
		if err != nil {
			return err
		}
		a.run("export card", func(ctx context.Context, n *node.Node) (func(*app), error) {
			var card *exchange.Card
			var err error
			data := raw
			if data == nil {
				card, data, err = n.Card(ctx)
			} else {
				card, err = exchange.DecodeCard(data)
			}
			if err != nil {
				return nil, err
			}
			fp, err := card.Fingerprint()
			if err != nil {
				return nil, err
			}
			if err := fsx.WriteNew(out, data); err != nil {
				return nil, err
			}
			return func(a *app) {
				a.done("card written to " + out)
				lines := append([]string{"file         " + out}, fpLines("fingerprint  ", fp)...)
				lines = append(lines, "", "Send the card file and read the fingerprint to the member over a different channel.")
				a.notify("Card exported", lines, false)
			}, nil
		})
		return nil
	})
}

func (a *app) renewDialog() {
	member := a.info.member
	lines := []string{
		"Renewing replaces the node KEM key, moves the TLS key into the core and signs a new card.",
		"Every member has to add the new card with its new fingerprint, and kmsd must be restarted.",
	}
	a.confirm("Renew card", lines, member, true, func(a *app) {
		a.run("renew card", func(ctx context.Context, n *node.Node) (func(*app), error) {
			card, raw, err := n.RenewCard(ctx)
			if err != nil {
				return nil, err
			}
			fp, _ := card.Fingerprint()
			info, err := loadInfo(ctx, n)
			if err != nil {
				return nil, err
			}
			return func(a *app) {
				a.info = info
				a.done("card renewed, new fingerprint " + fp)
				a.cardForm(raw, member+".renewed.card", []string{
					"New fingerprint " + fp,
					"Send the new card to every member and restart kmsd. Esc skips, c exports the card later.",
				})
				a.refresh()
			}, nil
		})
	})
}

func (a *app) keysKey(ev tui.Event) {
	switch {
	case ev.IsRune('n'):
		a.genForm()
		return
	case ev.IsRune('r'):
		a.receiveForm()
		return
	}
	k := a.keyByID(a.selected(tabKeys))
	if k == nil {
		return
	}
	switch {
	case ev.Is(tui.KeyEnter):
		a.keyInfo(k.KeyID)
	case ev.IsRune('s'):
		a.sendForm(k, false)
	case ev.IsRune('p') && !a.opts.Offline:
		a.sendForm(k, true)
	case ev.IsRune('e'):
		a.cryptForm(k, true)
	case ev.IsRune('d'):
		a.cryptForm(k, false)
	}
}

func (a *app) genForm() {
	fields := []*tui.Field{
		tui.TextField("Label", "", wire.MaxLabel),
		usageField("Usage", symUsage, wire.UsageEncrypt|wire.UsageDecrypt|wire.UsageExport),
	}
	fields[1].Hint = "export is needed to send the key to members"
	a.form("Generate key", []string{"Creates an AES-256-GCM key inside the core (key gen)."}, fields, func(a *app, f *tui.Form) error {
		label := f.Fields[0].Value()
		if !node.ValidLabel(label) {
			return node.ErrLabel
		}
		bits, err := usageBits(f.Fields[1])
		if err != nil {
			return err
		}
		a.run("generate key", func(ctx context.Context, n *node.Node) (func(*app), error) {
			rec, err := n.GenerateKey(ctx, label, bits)
			if err != nil {
				return nil, err
			}
			return func(a *app) {
				a.selID[tabKeys] = rec.KeyID
				a.done("generated " + rec.KeyID + " " + rec.Label)
				a.refresh()
			}, nil
		})
		return nil
	})
}

func keyLines(k *store.KeyRecord) []string {
	lines := []string{
		"id       " + k.KeyID,
		"alg      " + wire.AlgName(k.Alg),
		"usage    " + wire.FormatUsage(k.Usage),
		"label    " + k.Label,
		"created  " + stamp(k.CreatedAt),
	}
	if k.Origin != nil {
		lines = append(lines, "origin   "+k.Origin.Sender+"   sent "+stamp(k.Origin.SentAt))
	}
	return lines
}

func (a *app) keyInfo(id string) {
	a.run("key info", func(ctx context.Context, n *node.Node) (func(*app), error) {
		k, err := n.Key(ctx, id)
		if err != nil {
			return nil, err
		}
		return func(a *app) {
			a.notify("Key", append(keyLines(k), "", "The stored metadata matches what the core reports for this key."), false)
		}, nil
	})
}

func (a *app) sendForm(k *store.KeyRecord, push bool) {
	members := a.memberIDs()
	if len(members) == 0 {
		a.message("No members", []string{"Add the recipient on the Members tab first."}, true)
		return
	}
	def := uint32(wire.UsageDecrypt)
	if k.Usage&def == 0 {
		def = 0
	}
	fields := []*tui.Field{tui.ChoiceField("Recipient", members, 0), usageField("Grant", k.Usage, def)}
	fields[0].Hint = "Left/Right picks a registered member"
	fields[1].Hint = "only a subset of this key's usage can be granted"
	title, note := "Send key to file", []string{"Seals the key for one member into an envelope file (key send)."}
	if push {
		u := a.urls[members[0]]
		if u == "" {
			u = "https://"
		}
		fields = append(fields, tui.TextField("kmsd URL", u, maxURL))
		title, note = "Push key", []string{"Seals the key and delivers it to the member's kmsd over mutual TLS (key push)."}
	} else {
		fields = append(fields, tui.TextField("Output file", shortID(k.KeyID)+".kxp", maxPath))
	}
	id, label := k.KeyID, k.Label
	a.form(title, note, fields, func(a *app, f *tui.Form) error {
		to := f.Fields[0].Value()
		bits, err := usageBits(f.Fields[1])
		if err != nil {
			return err
		}
		var dest string
		if push {
			dest, err = checkURL(f.Fields[2].Value())
		} else {
			dest, err = outPath(f.Fields[2].Value())
		}
		if err != nil {
			return err
		}
		fp := "unknown"
		if m := a.memberRecord(to); m != nil {
			fp = m.fingerprint
		}
		lines := []string{"key          " + id + "  " + label, "recipient    " + to}
		lines = append(lines, fpLines("fingerprint  ", fp)...)
		lines = append(lines, "grant        "+wire.FormatUsage(bits))
		if push {
			lines = append(lines, "kmsd         "+dest)
		} else {
			lines = append(lines, "file         "+dest)
		}
		a.confirm(title, append(lines, "", "The recipient can use the key with this usage from now on. Continue?"), "", false, func(a *app) {
			a.run(strings.ToLower(title), func(ctx context.Context, n *node.Node) (func(*app), error) {
				env, err := n.Send(ctx, id, to, bits)
				if err != nil {
					return nil, err
				}
				if !push {
					if err := fsx.WriteNew(dest, env); err != nil {
						return nil, err
					}
					return func(a *app) {
						a.done("sent " + id + " to " + to + " in " + dest)
						a.notify("Envelope written", []string{"file " + dest, "Deliver it to " + to + ", who imports it with r on the Keys tab or key receive."}, false)
						a.refresh()
					}, nil
				}
				envID, err := api.NewClient(n, nil).Push(ctx, dest, to, env)
				if err != nil {
					return nil, err
				}
				return func(a *app) {
					a.urls[to] = dest
					a.done("pushed " + id + " to " + to + ", envelope " + envID)
					a.notify("Key pushed", []string{"envelope " + envID, to + " accepts it from the Inbox tab or with inbox accept."}, false)
					a.refresh()
				}, nil
			})
		})
		return nil
	})
}

func (a *app) cryptForm(k *store.KeyRecord, encrypt bool) {
	title, hint, op := "Decrypt file", "empty means the input name without .enc, or with .dec", "decrypt"
	note := []string{"The plaintext is written only to a new file that only your user can read. It is never shown."}
	if encrypt {
		title, hint, op = "Encrypt file", "empty means the input name with .enc", "encrypt"
		note = []string{"Encrypts up to 1 MiB with AES-256-GCM inside the core."}
	}
	fields := []*tui.Field{
		tui.TextField("Input file", "", maxPath),
		tui.TextField("Output file", "", maxPath),
		tui.TextField("AAD", "", maxAAD),
	}
	fields[1].Hint = hint
	fields[2].Hint = "associated data, must be the same for encrypt and decrypt"
	id := k.KeyID
	a.form(title+" with "+shortID(id), note, fields, func(a *app, f *tui.Form) error {
		in, err := inPath(f.Fields[0].Value())
		if err != nil {
			return err
		}
		outName := f.Fields[1].Value()
		if strings.TrimSpace(outName) == "" {
			switch {
			case encrypt:
				outName = in + ".enc"
			case strings.HasSuffix(in, ".enc"):
				outName = strings.TrimSuffix(in, ".enc")
			default:
				outName = in + ".dec"
			}
		}
		out, err := outPath(outName)
		if err != nil {
			return err
		}
		aad := []byte(f.Fields[2].Value())
		a.run(op, func(ctx context.Context, n *node.Node) (func(*app), error) {
			data, err := fsx.ReadFileLimited(in, maxInput)
			if err != nil {
				return nil, err
			}
			var res []byte
			if encrypt {
				res, err = n.Encrypt(ctx, id, data, aad)
				clear(data)
			} else {
				res, err = n.Decrypt(ctx, id, data, aad)
			}
			if err != nil {
				return nil, err
			}
			werr := fsx.WriteNew(out, res)
			size := len(res)
			if !encrypt {
				clear(res)
			}
			if werr != nil {
				return nil, werr
			}
			return func(a *app) {
				a.done(fmt.Sprintf("%s wrote %d bytes to %s", op, size, out))
				a.notify(title, []string{fmt.Sprintf("wrote %d bytes to %s", size, out)}, false)
			}, nil
		})
		return nil
	})
}

func (a *app) receiveForm() {
	fields := []*tui.Field{tui.TextField("Envelope file", "", maxPath)}
	note := []string{"Imports a key sent to this node after checking the signature, recipient and context (key receive)."}
	a.form("Receive key", note, fields, func(a *app, f *tui.Form) error {
		in, err := inPath(f.Fields[0].Value())
		if err != nil {
			return err
		}
		a.run("receive key", func(ctx context.Context, n *node.Node) (func(*app), error) {
			raw, err := fsx.ReadFileLimited(in, maxInput)
			if err != nil {
				return nil, err
			}
			rec, err := n.Receive(ctx, raw)
			if err != nil {
				return nil, err
			}
			return func(a *app) {
				a.selID[tabKeys] = rec.KeyID
				a.done("received " + rec.KeyID + " from " + rec.Origin.Sender)
				a.notify("Key received", keyLines(rec), false)
				a.refresh()
			}, nil
		})
		return nil
	})
}

func (a *app) membersKey(ev tui.Event) {
	if ev.IsRune('a') {
		a.addForm()
		return
	}
	m := a.memberRecord(a.selected(tabMembers))
	if m == nil {
		return
	}
	switch {
	case ev.IsRune('w'):
		a.witnessForm(m.id)
	case ev.IsRune('h') && !a.opts.Offline:
		a.healthForm(m.id)
	}
}

func (a *app) addForm() {
	fields := []*tui.Field{
		tui.TextField("Card file", "", maxPath),
		tui.TextField("Fingerprint", "", 256),
	}
	fields[1].Hint = "as the member read it to you, never copied from the card file"
	note := []string{
		"Registers or updates a member (member add). Type or paste the fingerprint you got",
		"over a separate channel, in person or by phone. It must match the card exactly.",
	}
	a.form("Add member", note, fields, func(a *app, f *tui.Form) error {
		in, err := inPath(f.Fields[0].Value())
		if err != nil {
			return err
		}
		fp := strings.TrimSpace(f.Fields[1].Value())
		if exchange.NormalizeFingerprint(fp) == "" {
			return errors.New("the fingerprint is required")
		}
		a.run("add member", func(ctx context.Context, n *node.Node) (func(*app), error) {
			raw, err := fsx.ReadFileLimited(in, maxInput)
			if err != nil {
				return nil, err
			}
			rec, err := n.AddMember(ctx, raw, fp)
			if err != nil {
				return nil, err
			}
			action := "added"
			if rec.UpdatedAt != 0 {
				action = "updated"
			}
			return func(a *app) {
				a.selID[tabMembers] = rec.MemberID
				a.done(action + " member " + rec.MemberID)
				a.notify("Member "+action, append([]string{"member       " + rec.MemberID}, fpLines("fingerprint  ", rec.Fingerprint)...), false)
				a.refresh()
			}, nil
		})
		return nil
	})
}

func (a *app) witnessForm(member string) {
	a.form("Export witnessed heads of "+member, []string{"Writes the audit heads this node saw from the member, one SEQ:HASH per line (member witness)."},
		[]*tui.Field{tui.TextField("Output file", member+".witness", maxPath)},
		func(a *app, f *tui.Form) error {
			out, err := outPath(f.Fields[0].Value())
			if err != nil {
				return err
			}
			a.run("export witnessed heads", func(ctx context.Context, n *node.Node) (func(*app), error) {
				heads, err := n.Witnessed(member)
				if err != nil {
					return nil, err
				}
				var b strings.Builder
				for _, h := range heads {
					b.WriteString(h.String())
					b.WriteByte('\n')
				}
				if err := fsx.WriteNew(out, []byte(b.String())); err != nil {
					return nil, err
				}
				return func(a *app) {
					a.done(fmt.Sprintf("wrote %d witnessed heads for %s to %s", len(heads), member, out))
					a.notify("Witnessed heads", []string{fmt.Sprintf("%d heads written to %s", len(heads), out), "The member verifies its log with them on the Audit tab or audit verify --anchor-file."}, false)
				}, nil
			})
			return nil
		})
}

func (a *app) healthForm(member string) {
	u := a.urls[member]
	if u == "" {
		u = "https://"
	}
	a.form("Health of "+member, []string{"Connects to the member's kmsd with mutual TLS pinned to its card (peer health)."},
		[]*tui.Field{tui.TextField("kmsd URL", u, maxURL)},
		func(a *app, f *tui.Form) error {
			dest, err := checkURL(f.Fields[0].Value())
			if err != nil {
				return err
			}
			a.run("peer health", func(ctx context.Context, n *node.Node) (func(*app), error) {
				if err := api.NewClient(n, nil).Health(ctx, dest, member); err != nil {
					return nil, err
				}
				return func(a *app) {
					a.urls[member] = dest
					a.done("health ok " + member + " at " + dest)
				}, nil
			})
			return nil
		})
}

func (a *app) inboxKey(ev tui.Event) {
	if ev.IsRune('i') {
		a.receiveForm()
		return
	}
	it := a.inboxByID(a.selected(tabInbox))
	if it == nil {
		return
	}
	item := *it
	from := item.Sender
	fp := "not a registered member, accepting will fail"
	if m := a.memberRecord(from); m != nil {
		fp = m.fingerprint
	}
	lines := []string{"envelope     " + item.ID, "from         " + from}
	lines = append(lines, fpLines("fingerprint  ", fp)...)
	lines = append(lines, "sent         "+stamp(item.SentAt), "received     "+stamp(item.ReceivedAt))
	switch {
	case ev.Is(tui.KeyEnter), ev.IsRune('a'):
		a.confirm("Accept envelope", append(lines, "", "The key is imported only if the signature, recipient and context verify. Accept?"), "", false, func(a *app) {
			a.run("accept envelope", func(ctx context.Context, n *node.Node) (func(*app), error) {
				rec, err := n.Accept(ctx, item.ID)
				if err != nil {
					return nil, err
				}
				return func(a *app) {
					a.selID[tabKeys] = rec.KeyID
					a.done("accepted " + item.ID + ", key " + rec.KeyID)
					a.notify("Key imported", keyLines(rec), false)
					a.refresh()
				}, nil
			})
		})
	case ev.IsRune('x'):
		a.confirm("Reject envelope", append(lines, "", "The envelope is deleted. The sender has to send it again. Reject?"), "", true, func(a *app) {
			a.run("reject envelope", func(ctx context.Context, n *node.Node) (func(*app), error) {
				if err := n.Reject(ctx, item.ID); err != nil {
					return nil, err
				}
				return func(a *app) {
					a.done("rejected " + item.ID)
					a.refresh()
				}, nil
			})
		})
	}
}

func parseAnchors(s string) ([]audit.Anchor, error) {
	var out []audit.Anchor
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == ';' }) {
		a, err := audit.ParseAnchor(tok)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", tok, err)
		}
		out = append(out, a)
	}
	return out, nil
}

func (a *app) verifyForm() {
	fields := []*tui.Field{
		tui.TextField("Anchors", "", 8192),
		tui.TextField("Anchor file", "", maxPath),
	}
	fields[0].Hint = "SEQ:HASH heads recorded out of band, separated by spaces"
	fields[1].Hint = "one SEQ:HASH per line, for example a member witness file"
	if !a.opts.Offline {
		peers := append([]string{noPeer}, a.memberIDs()...)
		fields = append(fields, tui.ChoiceField("Peer", peers, 0), tui.TextField("Peer kmsd URL", "https://", maxURL))
		fields[2].Hint = "a member whose kmsd returns the heads it witnessed"
	}
	note := []string{"Replays the hash chain and checkpoint signatures and checks every anchor (audit verify)."}
	now := a.opts.now
	a.form("Verify audit log", note, fields, func(a *app, f *tui.Form) error {
		anchors, err := parseAnchors(f.Fields[0].Value())
		if err != nil {
			return err
		}
		var file string
		if strings.TrimSpace(f.Fields[1].Value()) != "" {
			if file, err = inPath(f.Fields[1].Value()); err != nil {
				return err
			}
		}
		var peer, dest string
		if len(f.Fields) > 2 && f.Fields[2].Value() != noPeer {
			peer = f.Fields[2].Value()
			if dest, err = checkURL(f.Fields[3].Value()); err != nil {
				return err
			}
		}
		a.run("verify audit log", func(ctx context.Context, n *node.Node) (func(*app), error) {
			if file != "" {
				raw, err := fsx.ReadFileLimited(file, maxInput)
				if err != nil {
					return nil, err
				}
				more, err := parseAnchors(strings.ReplaceAll(string(raw), "\n", " "))
				if err != nil {
					return nil, fmt.Errorf("%s: %w", file, err)
				}
				anchors = append(anchors, more...)
			}
			if peer != "" {
				fetched, err := api.NewClient(n, nil).Witness(ctx, dest, peer)
				if err != nil {
					return nil, err
				}
				anchors = append(anchors, fetched...)
			}
			count, head, verr := n.VerifyAudit(anchors)
			at := now()
			return func(a *app) {
				if peer != "" {
					a.urls[peer] = dest
				}
				if verr != nil {
					a.verify = &verifyResult{err: verr.Error(), at: at}
					a.flash("audit verification failed", true)
					a.logs.add("audit verify failed: " + verr.Error())
					a.notify("Audit verification failed", []string{verr.Error()}, true)
					return
				}
				a.verify = &verifyResult{count: count, head: head, anchors: len(anchors), peer: peer, at: at}
				a.done(fmt.Sprintf("audit verified %d entries, head %s", count, head))
				a.notify("Audit log verified", []string{
					fmt.Sprintf("entries  %d", count),
					"head     " + head.String(),
					fmt.Sprintf("anchors  %d", len(anchors)),
					"",
					"Record the head somewhere the node cannot change to catch a later rollback.",
				}, false)
				a.refresh()
			}, nil
		})
		return nil
	})
}
