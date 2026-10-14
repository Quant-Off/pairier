package main

import (
	"context"
	"crypto/fips140"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Quant-Off/pairier/host/internal/api"
	"github.com/Quant-Off/pairier/host/internal/node"
	"github.com/Quant-Off/pairier/host/internal/wire"
)

var version = "dev"

const usageText = `usage: kmsctl [--dir DIR] [--core PATH] <command> [flags]

commands:
  init --id MEMBER [--pqc]
  card [--out FILE]
  member add --card FILE --fingerprint FP
  member list
  key gen --label LABEL [--usage encrypt,decrypt,export]
  key list
  key info --id KEYID
  key send --id KEYID --to MEMBER [--usage decrypt] [--out FILE]
  key receive --in FILE
  key push --id KEYID --to MEMBER --url https://HOST:PORT [--usage decrypt]
  inbox list
  inbox accept --id ENVELOPEID
  inbox reject --id ENVELOPEID
  peer health --member MEMBER --url https://HOST:PORT
  audit verify
  encrypt --id KEYID [--in FILE] [--out FILE] [--aad STRING]
  decrypt --id KEYID [--in FILE] [--out FILE] [--aad STRING]
  version
`

var usageNames = map[string]uint32{
	"encrypt":     wire.UsageEncrypt,
	"decrypt":     wire.UsageDecrypt,
	"sign":        wire.UsageSign,
	"verify":      wire.UsageVerify,
	"wrap":        wire.UsageWrap,
	"unwrap":      wire.UsageUnwrap,
	"derive":      wire.UsageDerive,
	"decapsulate": wire.UsageDecapsulate,
	"export":      wire.UsageExport,
}

var usageOrder = []string{"encrypt", "decrypt", "sign", "verify", "wrap", "unwrap", "derive", "decapsulate", "export"}

var algNames = map[uint16]string{
	wire.AlgAES256GCM:          "aes-256-gcm",
	wire.AlgECDSAP256SHA256:    "ecdsa-p256-sha256",
	wire.AlgECDSAP384SHA384:    "ecdsa-p384-sha384",
	wire.AlgEd25519:            "ed25519",
	wire.AlgDHKEMP256:          "dhkem-p256",
	wire.AlgMLDSA65:            "ml-dsa-65",
	wire.AlgMLDSA87:            "ml-dsa-87",
	wire.AlgMLKEM768:           "ml-kem-768",
	wire.AlgMLKEM1024:          "ml-kem-1024",
	wire.AlgHybridP256MLKEM768: "hybrid-p256-ml-kem-768",
}

type cli struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	opts   node.Options
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kmsctl", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", os.Getenv("KMS_DIR"), "node directory (default $KMS_DIR)")
	corePath := fs.String("core", os.Getenv("KMS_CORE"), "kms-core binary (default $KMS_CORE or next to kmsctl)")
	allowUnlocked := fs.Bool("allow-unlocked-memory", runtime.GOOS == "darwin", "run the core without locked memory")
	timeout := fs.Duration("timeout", 10*time.Second, "core call timeout")
	fs.Usage = func() { fmt.Fprint(stderr, usageText) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fs.Usage()
		return 2
	}
	if rest[0] == "version" {
		fmt.Fprintf(stdout, "kmsctl %s (go %s, go_fips=%v)\n", version, runtime.Version(), fips140.Enabled())
		return 0
	}
	if *dir == "" {
		fmt.Fprintln(stderr, "kmsctl: --dir or $KMS_DIR is required")
		return 2
	}
	if *corePath == "" {
		if exe, err := os.Executable(); err == nil {
			*corePath = filepath.Join(filepath.Dir(exe), "kms-core")
		}
	}
	c := &cli{stdin: stdin, stdout: stdout, stderr: stderr, opts: node.Options{
		Dir:                 *dir,
		CoreBinary:          *corePath,
		AllowUnlockedMemory: *allowUnlocked,
		Timeout:             *timeout,
		Stderr:              stderr,
	}}
	code, err := c.dispatch(rest)
	if err != nil {
		fmt.Fprintf(stderr, "kmsctl: %v\n", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

func (c *cli) dispatch(args []string) (int, error) {
	ctx := context.Background()
	switch args[0] {
	case "init":
		return c.cmdInit(ctx, args[1:])
	case "card":
		return c.cmdCard(ctx, args[1:])
	case "member":
		if len(args) < 2 {
			return 2, errors.New("member: subcommand required (add, list)")
		}
		switch args[1] {
		case "add":
			return c.cmdMemberAdd(ctx, args[2:])
		case "list":
			return c.cmdMemberList(ctx, args[2:])
		}
		return 2, fmt.Errorf("member: unknown subcommand %q", args[1])
	case "key":
		if len(args) < 2 {
			return 2, errors.New("key: subcommand required (gen, list, info, send, receive)")
		}
		switch args[1] {
		case "gen":
			return c.cmdKeyGen(ctx, args[2:])
		case "list":
			return c.cmdKeyList(ctx, args[2:])
		case "info":
			return c.cmdKeyInfo(ctx, args[2:])
		case "send":
			return c.cmdKeySend(ctx, args[2:])
		case "receive":
			return c.cmdKeyReceive(ctx, args[2:])
		case "push":
			return c.cmdKeyPush(ctx, args[2:])
		}
		return 2, fmt.Errorf("key: unknown subcommand %q", args[1])
	case "inbox":
		if len(args) < 2 {
			return 2, errors.New("inbox: subcommand required (list, accept, reject)")
		}
		switch args[1] {
		case "list":
			return c.cmdInboxList(ctx, args[2:])
		case "accept":
			return c.cmdInboxAccept(ctx, args[2:])
		case "reject":
			return c.cmdInboxReject(ctx, args[2:])
		}
		return 2, fmt.Errorf("inbox: unknown subcommand %q", args[1])
	case "audit":
		if len(args) < 2 || args[1] != "verify" {
			return 2, errors.New("audit: subcommand required (verify)")
		}
		return c.cmdAuditVerify(ctx, args[2:])
	case "peer":
		if len(args) < 2 || args[1] != "health" {
			return 2, errors.New("peer: subcommand required (health)")
		}
		return c.cmdPeerHealth(ctx, args[2:])
	case "encrypt":
		return c.cmdCrypt(ctx, args[1:], true)
	case "decrypt":
		return c.cmdCrypt(ctx, args[1:], false)
	}
	fmt.Fprint(c.stderr, usageText)
	return 2, fmt.Errorf("unknown command %q", args[0])
}

func (c *cli) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	return fs
}

func (c *cli) open(ctx context.Context) (*node.Node, error) {
	return node.Open(ctx, c.opts)
}

func (c *cli) cmdInit(ctx context.Context, args []string) (int, error) {
	fs := c.flags("init")
	id := fs.String("id", "", "member id")
	pqc := fs.Bool("pqc", false, "use post-quantum identity and kem algorithms")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2, errors.New("init: invalid arguments")
	}
	if *id == "" {
		return 2, errors.New("init: --id is required")
	}
	n, err := node.Init(ctx, c.opts, *id, *pqc)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	card, _, err := n.Card(ctx)
	if err != nil {
		return 1, err
	}
	fp, err := card.Fingerprint()
	if err != nil {
		return 1, err
	}
	fmt.Fprintf(c.stdout, "member\t%s\nidentity\t%s\nkem\t%s\ncore_fips\t%v\ngo_fips\t%v\npqc\t%v\nfingerprint\t%s\n",
		card.MemberID, algName(card.IdentityAlg), algName(card.KemAlg), n.FIPS(), fips140.Enabled(), n.PQC(), fp)
	return 0, nil
}

func (c *cli) cmdCard(ctx context.Context, args []string) (int, error) {
	fs := c.flags("card")
	out := fs.String("out", "", "output file (default stdout)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2, errors.New("card: invalid arguments")
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	card, raw, err := n.Card(ctx)
	if err != nil {
		return 1, err
	}
	fp, _ := card.Fingerprint()
	if err := c.writeOut(*out, raw); err != nil {
		return 1, err
	}
	fmt.Fprintf(c.stderr, "member\t%s\nfingerprint\t%s\n", card.MemberID, fp)
	return 0, nil
}

func (c *cli) cmdMemberAdd(ctx context.Context, args []string) (int, error) {
	fs := c.flags("member add")
	cardPath := fs.String("card", "", "member card file")
	fp := fs.String("fingerprint", "", "fingerprint verified out of band")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2, errors.New("member add: invalid arguments")
	}
	if *cardPath == "" || *fp == "" {
		return 2, errors.New("member add: --card and --fingerprint are required")
	}
	raw, err := c.readIn(*cardPath)
	if err != nil {
		return 1, err
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	rec, err := n.AddMember(ctx, raw, *fp)
	if err != nil {
		return 1, err
	}
	fmt.Fprintf(c.stdout, "added\t%s\t%s\n", rec.MemberID, rec.Fingerprint)
	return 0, nil
}

func (c *cli) cmdMemberList(ctx context.Context, args []string) (int, error) {
	if len(args) != 0 {
		return 2, errors.New("member list: no arguments expected")
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	members, err := n.Members()
	if err != nil {
		return 1, err
	}
	for _, m := range members {
		card, err := n.Member(ctx, m.MemberID)
		if err != nil {
			return 1, fmt.Errorf("member %s: %w", m.MemberID, err)
		}
		fmt.Fprintf(c.stdout, "%s\t%s\t%s\t%s\n", m.MemberID, algName(card.IdentityAlg), algName(card.KemAlg), m.Fingerprint)
	}
	return 0, nil
}

func (c *cli) cmdKeyGen(ctx context.Context, args []string) (int, error) {
	fs := c.flags("key gen")
	label := fs.String("label", "", "key label")
	usage := fs.String("usage", "encrypt,decrypt,export", "comma separated usage list")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2, errors.New("key gen: invalid arguments")
	}
	bits, err := parseUsage(*usage)
	if err != nil {
		return 2, err
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	rec, err := n.GenerateKey(ctx, *label, bits)
	if err != nil {
		return 1, err
	}
	fmt.Fprintf(c.stdout, "%s\t%s\t%s\t%s\n", rec.KeyID, algName(rec.Alg), formatUsage(rec.Usage), rec.Label)
	return 0, nil
}

func (c *cli) cmdKeyList(ctx context.Context, args []string) (int, error) {
	if len(args) != 0 {
		return 2, errors.New("key list: no arguments expected")
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	keys, err := n.Keys()
	if err != nil {
		return 1, err
	}
	for _, k := range keys {
		origin := "local"
		if k.Origin != nil {
			origin = "from " + k.Origin.Sender
		}
		fmt.Fprintf(c.stdout, "%s\t%s\t%s\t%s\t%s\n", k.KeyID, algName(k.Alg), formatUsage(k.Usage), k.Label, origin)
	}
	return 0, nil
}

func (c *cli) cmdKeyInfo(ctx context.Context, args []string) (int, error) {
	fs := c.flags("key info")
	id := fs.String("id", "", "key id")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *id == "" {
		return 2, errors.New("key info: --id is required")
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	k, err := n.Key(ctx, *id)
	if err != nil {
		return 1, err
	}
	fmt.Fprintf(c.stdout, "id\t%s\nalg\t%s\nusage\t%s\nlabel\t%s\ncreated\t%s\n", k.KeyID, algName(k.Alg), formatUsage(k.Usage), k.Label, time.Unix(k.CreatedAt, 0).UTC().Format(time.RFC3339))
	if k.Origin != nil {
		fmt.Fprintf(c.stdout, "origin\t%s\t%s\n", k.Origin.Sender, time.Unix(k.Origin.SentAt, 0).UTC().Format(time.RFC3339))
	}
	return 0, nil
}

func (c *cli) cmdKeySend(ctx context.Context, args []string) (int, error) {
	fs := c.flags("key send")
	id := fs.String("id", "", "key id")
	to := fs.String("to", "", "recipient member id")
	usage := fs.String("usage", "decrypt", "usage granted to the recipient")
	out := fs.String("out", "", "output file (default stdout)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2, errors.New("key send: invalid arguments")
	}
	if *id == "" || *to == "" {
		return 2, errors.New("key send: --id and --to are required")
	}
	bits, err := parseUsage(*usage)
	if err != nil {
		return 2, err
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	env, err := n.Send(ctx, *id, *to, bits)
	if err != nil {
		return 1, err
	}
	if err := c.writeOut(*out, env); err != nil {
		return 1, err
	}
	fmt.Fprintf(c.stderr, "sent\t%s\tto\t%s\tusage\t%s\n", *id, *to, formatUsage(bits))
	return 0, nil
}

func (c *cli) cmdKeyReceive(ctx context.Context, args []string) (int, error) {
	fs := c.flags("key receive")
	in := fs.String("in", "", "envelope file (default stdin)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2, errors.New("key receive: invalid arguments")
	}
	raw, err := c.readIn(*in)
	if err != nil {
		return 1, err
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	rec, err := n.Receive(ctx, raw)
	if err != nil {
		return 1, err
	}
	fmt.Fprintf(c.stdout, "%s\t%s\t%s\t%s\tfrom %s\n", rec.KeyID, algName(rec.Alg), formatUsage(rec.Usage), rec.Label, rec.Origin.Sender)
	return 0, nil
}

func (c *cli) cmdKeyPush(ctx context.Context, args []string) (int, error) {
	fs := c.flags("key push")
	id := fs.String("id", "", "key id")
	to := fs.String("to", "", "recipient member id")
	url := fs.String("url", "", "recipient kmsd base url")
	usage := fs.String("usage", "decrypt", "usage granted to the recipient")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2, errors.New("key push: invalid arguments")
	}
	if *id == "" || *to == "" || *url == "" {
		return 2, errors.New("key push: --id, --to and --url are required")
	}
	if !strings.HasPrefix(*url, "https://") {
		return 2, errors.New("key push: --url must use https")
	}
	bits, err := parseUsage(*usage)
	if err != nil {
		return 2, err
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	env, err := n.Send(ctx, *id, *to, bits)
	if err != nil {
		return 1, err
	}
	envID, err := api.NewClient(n, nil).Push(ctx, strings.TrimRight(*url, "/"), *to, env)
	if err != nil {
		return 1, err
	}
	fmt.Fprintf(c.stdout, "pushed\t%s\tto\t%s\tenvelope\t%s\n", *id, *to, envID)
	return 0, nil
}

func (c *cli) cmdInboxList(ctx context.Context, args []string) (int, error) {
	if len(args) != 0 {
		return 2, errors.New("inbox list: no arguments expected")
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	items, err := n.Inbox()
	if err != nil {
		return 1, err
	}
	for _, it := range items {
		fmt.Fprintf(c.stdout, "%s\t%s\t%s\t%s\n", it.ID, it.Sender, time.Unix(it.SentAt, 0).UTC().Format(time.RFC3339), time.Unix(it.ReceivedAt, 0).UTC().Format(time.RFC3339))
	}
	return 0, nil
}

func (c *cli) cmdInboxAccept(ctx context.Context, args []string) (int, error) {
	fs := c.flags("inbox accept")
	id := fs.String("id", "", "envelope id")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *id == "" {
		return 2, errors.New("inbox accept: --id is required")
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	rec, err := n.Accept(ctx, *id)
	if err != nil {
		return 1, err
	}
	fmt.Fprintf(c.stdout, "%s\t%s\t%s\t%s\tfrom %s\n", rec.KeyID, algName(rec.Alg), formatUsage(rec.Usage), rec.Label, rec.Origin.Sender)
	return 0, nil
}

func (c *cli) cmdInboxReject(ctx context.Context, args []string) (int, error) {
	fs := c.flags("inbox reject")
	id := fs.String("id", "", "envelope id")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *id == "" {
		return 2, errors.New("inbox reject: --id is required")
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	if err := n.Reject(ctx, *id); err != nil {
		return 1, err
	}
	fmt.Fprintf(c.stdout, "rejected\t%s\n", *id)
	return 0, nil
}

func (c *cli) cmdPeerHealth(ctx context.Context, args []string) (int, error) {
	fs := c.flags("peer health")
	member := fs.String("member", "", "member id")
	url := fs.String("url", "", "member kmsd base url")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *member == "" || *url == "" {
		return 2, errors.New("peer health: --member and --url are required")
	}
	if !strings.HasPrefix(*url, "https://") {
		return 2, errors.New("peer health: --url must use https")
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	if err := api.NewClient(n, nil).Health(ctx, strings.TrimRight(*url, "/"), *member); err != nil {
		return 1, err
	}
	fmt.Fprintf(c.stdout, "ok\t%s\n", *member)
	return 0, nil
}

func (c *cli) cmdAuditVerify(ctx context.Context, args []string) (int, error) {
	if len(args) != 0 {
		return 2, errors.New("audit verify: no arguments expected")
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	count, err := n.VerifyAudit()
	if err != nil {
		return 1, err
	}
	fmt.Fprintf(c.stdout, "verified\t%d\tentries\n", count)
	return 0, nil
}

func (c *cli) cmdCrypt(ctx context.Context, args []string, encrypt bool) (int, error) {
	name := "decrypt"
	if encrypt {
		name = "encrypt"
	}
	fs := c.flags(name)
	id := fs.String("id", "", "key id")
	in := fs.String("in", "", "input file (default stdin)")
	out := fs.String("out", "", "output file (default stdout)")
	aad := fs.String("aad", "", "associated data")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *id == "" {
		return 2, fmt.Errorf("%s: --id is required", name)
	}
	data, err := c.readIn(*in)
	if err != nil {
		return 1, err
	}
	n, err := c.open(ctx)
	if err != nil {
		return 1, err
	}
	defer n.Close()
	var result []byte
	if encrypt {
		result, err = n.Encrypt(ctx, *id, data, []byte(*aad))
	} else {
		result, err = n.Decrypt(ctx, *id, data, []byte(*aad))
	}
	if err != nil {
		return 1, err
	}
	if err := c.writeOut(*out, result); err != nil {
		return 1, err
	}
	return 0, nil
}

const maxInput = 1 << 20

func (c *cli) readIn(path string) ([]byte, error) {
	var r io.Reader = c.stdin
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, maxInput+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxInput {
		return nil, fmt.Errorf("input exceeds %d bytes", maxInput)
	}
	return b, nil
}

func (c *cli) writeOut(path string, data []byte) error {
	if path == "" {
		_, err := c.stdout.Write(data)
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func parseUsage(s string) (uint32, error) {
	var bits uint32
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		b, ok := usageNames[part]
		if !ok {
			return 0, fmt.Errorf("unknown usage %q", part)
		}
		bits |= b
	}
	if bits == 0 {
		return 0, errors.New("usage list is empty")
	}
	return bits, nil
}

func formatUsage(bits uint32) string {
	var parts []string
	for _, name := range usageOrder {
		if bits&usageNames[name] != 0 {
			parts = append(parts, name)
		}
	}
	return strings.Join(parts, ",")
}

func algName(alg uint16) string {
	if s, ok := algNames[alg]; ok {
		return s
	}
	return fmt.Sprintf("0x%04x", alg)
}
