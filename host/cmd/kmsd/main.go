package main

import (
	"context"
	"crypto/fips140"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/Quant-Off/pairier/host/internal/api"
	"github.com/Quant-Off/pairier/host/internal/config"
	"github.com/Quant-Off/pairier/host/internal/node"
)

var version = "dev"

const (
	defaultListen  = "127.0.0.1:7443"
	defaultTimeout = 10 * time.Second
	maxConns       = 64
)

type limitListener struct {
	net.Listener
	sem  chan struct{}
	done chan struct{}
	once sync.Once
}

func limit(ln net.Listener, n int) net.Listener {
	return &limitListener{Listener: ln, sem: make(chan struct{}, n), done: make(chan struct{})}
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.sem <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.sem
		return nil, err
	}
	return &limitConn{Conn: c, release: func() { <-l.sem }}, nil
}

func (l *limitListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

type limitConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

type settings struct {
	node   node.Options
	listen string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, nil))
}

func run(args []string, stdout, stderr io.Writer, ready func(addr string)) int {
	fs := flag.NewFlagSet("kmsd", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "configuration file (json)")
	dir := fs.String("dir", "", "node directory (default $KMS_DIR)")
	corePath := fs.String("core", "", "kms-core binary (default $KMS_CORE or next to kmsd)")
	listen := fs.String("listen", "", "listen address host:port")
	allowUnlocked := fs.Bool("allow-unlocked-memory", runtime.GOOS == "darwin", "run the core without locked memory")
	timeout := fs.Duration("timeout", defaultTimeout, "core call timeout")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintf(stdout, "kmsd %s (go %s, go_fips=%v)\n", version, runtime.Version(), fips140.Enabled())
		return 0
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "kmsd: unexpected arguments")
		return 2
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	s := settings{listen: defaultListen, node: node.Options{AllowUnlockedMemory: *allowUnlocked, Timeout: *timeout, Stderr: stderr}}
	if *cfgPath != "" {
		c, err := config.Load(*cfgPath)
		if err != nil {
			fmt.Fprintf(stderr, "kmsd: %v\n", err)
			return 2
		}
		s.node.Dir = c.Dir
		s.node.CoreBinary = c.Core
		if c.Listen != "" {
			s.listen = c.Listen
		}
		if c.AllowUnlockedMemory != nil {
			s.node.AllowUnlockedMemory = *c.AllowUnlockedMemory
		}
		s.node.Timeout = c.TimeoutDuration(*timeout)
	}
	if set["dir"] {
		s.node.Dir = *dir
	}
	if s.node.Dir == "" {
		s.node.Dir = os.Getenv("KMS_DIR")
	}
	if set["core"] {
		s.node.CoreBinary = *corePath
	}
	if s.node.CoreBinary == "" {
		s.node.CoreBinary = os.Getenv("KMS_CORE")
	}
	if set["listen"] {
		s.listen = *listen
	}
	if set["allow-unlocked-memory"] {
		s.node.AllowUnlockedMemory = *allowUnlocked
	}
	if set["timeout"] {
		s.node.Timeout = *timeout
	}
	if s.node.Dir == "" {
		fmt.Fprintln(stderr, "kmsd: --dir, config dir or $KMS_DIR is required")
		return 2
	}
	if s.node.CoreBinary == "" {
		if exe, err := os.Executable(); err == nil {
			s.node.CoreBinary = filepath.Join(filepath.Dir(exe), "kms-core")
		}
	}
	if err := (&config.Config{Listen: s.listen}).Validate(); err != nil {
		fmt.Fprintf(stderr, "kmsd: %v\n", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, s, stderr, ready); err != nil {
		fmt.Fprintf(stderr, "kmsd: %v\n", err)
		return 1
	}
	return 0
}

func serve(ctx context.Context, s settings, stderr io.Writer, ready func(addr string)) error {
	n, err := node.Open(ctx, s.node)
	if err != nil {
		return err
	}
	defer func() {
		if err := n.Close(); err != nil {
			fmt.Fprintf(stderr, "kmsd: close: %v\n", err)
		}
	}()
	srv := api.New(n, nil)
	tlsConfig, err := srv.TLSConfig()
	if err != nil {
		return err
	}
	hs := &http.Server{
		Handler:           srv.Handler(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	ln, err := net.Listen("tcp", s.listen)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "kmsd %s member %s listening on %s core_fips=%v go_fips=%v pqc=%v\n", version, n.MemberID(), ln.Addr(), n.FIPS(), fips140.Enabled(), n.PQC())
	if ready != nil {
		ready(ln.Addr().String())
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.ServeTLS(limit(ln, maxConns), "", "") }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutdownCtx); err != nil {
		_ = hs.Close()
	}
	fmt.Fprintln(stderr, "kmsd: stopped")
	return nil
}
