//go:build linux || darwin

package term

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/Quant-Off/pairier/host/internal/tui"
)

type winsize struct {
	Row, Col, X, Y uint16
}

func ioctl(fd, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

func getTermios(fd uintptr) (*syscall.Termios, error) {
	var t syscall.Termios
	if err := ioctl(fd, ioctlGetTermios, unsafe.Pointer(&t)); err != nil {
		return nil, err
	}
	return &t, nil
}

func setTermios(fd uintptr, t *syscall.Termios) error {
	return ioctl(fd, ioctlSetTermios, unsafe.Pointer(t))
}

func makeRaw(t *syscall.Termios) {
	t.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON
	t.Oflag &^= syscall.OPOST
	t.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	t.Cflag &^= syscall.CSIZE | syscall.PARENB
	t.Cflag |= syscall.CS8
	t.Cc[syscall.VMIN] = 1
	t.Cc[syscall.VTIME] = 0
}

func Open(in, out *os.File) (*TTY, error) {
	ifd, ofd := in.Fd(), out.Fd()
	old, err := getTermios(ifd)
	if err != nil {
		return nil, ErrNotTerminal
	}
	if _, err := getTermios(ofd); err != nil {
		return nil, ErrNotTerminal
	}
	raw := *old
	makeRaw(&raw)
	if err := setTermios(ifd, &raw); err != nil {
		return nil, fmt.Errorf("term: raw mode: %w", err)
	}
	t := newTTY(in, out)
	t.restore = func() error { return setTermios(ifd, old) }
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGWINCH)
	t.stop = func() { signal.Stop(sig) }
	chunks := make(chan []byte, 16)
	go t.read(chunks)
	go tui.Pump(chunks, t.send)
	go t.watch(sig)
	return t, nil
}

func (t *TTY) read(chunks chan<- []byte) {
	defer close(chunks)
	buf := make([]byte, 1024)
	for {
		n, err := t.in.Read(buf)
		if n > 0 {
			select {
			case chunks <- append([]byte(nil), buf[:n]...):
			case <-t.done:
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (t *TTY) watch(sig <-chan os.Signal) {
	for {
		select {
		case <-sig:
			if w, h, err := t.Size(); err == nil && !t.send(tui.ResizeEvent(w, h)) {
				return
			}
		case <-t.done:
			return
		}
	}
}

func (t *TTY) Size() (int, int, error) {
	var ws winsize
	if err := ioctl(t.out.Fd(), syscall.TIOCGWINSZ, unsafe.Pointer(&ws)); err != nil {
		return 0, 0, err
	}
	if ws.Col == 0 || ws.Row == 0 {
		return 80, 24, nil
	}
	return int(ws.Col), int(ws.Row), nil
}
