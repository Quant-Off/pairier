package term

import (
	"bytes"
	"os"
	"syscall"
	"unsafe"
)

func openPTY() (*os.File, *os.File, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := ioctl(master.Fd(), syscall.TIOCPTYGRANT, nil); err != nil {
		master.Close()
		return nil, nil, err
	}
	if err := ioctl(master.Fd(), syscall.TIOCPTYUNLK, nil); err != nil {
		master.Close()
		return nil, nil, err
	}
	var name [128]byte
	if err := ioctl(master.Fd(), syscall.TIOCPTYGNAME, unsafe.Pointer(&name)); err != nil {
		master.Close()
		return nil, nil, err
	}
	path := string(name[:bytes.IndexByte(name[:], 0)])
	slave, err := os.OpenFile(path, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}
