//go:build windows

package winsys

import (
	"syscall"
	"unsafe"
)

const (
	ConsoleProcessedOutput           = 0x1
	ConsoleVirtualTerminalProcessing = 0x4
	ConsoleDisableNewlineAutoReturn  = 0x8
	ConsoleWindowInput               = 0x8

	KeyEventType        = 0x1
	BufferSizeEventType = 0x4
)

type InputRecord struct {
	EventType uint16
	_         uint16
	Event     [4]uint32
}

type KeyRecord struct {
	Down         bool
	Repeat       uint16
	VirtualKey   uint16
	Char         uint16
	ControlState uint32
}

func (r *InputRecord) Key() KeyRecord {
	return KeyRecord{
		Down:         r.Event[0] != 0,
		Repeat:       uint16(r.Event[1]),
		VirtualKey:   uint16(r.Event[1] >> 16),
		Char:         uint16(r.Event[2] >> 16),
		ControlState: r.Event[3],
	}
}

type consoleScreenBufferInfo struct {
	size       [2]int16
	cursor     [2]int16
	attributes uint16
	window     [4]int16
	maxWindow  [2]int16
}

func GetConsoleMode(h syscall.Handle) (uint32, error) {
	var m uint32
	err := syscall.GetConsoleMode(h, &m)
	return m, err
}

func SetConsoleMode(h syscall.Handle, mode uint32) error {
	r, _, err := procSetConsoleMode.Call(uintptr(h), uintptr(mode))
	if r == 0 {
		return err
	}
	return nil
}

func ConsoleWindowSize(h syscall.Handle) (int, int, error) {
	var info consoleScreenBufferInfo
	r, _, err := procGetConsoleScreenBufferInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&info)))
	if r == 0 {
		return 0, 0, err
	}
	return int(info.window[2]-info.window[0]) + 1, int(info.window[3]-info.window[1]) + 1, nil
}

func ReadConsoleInput(h syscall.Handle, recs []InputRecord) (int, error) {
	if len(recs) == 0 {
		return 0, nil
	}
	var n uint32
	r, _, err := procReadConsoleInputW.Call(uintptr(h), uintptr(unsafe.Pointer(&recs[0])), uintptr(len(recs)), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return 0, err
	}
	return int(n), nil
}

func UserUILanguage() uint16 {
	r, _, _ := procGetUserDefaultUILanguage.Call()
	return uint16(r)
}
