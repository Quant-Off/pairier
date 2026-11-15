//go:build windows

package winsys

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

type PipePair struct {
	Name   string
	Server syscall.Handle
	Client syscall.Handle
}

func NewPipePair() (*PipePair, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, fmt.Errorf("winsys: pipe name: %w", err)
	}
	name := `\\.\pipe\pairier-` + hex.EncodeToString(token[:])
	wname, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	sa, free, err := PrivateAttributes("pipe")
	if err != nil {
		return nil, err
	}
	defer free()
	r, _, e := procCreateNamedPipeW.Call(
		uintptr(unsafe.Pointer(wname)),
		pipeAccessDuplex|syscall.FILE_FLAG_OVERLAPPED|fileFlagFirstPipeInstance,
		pipeTypeByte|pipeReadmodeByte|pipeWait|pipeRejectRemoteClients,
		1,
		uintptr(pipeBufferSize),
		uintptr(pipeBufferSize),
		0,
		uintptr(unsafe.Pointer(sa)),
	)
	server := syscall.Handle(r)
	if server == syscall.InvalidHandle {
		return nil, fmt.Errorf("winsys: create pipe: %w", e)
	}
	client, err := syscall.CreateFile(wname, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		syscall.CloseHandle(server)
		return nil, fmt.Errorf("winsys: open pipe client: %w", err)
	}
	p := &PipePair{Name: name, Server: server, Client: client}
	if err := p.connect(); err != nil {
		p.Close()
		return nil, err
	}
	pid, err := p.ClientProcessID()
	if err != nil {
		p.Close()
		return nil, err
	}
	if pid != syscall.Getpid() {
		p.Close()
		return nil, errors.New("winsys: pipe was connected by another process")
	}
	if err := syscall.SetHandleInformation(client, syscall.HANDLE_FLAG_INHERIT, syscall.HANDLE_FLAG_INHERIT); err != nil {
		p.Close()
		return nil, fmt.Errorf("winsys: mark pipe client inheritable: %w", err)
	}
	return p, nil
}

func (p *PipePair) connect() error {
	r0, _, e0 := procCreateEventW.Call(0, 1, 0, 0)
	ev := syscall.Handle(r0)
	if ev == 0 {
		return fmt.Errorf("winsys: create event: %w", e0)
	}
	defer syscall.CloseHandle(ev)
	ov := syscall.Overlapped{HEvent: ev}
	r, _, e := procConnectNamedPipe.Call(uintptr(p.Server), uintptr(unsafe.Pointer(&ov)))
	if r != 0 {
		return nil
	}
	switch e {
	case errorPipeConnected:
		return nil
	case syscall.ERROR_IO_PENDING:
		var done uint32
		if r, _, e := procGetOverlappedResult.Call(uintptr(p.Server), uintptr(unsafe.Pointer(&ov)), uintptr(unsafe.Pointer(&done)), 1); r == 0 {
			return fmt.Errorf("winsys: connect pipe: %w", e)
		}
		return nil
	default:
		return fmt.Errorf("winsys: connect pipe: %w", e)
	}
}

func (p *PipePair) ClientProcessID() (int, error) {
	var pid uint32
	r, _, e := procGetNamedPipeClientProcessId.Call(uintptr(p.Server), uintptr(unsafe.Pointer(&pid)))
	if r == 0 {
		return 0, fmt.Errorf("winsys: pipe client process: %w", e)
	}
	return int(pid), nil
}

func (p *PipePair) CloseClient() {
	if p.Client != syscall.InvalidHandle {
		syscall.CloseHandle(p.Client)
		p.Client = syscall.InvalidHandle
	}
}

func (p *PipePair) Close() {
	p.CloseClient()
	if p.Server != syscall.InvalidHandle {
		syscall.CloseHandle(p.Server)
		p.Server = syscall.InvalidHandle
	}
}
