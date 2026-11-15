//go:build windows

package winsys

import (
	"fmt"
	"syscall"
	"unsafe"
)

func CurrentUserSID() (*syscall.SID, error) {
	tok, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return nil, fmt.Errorf("winsys: open process token: %w", err)
	}
	defer tok.Close()
	user, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("winsys: token user: %w", err)
	}
	sid, err := user.User.Sid.Copy()
	if err != nil {
		return nil, fmt.Errorf("winsys: copy sid: %w", err)
	}
	return sid, nil
}

func wellKnownSID(s string) *syscall.SID {
	sid, err := syscall.StringToSid(s)
	if err != nil {
		panic("winsys: invalid well known sid " + s)
	}
	return sid
}

var (
	localSystemSID    = wellKnownSID("S-1-5-18")
	administratorsSID = wellKnownSID("S-1-5-32-544")
)

func equalSID(a, b *syscall.SID) bool {
	if a == nil || b == nil {
		return false
	}
	r, _, _ := procEqualSid.Call(uintptr(unsafe.Pointer(a)), uintptr(unsafe.Pointer(b)))
	return r != 0
}
