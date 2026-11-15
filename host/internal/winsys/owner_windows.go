//go:build windows

package winsys

import (
	"fmt"
	"syscall"
	"unsafe"
)

type tokenOwner struct {
	Owner *syscall.SID
}

var ownerErr = adoptOwner()

func adoptOwner() error {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return fmt.Errorf("winsys: current process: %w", err)
	}
	var tok syscall.Token
	if err := syscall.OpenProcessToken(process, syscall.TOKEN_QUERY|syscall.TOKEN_ADJUST_DEFAULT, &tok); err != nil {
		return fmt.Errorf("winsys: open process token: %w", err)
	}
	defer tok.Close()
	user, err := tok.GetTokenUser()
	if err != nil {
		return fmt.Errorf("winsys: token user: %w", err)
	}
	info := tokenOwner{Owner: user.User.Sid}
	r, _, e := procSetTokenInformation.Call(uintptr(tok), uintptr(syscall.TokenOwner), uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if r == 0 {
		return fmt.Errorf("winsys: set token owner: %w", e)
	}
	return nil
}

func pathOwner(path string) (*syscall.SID, func(), error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, nil, err
	}
	var owner *syscall.SID
	var sd uintptr
	r, _, _ := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(name)),
		seFileObject,
		ownerSecurityInformation,
		uintptr(unsafe.Pointer(&owner)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&sd)),
	)
	if r != 0 {
		return nil, nil, fmt.Errorf("winsys: security info for %s: %w", path, syscall.Errno(r))
	}
	return owner, func() { localFree(sd) }, nil
}
