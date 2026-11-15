//go:build windows

package winsys

import (
	"fmt"
	"syscall"
	"unsafe"
)

func Lock(h syscall.Handle) error {
	var ov syscall.Overlapped
	r, _, e := procLockFileEx.Call(uintptr(h), lockfileExclusiveLock, 0, 1, 0, uintptr(unsafe.Pointer(&ov)))
	if r == 0 {
		return fmt.Errorf("winsys: lock: %w", e)
	}
	return nil
}

func Unlock(h syscall.Handle) error {
	var ov syscall.Overlapped
	r, _, e := procUnlockFileEx.Call(uintptr(h), 0, 1, 0, uintptr(unsafe.Pointer(&ov)))
	if r == 0 {
		return fmt.Errorf("winsys: unlock: %w", e)
	}
	return nil
}
