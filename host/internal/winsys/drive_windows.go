//go:build windows

package winsys

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

func IsRemotePath(abs string) (bool, error) {
	if strings.HasPrefix(abs, `\\`) {
		return true, nil
	}
	name, err := syscall.UTF16PtrFromString(abs)
	if err != nil {
		return false, err
	}
	var root [syscall.MAX_LONG_PATH]uint16
	r, _, e := procGetVolumePathNameW.Call(uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&root[0])), uintptr(len(root)))
	if r == 0 {
		return false, fmt.Errorf("winsys: volume of %s: %w", abs, e)
	}
	kind, _, _ := procGetDriveTypeW.Call(uintptr(unsafe.Pointer(&root[0])))
	return kind == driveRemote, nil
}
