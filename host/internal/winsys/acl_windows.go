//go:build windows

package winsys

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

var ErrInsecure = errors.New("winsys: object is accessible by other users")

type Policy struct {
	AllowAdministrators bool
}

type aclSizeInformation struct {
	AceCount      uint32
	AclBytesInUse uint32
	AclBytesFree  uint32
}

type aceHeader struct {
	Type  uint8
	Flags uint8
	Size  uint16
}

type accessAllowedAce struct {
	Header   aceHeader
	Mask     uint32
	SidStart uint32
}

func localFree(p uintptr) {
	if p != 0 {
		procLocalFree.Call(p)
	}
}

func CheckPath(path string, p Policy) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	me, err := CurrentUserSID()
	if err != nil {
		return err
	}
	var owner *syscall.SID
	var dacl *byte
	var sd uintptr
	r, _, _ := procGetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(name)),
		seFileObject,
		ownerSecurityInformation|daclSecurityInformation,
		uintptr(unsafe.Pointer(&owner)),
		0,
		uintptr(unsafe.Pointer(&dacl)),
		0,
		uintptr(unsafe.Pointer(&sd)),
	)
	if r != 0 {
		return fmt.Errorf("winsys: security info for %s: %w", path, syscall.Errno(r))
	}
	defer localFree(sd)
	if owner == nil || !equalSID(me, owner) {
		return fmt.Errorf("%w: %s is not owned by the current user", ErrInsecure, path)
	}
	if dacl == nil {
		return fmt.Errorf("%w: %s has no DACL", ErrInsecure, path)
	}
	return checkACL(dacl, me, p, path)
}

func checkACL(dacl *byte, me *syscall.SID, p Policy, path string) error {
	var info aclSizeInformation
	r, _, e := procGetAclInformation.Call(uintptr(unsafe.Pointer(dacl)), uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info), aclSizeInformationClass)
	if r == 0 {
		return fmt.Errorf("winsys: acl information: %w", e)
	}
	for i := uint32(0); i < info.AceCount; i++ {
		var header *aceHeader
		r, _, e := procGetAce.Call(uintptr(unsafe.Pointer(dacl)), uintptr(i), uintptr(unsafe.Pointer(&header)))
		if r == 0 || header == nil {
			return fmt.Errorf("winsys: ace %d: %w", i, e)
		}
		if header.Type != accessAllowedAceType {
			return fmt.Errorf("%w: %s has a DACL entry that is not an allow entry", ErrInsecure, path)
		}
		allowed := (*accessAllowedAce)(unsafe.Pointer(header))
		sid := (*syscall.SID)(unsafe.Pointer(&allowed.SidStart))
		switch {
		case equalSID(sid, me), equalSID(sid, localSystemSID):
		case p.AllowAdministrators && equalSID(sid, administratorsSID):
		default:
			return fmt.Errorf("%w: %s grants access to other users", ErrInsecure, path)
		}
	}
	return nil
}

type descriptor struct {
	sd uintptr
}

func newDescriptor(sddl string) (*descriptor, error) {
	text, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return nil, err
	}
	var sd uintptr
	r, _, e := procConvertStringSDToSD.Call(uintptr(unsafe.Pointer(text)), sddlRevision1, uintptr(unsafe.Pointer(&sd)), 0)
	if r == 0 || sd == 0 {
		return nil, fmt.Errorf("winsys: security descriptor: %w", e)
	}
	return &descriptor{sd: sd}, nil
}

func (d *descriptor) dacl() (uintptr, error) {
	var present, defaulted int32
	var dacl uintptr
	r, _, e := procGetSecurityDescriptorDacl.Call(d.sd, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted)))
	if r == 0 {
		return 0, fmt.Errorf("winsys: descriptor dacl: %w", e)
	}
	if present == 0 || dacl == 0 {
		return 0, errors.New("winsys: descriptor has no DACL")
	}
	return dacl, nil
}

func (d *descriptor) free() { localFree(d.sd) }

func privateSDDL(kind string, me *syscall.SID) (string, error) {
	s, err := me.String()
	if err != nil {
		return "", err
	}
	switch kind {
	case "dir":
		return fmt.Sprintf("O:%sD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%s)", s, s), nil
	case "file":
		return fmt.Sprintf("O:%sD:P(A;;FA;;;SY)(A;;FA;;;%s)", s, s), nil
	default:
		return fmt.Sprintf("O:%sD:P(A;;GA;;;SY)(A;;GA;;;%s)", s, s), nil
	}
}

func PrivateAttributes(kind string) (*syscall.SecurityAttributes, func(), error) {
	if ownerErr != nil {
		return nil, nil, ownerErr
	}
	me, err := CurrentUserSID()
	if err != nil {
		return nil, nil, err
	}
	sddl, err := privateSDDL(kind, me)
	if err != nil {
		return nil, nil, err
	}
	d, err := newDescriptor(sddl)
	if err != nil {
		return nil, nil, err
	}
	sa := &syscall.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(syscall.SecurityAttributes{})),
		SecurityDescriptor: d.sd,
		InheritHandle:      0,
	}
	return sa, d.free, nil
}

func SetPrivate(path string, kind string) error {
	if ownerErr != nil {
		return ownerErr
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	me, err := CurrentUserSID()
	if err != nil {
		return err
	}
	owner, free, err := pathOwner(path)
	if err != nil {
		return err
	}
	owned := equalSID(me, owner)
	free()
	if !owned {
		r, _, _ := procSetNamedSecurityInfoW.Call(
			uintptr(unsafe.Pointer(name)),
			seFileObject,
			ownerSecurityInformation,
			uintptr(unsafe.Pointer(me)),
			0,
			0,
			0,
		)
		if r != 0 {
			return fmt.Errorf("winsys: set owner for %s: %w", path, syscall.Errno(r))
		}
	}
	sddl, err := privateSDDL(kind, me)
	if err != nil {
		return err
	}
	d, err := newDescriptor(sddl)
	if err != nil {
		return err
	}
	defer d.free()
	dacl, err := d.dacl()
	if err != nil {
		return err
	}
	r, _, _ := procSetNamedSecurityInfoW.Call(
		uintptr(unsafe.Pointer(name)),
		seFileObject,
		daclSecurityInformation|protectedDaclSecurityInfo,
		0,
		0,
		dacl,
		0,
	)
	if r != 0 {
		return fmt.Errorf("winsys: set security info for %s: %w", path, syscall.Errno(r))
	}
	return nil
}
