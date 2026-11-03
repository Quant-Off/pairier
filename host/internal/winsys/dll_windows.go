//go:build windows

package winsys

import "syscall"

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	advapi32 = syscall.NewLazyDLL("advapi32.dll")

	procCreateNamedPipeW            = kernel32.NewProc("CreateNamedPipeW")
	procConnectNamedPipe            = kernel32.NewProc("ConnectNamedPipe")
	procCreateEventW                = kernel32.NewProc("CreateEventW")
	procGetOverlappedResult         = kernel32.NewProc("GetOverlappedResult")
	procGetNamedPipeClientProcessId = kernel32.NewProc("GetNamedPipeClientProcessId")
	procLockFileEx                  = kernel32.NewProc("LockFileEx")
	procUnlockFileEx                = kernel32.NewProc("UnlockFileEx")
	procGetDriveTypeW               = kernel32.NewProc("GetDriveTypeW")
	procGetVolumePathNameW          = kernel32.NewProc("GetVolumePathNameW")
	procLocalFree                   = kernel32.NewProc("LocalFree")
	procGetNamedSecurityInfoW       = advapi32.NewProc("GetNamedSecurityInfoW")
	procSetNamedSecurityInfoW       = advapi32.NewProc("SetNamedSecurityInfoW")
	procConvertStringSDToSD         = advapi32.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	procGetSecurityDescriptorDacl   = advapi32.NewProc("GetSecurityDescriptorDacl")
	procGetAclInformation           = advapi32.NewProc("GetAclInformation")
	procGetAce                      = advapi32.NewProc("GetAce")
	procEqualSid                    = advapi32.NewProc("EqualSid")
)

const (
	seFileObject                     = 1
	ownerSecurityInformation         = 0x00000001
	daclSecurityInformation          = 0x00000004
	protectedDaclSecurityInfo        = 0x80000000
	sddlRevision1                    = 1
	aclSizeInformationClass          = 2
	accessAllowedAceType             = 0
	lockfileExclusiveLock            = 0x00000002
	driveRemote                      = 4
	pipeAccessDuplex                 = 0x00000003
	fileFlagFirstPipeInstance        = 0x00080000
	pipeTypeByte                     = 0x00000000
	pipeReadmodeByte                 = 0x00000000
	pipeWait                         = 0x00000000
	pipeRejectRemoteClients          = 0x00000008
	errorPipeConnected               = syscall.Errno(535)
	errorSharingViolation            = syscall.Errno(32)
	errorLockViolation               = syscall.Errno(33)
	errorInsufficientBuffer          = syscall.Errno(122)
	pipeBufferSize            uint32 = 64 * 1024
)
