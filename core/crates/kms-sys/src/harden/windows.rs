use core::ptr::null_mut;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::Authorization::{SE_KERNEL_OBJECT, SetSecurityInfo};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX, SetErrorMode,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};

use crate::error::Error;
use crate::win::SecurityDescriptor;

const PROCESS_SDDL: &str = "D:P(A;;GA;;;SY)(A;;0x00121001;;;OW)";
const THREAD_SDDL: &str = "D:P(A;;GA;;;SY)(A;;0x00120801;;;OW)";

pub fn restrict_umask() {}

pub fn disable_core_dumps() -> Result<(), Error> {
    unsafe {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    }
    Ok(())
}

pub fn deny_ptrace() -> Result<(), Error> {
    restrict_object(unsafe { GetCurrentProcess() }, PROCESS_SDDL)?;
    restrict_object(unsafe { GetCurrentThread() }, THREAD_SDDL)
}

fn restrict_object(handle: HANDLE, sddl: &str) -> Result<(), Error> {
    let descriptor = SecurityDescriptor::from_sddl(sddl)?;
    let dacl = descriptor.dacl()?;
    let rc = unsafe {
        SetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl,
            null_mut(),
        )
    };
    if rc != 0 {
        return Err(Error::code("SetSecurityInfo", rc));
    }
    Ok(())
}

pub fn no_new_privs() -> Result<(), Error> {
    Ok(())
}

pub fn lock_all_memory() -> Result<(), Error> {
    Err(Error::unsupported("VirtualLock"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        PROCESS_VM_READ,
    };

    use super::{deny_ptrace, disable_core_dumps, lock_all_memory, no_new_privs, restrict_umask};
    use crate::win;

    #[test]
    fn owner_keeps_only_limited_process_rights() {
        if win::current_user_sid().unwrap() == win::local_system_sid().unwrap() {
            return;
        }
        deny_ptrace().unwrap();
        no_new_privs().unwrap();
        let pid = unsafe { GetCurrentProcessId() };
        let denied = unsafe { OpenProcess(PROCESS_VM_READ, 0, pid) };
        assert!(denied.is_null());
        assert_eq!(unsafe { GetLastError() }, ERROR_ACCESS_DENIED);
        let allowed = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                0,
                pid,
            )
        };
        assert!(!allowed.is_null());
        unsafe {
            CloseHandle(allowed);
        }
    }

    #[test]
    fn core_dumps_and_umask_are_no_ops() {
        disable_core_dumps().unwrap();
        restrict_umask();
    }

    #[test]
    fn memory_lock_is_reported_unsupported() {
        let err = lock_all_memory().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(err.op(), "VirtualLock");
    }
}
