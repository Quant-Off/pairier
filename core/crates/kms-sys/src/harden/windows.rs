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
    use core::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, GetLastError, HANDLE, LUID,
    };
    use windows_sys::Win32::Security::Authorization::SE_KERNEL_OBJECT;
    use windows_sys::Win32::Security::{
        GetTokenInformation, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_PRIVILEGES,
        TOKEN_QUERY, TokenPrivileges,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, PROCESS_VM_READ,
    };

    use super::{deny_ptrace, disable_core_dumps, lock_all_memory, no_new_privs, restrict_umask};
    use crate::win;

    fn debug_privilege_enabled() -> bool {
        let mut token: HANDLE = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
            return false;
        }
        let name = win::wide("SeDebugPrivilege");
        let mut luid: LUID = unsafe { core::mem::zeroed() };
        if unsafe { LookupPrivilegeValueW(null(), name.as_ptr(), &raw mut luid) } == 0 {
            unsafe { CloseHandle(token) };
            return false;
        }
        let mut needed: u32 = 0;
        unsafe {
            GetTokenInformation(token, TokenPrivileges, null_mut(), 0, &raw mut needed);
        }
        let words = usize::try_from(needed).unwrap().div_ceil(8);
        let mut buf = vec![0u64; words];
        let rc = unsafe {
            GetTokenInformation(
                token,
                TokenPrivileges,
                buf.as_mut_ptr().cast(),
                needed,
                &raw mut needed,
            )
        };
        unsafe { CloseHandle(token) };
        if rc == 0 {
            return false;
        }
        let privileges = unsafe { &*buf.as_ptr().cast::<TOKEN_PRIVILEGES>() };
        let first = privileges.Privileges.as_ptr();
        for i in 0..usize::try_from(privileges.PrivilegeCount).unwrap() {
            let entry = unsafe { &*first.add(i) };
            if entry.Luid.LowPart == luid.LowPart && entry.Luid.HighPart == luid.HighPart {
                return entry.Attributes & SE_PRIVILEGE_ENABLED != 0;
            }
        }
        false
    }

    #[test]
    fn process_dacl_limits_the_owner() {
        deny_ptrace().unwrap();
        no_new_privs().unwrap();
        let security =
            win::object_security(unsafe { GetCurrentProcess() }, SE_KERNEL_OBJECT).unwrap();
        let entries = security.dacl.unwrap();
        let sids: Vec<String> = entries.iter().map(|a| a.sid.display().unwrap()).collect();
        assert_eq!(entries.len(), 2, "{sids:?}");
        assert!(sids.contains(&"S-1-5-18".to_owned()), "{sids:?}");
        assert!(sids.contains(&"S-1-3-4".to_owned()), "{sids:?}");
        assert!(entries.iter().all(|a| a.kind == 0));
        let owner_rights = entries
            .iter()
            .find(|a| a.sid.display().unwrap() == "S-1-3-4")
            .unwrap();
        assert_eq!(owner_rights.mask & PROCESS_VM_READ, 0);

        if win::current_user_sid().unwrap() == win::local_system_sid().unwrap()
            || debug_privilege_enabled()
        {
            return;
        }
        let pid = unsafe { GetCurrentProcessId() };
        let denied = unsafe { OpenProcess(PROCESS_VM_READ, 0, pid) };
        assert!(denied.is_null(), "VM_READ granted to the owner");
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
