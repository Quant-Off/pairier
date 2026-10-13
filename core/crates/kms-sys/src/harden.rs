use std::ffi::OsString;

use crate::error::Error;

pub fn restrict_umask() {
    unsafe {
        libc::umask(0o077);
    }
}

pub fn disable_core_dumps() -> Result<(), Error> {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const lim) };
    if rc != 0 {
        return Err(Error::last("setrlimit(RLIMIT_CORE)"));
    }
    Ok(())
}

pub fn core_dump_limit() -> Result<u64, Error> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut lim) };
    if rc != 0 {
        return Err(Error::last("getrlimit(RLIMIT_CORE)"));
    }
    Ok(lim.rlim_cur)
}

#[cfg(target_os = "linux")]
pub fn deny_ptrace() -> Result<(), Error> {
    let zero: libc::c_ulong = 0;
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, zero, zero, zero, zero) };
    if rc != 0 {
        return Err(Error::last("prctl(PR_SET_DUMPABLE)"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn deny_ptrace() -> Result<(), Error> {
    let rc = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, core::ptr::null_mut(), 0) };
    if rc != 0 {
        return Err(Error::last("ptrace(PT_DENY_ATTACH)"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn no_new_privs() -> Result<(), Error> {
    let one: libc::c_ulong = 1;
    let zero: libc::c_ulong = 0;
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero, zero, zero) };
    if rc != 0 {
        return Err(Error::last("prctl(PR_SET_NO_NEW_PRIVS)"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn no_new_privs() -> Result<(), Error> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn lock_all_memory() -> Result<(), Error> {
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc != 0 {
        return Err(Error::last("mlockall"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn lock_all_memory() -> Result<(), Error> {
    Err(Error::unsupported("mlockall"))
}

pub fn scrub_environment(keep: &[&str]) {
    let keys: Vec<OsString> = std::env::vars_os()
        .map(|(k, _)| k)
        .filter(|k| !keep.iter().any(|want| k.as_os_str() == *want))
        .collect();
    for k in keys {
        unsafe {
            std::env::remove_var(&k);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        core_dump_limit, deny_ptrace, disable_core_dumps, lock_all_memory, no_new_privs,
        restrict_umask,
    };

    #[test]
    fn core_dumps_are_disabled() {
        disable_core_dumps().unwrap();
        assert_eq!(core_dump_limit().unwrap(), 0);
        disable_core_dumps().unwrap();
    }

    #[test]
    fn ptrace_denied_and_privs_locked() {
        deny_ptrace().unwrap();
        no_new_privs().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memory_can_be_locked() {
        lock_all_memory().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn memory_lock_is_reported_unsupported() {
        let err = lock_all_memory().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        assert_eq!(err.op(), "mlockall");
    }

    #[test]
    fn umask_is_restrictive() {
        restrict_umask();
        let prev = unsafe { libc::umask(0o077) };
        assert_eq!(prev, 0o077);
    }
}
