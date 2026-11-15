use std::ffi::OsString;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{
    core_dump_limit, deny_ptrace, disable_core_dumps, lock_all_memory, no_new_privs, restrict_umask,
};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{deny_ptrace, disable_core_dumps, lock_all_memory, no_new_privs, restrict_umask};

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
