use core::ptr::NonNull;

use crate::error::Error;

pub(super) fn page_size() -> Result<usize, Error> {
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(v)
        .ok()
        .filter(|p| *p > 0 && p.is_power_of_two())
        .ok_or_else(|| Error::unsupported("sysconf(_SC_PAGESIZE)"))
}

pub(super) unsafe fn map(len: usize) -> Result<NonNull<u8>, Error> {
    let raw = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if raw == libc::MAP_FAILED {
        return Err(Error::last("mmap"));
    }
    NonNull::new(raw.cast::<u8>()).ok_or_else(|| Error::invalid("mmap", "null map"))
}

pub(super) unsafe fn guard(ptr: *mut u8, len: usize) -> Result<(), Error> {
    if unsafe { libc::mprotect(ptr.cast(), len, libc::PROT_NONE) } != 0 {
        return Err(Error::last("mprotect"));
    }
    Ok(())
}

pub(super) unsafe fn lock(ptr: *mut u8, len: usize) -> Result<(), Error> {
    if unsafe { libc::mlock(ptr.cast(), len) } != 0 {
        return Err(Error::last("mlock"));
    }
    #[cfg(target_os = "linux")]
    if unsafe { libc::madvise(ptr.cast(), len, libc::MADV_DONTDUMP) } != 0 {
        return Err(Error::last("madvise(MADV_DONTDUMP)"));
    }
    Ok(())
}

pub(super) unsafe fn unlock(ptr: *mut u8, len: usize) {
    unsafe {
        libc::munlock(ptr.cast(), len);
    }
}

pub(super) unsafe fn unmap(base: *mut u8, len: usize) {
    unsafe {
        libc::munmap(base.cast(), len);
    }
}
