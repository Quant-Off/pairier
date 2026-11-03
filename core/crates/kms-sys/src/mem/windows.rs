use core::ffi::c_void;
use core::ptr::NonNull;

use windows_sys::Win32::Foundation::{ERROR_WORKING_SET_QUOTA, GetLastError};
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    VirtualAlloc, VirtualFree, VirtualLock, VirtualProtect, VirtualUnlock,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessWorkingSetSize, SetProcessWorkingSetSize,
};

use crate::error::Error;

const WORKING_SET_SLACK: usize = 1 << 20;

pub(super) fn page_size() -> Result<usize, Error> {
    let mut info: SYSTEM_INFO = unsafe { core::mem::zeroed() };
    unsafe { GetSystemInfo(&raw mut info) };
    usize::try_from(info.dwPageSize)
        .ok()
        .filter(|p| *p > 0 && p.is_power_of_two())
        .ok_or_else(|| Error::unsupported("GetSystemInfo"))
}

pub(super) unsafe fn map(len: usize) -> Result<NonNull<u8>, Error> {
    let raw = unsafe {
        VirtualAlloc(
            core::ptr::null(),
            len,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
    };
    NonNull::new(raw.cast::<u8>()).ok_or_else(|| Error::last("VirtualAlloc"))
}

pub(super) unsafe fn guard(ptr: *mut u8, len: usize) -> Result<(), Error> {
    let mut old: PAGE_PROTECTION_FLAGS = 0;
    let rc = unsafe {
        VirtualProtect(
            ptr.cast::<c_void>().cast_const(),
            len,
            PAGE_NOACCESS,
            &raw mut old,
        )
    };
    if rc == 0 {
        return Err(Error::last("VirtualProtect"));
    }
    Ok(())
}

pub(super) unsafe fn lock(ptr: *mut u8, len: usize) -> Result<(), Error> {
    let addr = ptr.cast::<c_void>().cast_const();
    if unsafe { VirtualLock(addr, len) } != 0 {
        return Ok(());
    }
    if unsafe { GetLastError() } != ERROR_WORKING_SET_QUOTA {
        return Err(Error::last("VirtualLock"));
    }
    grow_working_set(len)?;
    if unsafe { VirtualLock(addr, len) } == 0 {
        return Err(Error::last("VirtualLock"));
    }
    Ok(())
}

fn grow_working_set(extra: usize) -> Result<(), Error> {
    let overflow = || Error::invalid("SetProcessWorkingSetSize", "size overflow");
    let process = unsafe { GetCurrentProcess() };
    let mut min: usize = 0;
    let mut max: usize = 0;
    if unsafe { GetProcessWorkingSetSize(process, &raw mut min, &raw mut max) } == 0 {
        return Err(Error::last("GetProcessWorkingSetSize"));
    }
    let grow = extra.checked_add(WORKING_SET_SLACK).ok_or_else(overflow)?;
    let new_min = min.checked_add(grow).ok_or_else(overflow)?;
    let new_max = max.max(new_min).checked_add(grow).ok_or_else(overflow)?;
    if unsafe { SetProcessWorkingSetSize(process, new_min, new_max) } == 0 {
        return Err(Error::last("SetProcessWorkingSetSize"));
    }
    Ok(())
}

pub(super) unsafe fn unlock(ptr: *mut u8, len: usize) {
    let _ = unsafe { VirtualUnlock(ptr.cast::<c_void>().cast_const(), len) };
}

pub(super) unsafe fn unmap(base: *mut u8, _len: usize) {
    let _ = unsafe { VirtualFree(base.cast::<c_void>(), 0, MEM_RELEASE) };
}
