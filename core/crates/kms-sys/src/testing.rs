use core::ptr::{null, null_mut};
use std::fs::File;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use crate::error::Error;
use crate::win;

pub fn pipe_pair(tag: &str) -> Result<(File, OwnedHandle), Error> {
    let name = win::wide(&format!(r"\\.\pipe\kms-sys-{}-{tag}", std::process::id()));
    let server = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            null(),
        )
    };
    if server == INVALID_HANDLE_VALUE {
        return Err(Error::last("CreateNamedPipeW"));
    }
    let server = unsafe { OwnedHandle::from_raw_handle(server) };
    let client = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            0,
            null_mut(),
        )
    };
    if client == INVALID_HANDLE_VALUE {
        return Err(Error::last("CreateFileW"));
    }
    let client = unsafe { OwnedHandle::from_raw_handle(client) };
    let rc = unsafe {
        SetHandleInformation(
            client.as_raw_handle(),
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        )
    };
    if rc == 0 {
        return Err(Error::last("SetHandleInformation"));
    }
    Ok((File::from(server), client))
}
