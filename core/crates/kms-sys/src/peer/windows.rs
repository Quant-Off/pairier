use core::ptr::null_mut;
use std::fs::File;
use std::io;
use std::os::windows::io::FromRawHandle;
use std::path::Path;

use windows_sys::Win32::Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation};
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeInfo, GetNamedPipeServerProcessId, PIPE_SERVER_END,
};

use super::PeerInfo;
use crate::error::Error;
use crate::win::{self, Sid};

pub(super) type RawStream = File;
pub(super) type Identity = Sid;

pub(super) fn current_identity() -> Result<Identity, Error> {
    win::current_user_sid()
}

pub(super) fn uid_identity(_uid: u32) -> Result<Identity, Error> {
    Err(Error::unsupported("--peer-uid"))
}

pub(super) fn inherited_fd(_fd: u64, _expected: &Identity) -> Result<(RawStream, PeerInfo), Error> {
    Err(Error::unsupported("--fd"))
}

pub(super) fn listen(
    _path: &Path,
    _expected: &Identity,
    _reject: &mut dyn FnMut(&str),
) -> Result<(RawStream, PeerInfo), Error> {
    Err(Error::unsupported("--socket"))
}

pub(super) fn inherited_handle(
    raw: u64,
    expected: &Identity,
) -> Result<(RawStream, PeerInfo), Error> {
    let addr = usize::try_from(raw)
        .map_err(|_| Error::invalid("inherited_handle", "handle out of range"))?;
    if addr == 0 || addr == usize::MAX {
        return Err(Error::invalid("inherited_handle", "invalid handle value"));
    }
    let handle: HANDLE = core::ptr::with_exposed_provenance_mut(addr);
    if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
        return Err(Error::invalid("inherited_handle", "handle is not a pipe"));
    }
    let mut flags: u32 = 0;
    let rc =
        unsafe { GetNamedPipeInfo(handle, &raw mut flags, null_mut(), null_mut(), null_mut()) };
    if rc == 0 {
        return Err(Error::last("GetNamedPipeInfo"));
    }
    if flags & PIPE_SERVER_END != 0 {
        return Err(Error::invalid(
            "inherited_handle",
            "handle is the server end of the pipe",
        ));
    }
    let mut pid: u32 = 0;
    if unsafe { GetNamedPipeServerProcessId(handle, &raw mut pid) } == 0 {
        return Err(Error::last("GetNamedPipeServerProcessId"));
    }
    let peer = win::process_user_sid(pid)?;
    if peer != *expected {
        return Err(Error::message(
            "peer identity",
            io::ErrorKind::PermissionDenied,
            format!(
                "peer user {} does not match expected user {}",
                peer.display()?,
                expected.display()?
            ),
        ));
    }
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(Error::last("SetHandleInformation"));
    }
    let file = unsafe { File::from_raw_handle(handle) };
    Ok((file, PeerInfo { pid: Some(pid) }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use core::ptr::{null, null_mut};
    use std::io::{Read, Write};
    use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle};

    use windows_sys::Win32::Foundation::{
        GENERIC_READ, GENERIC_WRITE, GetHandleInformation, HANDLE_FLAG_INHERIT,
        INVALID_HANDLE_VALUE, SetHandleInformation,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    use super::{current_identity, inherited_fd, inherited_handle, uid_identity};
    use crate::win;

    fn pipe_pair(tag: &str) -> (OwnedHandle, OwnedHandle) {
        let name = win::wide(&format!(
            r"\\.\pipe\kms-sys-test-{}-{tag}",
            std::process::id()
        ));
        let server = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                0,
                null(),
            )
        };
        assert_ne!(server, INVALID_HANDLE_VALUE);
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
        assert_ne!(client, INVALID_HANDLE_VALUE);
        unsafe {
            (
                OwnedHandle::from_raw_handle(server),
                OwnedHandle::from_raw_handle(client),
            )
        }
    }

    fn raw(h: RawHandle) -> u64 {
        u64::try_from(h.expose_provenance()).unwrap()
    }

    #[test]
    fn accepts_client_end_and_clears_inheritance() {
        let (server, client) = pipe_pair("ok");
        unsafe {
            SetHandleInformation(
                client.as_raw_handle(),
                HANDLE_FLAG_INHERIT,
                HANDLE_FLAG_INHERIT,
            );
        }
        let value = raw(client.as_raw_handle());
        let client_raw = client.into_raw_handle();
        let me = current_identity().unwrap();
        let (mut stream, info) = inherited_handle(value, &me).unwrap();
        assert_eq!(info.pid, Some(std::process::id()));
        let mut flags: u32 = 0;
        assert_ne!(
            unsafe { GetHandleInformation(client_raw, &raw mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);

        let mut server = unsafe { std::fs::File::from_raw_handle(server.into_raw_handle()) };
        server.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        stream.write_all(b"pong").unwrap();
        server.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[test]
    fn rejects_server_end_non_pipes_and_bad_values() {
        let me = current_identity().unwrap();
        let (server, _client) = pipe_pair("server");
        assert!(inherited_handle(raw(server.as_raw_handle()), &me).is_err());
        let path = std::env::temp_dir().join(format!("kms-sys-peer-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        assert!(inherited_handle(raw(file.as_raw_handle()), &me).is_err());
        drop(file);
        std::fs::remove_file(&path).unwrap();
        assert!(inherited_handle(0, &me).is_err());
        assert!(inherited_handle(u64::MAX, &me).is_err());
        assert!(inherited_fd(3, &me).is_err());
        assert!(uid_identity(0).is_err());
    }
}
