use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use kms_sys::peer::{self, PeerCred};

use crate::args::Transport;

const STICKY: u32 = 0o1000;
const GROUP_OTHER_WRITE: u32 = 0o022;
const CROSS_UID_SOCKET_MODE: u32 = 0o666;

pub(crate) fn acquire(t: &Transport, expected_uid: u32) -> Result<(UnixStream, PeerCred), String> {
    let (stream, cred) = match t {
        Transport::Fd(fd) => {
            let s = peer::inherited_socket(*fd).map_err(|e| e.to_string())?;
            let cred = peer::peer_credentials(&s).map_err(|e| e.to_string())?;
            if cred.uid != expected_uid {
                return Err(mismatch(cred.uid, expected_uid));
            }
            (s, cred)
        }
        Transport::Socket(path) => listen(path, expected_uid)?,
    };
    peer::close_other_fds(&[0, 1, 2, stream.as_raw_fd()]).map_err(|e| e.to_string())?;
    Ok((stream, cred))
}

fn mismatch(got: u32, want: u32) -> String {
    format!("peer uid {got} does not match expected uid {want}")
}

fn check_parent(path: &Path) -> Result<(), String> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let md = fs::symlink_metadata(parent)
        .map_err(|e| format!("socket directory {}: {e}", parent.display()))?;
    if !md.file_type().is_dir() {
        return Err(format!(
            "socket directory {} is not a directory",
            parent.display()
        ));
    }
    if md.uid() != peer::current_uid() && md.uid() != 0 {
        return Err(format!(
            "socket directory {} must be owned by this user or root",
            parent.display()
        ));
    }
    if md.mode() & GROUP_OTHER_WRITE != 0 && md.mode() & STICKY == 0 {
        return Err(format!(
            "socket directory {} is writable by other users",
            parent.display()
        ));
    }
    Ok(())
}

fn listen(path: &Path, expected_uid: u32) -> Result<(UnixStream, PeerCred), String> {
    check_parent(path)?;
    let listener = UnixListener::bind(path).map_err(|e| format!("bind {}: {e}", path.display()))?;
    let md = fs::symlink_metadata(path).map_err(|e| format!("socket {}: {e}", path.display()))?;
    let identity = (md.dev(), md.ino());
    let accepted = open_to(path, expected_uid).and_then(|()| accept_peer(&listener, expected_uid));
    drop(listener);
    let removed = remove_if_same(path, identity);
    let (stream, cred) = accepted?;
    removed?;
    Ok((stream, cred))
}

fn open_to(path: &Path, expected_uid: u32) -> Result<(), String> {
    if expected_uid == peer::current_uid() {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(CROSS_UID_SOCKET_MODE))
        .map_err(|e| format!("socket {}: {e}", path.display()))
}

fn accept_peer(
    listener: &UnixListener,
    expected_uid: u32,
) -> Result<(UnixStream, PeerCred), String> {
    loop {
        let (s, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        match peer::peer_credentials(&s) {
            Ok(c) if c.uid == expected_uid => return Ok((s, c)),
            Ok(c) => crate::log(&format!(
                "rejected connection: {}",
                mismatch(c.uid, expected_uid)
            )),
            Err(e) => crate::log(&format!("rejected connection: {e}")),
        }
    }
}

fn remove_if_same(path: &Path, identity: (u64, u64)) -> Result<(), String> {
    let md = fs::symlink_metadata(path).map_err(|e| format!("socket {}: {e}", path.display()))?;
    if !md.file_type().is_socket() || (md.dev(), md.ino()) != identity {
        return Err(format!(
            "socket path {} was replaced; refusing to remove it",
            path.display()
        ));
    }
    fs::remove_file(path).map_err(|e| format!("socket {}: {e}", path.display()))
}
