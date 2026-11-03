#![allow(clippy::trivially_copy_pass_by_ref, clippy::unnecessary_wraps)]

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use super::PeerInfo;
use crate::error::Error;

pub(super) type RawStream = UnixStream;
pub(super) type Identity = u32;

const STICKY: u32 = 0o1000;
const GROUP_OTHER_WRITE: u32 = 0o022;
const CROSS_UID_SOCKET_MODE: u32 = 0o666;

pub(super) fn current_identity() -> Result<Identity, Error> {
    Ok(current_uid())
}

pub(super) fn uid_identity(uid: u32) -> Result<Identity, Error> {
    Ok(uid)
}

pub(super) fn inherited_fd(fd: u64, expected: &Identity) -> Result<(RawStream, PeerInfo), Error> {
    let fd =
        RawFd::try_from(fd).map_err(|_| Error::invalid("inherited_socket", "fd out of range"))?;
    let stream = inherited_socket(fd)?;
    let cred = peer_credentials(&stream)?;
    if cred.uid != *expected {
        return Err(mismatch(cred.uid, *expected));
    }
    close_other_fds(&[0, 1, 2, stream.as_raw_fd()])?;
    Ok((stream, cred.info()))
}

pub(super) fn inherited_handle(
    _handle: u64,
    _expected: &Identity,
) -> Result<(RawStream, PeerInfo), Error> {
    Err(Error::unsupported("--handle"))
}

pub(super) fn listen(
    path: &Path,
    expected: &Identity,
    reject: &mut dyn FnMut(&str),
) -> Result<(RawStream, PeerInfo), Error> {
    check_parent(path)?;
    let listener = UnixListener::bind(path)
        .map_err(|e| Error::message("bind", e.kind(), format!("{}: {e}", path.display())))?;
    let md = socket_metadata(path)?;
    let identity = (md.dev(), md.ino());
    let accepted =
        open_to(path, *expected).and_then(|()| accept_peer(&listener, *expected, reject));
    drop(listener);
    let removed = remove_if_same(path, identity);
    let (stream, cred) = accepted?;
    removed?;
    close_other_fds(&[0, 1, 2, stream.as_raw_fd()])?;
    Ok((stream, cred.info()))
}

fn mismatch(got: u32, want: u32) -> Error {
    Error::message(
        "peer identity",
        io::ErrorKind::PermissionDenied,
        format!("peer uid {got} does not match expected uid {want}"),
    )
}

fn socket_metadata(path: &Path) -> Result<fs::Metadata, Error> {
    fs::symlink_metadata(path)
        .map_err(|e| Error::message("socket", e.kind(), format!("{}: {e}", path.display())))
}

fn check_parent(path: &Path) -> Result<(), Error> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let md = fs::symlink_metadata(parent).map_err(|e| {
        Error::message(
            "socket directory",
            e.kind(),
            format!("{}: {e}", parent.display()),
        )
    })?;
    let problem = if !md.file_type().is_dir() {
        Some("is not a directory")
    } else if md.uid() != current_uid() && md.uid() != 0 {
        Some("must be owned by this user or root")
    } else if md.mode() & GROUP_OTHER_WRITE != 0 && md.mode() & STICKY == 0 {
        Some("is writable by other users")
    } else {
        None
    };
    match problem {
        Some(why) => Err(Error::message(
            "socket directory",
            io::ErrorKind::PermissionDenied,
            format!("{} {why}", parent.display()),
        )),
        None => Ok(()),
    }
}

fn open_to(path: &Path, expected: u32) -> Result<(), Error> {
    if expected == current_uid() {
        return Ok(());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(CROSS_UID_SOCKET_MODE))
        .map_err(|e| Error::message("socket", e.kind(), format!("{}: {e}", path.display())))
}

fn accept_peer(
    listener: &UnixListener,
    expected: u32,
    reject: &mut dyn FnMut(&str),
) -> Result<(UnixStream, PeerCred), Error> {
    loop {
        let (s, _) = listener.accept().map_err(|e| Error::new("accept", e))?;
        match peer_credentials(&s) {
            Ok(c) if c.uid == expected => return Ok((s, c)),
            Ok(c) => reject(&mismatch(c.uid, expected).to_string()),
            Err(e) => reject(&e.to_string()),
        }
    }
}

fn remove_if_same(path: &Path, identity: (u64, u64)) -> Result<(), Error> {
    let md = socket_metadata(path)?;
    if !md.file_type().is_socket() || (md.dev(), md.ino()) != identity {
        return Err(Error::message(
            "socket",
            io::ErrorKind::AlreadyExists,
            format!("{} was replaced; refusing to remove it", path.display()),
        ));
    }
    fs::remove_file(path)
        .map_err(|e| Error::message("socket", e.kind(), format!("{}: {e}", path.display())))
}

fn socklen_of<T>() -> Result<libc::socklen_t, Error> {
    libc::socklen_t::try_from(size_of::<T>())
        .map_err(|_| Error::invalid("socklen", "size overflow"))
}

fn inherited_socket(fd: RawFd) -> Result<UnixStream, Error> {
    if fd < 0 {
        return Err(Error::invalid("inherited_socket", "negative fd"));
    }
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    if unsafe { libc::fstat(fd, &raw mut st) } != 0 {
        return Err(Error::last("fstat"));
    }
    if st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return Err(Error::invalid("inherited_socket", "fd is not a socket"));
    }

    let mut ty: libc::c_int = 0;
    let mut len = socklen_of::<libc::c_int>()?;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut ty).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(Error::last("getsockopt(SO_TYPE)"));
    }
    if ty != libc::SOCK_STREAM {
        return Err(Error::invalid(
            "inherited_socket",
            "socket is not SOCK_STREAM",
        ));
    }

    let mut addr: libc::sockaddr_storage = unsafe { core::mem::zeroed() };
    let mut alen = socklen_of::<libc::sockaddr_storage>()?;
    let rc = unsafe { libc::getsockname(fd, (&raw mut addr).cast(), &raw mut alen) };
    if rc != 0 {
        return Err(Error::last("getsockname"));
    }
    let af_unix = libc::sa_family_t::try_from(libc::AF_UNIX)
        .map_err(|_| Error::invalid("inherited_socket", "AF_UNIX overflow"))?;
    if addr.ss_family != af_unix {
        return Err(Error::invalid("inherited_socket", "socket is not AF_UNIX"));
    }

    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(Error::last("fcntl(F_GETFD)"));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(Error::last("fcntl(F_SETFD)"));
    }

    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerCred {
    uid: libc::uid_t,
    gid: libc::gid_t,
    pid: Option<libc::pid_t>,
}

impl PeerCred {
    fn info(self) -> PeerInfo {
        PeerInfo {
            pid: self.pid.and_then(|p| u32::try_from(p).ok()),
        }
    }
}

#[cfg(target_os = "linux")]
fn peer_credentials(sock: &UnixStream) -> Result<PeerCred, Error> {
    let fd = sock.as_raw_fd();
    let mut cred: libc::ucred = unsafe { core::mem::zeroed() };
    let want = socklen_of::<libc::ucred>()?;
    let mut len = want;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(Error::last("getsockopt(SO_PEERCRED)"));
    }
    if len != want {
        return Err(Error::invalid("getsockopt(SO_PEERCRED)", "short ucred"));
    }
    Ok(PeerCred {
        uid: cred.uid,
        gid: cred.gid,
        pid: Some(cred.pid),
    })
}

#[cfg(target_os = "macos")]
fn peer_credentials(sock: &UnixStream) -> Result<PeerCred, Error> {
    let fd = sock.as_raw_fd();
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    if unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) } != 0 {
        return Err(Error::last("getpeereid"));
    }
    let mut pid: libc::pid_t = 0;
    let mut len = socklen_of::<libc::pid_t>()?;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&raw mut pid).cast(),
            &raw mut len,
        )
    };
    let pid = if rc == 0 { Some(pid) } else { None };
    Ok(PeerCred { uid, gid, pid })
}

fn current_uid() -> libc::uid_t {
    unsafe { libc::getuid() }
}

#[cfg(target_os = "linux")]
fn close_other_fds(keep: &[RawFd]) -> Result<(), Error> {
    let mut keep: Vec<RawFd> = keep.iter().copied().filter(|f| *f >= 0).collect();
    keep.sort_unstable();
    keep.dedup();
    let mut lo: RawFd = 0;
    for k in keep {
        if k > lo {
            let last = k
                .checked_sub(1)
                .ok_or_else(|| Error::invalid("close_range", "fd underflow"))?;
            close_range(lo, last)?;
        }
        lo = k
            .checked_add(1)
            .ok_or_else(|| Error::invalid("close_range", "fd overflow"))?;
    }
    close_range(lo, RawFd::MAX)
}

#[cfg(target_os = "linux")]
fn close_range(first: RawFd, last: RawFd) -> Result<(), Error> {
    let first = libc::c_uint::try_from(first).map_err(|_| Error::invalid("close_range", "fd"))?;
    let last = libc::c_uint::try_from(last).map_err(|_| Error::invalid("close_range", "fd"))?;
    if unsafe { libc::close_range(first, last, 0) } != 0 {
        return Err(Error::last("close_range"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn close_other_fds(keep: &[RawFd]) -> Result<(), Error> {
    let max = unsafe { libc::getdtablesize() };
    if max < 0 {
        return Err(Error::last("getdtablesize"));
    }
    for fd in 0..max {
        if !keep.contains(&fd) {
            unsafe {
                libc::close(fd);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn fd_is_open(fd: RawFd) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::process::Command;

    use super::{
        close_other_fds, current_uid, fd_is_open, inherited_handle, inherited_socket,
        peer_credentials,
    };

    #[test]
    fn accepts_stream_unix_socket_and_reports_peer() {
        let (a, b) = UnixStream::pair().unwrap();
        let fd = a.into_raw_fd();
        let a = inherited_socket(fd).unwrap();
        assert_eq!(a.as_raw_fd(), fd);
        let cred = peer_credentials(&b).unwrap();
        assert_eq!(cred.uid, current_uid());
        assert_eq!(cred.info().pid, Some(std::process::id()));
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn rejects_non_socket_and_datagram() {
        let f = std::fs::File::open("/dev/null").unwrap();
        assert!(inherited_socket(f.as_raw_fd()).is_err());
        let (d, _e) = UnixDatagram::pair().unwrap();
        assert!(inherited_socket(d.as_raw_fd()).is_err());
        assert!(inherited_socket(-1).is_err());
        assert!(inherited_socket(RawFdProbe::unused()).is_err());
        assert!(inherited_handle(3, &current_uid()).is_err());
    }

    struct RawFdProbe;

    impl RawFdProbe {
        fn unused() -> std::os::fd::RawFd {
            let f = std::fs::File::open("/dev/null").unwrap();
            let fd = f.as_raw_fd();
            drop(f);
            fd
        }
    }

    #[test]
    fn close_other_fds_in_child() {
        if std::env::var_os("KMS_SYS_CHILD").is_some() {
            let victim = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
            let (keep_a, keep_b) = UnixStream::pair().unwrap();
            let keep = [0, 1, 2, keep_a.as_raw_fd(), keep_b.as_raw_fd()];
            close_other_fds(&keep).unwrap();
            assert!(!fd_is_open(victim));
            assert!(fd_is_open(keep_a.as_raw_fd()));
            assert!(fd_is_open(keep_b.as_raw_fd()));
            return;
        }
        let exe = std::env::current_exe().unwrap();
        let status = Command::new(exe)
            .args([
                "--exact",
                "peer::unix::tests::close_other_fds_in_child",
                "--nocapture",
            ])
            .env("KMS_SYS_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success(), "child test failed: {status}");
    }
}
