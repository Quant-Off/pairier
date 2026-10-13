use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

use crate::error::Error;

pub const IPC_FD: RawFd = 3;

fn socklen_of<T>() -> Result<libc::socklen_t, Error> {
    libc::socklen_t::try_from(size_of::<T>())
        .map_err(|_| Error::invalid("socklen", "size overflow"))
}

pub fn inherited_socket(fd: RawFd) -> Result<UnixStream, Error> {
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
pub struct PeerCred {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub pid: Option<libc::pid_t>,
}

#[cfg(target_os = "linux")]
pub fn peer_credentials(sock: &UnixStream) -> Result<PeerCred, Error> {
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
pub fn peer_credentials(sock: &UnixStream) -> Result<PeerCred, Error> {
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

#[must_use]
pub fn current_uid() -> libc::uid_t {
    unsafe { libc::getuid() }
}

#[must_use]
pub fn current_pid() -> libc::pid_t {
    unsafe { libc::getpid() }
}

#[cfg(target_os = "linux")]
pub fn close_other_fds(keep: &[RawFd]) -> Result<(), Error> {
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
pub fn close_other_fds(keep: &[RawFd]) -> Result<(), Error> {
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

#[must_use]
pub fn fd_is_open(fd: RawFd) -> bool {
    unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::os::fd::{AsRawFd, IntoRawFd};
    use std::os::unix::net::{UnixDatagram, UnixStream};
    use std::process::Command;

    use super::{
        close_other_fds, current_pid, current_uid, fd_is_open, inherited_socket, peer_credentials,
    };

    #[test]
    fn accepts_stream_unix_socket_and_reports_peer() {
        let (a, b) = UnixStream::pair().unwrap();
        let fd = a.into_raw_fd();
        let a = inherited_socket(fd).unwrap();
        assert_eq!(a.as_raw_fd(), fd);
        let cred = peer_credentials(&b).unwrap();
        assert_eq!(cred.uid, current_uid());
        assert_eq!(cred.pid, Some(current_pid()));
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
                "peer::tests::close_other_fds_in_child",
                "--nocapture",
            ])
            .env("KMS_SYS_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success(), "child test failed: {status}");
    }
}
