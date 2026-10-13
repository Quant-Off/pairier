use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};

use crate::args::Transport;

pub(crate) fn acquire(t: &Transport) -> io::Result<UnixStream> {
    let stream = match t {
        Transport::Fd(fd) => kms_sys::peer::inherited_socket(*fd).map_err(io::Error::other)?,
        Transport::Socket(path) => {
            let listener = UnixListener::bind(path)?;
            let (stream, _) = listener.accept()?;
            drop(listener);
            std::fs::remove_file(path)?;
            stream
        }
    };
    kms_sys::peer::close_other_fds(&[0, 1, 2, stream.as_raw_fd()]).map_err(io::Error::other)?;
    Ok(stream)
}
