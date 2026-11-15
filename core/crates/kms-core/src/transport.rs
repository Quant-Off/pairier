use kms_sys::peer::{self, Expected, PeerInfo, Stream};

use crate::args::Transport;

pub(crate) fn acquire(t: &Transport, expected: &Expected) -> Result<(Stream, PeerInfo), String> {
    let acquired = match t {
        Transport::Fd(fd) => peer::inherited_fd(*fd, expected),
        Transport::Handle(handle) => peer::inherited_handle(*handle, expected),
        Transport::Socket(path) => peer::listen(path, expected, &mut |why| {
            crate::log(&format!("rejected connection: {why}"));
        }),
    };
    acquired.map_err(|e| e.to_string())
}
