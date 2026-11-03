use std::io::{self, Read, Write};
use std::path::Path;

use crate::error::Error;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix as sys;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;

#[derive(Debug)]
pub struct Stream(sys::RawStream);

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInfo {
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected(sys::Identity);

impl Expected {
    pub fn current() -> Result<Self, Error> {
        sys::current_identity().map(Self)
    }

    pub fn uid(uid: u32) -> Result<Self, Error> {
        sys::uid_identity(uid).map(Self)
    }
}

pub fn inherited_fd(fd: u64, expected: &Expected) -> Result<(Stream, PeerInfo), Error> {
    sys::inherited_fd(fd, &expected.0).map(|(s, info)| (Stream(s), info))
}

pub fn inherited_handle(handle: u64, expected: &Expected) -> Result<(Stream, PeerInfo), Error> {
    sys::inherited_handle(handle, &expected.0).map(|(s, info)| (Stream(s), info))
}

pub fn listen(
    path: &Path,
    expected: &Expected,
    reject: &mut dyn FnMut(&str),
) -> Result<(Stream, PeerInfo), Error> {
    sys::listen(path, &expected.0, reject).map(|(s, info)| (Stream(s), info))
}
