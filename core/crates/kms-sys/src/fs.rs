use std::fs::File;
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

pub fn open_private(path: &Path) -> Result<File, Error> {
    sys::open_private(path)
}

pub fn create_private(path: &Path) -> Result<File, Error> {
    sys::create_private(path)
}
