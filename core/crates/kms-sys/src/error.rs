use std::fmt;
use std::io;

#[derive(Debug)]
pub struct Error {
    op: &'static str,
    source: io::Error,
}

impl Error {
    pub(crate) fn last(op: &'static str) -> Self {
        Self {
            op,
            source: io::Error::last_os_error(),
        }
    }

    pub(crate) fn new(op: &'static str, source: io::Error) -> Self {
        Self { op, source }
    }

    pub(crate) fn invalid(op: &'static str, msg: &'static str) -> Self {
        Self::new(op, io::Error::new(io::ErrorKind::InvalidInput, msg))
    }

    #[must_use]
    pub fn unsupported(op: &'static str) -> Self {
        Self::new(op, io::Error::from(io::ErrorKind::Unsupported))
    }

    #[must_use]
    pub fn op(&self) -> &'static str {
        self.op
    }

    #[must_use]
    pub fn kind(&self) -> io::ErrorKind {
        self.source.kind()
    }

    #[must_use]
    pub fn raw_os_error(&self) -> Option<i32> {
        self.source.raw_os_error()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.op, self.source)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}
