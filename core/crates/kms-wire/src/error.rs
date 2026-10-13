use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Truncated,
    TrailingBytes,
    BadMagic,
    BadKind,
    BadStatus,
    BadBool,
    BadUtf8,
    BadLength,
    TooLarge,
    BodyTooLarge,
    UnknownOp,
    Overflow,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Truncated => "truncated input",
            Self::TrailingBytes => "trailing bytes after message",
            Self::BadMagic => "bad frame magic",
            Self::BadKind => "bad frame kind",
            Self::BadStatus => "bad frame status",
            Self::BadBool => "bad boolean encoding",
            Self::BadUtf8 => "string is not valid utf-8",
            Self::BadLength => "field has wrong length",
            Self::TooLarge => "field exceeds its size limit",
            Self::BodyTooLarge => "body exceeds maximum frame size",
            Self::UnknownOp => "unknown operation code",
            Self::Overflow => "arithmetic overflow",
        };
        f.write_str(s)
    }
}

impl core::error::Error for Error {}
