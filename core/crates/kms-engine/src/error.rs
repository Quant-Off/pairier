use core::fmt;

use kms_wire::Status;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidArgument,
    UnsupportedAlgorithm,
    CapabilityDisabled,
    InvalidKeyBlob,
    UsageDenied,
    CryptoFailure,
    LimitExceeded,
    Internal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InvalidArgument => "invalid argument",
            Self::UnsupportedAlgorithm => "unsupported algorithm",
            Self::CapabilityDisabled => "capability disabled",
            Self::InvalidKeyBlob => "invalid key blob",
            Self::UsageDenied => "key usage denied",
            Self::CryptoFailure => "cryptographic failure",
            Self::LimitExceeded => "limit exceeded",
            Self::Internal => "internal error",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Error {}

impl From<Error> for Status {
    fn from(e: Error) -> Self {
        match e {
            Error::InvalidArgument | Error::UnsupportedAlgorithm => Self::InvalidArgument,
            Error::CapabilityDisabled => Self::CapabilityDisabled,
            Error::InvalidKeyBlob => Self::InvalidKeyBlob,
            Error::UsageDenied => Self::UsageDenied,
            Error::CryptoFailure => Self::CryptoFailure,
            Error::LimitExceeded => Self::LimitExceeded,
            Error::Internal => Self::Internal,
        }
    }
}
