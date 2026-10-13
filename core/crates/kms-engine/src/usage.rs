use kms_wire::usage as wire;

use crate::alg::{Alg, AlgKind};
use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Usage(u32);

impl Usage {
    pub fn from_bits(bits: u32) -> Result<Self, Error> {
        if bits == 0 || bits & !wire::ALL != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(bits))
    }

    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    #[must_use]
    pub fn contains(self, flags: u32) -> bool {
        flags != 0 && self.0 & flags == flags
    }

    #[must_use]
    pub fn is_subset_of(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    #[must_use]
    pub fn allowed_for(alg: Alg) -> u32 {
        match alg.kind() {
            AlgKind::Symmetric => {
                wire::ENCRYPT
                    | wire::DECRYPT
                    | wire::WRAP
                    | wire::UNWRAP
                    | wire::DERIVE
                    | wire::EXPORT
            }
            AlgKind::Signature => wire::SIGN | wire::VERIFY,
            AlgKind::Kem => wire::DECAPSULATE | wire::DERIVE,
        }
    }

    pub fn check_for(self, alg: Alg) -> Result<(), Error> {
        if self.0 & !Self::allowed_for(alg) != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}
