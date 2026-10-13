use core::fmt;

use kms_sys::mem::LockedBuf;

use crate::error::Error;

pub const ROOT_KEY_LEN: usize = 32;

pub struct RootKey(LockedBuf);

impl RootKey {
    pub fn generate() -> Result<Self, Error> {
        let mut buf = LockedBuf::new(ROOT_KEY_LEN).map_err(|_| Error::Internal)?;
        aws_lc_rs::rand::fill(buf.as_mut_slice()).map_err(|_| Error::Internal)?;
        Ok(Self(buf))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ROOT_KEY_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut buf = LockedBuf::new(ROOT_KEY_LEN).map_err(|_| Error::Internal)?;
        buf.as_mut_slice().copy_from_slice(bytes);
        Ok(Self(buf))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RootKey(..)")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{ROOT_KEY_LEN, RootKey};

    #[test]
    fn generate_and_import() {
        let a = RootKey::generate().unwrap();
        let b = RootKey::generate().unwrap();
        assert_eq!(a.as_bytes().len(), ROOT_KEY_LEN);
        assert_ne!(a.as_bytes(), b.as_bytes());
        let c = RootKey::from_slice(a.as_bytes()).unwrap();
        assert_eq!(c.as_bytes(), a.as_bytes());
        assert!(RootKey::from_slice(&[0u8; 31]).is_err());
        assert!(RootKey::from_slice(&[0u8; 33]).is_err());
        assert!(!format!("{a:?}").contains("00"));
    }
}
