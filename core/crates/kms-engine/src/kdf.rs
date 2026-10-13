use aws_lc_rs::aead::{AES_256_GCM, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};
use zeroize::Zeroizing;

use crate::error::Error;

pub(crate) const SALT_LEN: usize = 32;
pub(crate) const KEY_LEN: usize = 32;
pub(crate) const TAG_LEN: usize = 16;

struct OkmLen(usize);

impl KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

pub(crate) struct DerivedAead {
    pub(crate) key: LessSafeKey,
    pub(crate) nonce: Nonce,
}

pub(crate) fn derive_aead(ikm: &[u8], salt: &[u8], info: &[&[u8]]) -> Result<DerivedAead, Error> {
    const OKM_LEN: usize = KEY_LEN + NONCE_LEN;
    let prk = Salt::new(HKDF_SHA256, salt).extract(ikm);
    let mut okm = Zeroizing::new([0u8; OKM_LEN]);
    prk.expand(info, OkmLen(OKM_LEN))
        .map_err(|_| Error::Internal)?
        .fill(okm.as_mut_slice())
        .map_err(|_| Error::Internal)?;
    let (key_bytes, nonce_bytes) = okm.split_at(KEY_LEN);
    let key = UnboundKey::new(&AES_256_GCM, key_bytes).map_err(|_| Error::Internal)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| Error::Internal)?;
    Ok(DerivedAead {
        key: LessSafeKey::new(key),
        nonce,
    })
}

pub(crate) fn random_salt() -> Result<[u8; SALT_LEN], Error> {
    let mut salt = [0u8; SALT_LEN];
    aws_lc_rs::rand::fill(&mut salt).map_err(|_| Error::Internal)?;
    Ok(salt)
}
