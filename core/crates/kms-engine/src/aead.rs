use aws_lc_rs::aead::Aad;
use kms_wire::msg::{MAX_AAD, MAX_CIPHERTEXT, MAX_PLAINTEXT};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::kdf::{self, SALT_LEN, TAG_LEN};

pub(crate) const KEY_LEN: usize = kdf::KEY_LEN;
pub(crate) const OVERHEAD: usize = SALT_LEN + TAG_LEN;
const INFO: &[u8] = b"pairier/kms/aead/v1";

pub(crate) fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != KEY_LEN {
        return Err(Error::InvalidKeyBlob);
    }
    if plaintext.len() > MAX_PLAINTEXT || aad.len() > MAX_AAD {
        return Err(Error::LimitExceeded);
    }
    let salt = kdf::random_salt()?;
    let d = kdf::derive_aead(key, &salt, &[INFO])?;
    let cap = plaintext
        .len()
        .checked_add(OVERHEAD)
        .ok_or(Error::LimitExceeded)?;
    let mut out = Vec::with_capacity(cap);
    out.extend_from_slice(&salt);
    let mut body = plaintext.to_vec();
    d.key
        .seal_in_place_append_tag(d.nonce, Aad::from(aad), &mut body)
        .map_err(|_| Error::Internal)?;
    out.extend_from_slice(&body);
    Ok(out)
}

pub(crate) fn decrypt(
    key: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if key.len() != KEY_LEN {
        return Err(Error::InvalidKeyBlob);
    }
    if ciphertext.len() > MAX_CIPHERTEXT || aad.len() > MAX_AAD {
        return Err(Error::LimitExceeded);
    }
    let (salt, body) = ciphertext
        .split_at_checked(SALT_LEN)
        .ok_or(Error::CryptoFailure)?;
    if body.len() < TAG_LEN {
        return Err(Error::CryptoFailure);
    }
    let d = kdf::derive_aead(key, salt, &[INFO])?;
    let mut buf = Zeroizing::new(body.to_vec());
    let n = d
        .key
        .open_in_place(d.nonce, Aad::from(aad), buf.as_mut_slice())
        .map_err(|_| Error::CryptoFailure)?
        .len();
    buf.truncate(n);
    Ok(buf)
}
