use core::fmt;

use aws_lc_rs::aead::Aad;
use kms_wire::msg::{KEY_ID_LEN, MAX_KEY_BLOB, MAX_LABEL};
use kms_wire::{Reader, Writer};
use zeroize::Zeroizing;

use crate::alg::Alg;
use crate::error::Error;
use crate::kdf::{self, SALT_LEN, TAG_LEN};
use crate::root::RootKey;
use crate::usage::Usage;

const VERSION: u8 = 1;
const INFO: &[u8] = b"pairier/kms/key-blob/v1";

pub(crate) struct Header<'a> {
    pub(crate) alg: Alg,
    pub(crate) usage: Usage,
    pub(crate) key_id: [u8; KEY_ID_LEN],
    pub(crate) label: &'a str,
}

pub(crate) struct Unsealed {
    pub(crate) alg: Alg,
    pub(crate) usage: Usage,
    pub(crate) key_id: [u8; KEY_ID_LEN],
    pub(crate) label: String,
    pub(crate) secret: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Unsealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unsealed")
            .field("alg", &self.alg)
            .field("usage", &self.usage)
            .field("key_id", &self.key_id)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

struct ParsedHeader {
    alg: Alg,
    usage: Usage,
    key_id: [u8; KEY_ID_LEN],
    label: String,
    salt: [u8; SALT_LEN],
}

fn parse_header(r: &mut Reader<'_>) -> Result<ParsedHeader, Error> {
    let version = r.read_u8().map_err(|_| Error::InvalidKeyBlob)?;
    if version != VERSION {
        return Err(Error::InvalidKeyBlob);
    }
    let alg = r.read_u16().map_err(|_| Error::InvalidKeyBlob)?;
    let usage = r.read_u32().map_err(|_| Error::InvalidKeyBlob)?;
    let key_id = r
        .read_array::<KEY_ID_LEN>()
        .map_err(|_| Error::InvalidKeyBlob)?;
    let label = r
        .read_str(MAX_LABEL)
        .map_err(|_| Error::InvalidKeyBlob)?
        .to_owned();
    let salt = r
        .read_array::<SALT_LEN>()
        .map_err(|_| Error::InvalidKeyBlob)?;
    let alg = Alg::try_from(alg).map_err(|_| Error::InvalidKeyBlob)?;
    let usage = Usage::from_bits(usage).map_err(|_| Error::InvalidKeyBlob)?;
    Ok(ParsedHeader {
        alg,
        usage,
        key_id,
        label,
        salt,
    })
}

fn encode_header(h: &Header<'_>, salt: &[u8; SALT_LEN]) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new();
    w.write_u8(VERSION).map_err(|_| Error::Internal)?;
    w.write_u16(h.alg.wire_id()).map_err(|_| Error::Internal)?;
    w.write_u32(h.usage.bits()).map_err(|_| Error::Internal)?;
    w.write_bytes(&h.key_id).map_err(|_| Error::Internal)?;
    w.write_str(h.label).map_err(|_| Error::Internal)?;
    w.write_bytes(salt).map_err(|_| Error::Internal)?;
    Ok(w.finish())
}

pub(crate) fn check_label(label: &str) -> Result<(), Error> {
    if label.len() > MAX_LABEL || label.chars().any(forbidden_in_label) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

fn forbidden_in_label(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

pub(crate) fn seal(root: &RootKey, h: &Header<'_>, secret: &[u8]) -> Result<Vec<u8>, Error> {
    check_label(h.label)?;
    let salt = kdf::random_salt()?;
    let aad = encode_header(h, &salt)?;
    let d = kdf::derive_aead(root.as_bytes(), &salt, &[INFO, &h.key_id])?;
    let mut body = Zeroizing::new(secret.to_vec());
    d.key
        .seal_in_place_append_tag(d.nonce, Aad::from(aad.as_slice()), &mut *body)
        .map_err(|_| Error::Internal)?;
    let total = aad
        .len()
        .checked_add(body.len())
        .ok_or(Error::LimitExceeded)?;
    if total > MAX_KEY_BLOB {
        return Err(Error::LimitExceeded);
    }
    let mut out = aad;
    out.extend_from_slice(&body);
    Ok(out)
}

pub(crate) fn open(root: &RootKey, blob: &[u8]) -> Result<Unsealed, Error> {
    if blob.len() > MAX_KEY_BLOB {
        return Err(Error::LimitExceeded);
    }
    let mut r = Reader::new(blob);
    let ParsedHeader {
        alg,
        usage,
        key_id,
        label,
        salt,
    } = parse_header(&mut r)?;

    let header_len = blob
        .len()
        .checked_sub(r.remaining())
        .ok_or(Error::InvalidKeyBlob)?;
    let (aad, body) = blob
        .split_at_checked(header_len)
        .ok_or(Error::InvalidKeyBlob)?;
    if body.len() < TAG_LEN {
        return Err(Error::InvalidKeyBlob);
    }
    let d = kdf::derive_aead(root.as_bytes(), &salt, &[INFO, &key_id])?;
    let mut buf = Zeroizing::new(body.to_vec());
    let n = d
        .key
        .open_in_place(d.nonce, Aad::from(aad), buf.as_mut_slice())
        .map_err(|_| Error::InvalidKeyBlob)?
        .len();
    buf.truncate(n);
    Ok(Unsealed {
        alg,
        usage,
        key_id,
        label,
        secret: buf,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::{Header, check_label, open, seal};
    use crate::alg::Alg;
    use crate::error::Error;
    use crate::root::RootKey;
    use crate::usage::Usage;

    #[test]
    fn roundtrip_preserves_metadata() {
        let root = RootKey::generate().unwrap();
        let h = Header {
            alg: Alg::Ed25519,
            usage: Usage::from_bits(kms_wire::usage::SIGN).unwrap(),
            key_id: [7u8; 16],
            label: "team/a",
        };
        let blob = seal(&root, &h, b"secret-material").unwrap();
        let u = open(&root, &blob).unwrap();
        assert_eq!(u.alg, Alg::Ed25519);
        assert_eq!(u.usage.bits(), kms_wire::usage::SIGN);
        assert_eq!(u.key_id, [7u8; 16]);
        assert_eq!(u.label, "team/a");
        assert_eq!(u.secret.as_slice(), b"secret-material");
    }

    #[test]
    fn every_header_byte_is_authenticated() {
        let root = RootKey::generate().unwrap();
        let h = Header {
            alg: Alg::Aes256Gcm,
            usage: Usage::from_bits(kms_wire::usage::ENCRYPT).unwrap(),
            key_id: [1u8; 16],
            label: "x",
        };
        let blob = seal(&root, &h, &[9u8; 32]).unwrap();
        for i in 0..blob.len() {
            let mut t = blob.clone();
            t[i] ^= 0x01;
            assert_eq!(
                open(&root, &t).unwrap_err(),
                Error::InvalidKeyBlob,
                "byte {i}"
            );
        }
        assert_eq!(
            open(&root, &blob[..blob.len() - 1]).unwrap_err(),
            Error::InvalidKeyBlob
        );
        assert_eq!(open(&root, &[]).unwrap_err(), Error::InvalidKeyBlob);
    }

    #[test]
    fn labels_reject_control_and_bidi_characters() {
        for ok in ["", "team/a", "프로젝트/db", "a b-c_d.e"] {
            assert!(check_label(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "a\nb",
            "a\tb",
            "\u{1b}[2J",
            "a\u{7f}",
            "a\u{85}",
            "a\u{202e}b",
            "\u{2066}x",
            "a\u{200f}",
        ] {
            assert_eq!(
                check_label(bad).unwrap_err(),
                Error::InvalidArgument,
                "{bad:?}"
            );
        }
        let root = RootKey::generate().unwrap();
        let h = Header {
            alg: Alg::Aes256Gcm,
            usage: Usage::from_bits(kms_wire::usage::ENCRYPT).unwrap(),
            key_id: [2u8; 16],
            label: "x\ny",
        };
        assert_eq!(
            seal(&root, &h, &[0u8; 32]).unwrap_err(),
            Error::InvalidArgument
        );
    }
}
