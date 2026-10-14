use aws_lc_rs::aead::Aad;
use aws_lc_rs::constant_time::verify_slices_are_equal;
use kms_wire::msg::{KEY_ID_LEN, MAX_CONTEXT, MAX_LABEL, MAX_PACKAGE};
use kms_wire::{Reader, Writer};
use zeroize::Zeroizing;

use crate::alg::{Alg, AlgKind};
use crate::blob;
use crate::error::Error;
use crate::kdf::{self, SALT_LEN, TAG_LEN};
use crate::kem;
use crate::usage::Usage;

const VERSION: u8 = 1;
const INFO: &[u8] = b"pairier/kms/key-export/v1";

pub(crate) struct Export<'a> {
    pub(crate) kem_alg: Alg,
    pub(crate) alg: Alg,
    pub(crate) usage: Usage,
    pub(crate) key_id: [u8; KEY_ID_LEN],
    pub(crate) label: &'a str,
    pub(crate) context: &'a [u8],
}

pub(crate) struct Imported {
    pub(crate) alg: Alg,
    pub(crate) usage: Usage,
    pub(crate) key_id: [u8; KEY_ID_LEN],
    pub(crate) label: String,
    pub(crate) secret: Zeroizing<Vec<u8>>,
}

struct ParsedHeader<'a> {
    kem_alg: Alg,
    alg: Alg,
    usage: Usage,
    key_id: [u8; KEY_ID_LEN],
    label: &'a str,
    context: &'a [u8],
    salt: [u8; SALT_LEN],
    enc: &'a [u8],
}

fn encode_header(e: &Export<'_>, salt: &[u8; SALT_LEN], enc: &[u8]) -> Result<Vec<u8>, Error> {
    let mut w = Writer::new();
    w.write_u8(VERSION).map_err(|_| Error::Internal)?;
    w.write_u16(e.kem_alg.wire_id())
        .map_err(|_| Error::Internal)?;
    w.write_u16(e.alg.wire_id()).map_err(|_| Error::Internal)?;
    w.write_u32(e.usage.bits()).map_err(|_| Error::Internal)?;
    w.write_bytes(&e.key_id).map_err(|_| Error::Internal)?;
    w.write_str(e.label).map_err(|_| Error::Internal)?;
    w.write_bytes(e.context).map_err(|_| Error::Internal)?;
    w.write_bytes(salt).map_err(|_| Error::Internal)?;
    w.write_bytes(enc).map_err(|_| Error::Internal)?;
    Ok(w.finish())
}

fn parse_header<'a>(r: &mut Reader<'a>) -> Result<ParsedHeader<'a>, Error> {
    let version = r.read_u8().map_err(|_| Error::InvalidArgument)?;
    if version != VERSION {
        return Err(Error::InvalidArgument);
    }
    let kem_alg = r.read_u16().map_err(|_| Error::InvalidArgument)?;
    let alg = r.read_u16().map_err(|_| Error::InvalidArgument)?;
    let usage = r.read_u32().map_err(|_| Error::InvalidArgument)?;
    let key_id = r
        .read_array::<KEY_ID_LEN>()
        .map_err(|_| Error::InvalidArgument)?;
    let label = r.read_str(MAX_LABEL).map_err(|_| Error::InvalidArgument)?;
    blob::check_label(label)?;
    let context = r
        .read_bytes(MAX_CONTEXT)
        .map_err(|_| Error::InvalidArgument)?;
    let salt = r
        .read_array::<SALT_LEN>()
        .map_err(|_| Error::InvalidArgument)?;
    let kem_alg = Alg::try_from(kem_alg).map_err(|_| Error::InvalidArgument)?;
    let enc_len = kem_alg.kem_ciphertext_len().ok_or(Error::InvalidArgument)?;
    let enc = r.read_bytes(enc_len).map_err(|_| Error::InvalidArgument)?;
    if enc.len() != enc_len {
        return Err(Error::InvalidArgument);
    }
    let alg = Alg::try_from(alg).map_err(|_| Error::InvalidArgument)?;
    let usage = Usage::from_bits(usage).map_err(|_| Error::InvalidArgument)?;
    usage.check_for(alg)?;
    Ok(ParsedHeader {
        kem_alg,
        alg,
        usage,
        key_id,
        label,
        context,
        salt,
        enc,
    })
}

pub(crate) fn seal(
    e: &Export<'_>,
    recipient_public_key: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>, Error> {
    if e.kem_alg.kind() != AlgKind::Kem {
        return Err(Error::InvalidArgument);
    }
    blob::check_label(e.label)?;
    if e.context.len() > MAX_CONTEXT {
        return Err(Error::LimitExceeded);
    }
    let (enc, ss) = kem::encapsulate(e.kem_alg, recipient_public_key)?;
    let salt = kdf::random_salt()?;
    let aad = encode_header(e, &salt, &enc)?;
    let d = kdf::derive_aead(&ss, &salt, &[INFO, &e.key_id])?;
    let mut body = Zeroizing::new(secret.to_vec());
    d.key
        .seal_in_place_append_tag(d.nonce, Aad::from(aad.as_slice()), &mut *body)
        .map_err(|_| Error::Internal)?;
    let total = aad
        .len()
        .checked_add(body.len())
        .ok_or(Error::LimitExceeded)?;
    if total > MAX_PACKAGE {
        return Err(Error::LimitExceeded);
    }
    let mut out = aad;
    out.extend_from_slice(&body);
    Ok(out)
}

pub(crate) fn open(
    kem_alg: Alg,
    kem_secret: &[u8],
    package: &[u8],
    expected_context: &[u8],
) -> Result<Imported, Error> {
    if package.len() > MAX_PACKAGE || expected_context.len() > MAX_CONTEXT {
        return Err(Error::LimitExceeded);
    }
    let mut r = Reader::new(package);
    let h = parse_header(&mut r)?;
    if h.kem_alg != kem_alg {
        return Err(Error::InvalidArgument);
    }
    if verify_slices_are_equal(h.context, expected_context).is_err() {
        return Err(Error::InvalidArgument);
    }
    let header_len = package
        .len()
        .checked_sub(r.remaining())
        .ok_or(Error::InvalidArgument)?;
    let (aad, body) = package
        .split_at_checked(header_len)
        .ok_or(Error::InvalidArgument)?;
    if body.len() < TAG_LEN {
        return Err(Error::InvalidArgument);
    }
    let ss = kem::decapsulate(kem_alg, kem_secret, h.enc)?;
    let d = kdf::derive_aead(&ss, &h.salt, &[INFO, &h.key_id])?;
    let mut buf = Zeroizing::new(body.to_vec());
    let n = d
        .key
        .open_in_place(d.nonce, Aad::from(aad), buf.as_mut_slice())
        .map_err(|_| Error::CryptoFailure)?
        .len();
    buf.truncate(n);
    Ok(Imported {
        alg: h.alg,
        usage: h.usage,
        key_id: h.key_id,
        label: h.label.to_owned(),
        secret: buf,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use kms_wire::Reader;

    use super::{Export, encode_header, parse_header};
    use crate::alg::Alg;
    use crate::error::Error;
    use crate::usage::Usage;

    #[test]
    fn imported_label_must_be_printable() {
        let bad = Export {
            kem_alg: Alg::DhkemP256,
            alg: Alg::Aes256Gcm,
            usage: Usage::from_bits(kms_wire::usage::DECRYPT).unwrap(),
            key_id: [3u8; 16],
            label: "a\u{1b}[2Jb",
            context: b"ctx",
        };
        let raw = encode_header(&bad, &[0u8; 32], &[4u8; 65]).unwrap();
        assert_eq!(
            parse_header(&mut Reader::new(&raw)).err(),
            Some(Error::InvalidArgument)
        );
        let good = Export {
            label: "a/b",
            ..bad
        };
        let raw = encode_header(&good, &[0u8; 32], &[4u8; 65]).unwrap();
        assert!(parse_header(&mut Reader::new(&raw)).is_ok());
    }
}
