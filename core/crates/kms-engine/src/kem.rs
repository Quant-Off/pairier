use aws_lc_rs::agreement::{self, ECDH_P256, PrivateKey, UnparsedPublicKey};
use aws_lc_rs::encoding::{AsBigEndian, EcPrivateKeyBin};
#[cfg(feature = "pqc")]
use aws_lc_rs::kem::{
    Algorithm, Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768, ML_KEM_1024,
};
use zeroize::Zeroizing;

use crate::alg::Alg;
use crate::error::Error;
use crate::kdf;

pub(crate) const SHARED_SECRET_LEN: usize = 32;
const P256_SECRET_LEN: usize = 32;
const P256_PUBLIC_LEN: usize = 65;
const DHKEM_P256_SUITE_ID: [u8; 5] = [b'K', b'E', b'M', 0x00, 0x10];
const HPKE_VERSION: &[u8] = b"HPKE-v1";
#[cfg(feature = "pqc")]
const HYBRID_SALT: &[u8] = b"pairier/kms/hybrid-kem/v1";
#[cfg(feature = "pqc")]
const ML_KEM_768_PUBLIC_LEN: usize = 1184;
#[cfg(feature = "pqc")]
const ML_KEM_768_SECRET_LEN: usize = 2400;
#[cfg(feature = "pqc")]
const ML_KEM_768_CIPHERTEXT_LEN: usize = 1088;
#[cfg(feature = "pqc")]
const ML_KEM_768_EK_OFFSET: usize = 1152;
#[cfg(feature = "pqc")]
const ML_KEM_768_EK_END: usize = ML_KEM_768_EK_OFFSET + ML_KEM_768_PUBLIC_LEN;

pub(crate) type Secret = Zeroizing<Vec<u8>>;
pub(crate) type Generated = (Secret, Vec<u8>);
pub(crate) type Encapsulated = (Vec<u8>, Secret);

pub(crate) fn generate(alg: Alg) -> Result<Generated, Error> {
    match alg {
        Alg::DhkemP256 => dhkem_generate(),
        #[cfg(feature = "pqc")]
        Alg::MlKem768 => mlkem_generate(&ML_KEM_768),
        #[cfg(feature = "pqc")]
        Alg::MlKem1024 => mlkem_generate(&ML_KEM_1024),
        #[cfg(feature = "pqc")]
        Alg::HybridP256MlKem768 => hybrid_generate(),
        #[cfg(not(feature = "pqc"))]
        Alg::MlKem768 | Alg::MlKem1024 | Alg::HybridP256MlKem768 => Err(Error::CapabilityDisabled),
        Alg::Aes256Gcm
        | Alg::EcdsaP256Sha256
        | Alg::EcdsaP384Sha384
        | Alg::Ed25519
        | Alg::MlDsa65
        | Alg::MlDsa87 => Err(Error::InvalidArgument),
    }
}

pub(crate) fn encapsulate(alg: Alg, public_key: &[u8]) -> Result<Encapsulated, Error> {
    if Some(public_key.len()) != alg.public_key_len() {
        return Err(Error::InvalidArgument);
    }
    match alg {
        Alg::DhkemP256 => dhkem_encapsulate(public_key),
        #[cfg(feature = "pqc")]
        Alg::MlKem768 => mlkem_encapsulate(&ML_KEM_768, public_key),
        #[cfg(feature = "pqc")]
        Alg::MlKem1024 => mlkem_encapsulate(&ML_KEM_1024, public_key),
        #[cfg(feature = "pqc")]
        Alg::HybridP256MlKem768 => hybrid_encapsulate(public_key),
        #[cfg(not(feature = "pqc"))]
        Alg::MlKem768 | Alg::MlKem1024 | Alg::HybridP256MlKem768 => Err(Error::CapabilityDisabled),
        Alg::Aes256Gcm
        | Alg::EcdsaP256Sha256
        | Alg::EcdsaP384Sha384
        | Alg::Ed25519
        | Alg::MlDsa65
        | Alg::MlDsa87 => Err(Error::InvalidArgument),
    }
}

pub(crate) fn decapsulate(alg: Alg, secret: &[u8], ciphertext: &[u8]) -> Result<Secret, Error> {
    if Some(ciphertext.len()) != alg.kem_ciphertext_len() {
        return Err(Error::CryptoFailure);
    }
    match alg {
        Alg::DhkemP256 => dhkem_decapsulate(secret, ciphertext),
        #[cfg(feature = "pqc")]
        Alg::MlKem768 => mlkem_decapsulate(&ML_KEM_768, secret, ciphertext),
        #[cfg(feature = "pqc")]
        Alg::MlKem1024 => mlkem_decapsulate(&ML_KEM_1024, secret, ciphertext),
        #[cfg(feature = "pqc")]
        Alg::HybridP256MlKem768 => hybrid_decapsulate(secret, ciphertext),
        #[cfg(not(feature = "pqc"))]
        Alg::MlKem768 | Alg::MlKem1024 | Alg::HybridP256MlKem768 => Err(Error::CapabilityDisabled),
        Alg::Aes256Gcm
        | Alg::EcdsaP256Sha256
        | Alg::EcdsaP384Sha384
        | Alg::Ed25519
        | Alg::MlDsa65
        | Alg::MlDsa87 => Err(Error::InvalidArgument),
    }
}

fn p256_public(sk: &PrivateKey) -> Result<Vec<u8>, Error> {
    let pk = sk.compute_public_key().map_err(|_| Error::Internal)?;
    let bytes = pk.as_ref();
    if bytes.len() != P256_PUBLIC_LEN {
        return Err(Error::Internal);
    }
    Ok(bytes.to_vec())
}

fn p256_dh(sk: &PrivateKey, peer: &[u8], err: Error) -> Result<Secret, Error> {
    if peer.len() != P256_PUBLIC_LEN {
        return Err(err);
    }
    agreement::agree(sk, UnparsedPublicKey::new(&ECDH_P256, peer), err, |dh| {
        Ok(Zeroizing::new(dh.to_vec()))
    })
}

fn dhkem_shared_secret(dh: &[u8], enc: &[u8], pk_r: &[u8]) -> Result<Secret, Error> {
    let mut labeled_ikm = Zeroizing::new(Vec::new());
    labeled_ikm.extend_from_slice(HPKE_VERSION);
    labeled_ikm.extend_from_slice(&DHKEM_P256_SUITE_ID);
    labeled_ikm.extend_from_slice(b"eae_prk");
    labeled_ikm.extend_from_slice(dh);
    let len = u16::try_from(SHARED_SECRET_LEN)
        .map_err(|_| Error::Internal)?
        .to_be_bytes();
    let mut ss = Zeroizing::new(vec![0u8; SHARED_SECRET_LEN]);
    kdf::expand(
        &[],
        &labeled_ikm,
        &[
            &len,
            HPKE_VERSION,
            &DHKEM_P256_SUITE_ID,
            b"shared_secret",
            enc,
            pk_r,
        ],
        ss.as_mut_slice(),
    )?;
    Ok(ss)
}

fn dhkem_generate() -> Result<Generated, Error> {
    let sk = PrivateKey::generate(&ECDH_P256).map_err(|_| Error::Internal)?;
    let scalar =
        AsBigEndian::<EcPrivateKeyBin<'static>>::as_be_bytes(&sk).map_err(|_| Error::Internal)?;
    if scalar.as_ref().len() != P256_SECRET_LEN {
        return Err(Error::Internal);
    }
    let pk = p256_public(&sk)?;
    Ok((Zeroizing::new(scalar.as_ref().to_vec()), pk))
}

fn dhkem_encap_with(sk_e: &PrivateKey, pk_r: &[u8]) -> Result<Encapsulated, Error> {
    let dh = p256_dh(sk_e, pk_r, Error::InvalidArgument)?;
    let enc = p256_public(sk_e)?;
    let ss = dhkem_shared_secret(&dh, &enc, pk_r)?;
    Ok((enc, ss))
}

fn dhkem_encapsulate(pk_r: &[u8]) -> Result<Encapsulated, Error> {
    let sk_e = PrivateKey::generate(&ECDH_P256).map_err(|_| Error::Internal)?;
    dhkem_encap_with(&sk_e, pk_r)
}

fn dhkem_decapsulate(secret: &[u8], enc: &[u8]) -> Result<Secret, Error> {
    let sk = PrivateKey::from_private_key(&ECDH_P256, secret).map_err(|_| Error::InvalidKeyBlob)?;
    let dh = p256_dh(&sk, enc, Error::CryptoFailure)?;
    let pk_r = p256_public(&sk)?;
    dhkem_shared_secret(&dh, enc, &pk_r)
}

#[cfg(feature = "pqc")]
fn mlkem_generate(a: &'static Algorithm) -> Result<Generated, Error> {
    let dk = DecapsulationKey::generate(a).map_err(|_| Error::Internal)?;
    let secret = dk.key_bytes().map_err(|_| Error::Internal)?;
    let ek = dk
        .encapsulation_key()
        .map_err(|_| Error::Internal)?
        .key_bytes()
        .map_err(|_| Error::Internal)?;
    Ok((
        Zeroizing::new(secret.as_ref().to_vec()),
        ek.as_ref().to_vec(),
    ))
}

#[cfg(feature = "pqc")]
fn mlkem768_public(dk_bytes: &[u8]) -> Result<&[u8], Error> {
    if dk_bytes.len() != ML_KEM_768_SECRET_LEN {
        return Err(Error::InvalidKeyBlob);
    }
    dk_bytes
        .get(ML_KEM_768_EK_OFFSET..ML_KEM_768_EK_END)
        .ok_or(Error::InvalidKeyBlob)
}

#[cfg(feature = "pqc")]
fn mlkem_encapsulate(a: &'static Algorithm, ek_bytes: &[u8]) -> Result<Encapsulated, Error> {
    let ek = EncapsulationKey::new(a, ek_bytes).map_err(|_| Error::InvalidArgument)?;
    let (ct, ss) = ek.encapsulate().map_err(|_| Error::CryptoFailure)?;
    Ok((ct.as_ref().to_vec(), Zeroizing::new(ss.as_ref().to_vec())))
}

#[cfg(feature = "pqc")]
fn mlkem_decapsulate(
    a: &'static Algorithm,
    dk_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Secret, Error> {
    let dk = DecapsulationKey::new(a, dk_bytes).map_err(|_| Error::InvalidKeyBlob)?;
    let ss = dk
        .decapsulate(Ciphertext::from(ciphertext))
        .map_err(|_| Error::CryptoFailure)?;
    Ok(Zeroizing::new(ss.as_ref().to_vec()))
}

#[cfg(feature = "pqc")]
fn hybrid_combine(
    ss_dh: &[u8],
    ss_ml: &[u8],
    enc_dh: &[u8],
    ct_ml: &[u8],
    dh_pk: &[u8],
    ml_pk: &[u8],
) -> Result<Secret, Error> {
    let mut ikm = Zeroizing::new(Vec::new());
    ikm.extend_from_slice(ss_dh);
    ikm.extend_from_slice(ss_ml);
    let mut ss = Zeroizing::new(vec![0u8; SHARED_SECRET_LEN]);
    kdf::expand(
        HYBRID_SALT,
        &ikm,
        &[enc_dh, ct_ml, dh_pk, ml_pk],
        ss.as_mut_slice(),
    )?;
    Ok(ss)
}

#[cfg(feature = "pqc")]
fn hybrid_generate() -> Result<Generated, Error> {
    let (dh_secret, dh_public) = dhkem_generate()?;
    let (ml_secret, ml_public) = mlkem_generate(&ML_KEM_768)?;
    let mut secret = Zeroizing::new(Vec::new());
    secret.extend_from_slice(&dh_secret);
    secret.extend_from_slice(&ml_secret);
    let mut public = dh_public;
    public.extend_from_slice(&ml_public);
    Ok((secret, public))
}

#[cfg(feature = "pqc")]
fn hybrid_encapsulate(public_key: &[u8]) -> Result<Encapsulated, Error> {
    let (dh_pk, ml_pk) = public_key
        .split_at_checked(P256_PUBLIC_LEN)
        .ok_or(Error::InvalidArgument)?;
    if ml_pk.len() != ML_KEM_768_PUBLIC_LEN {
        return Err(Error::InvalidArgument);
    }
    let (enc_dh, ss_dh) = dhkem_encapsulate(dh_pk)?;
    let (ct_ml, ss_ml) = mlkem_encapsulate(&ML_KEM_768, ml_pk)?;
    let ss = hybrid_combine(&ss_dh, &ss_ml, &enc_dh, &ct_ml, dh_pk, ml_pk)?;
    let mut ct = enc_dh;
    ct.extend_from_slice(&ct_ml);
    Ok((ct, ss))
}

#[cfg(feature = "pqc")]
fn hybrid_decapsulate(secret: &[u8], ciphertext: &[u8]) -> Result<Secret, Error> {
    let (dh_sk, ml_sk) = secret
        .split_at_checked(P256_SECRET_LEN)
        .ok_or(Error::InvalidKeyBlob)?;
    if ml_sk.len() != ML_KEM_768_SECRET_LEN {
        return Err(Error::InvalidKeyBlob);
    }
    let (enc_dh, ct_ml) = ciphertext
        .split_at_checked(P256_PUBLIC_LEN)
        .ok_or(Error::CryptoFailure)?;
    if ct_ml.len() != ML_KEM_768_CIPHERTEXT_LEN {
        return Err(Error::CryptoFailure);
    }
    let ss_dh = dhkem_decapsulate(dh_sk, enc_dh)?;
    let ss_ml = mlkem_decapsulate(&ML_KEM_768, ml_sk, ct_ml)?;
    let sk = PrivateKey::from_private_key(&ECDH_P256, dh_sk).map_err(|_| Error::InvalidKeyBlob)?;
    let dh_public = p256_public(&sk)?;
    let ml_public = mlkem768_public(ml_sk)?;
    hybrid_combine(&ss_dh, &ss_ml, enc_dh, ct_ml, &dh_public, ml_public)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{
        ECDH_P256, Error, P256_PUBLIC_LEN, PrivateKey, dhkem_decapsulate, dhkem_encap_with,
        dhkem_encapsulate, dhkem_generate, p256_public,
    };

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn dhkem_p256_matches_rfc9180_a3_1() {
        let sk_e = unhex("4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb");
        let sk_r = unhex("f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
        let expected = unhex("c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8");
        let recipient = PrivateKey::from_private_key(&ECDH_P256, &sk_r).unwrap();
        let pk_r = p256_public(&recipient).unwrap();
        let ephemeral = PrivateKey::from_private_key(&ECDH_P256, &sk_e).unwrap();
        let (enc, ss) = dhkem_encap_with(&ephemeral, &pk_r).unwrap();
        assert_eq!(ss.as_slice(), expected.as_slice());
        assert_eq!(enc, p256_public(&ephemeral).unwrap());
        let ss2 = dhkem_decapsulate(&sk_r, &enc).unwrap();
        assert_eq!(ss2.as_slice(), expected.as_slice());
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn mlkem768_public_key_is_embedded_in_secret() {
        let (dk, ek) = super::mlkem_generate(&super::ML_KEM_768).unwrap();
        assert_eq!(super::mlkem768_public(&dk).unwrap(), ek.as_slice());
        assert_eq!(
            super::mlkem768_public(&dk[1..]).unwrap_err(),
            Error::InvalidKeyBlob
        );
        let (sk, pk) = super::hybrid_generate().unwrap();
        assert_eq!(sk.len(), 32 + 2400);
        assert_eq!(pk.len(), 65 + 1184);
        let (ct, ss) = super::hybrid_encapsulate(&pk).unwrap();
        assert_eq!(ct.len(), 65 + 1088);
        assert_eq!(
            super::hybrid_decapsulate(&sk, &ct).unwrap().as_slice(),
            ss.as_slice()
        );
        let mut swapped = ct.clone();
        swapped[70] ^= 1;
        assert_ne!(
            super::hybrid_decapsulate(&sk, &swapped).unwrap().as_slice(),
            ss.as_slice()
        );
    }

    #[test]
    fn dhkem_rejects_invalid_points_and_keys() {
        let (sk, pk) = dhkem_generate().unwrap();
        assert_eq!(pk.len(), P256_PUBLIC_LEN);
        assert_eq!(pk[0], 0x04);
        let mut off_curve = vec![0u8; P256_PUBLIC_LEN];
        off_curve[0] = 0x04;
        assert_eq!(
            dhkem_encapsulate(&off_curve).unwrap_err(),
            Error::InvalidArgument
        );
        assert_eq!(
            dhkem_decapsulate(&sk, &off_curve).unwrap_err(),
            Error::CryptoFailure
        );
        let mut wrong_prefix = pk.clone();
        wrong_prefix[0] = 0x05;
        assert_eq!(
            dhkem_encapsulate(&wrong_prefix).unwrap_err(),
            Error::InvalidArgument
        );
        let (enc, _) = dhkem_encapsulate(&pk).unwrap();
        assert_eq!(
            dhkem_decapsulate(&sk[1..], &enc).unwrap_err(),
            Error::InvalidKeyBlob
        );
        assert_eq!(
            dhkem_decapsulate(&[0u8; 32], &enc).unwrap_err(),
            Error::InvalidKeyBlob
        );
    }
}
