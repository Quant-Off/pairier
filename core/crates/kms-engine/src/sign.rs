use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_FIXED,
    ECDSA_P384_SHA384_FIXED_SIGNING, ED25519, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
    UnparsedPublicKey, VerificationAlgorithm,
};
#[cfg(feature = "pqc")]
use aws_lc_rs::signature::{
    ML_DSA_65, ML_DSA_65_SIGNING, ML_DSA_87, ML_DSA_87_SIGNING, PqdsaKeyPair,
};
use zeroize::Zeroizing;

use crate::alg::Alg;
use crate::error::Error;

type Generated = (Zeroizing<Vec<u8>>, Vec<u8>);

pub(crate) fn generate(alg: Alg) -> Result<Generated, Error> {
    match alg {
        Alg::EcdsaP256Sha256 | Alg::EcdsaP384Sha384 => {
            let sa = if alg == Alg::EcdsaP256Sha256 {
                &ECDSA_P256_SHA256_FIXED_SIGNING
            } else {
                &ECDSA_P384_SHA384_FIXED_SIGNING
            };
            let kp = EcdsaKeyPair::generate(sa).map_err(|_| Error::Internal)?;
            let doc = kp.to_pkcs8v1().map_err(|_| Error::Internal)?;
            Ok((
                Zeroizing::new(doc.as_ref().to_vec()),
                kp.public_key().as_ref().to_vec(),
            ))
        }
        Alg::Ed25519 => {
            let kp = Ed25519KeyPair::generate().map_err(|_| Error::Internal)?;
            let doc = kp.to_pkcs8v1().map_err(|_| Error::Internal)?;
            Ok((
                Zeroizing::new(doc.as_ref().to_vec()),
                kp.public_key().as_ref().to_vec(),
            ))
        }
        #[cfg(feature = "pqc")]
        Alg::MlDsa65 | Alg::MlDsa87 => {
            let sa = if alg == Alg::MlDsa65 {
                &ML_DSA_65_SIGNING
            } else {
                &ML_DSA_87_SIGNING
            };
            let kp = PqdsaKeyPair::generate(sa).map_err(|_| Error::Internal)?;
            let doc = kp.to_pkcs8v1().map_err(|_| Error::Internal)?;
            Ok((
                Zeroizing::new(doc.as_ref().to_vec()),
                kp.public_key().as_ref().to_vec(),
            ))
        }
        #[cfg(not(feature = "pqc"))]
        Alg::MlDsa65 | Alg::MlDsa87 => Err(Error::CapabilityDisabled),
        Alg::Aes256Gcm | Alg::MlKem768 | Alg::MlKem1024 => Err(Error::InvalidArgument),
    }
}

pub(crate) fn sign(alg: Alg, pkcs8: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
    match alg {
        Alg::EcdsaP256Sha256 | Alg::EcdsaP384Sha384 => {
            let sa = if alg == Alg::EcdsaP256Sha256 {
                &ECDSA_P256_SHA256_FIXED_SIGNING
            } else {
                &ECDSA_P384_SHA384_FIXED_SIGNING
            };
            let kp = EcdsaKeyPair::from_pkcs8(sa, pkcs8).map_err(|_| Error::InvalidKeyBlob)?;
            let sig = kp
                .sign(&SystemRandom::new(), message)
                .map_err(|_| Error::CryptoFailure)?;
            Ok(sig.as_ref().to_vec())
        }
        Alg::Ed25519 => {
            let kp = Ed25519KeyPair::from_pkcs8(pkcs8).map_err(|_| Error::InvalidKeyBlob)?;
            let sig = kp.try_sign(message).map_err(|_| Error::CryptoFailure)?;
            Ok(sig.as_ref().to_vec())
        }
        #[cfg(feature = "pqc")]
        Alg::MlDsa65 | Alg::MlDsa87 => {
            let sa = if alg == Alg::MlDsa65 {
                &ML_DSA_65_SIGNING
            } else {
                &ML_DSA_87_SIGNING
            };
            let kp = PqdsaKeyPair::from_pkcs8(sa, pkcs8).map_err(|_| Error::InvalidKeyBlob)?;
            let mut sig = vec![0u8; sa.signature_len()];
            let n = kp
                .sign(message, &mut sig)
                .map_err(|_| Error::CryptoFailure)?;
            sig.truncate(n);
            Ok(sig)
        }
        #[cfg(not(feature = "pqc"))]
        Alg::MlDsa65 | Alg::MlDsa87 => Err(Error::CapabilityDisabled),
        Alg::Aes256Gcm | Alg::MlKem768 | Alg::MlKem1024 => Err(Error::InvalidArgument),
    }
}

pub(crate) fn verify(
    alg: Alg,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    if Some(public_key.len()) != alg.public_key_len() {
        return Err(Error::InvalidArgument);
    }
    let va: &'static dyn VerificationAlgorithm = match alg {
        Alg::EcdsaP256Sha256 => &ECDSA_P256_SHA256_FIXED,
        Alg::EcdsaP384Sha384 => &ECDSA_P384_SHA384_FIXED,
        Alg::Ed25519 => &ED25519,
        #[cfg(feature = "pqc")]
        Alg::MlDsa65 => &ML_DSA_65,
        #[cfg(feature = "pqc")]
        Alg::MlDsa87 => &ML_DSA_87,
        #[cfg(not(feature = "pqc"))]
        Alg::MlDsa65 | Alg::MlDsa87 => return Err(Error::CapabilityDisabled),
        Alg::Aes256Gcm | Alg::MlKem768 | Alg::MlKem1024 => return Err(Error::InvalidArgument),
    };
    Ok(UnparsedPublicKey::new(va, public_key)
        .verify(message, signature)
        .is_ok())
}
