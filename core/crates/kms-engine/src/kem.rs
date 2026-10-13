use aws_lc_rs::kem::{
    Algorithm, Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768, ML_KEM_1024,
};
use zeroize::Zeroizing;

use crate::alg::Alg;
use crate::error::Error;

fn kem_alg(alg: Alg) -> Result<&'static Algorithm, Error> {
    match alg {
        Alg::MlKem768 => Ok(&ML_KEM_768),
        Alg::MlKem1024 => Ok(&ML_KEM_1024),
        _ => Err(Error::InvalidArgument),
    }
}

pub(crate) fn generate(alg: Alg) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>), Error> {
    let a = kem_alg(alg)?;
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

pub(crate) fn encapsulate(
    alg: Alg,
    ek_bytes: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
    let a = kem_alg(alg)?;
    if Some(ek_bytes.len()) != alg.public_key_len() {
        return Err(Error::InvalidArgument);
    }
    let ek = EncapsulationKey::new(a, ek_bytes).map_err(|_| Error::InvalidArgument)?;
    let (ct, ss) = ek.encapsulate().map_err(|_| Error::CryptoFailure)?;
    Ok((ct.as_ref().to_vec(), Zeroizing::new(ss.as_ref().to_vec())))
}

pub(crate) fn decapsulate(
    alg: Alg,
    dk_bytes: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let a = kem_alg(alg)?;
    if Some(ciphertext.len()) != alg.kem_ciphertext_len() {
        return Err(Error::CryptoFailure);
    }
    let dk = DecapsulationKey::new(a, dk_bytes).map_err(|_| Error::InvalidKeyBlob)?;
    let ss = dk
        .decapsulate(Ciphertext::from(ciphertext))
        .map_err(|_| Error::CryptoFailure)?;
    Ok(Zeroizing::new(ss.as_ref().to_vec()))
}
