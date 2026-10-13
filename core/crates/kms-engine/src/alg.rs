use kms_wire::alg as wire;

use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alg {
    Aes256Gcm,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
    Ed25519,
    DhkemP256,
    MlDsa65,
    MlDsa87,
    MlKem768,
    MlKem1024,
    HybridP256MlKem768,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgKind {
    Symmetric,
    Signature,
    Kem,
}

impl Alg {
    #[must_use]
    pub fn kind(self) -> AlgKind {
        match self {
            Self::Aes256Gcm => AlgKind::Symmetric,
            Self::EcdsaP256Sha256
            | Self::EcdsaP384Sha384
            | Self::Ed25519
            | Self::MlDsa65
            | Self::MlDsa87 => AlgKind::Signature,
            Self::DhkemP256 | Self::MlKem768 | Self::MlKem1024 | Self::HybridP256MlKem768 => {
                AlgKind::Kem
            }
        }
    }

    #[must_use]
    pub fn is_pqc(self) -> bool {
        matches!(
            self,
            Self::MlDsa65
                | Self::MlDsa87
                | Self::MlKem768
                | Self::MlKem1024
                | Self::HybridP256MlKem768
        )
    }

    #[must_use]
    pub fn wire_id(self) -> u16 {
        match self {
            Self::Aes256Gcm => wire::AES_256_GCM,
            Self::EcdsaP256Sha256 => wire::ECDSA_P256_SHA256,
            Self::EcdsaP384Sha384 => wire::ECDSA_P384_SHA384,
            Self::Ed25519 => wire::ED25519,
            Self::DhkemP256 => wire::DHKEM_P256,
            Self::MlDsa65 => wire::ML_DSA_65,
            Self::MlDsa87 => wire::ML_DSA_87,
            Self::MlKem768 => wire::ML_KEM_768,
            Self::MlKem1024 => wire::ML_KEM_1024,
            Self::HybridP256MlKem768 => wire::HYBRID_P256_ML_KEM_768,
        }
    }

    #[must_use]
    pub fn public_key_len(self) -> Option<usize> {
        match self {
            Self::Aes256Gcm => None,
            Self::EcdsaP256Sha256 | Self::DhkemP256 => Some(65),
            Self::EcdsaP384Sha384 => Some(97),
            Self::Ed25519 => Some(32),
            Self::MlDsa65 => Some(1952),
            Self::MlDsa87 => Some(2592),
            Self::MlKem768 => Some(1184),
            Self::MlKem1024 => Some(1568),
            Self::HybridP256MlKem768 => Some(1249),
        }
    }

    #[must_use]
    pub fn signature_len(self) -> Option<usize> {
        match self {
            Self::EcdsaP256Sha256 | Self::Ed25519 => Some(64),
            Self::EcdsaP384Sha384 => Some(96),
            Self::MlDsa65 => Some(3309),
            Self::MlDsa87 => Some(4627),
            Self::Aes256Gcm
            | Self::DhkemP256
            | Self::MlKem768
            | Self::MlKem1024
            | Self::HybridP256MlKem768 => None,
        }
    }

    #[must_use]
    pub fn kem_ciphertext_len(self) -> Option<usize> {
        match self {
            Self::DhkemP256 => Some(65),
            Self::MlKem768 => Some(1088),
            Self::MlKem1024 => Some(1568),
            Self::HybridP256MlKem768 => Some(1153),
            Self::Aes256Gcm
            | Self::EcdsaP256Sha256
            | Self::EcdsaP384Sha384
            | Self::Ed25519
            | Self::MlDsa65
            | Self::MlDsa87 => None,
        }
    }
}

impl TryFrom<u16> for Alg {
    type Error = Error;

    fn try_from(v: u16) -> Result<Self, Error> {
        match v {
            wire::AES_256_GCM => Ok(Self::Aes256Gcm),
            wire::ECDSA_P256_SHA256 => Ok(Self::EcdsaP256Sha256),
            wire::ECDSA_P384_SHA384 => Ok(Self::EcdsaP384Sha384),
            wire::ED25519 => Ok(Self::Ed25519),
            wire::DHKEM_P256 => Ok(Self::DhkemP256),
            wire::ML_DSA_65 => Ok(Self::MlDsa65),
            wire::ML_DSA_87 => Ok(Self::MlDsa87),
            wire::ML_KEM_768 => Ok(Self::MlKem768),
            wire::ML_KEM_1024 => Ok(Self::MlKem1024),
            wire::HYBRID_P256_ML_KEM_768 => Ok(Self::HybridP256MlKem768),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}
