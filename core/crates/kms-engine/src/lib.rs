#![forbid(unsafe_code)]

mod aead;
mod alg;
mod blob;
mod error;
mod export;
mod kdf;
mod kem;
mod root;
mod sign;
mod usage;

use kms_wire::msg::{KEY_ID_LEN, MAX_RANDOM};
use zeroize::Zeroizing;

pub use alg::{Alg, AlgKind};
pub use error::Error;
pub use root::{ROOT_KEY_LEN, RootKey};
pub use usage::Usage;

pub const ENGINE_NAME: &str = "kms-engine";
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const AEAD_OVERHEAD: usize = aead::OVERHEAD;

pub fn fill_random(out: &mut [u8]) -> Result<(), Error> {
    aws_lc_rs::rand::fill(out).map_err(|_| Error::Internal)
}

#[derive(Debug)]
pub struct GeneratedKey {
    pub key_id: [u8; KEY_ID_LEN],
    pub blob: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub alg: Alg,
    pub usage: Usage,
    pub key_id: [u8; KEY_ID_LEN],
    pub label: String,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedKey {
    pub key_id: [u8; KEY_ID_LEN],
    pub blob: Vec<u8>,
    pub alg: Alg,
    pub usage: Usage,
    pub label: String,
}

#[derive(Debug)]
pub struct Engine {
    root: RootKey,
    pqc_enabled: bool,
}

impl Engine {
    #[must_use]
    pub fn new(root: RootKey, pqc_enabled: bool) -> Self {
        Self { root, pqc_enabled }
    }

    #[must_use]
    pub fn fips_mode() -> bool {
        aws_lc_rs::try_fips_mode().is_ok()
    }

    #[must_use]
    pub fn pqc_available(&self) -> bool {
        cfg!(feature = "pqc") && self.pqc_enabled
    }

    #[must_use]
    pub fn capabilities(&self) -> u64 {
        let mut caps = 0;
        if Self::fips_mode() {
            caps |= kms_wire::cap::FIPS;
        }
        if self.pqc_available() {
            caps |= kms_wire::cap::PQC;
        }
        caps
    }

    fn check_enabled(&self, alg: Alg) -> Result<(), Error> {
        if alg.is_pqc() && !self.pqc_available() {
            return Err(Error::CapabilityDisabled);
        }
        Ok(())
    }

    fn check_current(&self, alg: Alg) -> Result<(), Error> {
        self.check_enabled(alg)?;
        if alg.is_retired() {
            return Err(Error::UnsupportedAlgorithm);
        }
        Ok(())
    }

    pub fn generate_key(&self, alg: Alg, usage: Usage, label: &str) -> Result<GeneratedKey, Error> {
        self.check_current(alg)?;
        usage.check_for(alg)?;
        blob::check_label(label)?;
        let mut key_id = [0u8; KEY_ID_LEN];
        aws_lc_rs::rand::fill(&mut key_id).map_err(|_| Error::Internal)?;

        let (secret, public_key) = match alg.kind() {
            AlgKind::Symmetric => {
                let mut k = Zeroizing::new(vec![0u8; aead::KEY_LEN]);
                aws_lc_rs::rand::fill(k.as_mut_slice()).map_err(|_| Error::Internal)?;
                (k, Vec::new())
            }
            AlgKind::Signature => sign::generate(alg)?,
            AlgKind::Kem => kem::generate(alg)?,
        };

        let header = blob::Header {
            alg,
            usage,
            key_id,
            label,
        };
        let blob = blob::seal(&self.root, &header, &secret)?;
        Ok(GeneratedKey {
            key_id,
            blob,
            public_key,
        })
    }

    pub fn inspect(&self, blob: &[u8]) -> Result<KeyInfo, Error> {
        let k = blob::open(&self.root, blob)?;
        self.check_enabled(k.alg)?;
        let public_key = match k.alg.kind() {
            AlgKind::Symmetric => Vec::new(),
            AlgKind::Signature => sign::public_key(k.alg, &k.secret)?,
            AlgKind::Kem => kem::public_key(k.alg, &k.secret)?,
        };
        Ok(KeyInfo {
            alg: k.alg,
            usage: k.usage,
            key_id: k.key_id,
            label: k.label,
            public_key,
        })
    }

    fn open_for(&self, blob: &[u8], kind: AlgKind, required: u32) -> Result<blob::Unsealed, Error> {
        let k = blob::open(&self.root, blob)?;
        self.check_enabled(k.alg)?;
        if k.alg.kind() != kind {
            return Err(Error::InvalidArgument);
        }
        if !k.usage.contains(required) {
            return Err(Error::UsageDenied);
        }
        Ok(k)
    }

    pub fn aead_encrypt(
        &self,
        blob: &[u8],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let k = self.open_for(blob, AlgKind::Symmetric, kms_wire::usage::ENCRYPT)?;
        aead::encrypt(&k.secret, plaintext, aad)
    }

    pub fn aead_decrypt(
        &self,
        blob: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let k = self.open_for(blob, AlgKind::Symmetric, kms_wire::usage::DECRYPT)?;
        aead::decrypt(&k.secret, ciphertext, aad)
    }

    pub fn sign(&self, blob: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
        if message.len() > kms_wire::msg::MAX_MESSAGE {
            return Err(Error::LimitExceeded);
        }
        let k = self.open_for(blob, AlgKind::Signature, kms_wire::usage::SIGN)?;
        sign::sign(k.alg, &k.secret, message)
    }

    pub fn verify(
        &self,
        alg: Alg,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        self.check_enabled(alg)?;
        if alg.kind() != AlgKind::Signature {
            return Err(Error::InvalidArgument);
        }
        if message.len() > kms_wire::msg::MAX_MESSAGE
            || signature.len() > kms_wire::msg::MAX_SIGNATURE
        {
            return Err(Error::LimitExceeded);
        }
        sign::verify(alg, public_key, message, signature)
    }

    pub fn random(&self, len: usize) -> Result<Vec<u8>, Error> {
        let max = usize::try_from(MAX_RANDOM).map_err(|_| Error::Internal)?;
        if len > max {
            return Err(Error::LimitExceeded);
        }
        let mut out = vec![0u8; len];
        aws_lc_rs::rand::fill(&mut out).map_err(|_| Error::Internal)?;
        Ok(out)
    }

    pub fn encapsulate(
        &self,
        alg: Alg,
        encapsulation_key: &[u8],
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), Error> {
        self.check_current(alg)?;
        if alg.kind() != AlgKind::Kem {
            return Err(Error::InvalidArgument);
        }
        kem::encapsulate(alg, encapsulation_key)
    }

    pub fn export_key(
        &self,
        blob: &[u8],
        kem_alg: Alg,
        recipient_public_key: &[u8],
        usage: Usage,
        context: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.check_current(kem_alg)?;
        if kem_alg.kind() != AlgKind::Kem {
            return Err(Error::InvalidArgument);
        }
        if context.len() > kms_wire::msg::MAX_CONTEXT {
            return Err(Error::LimitExceeded);
        }
        let k = self.open_for(blob, AlgKind::Symmetric, kms_wire::usage::EXPORT)?;
        usage.check_for(k.alg)?;
        if !usage.is_subset_of(k.usage) {
            return Err(Error::UsageDenied);
        }
        let e = export::Export {
            kem_alg,
            alg: k.alg,
            usage,
            key_id: k.key_id,
            label: &k.label,
            context,
        };
        export::seal(&e, recipient_public_key, &k.secret)
    }

    pub fn import_key(
        &self,
        kem_blob: &[u8],
        package: &[u8],
        context: &[u8],
    ) -> Result<ImportedKey, Error> {
        if package.len() > kms_wire::msg::MAX_PACKAGE || context.len() > kms_wire::msg::MAX_CONTEXT
        {
            return Err(Error::LimitExceeded);
        }
        let k = self.open_for(kem_blob, AlgKind::Kem, kms_wire::usage::DECAPSULATE)?;
        let imported = export::open(k.alg, &k.secret, package, context)?;
        if imported.alg.kind() != AlgKind::Symmetric || imported.secret.len() != aead::KEY_LEN {
            return Err(Error::InvalidArgument);
        }
        let header = blob::Header {
            alg: imported.alg,
            usage: imported.usage,
            key_id: imported.key_id,
            label: &imported.label,
        };
        let blob = blob::seal(&self.root, &header, &imported.secret)?;
        Ok(ImportedKey {
            key_id: imported.key_id,
            blob,
            alg: imported.alg,
            usage: imported.usage,
            label: imported.label,
        })
    }

    pub fn decapsulate(&self, blob: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let k = self.open_for(blob, AlgKind::Kem, kms_wire::usage::DECAPSULATE)?;
        kem::decapsulate(k.alg, &k.secret, ciphertext)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]
mod tests {
    use super::{Alg, Engine, Error, RootKey, Usage};
    use kms_wire::usage;

    fn engine() -> Engine {
        Engine::new(RootKey::generate().unwrap(), true)
    }

    #[test]
    fn capabilities_reflect_build() {
        let e = engine();
        assert_eq!(Engine::fips_mode(), cfg!(feature = "fips"));
        assert_eq!(e.pqc_available(), cfg!(feature = "pqc"));
        let caps = e.capabilities();
        assert_eq!(caps & kms_wire::cap::FIPS != 0, cfg!(feature = "fips"));
        assert_eq!(caps & kms_wire::cap::PQC != 0, cfg!(feature = "pqc"));
        let off = Engine::new(RootKey::generate().unwrap(), false);
        assert!(!off.pqc_available());
        assert_eq!(
            off.generate_key(Alg::MlDsa65, Usage::from_bits(usage::SIGN).unwrap(), "")
                .unwrap_err(),
            Error::CapabilityDisabled
        );
    }

    #[test]
    fn symmetric_roundtrip_with_usage_enforcement() {
        let e = engine();
        let both = Usage::from_bits(usage::ENCRYPT | usage::DECRYPT).unwrap();
        let k = e.generate_key(Alg::Aes256Gcm, both, "tenant/db").unwrap();
        assert!(k.public_key.is_empty());
        let info = e.inspect(&k.blob).unwrap();
        assert_eq!(info.alg, Alg::Aes256Gcm);
        assert!(info.public_key.is_empty());
        assert_eq!(info.usage, both);
        assert_eq!(info.key_id, k.key_id);
        assert_eq!(info.label, "tenant/db");
        let ct = e.aead_encrypt(&k.blob, b"hello", b"ctx").unwrap();
        assert_eq!(ct.len(), 5 + super::AEAD_OVERHEAD);
        let pt = e.aead_decrypt(&k.blob, &ct, b"ctx").unwrap();
        assert_eq!(pt.as_slice(), b"hello");
        assert_eq!(
            e.aead_decrypt(&k.blob, &ct, b"other"),
            Err(Error::CryptoFailure)
        );
        let mut bad = ct.clone();
        bad[40] ^= 1;
        assert_eq!(
            e.aead_decrypt(&k.blob, &bad, b"ctx"),
            Err(Error::CryptoFailure)
        );
        let ct2 = e.aead_encrypt(&k.blob, b"hello", b"ctx").unwrap();
        assert_ne!(ct, ct2);

        let enc_only = Usage::from_bits(usage::ENCRYPT).unwrap();
        let k2 = e.generate_key(Alg::Aes256Gcm, enc_only, "").unwrap();
        let ct3 = e.aead_encrypt(&k2.blob, b"x", b"").unwrap();
        assert_eq!(e.aead_decrypt(&k2.blob, &ct3, b""), Err(Error::UsageDenied));
        assert_eq!(e.sign(&k2.blob, b"m"), Err(Error::InvalidArgument));
    }

    #[test]
    fn blobs_are_bound_to_root_key() {
        let e1 = engine();
        let e2 = engine();
        let u = Usage::from_bits(usage::ENCRYPT | usage::DECRYPT).unwrap();
        let k = e1.generate_key(Alg::Aes256Gcm, u, "").unwrap();
        assert_eq!(
            e2.aead_encrypt(&k.blob, b"x", b""),
            Err(Error::InvalidKeyBlob)
        );
        let mut tampered = k.blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            e1.aead_encrypt(&tampered, b"x", b""),
            Err(Error::InvalidKeyBlob)
        );
        let mut relabel = k.blob.clone();
        relabel[3] ^= 1;
        assert_eq!(
            e1.aead_encrypt(&relabel, b"x", b""),
            Err(Error::InvalidKeyBlob)
        );
        assert_eq!(
            e1.aead_encrypt(&k.blob[..20], b"x", b""),
            Err(Error::InvalidKeyBlob)
        );
        assert_eq!(e1.aead_encrypt(&[], b"x", b""), Err(Error::InvalidKeyBlob));
    }

    #[test]
    fn invalid_usage_and_label_rejected() {
        let e = engine();
        assert_eq!(Usage::from_bits(0), Err(Error::InvalidArgument));
        assert_eq!(Usage::from_bits(1 << 31), Err(Error::InvalidArgument));
        let sign = Usage::from_bits(usage::SIGN).unwrap();
        assert_eq!(
            e.generate_key(Alg::Aes256Gcm, sign, "").unwrap_err(),
            Error::InvalidArgument
        );
        let enc = Usage::from_bits(usage::ENCRYPT).unwrap();
        assert_eq!(
            e.generate_key(Alg::Ed25519, enc, "").unwrap_err(),
            Error::InvalidArgument
        );
        let long = "a".repeat(257);
        assert_eq!(
            e.generate_key(Alg::Aes256Gcm, enc, &long).unwrap_err(),
            Error::InvalidArgument
        );
    }

    fn signature_roundtrip(e: &Engine, alg: Alg) {
        let u = Usage::from_bits(usage::SIGN | usage::VERIFY).unwrap();
        let k = e.generate_key(alg, u, "signer").unwrap();
        assert_eq!(k.public_key.len(), alg.public_key_len().unwrap());
        assert_eq!(e.inspect(&k.blob).unwrap().public_key, k.public_key);
        let sig = e.sign(&k.blob, b"message").unwrap();
        assert_eq!(sig.len(), alg.signature_len().unwrap());
        assert!(e.verify(alg, &k.public_key, b"message", &sig).unwrap());
        assert!(!e.verify(alg, &k.public_key, b"messagf", &sig).unwrap());
        let mut bad = sig.clone();
        bad[10] ^= 1;
        assert!(!e.verify(alg, &k.public_key, b"message", &bad).unwrap());
        assert_eq!(
            e.verify(alg, &k.public_key[1..], b"message", &sig),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            e.aead_encrypt(&k.blob, b"x", b""),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn classical_signatures() {
        let e = engine();
        signature_roundtrip(&e, Alg::EcdsaP256Sha256);
        signature_roundtrip(&e, Alg::EcdsaP384Sha384);
        signature_roundtrip(&e, Alg::Ed25519);
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn pqc_signatures() {
        let e = engine();
        signature_roundtrip(&e, Alg::MlDsa65);
        signature_roundtrip(&e, Alg::MlDsa87);
    }

    fn kem_roundtrip(e: &Engine, alg: Alg) {
        let u = Usage::from_bits(usage::DECAPSULATE).unwrap();
        let k = e.generate_key(alg, u, "kem").unwrap();
        assert_eq!(k.public_key.len(), alg.public_key_len().unwrap());
        assert_eq!(e.inspect(&k.blob).unwrap().public_key, k.public_key);
        let (ct, ss1) = e.encapsulate(alg, &k.public_key).unwrap();
        assert_eq!(ct.len(), alg.kem_ciphertext_len().unwrap());
        let ss2 = e
            .decapsulate(&k.blob, &ct)
            .unwrap_or_else(|err| panic!("{alg:?}: decapsulate {err}"));
        assert_eq!(ss1.as_slice(), ss2.as_slice());
        assert_eq!(ss1.len(), 32);
        let (ct2, ss3) = e.encapsulate(alg, &k.public_key).unwrap();
        assert_ne!(ct, ct2);
        assert_ne!(ss1.as_slice(), ss3.as_slice());
        let mut bad = ct.clone();
        bad[ct.len() - 1] ^= 1;
        match e.decapsulate(&k.blob, &bad) {
            Ok(ss) => assert_ne!(ss1.as_slice(), ss.as_slice()),
            Err(err) => assert_eq!(err, Error::CryptoFailure),
        }
        assert_eq!(e.decapsulate(&k.blob, &ct[1..]), Err(Error::CryptoFailure));
        assert_eq!(
            e.encapsulate(alg, &k.public_key[1..]),
            Err(Error::InvalidArgument)
        );
        assert_eq!(e.sign(&k.blob, b"m"), Err(Error::InvalidArgument));
        assert_eq!(
            e.aead_encrypt(&k.blob, b"x", b""),
            Err(Error::InvalidArgument)
        );
        let other = e.generate_key(alg, u, "other").unwrap();
        let ss4 = e.decapsulate(&other.blob, &ct);
        assert!(ss4.map_or(true, |s| s.as_slice() != ss1.as_slice()));
    }

    #[test]
    fn classical_kem() {
        let e = engine();
        kem_roundtrip(&e, Alg::DhkemP256);
        let enc = Usage::from_bits(usage::ENCRYPT).unwrap();
        assert_eq!(
            e.generate_key(Alg::DhkemP256, enc, "").unwrap_err(),
            Error::InvalidArgument
        );
        assert_eq!(
            e.encapsulate(Alg::Aes256Gcm, &[0u8; 65]),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn pqc_kems_follow_capability() {
        let e = engine();
        for alg in [Alg::MlKem768, Alg::MlKem1024, Alg::MlKem768P256] {
            if cfg!(feature = "pqc") {
                kem_roundtrip(&e, alg);
            } else {
                let u = Usage::from_bits(usage::DECAPSULATE).unwrap();
                assert_eq!(
                    e.generate_key(alg, u, "").unwrap_err(),
                    Error::CapabilityDisabled
                );
                assert_eq!(
                    e.encapsulate(alg, &[0u8; 65]),
                    Err(Error::CapabilityDisabled)
                );
            }
        }
        let off = Engine::new(RootKey::generate().unwrap(), false);
        assert_eq!(
            off.encapsulate(Alg::HybridP256MlKem768, &[0u8; 1249]),
            Err(Error::CapabilityDisabled)
        );
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn retired_hybrid_opens_but_never_seals() {
        let e = engine();
        let decap = Usage::from_bits(usage::DECAPSULATE).unwrap();
        let legacy = Alg::HybridP256MlKem768;
        assert_eq!(
            e.generate_key(legacy, decap, "").unwrap_err(),
            Error::UnsupportedAlgorithm
        );
        let (secret, public_key) = super::kem::generate(legacy).unwrap();
        let header = super::blob::Header {
            alg: legacy,
            usage: decap,
            key_id: [7u8; 16],
            label: "kem/legacy",
        };
        let kem_blob = super::blob::seal(&e.root, &header, &secret).unwrap();
        assert_eq!(e.inspect(&kem_blob).unwrap().public_key, public_key);
        assert_eq!(
            e.encapsulate(legacy, &public_key),
            Err(Error::UnsupportedAlgorithm)
        );
        let full = Usage::from_bits(usage::DECRYPT | usage::EXPORT).unwrap();
        let k = e.generate_key(Alg::Aes256Gcm, full, "shared").unwrap();
        let grant = Usage::from_bits(usage::DECRYPT).unwrap();
        assert_eq!(
            e.export_key(&k.blob, legacy, &public_key, grant, b"ctx"),
            Err(Error::UnsupportedAlgorithm)
        );
        let opened = e
            .open_for(&k.blob, super::AlgKind::Symmetric, usage::EXPORT)
            .unwrap();
        let pending = super::export::Export {
            kem_alg: legacy,
            alg: Alg::Aes256Gcm,
            usage: grant,
            key_id: opened.key_id,
            label: "shared",
            context: b"ctx",
        };
        let pkg = super::export::seal(&pending, &public_key, &opened.secret).unwrap();
        let imp = e.import_key(&kem_blob, &pkg, b"ctx").unwrap();
        assert_eq!(imp.key_id, k.key_id);
        assert_eq!(imp.usage, grant);
    }

    fn exchange_roundtrip(sender: &Engine, recipient: &Engine, kem_alg: Alg) {
        let decap = Usage::from_bits(usage::DECAPSULATE).unwrap();
        let kem = recipient.generate_key(kem_alg, decap, "kem").unwrap();
        let full = Usage::from_bits(usage::ENCRYPT | usage::DECRYPT | usage::EXPORT).unwrap();
        let k = sender.generate_key(Alg::Aes256Gcm, full, "shared").unwrap();
        let ct = sender.aead_encrypt(&k.blob, b"payload", b"aad").unwrap();
        let grant = Usage::from_bits(usage::DECRYPT).unwrap();
        let ctx = b"from=a;to=b;t=1";
        let pkg = sender
            .export_key(&k.blob, kem_alg, &kem.public_key, grant, ctx)
            .unwrap();
        assert!(pkg.len() <= kms_wire::msg::MAX_PACKAGE);

        let imp = recipient.import_key(&kem.blob, &pkg, ctx).unwrap();
        assert_eq!(imp.key_id, k.key_id);
        assert_eq!(imp.alg, Alg::Aes256Gcm);
        assert_eq!(imp.usage, grant);
        assert_eq!(imp.label, "shared");
        assert_eq!(
            recipient
                .aead_decrypt(&imp.blob, &ct, b"aad")
                .unwrap()
                .as_slice(),
            b"payload"
        );
        assert_eq!(
            recipient.aead_encrypt(&imp.blob, b"x", b""),
            Err(Error::UsageDenied)
        );
        assert_eq!(
            recipient.export_key(&imp.blob, kem_alg, &kem.public_key, grant, ctx),
            Err(Error::UsageDenied)
        );
        let info = recipient.inspect(&imp.blob).unwrap();
        assert_eq!(info.key_id, k.key_id);
        assert_eq!(info.usage, grant);

        let pkg2 = sender
            .export_key(&k.blob, kem_alg, &kem.public_key, grant, ctx)
            .unwrap();
        assert_ne!(pkg, pkg2);

        assert_eq!(
            recipient.import_key(&kem.blob, &pkg, b"from=a;to=c;t=1"),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            recipient.import_key(&kem.blob, &pkg, b""),
            Err(Error::InvalidArgument)
        );
        let other = recipient.generate_key(kem_alg, decap, "kem2").unwrap();
        assert_eq!(
            recipient.import_key(&other.blob, &pkg, ctx),
            Err(Error::CryptoFailure)
        );
        assert_eq!(
            sender.import_key(&kem.blob, &pkg, ctx),
            Err(Error::InvalidKeyBlob)
        );
        for i in 0..pkg.len() {
            let mut t = pkg.clone();
            t[i] ^= 0x01;
            assert!(
                recipient.import_key(&kem.blob, &t, ctx).is_err(),
                "byte {i}"
            );
        }
        assert!(
            recipient
                .import_key(&kem.blob, &pkg[..pkg.len() - 1], ctx)
                .is_err()
        );
        let mut extended = pkg.clone();
        extended.push(0);
        assert!(recipient.import_key(&kem.blob, &extended, ctx).is_err());
        assert_eq!(
            recipient.import_key(&kem.blob, &[], ctx),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn export_import_classical() {
        let a = engine();
        let b = engine();
        exchange_roundtrip(&a, &b, Alg::DhkemP256);
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn export_import_pqc() {
        let a = engine();
        let b = engine();
        for alg in [Alg::MlKem768, Alg::MlKem1024, Alg::MlKem768P256] {
            exchange_roundtrip(&a, &b, alg);
        }
    }

    #[test]
    fn export_enforces_usage_and_kinds() {
        let a = engine();
        let b = engine();
        let decap = Usage::from_bits(usage::DECAPSULATE).unwrap();
        let kem = b.generate_key(Alg::DhkemP256, decap, "").unwrap();
        let ctx = b"ctx";

        let no_export = Usage::from_bits(usage::ENCRYPT | usage::DECRYPT).unwrap();
        let k = a.generate_key(Alg::Aes256Gcm, no_export, "").unwrap();
        let grant = Usage::from_bits(usage::DECRYPT).unwrap();
        assert_eq!(
            a.export_key(&k.blob, Alg::DhkemP256, &kem.public_key, grant, ctx),
            Err(Error::UsageDenied)
        );

        let exportable = Usage::from_bits(usage::DECRYPT | usage::EXPORT).unwrap();
        let k = a.generate_key(Alg::Aes256Gcm, exportable, "").unwrap();
        let escalate = Usage::from_bits(usage::ENCRYPT | usage::DECRYPT).unwrap();
        assert_eq!(
            a.export_key(&k.blob, Alg::DhkemP256, &kem.public_key, escalate, ctx),
            Err(Error::UsageDenied)
        );
        let wrong_kind = Usage::from_bits(usage::SIGN).unwrap();
        assert_eq!(
            a.export_key(&k.blob, Alg::DhkemP256, &kem.public_key, wrong_kind, ctx),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            a.export_key(&k.blob, Alg::Aes256Gcm, &kem.public_key, grant, ctx),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            a.export_key(&k.blob, Alg::DhkemP256, &kem.public_key[1..], grant, ctx),
            Err(Error::InvalidArgument)
        );
        let big = vec![0u8; kms_wire::msg::MAX_CONTEXT + 1];
        assert_eq!(
            a.export_key(&k.blob, Alg::DhkemP256, &kem.public_key, grant, &big),
            Err(Error::LimitExceeded)
        );
        let pkg = a
            .export_key(&k.blob, Alg::DhkemP256, &kem.public_key, grant, ctx)
            .unwrap();
        assert_eq!(b.import_key(&k.blob, &pkg, ctx), Err(Error::InvalidKeyBlob));
        assert_eq!(
            b.import_key(&kem.blob, &pkg, &big),
            Err(Error::LimitExceeded)
        );

        let signer = a
            .generate_key(Alg::Ed25519, Usage::from_bits(usage::SIGN).unwrap(), "")
            .unwrap();
        assert_eq!(
            a.export_key(&signer.blob, Alg::DhkemP256, &kem.public_key, grant, ctx),
            Err(Error::InvalidArgument)
        );

        let off = Engine::new(RootKey::generate().unwrap(), false);
        let k2 = off.generate_key(Alg::Aes256Gcm, exportable, "").unwrap();
        assert_eq!(
            off.export_key(&k2.blob, Alg::HybridP256MlKem768, &[0u8; 1249], grant, ctx),
            Err(Error::CapabilityDisabled)
        );
    }

    #[test]
    fn random_is_bounded_and_fresh() {
        let e = engine();
        assert!(e.random(0).unwrap().is_empty());
        let a = e.random(32).unwrap();
        let b = e.random(32).unwrap();
        assert_ne!(a, b);
        assert_eq!(e.random(1025), Err(Error::LimitExceeded));
    }

    #[test]
    fn limits_enforced() {
        let e = engine();
        let u = Usage::from_bits(usage::ENCRYPT | usage::DECRYPT).unwrap();
        let k = e.generate_key(Alg::Aes256Gcm, u, "").unwrap();
        let big = vec![0u8; kms_wire::msg::MAX_PLAINTEXT + 1];
        assert_eq!(
            e.aead_encrypt(&k.blob, &big, b""),
            Err(Error::LimitExceeded)
        );
        let ok = vec![0u8; kms_wire::msg::MAX_PLAINTEXT];
        let ct = e.aead_encrypt(&k.blob, &ok, b"").unwrap();
        assert!(ct.len() <= kms_wire::msg::MAX_CIPHERTEXT);
        assert_eq!(
            e.aead_decrypt(&k.blob, &ct[..10], b""),
            Err(Error::CryptoFailure)
        );
        let big_aad = vec![0u8; kms_wire::msg::MAX_AAD + 1];
        assert_eq!(
            e.aead_encrypt(&k.blob, b"x", &big_aad),
            Err(Error::LimitExceeded)
        );
    }
}
