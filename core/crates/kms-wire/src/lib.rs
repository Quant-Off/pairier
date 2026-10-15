#![forbid(unsafe_code)]
#![no_std]

extern crate alloc;

mod codec;
mod error;
mod header;
pub mod msg;

pub use codec::{Reader, Writer};
pub use error::Error;
pub use header::{HEADER_LEN, Header, Kind, MAGIC, MAX_BODY, Op, PROTOCOL_VERSION, Status};

pub mod alg {
    pub const AES_256_GCM: u16 = 0x0001;
    pub const ECDSA_P256_SHA256: u16 = 0x0010;
    pub const ECDSA_P384_SHA384: u16 = 0x0011;
    pub const ED25519: u16 = 0x0020;
    pub const DHKEM_P256: u16 = 0x0030;
    pub const ML_DSA_65: u16 = 0x0100;
    pub const ML_DSA_87: u16 = 0x0101;
    pub const ML_KEM_768: u16 = 0x0200;
    pub const ML_KEM_1024: u16 = 0x0201;
    pub const HYBRID_P256_ML_KEM_768: u16 = 0x0210;
    pub const ML_KEM_768_P256: u16 = 0x0211;
}

pub mod usage {
    pub const ENCRYPT: u32 = 1 << 0;
    pub const DECRYPT: u32 = 1 << 1;
    pub const SIGN: u32 = 1 << 2;
    pub const VERIFY: u32 = 1 << 3;
    pub const WRAP: u32 = 1 << 4;
    pub const UNWRAP: u32 = 1 << 5;
    pub const DERIVE: u32 = 1 << 6;
    pub const DECAPSULATE: u32 = 1 << 7;
    pub const EXPORT: u32 = 1 << 8;
    pub const ALL: u32 = (1 << 9) - 1;
}

pub mod cap {
    pub const FIPS: u64 = 1 << 0;
    pub const PQC: u64 = 1 << 1;
}
