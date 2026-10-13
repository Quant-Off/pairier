use alloc::vec::Vec;

use crate::codec::{Reader, Writer};
use crate::error::Error;
use crate::header::Op;

pub const KEY_ID_LEN: usize = 16;
pub const MAX_LABEL: usize = 256;
pub const MAX_NAME: usize = 64;
pub const MAX_KEY_BLOB: usize = 16 * 1024;
pub const MAX_PUBLIC_KEY: usize = 8 * 1024;
pub const MAX_SIGNATURE: usize = 8 * 1024;
pub const MAX_AAD: usize = 64 * 1024;
pub const MAX_PLAINTEXT: usize = 64 * 1024;
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 64;
pub const MAX_MESSAGE: usize = 64 * 1024;
pub const MAX_RANDOM: u32 = 1024;
pub const MAX_CONTEXT: usize = 1024;
pub const MAX_PACKAGE: usize = 8 * 1024;

pub trait Message<'a>: Sized {
    const OP: Op;

    fn encode(&self, w: &mut Writer) -> Result<(), Error>;

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error>;

    fn encode_body(&self) -> Result<Vec<u8>, Error> {
        let mut w = Writer::new();
        self.encode(&mut w)?;
        Ok(w.finish())
    }

    fn decode_body(body: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        let m = Self::decode(&mut r)?;
        r.finish()?;
        Ok(m)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloRequest {
    pub protocol_version: u32,
}

impl Message<'_> for HelloRequest {
    const OP: Op = Op::Hello;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_u32(self.protocol_version)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            protocol_version: r.read_u32()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloResponse<'a> {
    pub protocol_version: u32,
    pub capabilities: u64,
    pub engine_name: &'a str,
    pub engine_version: &'a str,
}

impl<'a> Message<'a> for HelloResponse<'a> {
    const OP: Op = Op::Hello;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_u32(self.protocol_version)?;
        w.write_u64(self.capabilities)?;
        w.write_str(self.engine_name)?;
        w.write_str(self.engine_version)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            protocol_version: r.read_u32()?,
            capabilities: r.read_u64()?,
            engine_name: r.read_str(MAX_NAME)?,
            engine_version: r.read_str(MAX_NAME)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PingRequest;

impl Message<'_> for PingRequest {
    const OP: Op = Op::Ping;

    fn encode(&self, _w: &mut Writer) -> Result<(), Error> {
        Ok(())
    }

    fn decode(_r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PingResponse;

impl Message<'_> for PingResponse {
    const OP: Op = Op::Ping;

    fn encode(&self, _w: &mut Writer) -> Result<(), Error> {
        Ok(())
    }

    fn decode(_r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyGenerateRequest<'a> {
    pub alg: u16,
    pub usage: u32,
    pub label: &'a str,
}

impl<'a> Message<'a> for KeyGenerateRequest<'a> {
    const OP: Op = Op::KeyGenerate;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_u16(self.alg)?;
        w.write_u32(self.usage)?;
        w.write_str(self.label)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            alg: r.read_u16()?,
            usage: r.read_u32()?,
            label: r.read_str(MAX_LABEL)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyGenerateResponse<'a> {
    pub key_id: [u8; KEY_ID_LEN],
    pub key_blob: &'a [u8],
    pub public_key: &'a [u8],
}

impl<'a> Message<'a> for KeyGenerateResponse<'a> {
    const OP: Op = Op::KeyGenerate;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bytes(&self.key_id)?;
        w.write_bytes(self.key_blob)?;
        w.write_bytes(self.public_key)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            key_id: r.read_array::<KEY_ID_LEN>()?,
            key_blob: r.read_bytes(MAX_KEY_BLOB)?,
            public_key: r.read_bytes(MAX_PUBLIC_KEY)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadEncryptRequest<'a> {
    pub key_blob: &'a [u8],
    pub plaintext: &'a [u8],
    pub aad: &'a [u8],
}

impl<'a> Message<'a> for AeadEncryptRequest<'a> {
    const OP: Op = Op::AeadEncrypt;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bytes(self.key_blob)?;
        w.write_bytes(self.plaintext)?;
        w.write_bytes(self.aad)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            key_blob: r.read_bytes(MAX_KEY_BLOB)?,
            plaintext: r.read_bytes(MAX_PLAINTEXT)?,
            aad: r.read_bytes(MAX_AAD)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadEncryptResponse<'a> {
    pub ciphertext: &'a [u8],
}

impl<'a> Message<'a> for AeadEncryptResponse<'a> {
    const OP: Op = Op::AeadEncrypt;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bytes(self.ciphertext)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            ciphertext: r.read_bytes(MAX_CIPHERTEXT)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadDecryptRequest<'a> {
    pub key_blob: &'a [u8],
    pub ciphertext: &'a [u8],
    pub aad: &'a [u8],
}

impl<'a> Message<'a> for AeadDecryptRequest<'a> {
    const OP: Op = Op::AeadDecrypt;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bytes(self.key_blob)?;
        w.write_bytes(self.ciphertext)?;
        w.write_bytes(self.aad)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            key_blob: r.read_bytes(MAX_KEY_BLOB)?,
            ciphertext: r.read_bytes(MAX_CIPHERTEXT)?,
            aad: r.read_bytes(MAX_AAD)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadDecryptResponse<'a> {
    pub plaintext: &'a [u8],
}

impl<'a> Message<'a> for AeadDecryptResponse<'a> {
    const OP: Op = Op::AeadDecrypt;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bytes(self.plaintext)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            plaintext: r.read_bytes(MAX_PLAINTEXT)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignRequest<'a> {
    pub key_blob: &'a [u8],
    pub message: &'a [u8],
}

impl<'a> Message<'a> for SignRequest<'a> {
    const OP: Op = Op::Sign;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bytes(self.key_blob)?;
        w.write_bytes(self.message)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            key_blob: r.read_bytes(MAX_KEY_BLOB)?,
            message: r.read_bytes(MAX_MESSAGE)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignResponse<'a> {
    pub signature: &'a [u8],
}

impl<'a> Message<'a> for SignResponse<'a> {
    const OP: Op = Op::Sign;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bytes(self.signature)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            signature: r.read_bytes(MAX_SIGNATURE)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyRequest<'a> {
    pub alg: u16,
    pub public_key: &'a [u8],
    pub message: &'a [u8],
    pub signature: &'a [u8],
}

impl<'a> Message<'a> for VerifyRequest<'a> {
    const OP: Op = Op::Verify;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_u16(self.alg)?;
        w.write_bytes(self.public_key)?;
        w.write_bytes(self.message)?;
        w.write_bytes(self.signature)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            alg: r.read_u16()?,
            public_key: r.read_bytes(MAX_PUBLIC_KEY)?,
            message: r.read_bytes(MAX_MESSAGE)?,
            signature: r.read_bytes(MAX_SIGNATURE)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyResponse {
    pub valid: bool,
}

impl Message<'_> for VerifyResponse {
    const OP: Op = Op::Verify;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bool(self.valid)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self {
            valid: r.read_bool()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomRequest {
    pub len: u32,
}

impl Message<'_> for RandomRequest {
    const OP: Op = Op::Random;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_u32(self.len)
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, Error> {
        let len = r.read_u32()?;
        if len > MAX_RANDOM {
            return Err(Error::TooLarge);
        }
        Ok(Self { len })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RandomResponse<'a> {
    pub bytes: &'a [u8],
}

impl<'a> Message<'a> for RandomResponse<'a> {
    const OP: Op = Op::Random;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bytes(self.bytes)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        let max = usize::try_from(MAX_RANDOM).map_err(|_| Error::TooLarge)?;
        Ok(Self {
            bytes: r.read_bytes(max)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyInspectRequest<'a> {
    pub key_blob: &'a [u8],
}

impl<'a> Message<'a> for KeyInspectRequest<'a> {
    const OP: Op = Op::KeyInspect;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bytes(self.key_blob)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            key_blob: r.read_bytes(MAX_KEY_BLOB)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyInspectResponse<'a> {
    pub alg: u16,
    pub usage: u32,
    pub key_id: [u8; KEY_ID_LEN],
    pub label: &'a str,
}

impl<'a> Message<'a> for KeyInspectResponse<'a> {
    const OP: Op = Op::KeyInspect;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_u16(self.alg)?;
        w.write_u32(self.usage)?;
        w.write_bytes(&self.key_id)?;
        w.write_str(self.label)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            alg: r.read_u16()?,
            usage: r.read_u32()?,
            key_id: r.read_array::<KEY_ID_LEN>()?,
            label: r.read_str(MAX_LABEL)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyExportRequest<'a> {
    pub key_blob: &'a [u8],
    pub kem_alg: u16,
    pub recipient_public_key: &'a [u8],
    pub usage: u32,
    pub context: &'a [u8],
}

impl<'a> Message<'a> for KeyExportRequest<'a> {
    const OP: Op = Op::KeyExport;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bytes(self.key_blob)?;
        w.write_u16(self.kem_alg)?;
        w.write_bytes(self.recipient_public_key)?;
        w.write_u32(self.usage)?;
        w.write_bytes(self.context)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            key_blob: r.read_bytes(MAX_KEY_BLOB)?,
            kem_alg: r.read_u16()?,
            recipient_public_key: r.read_bytes(MAX_PUBLIC_KEY)?,
            usage: r.read_u32()?,
            context: r.read_bytes(MAX_CONTEXT)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyExportResponse<'a> {
    pub package: &'a [u8],
}

impl<'a> Message<'a> for KeyExportResponse<'a> {
    const OP: Op = Op::KeyExport;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bytes(self.package)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            package: r.read_bytes(MAX_PACKAGE)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyImportRequest<'a> {
    pub kem_key_blob: &'a [u8],
    pub package: &'a [u8],
    pub context: &'a [u8],
}

impl<'a> Message<'a> for KeyImportRequest<'a> {
    const OP: Op = Op::KeyImport;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bytes(self.kem_key_blob)?;
        w.write_bytes(self.package)?;
        w.write_bytes(self.context)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            kem_key_blob: r.read_bytes(MAX_KEY_BLOB)?,
            package: r.read_bytes(MAX_PACKAGE)?,
            context: r.read_bytes(MAX_CONTEXT)?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyImportResponse<'a> {
    pub key_id: [u8; KEY_ID_LEN],
    pub key_blob: &'a [u8],
    pub alg: u16,
    pub usage: u32,
    pub label: &'a str,
}

impl<'a> Message<'a> for KeyImportResponse<'a> {
    const OP: Op = Op::KeyImport;

    fn encode(&self, w: &mut Writer) -> Result<(), Error> {
        w.write_bytes(&self.key_id)?;
        w.write_bytes(self.key_blob)?;
        w.write_u16(self.alg)?;
        w.write_u32(self.usage)?;
        w.write_str(self.label)
    }

    fn decode(r: &mut Reader<'a>) -> Result<Self, Error> {
        Ok(Self {
            key_id: r.read_array::<KEY_ID_LEN>()?,
            key_blob: r.read_bytes(MAX_KEY_BLOB)?,
            alg: r.read_u16()?,
            usage: r.read_u32()?,
            label: r.read_str(MAX_LABEL)?,
        })
    }
}
