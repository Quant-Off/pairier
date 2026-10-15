use crate::error::Error;

pub const MAGIC: [u8; 4] = *b"KWP1";
pub const HEADER_LEN: usize = 16;
pub const MAX_BODY: u32 = 1 << 20;
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Request = 1,
    Response = 2,
}

impl From<Kind> for u8 {
    fn from(k: Kind) -> Self {
        match k {
            Kind::Request => 1,
            Kind::Response => 2,
        }
    }
}

impl TryFrom<u8> for Kind {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self, Error> {
        match v {
            1 => Ok(Self::Request),
            2 => Ok(Self::Response),
            _ => Err(Error::BadKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    Protocol = 1,
    UnsupportedOp = 2,
    InvalidArgument = 3,
    InvalidKeyBlob = 4,
    UsageDenied = 5,
    CryptoFailure = 6,
    CapabilityDisabled = 7,
    LimitExceeded = 8,
    Internal = 9,
}

impl From<Status> for u8 {
    fn from(s: Status) -> Self {
        match s {
            Status::Ok => 0,
            Status::Protocol => 1,
            Status::UnsupportedOp => 2,
            Status::InvalidArgument => 3,
            Status::InvalidKeyBlob => 4,
            Status::UsageDenied => 5,
            Status::CryptoFailure => 6,
            Status::CapabilityDisabled => 7,
            Status::LimitExceeded => 8,
            Status::Internal => 9,
        }
    }
}

impl TryFrom<u8> for Status {
    type Error = Error;

    fn try_from(v: u8) -> Result<Self, Error> {
        match v {
            0 => Ok(Self::Ok),
            1 => Ok(Self::Protocol),
            2 => Ok(Self::UnsupportedOp),
            3 => Ok(Self::InvalidArgument),
            4 => Ok(Self::InvalidKeyBlob),
            5 => Ok(Self::UsageDenied),
            6 => Ok(Self::CryptoFailure),
            7 => Ok(Self::CapabilityDisabled),
            8 => Ok(Self::LimitExceeded),
            9 => Ok(Self::Internal),
            _ => Err(Error::BadStatus),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Op {
    Hello = 0x0001,
    Ping = 0x0002,
    KeyGenerate = 0x0010,
    KeyInspect = 0x0011,
    AeadEncrypt = 0x0020,
    AeadDecrypt = 0x0021,
    Sign = 0x0022,
    Verify = 0x0023,
    KeyExport = 0x0030,
    KeyImport = 0x0031,
    Random = 0x0040,
}

impl From<Op> for u16 {
    fn from(op: Op) -> Self {
        match op {
            Op::Hello => 0x0001,
            Op::Ping => 0x0002,
            Op::KeyGenerate => 0x0010,
            Op::KeyInspect => 0x0011,
            Op::AeadEncrypt => 0x0020,
            Op::AeadDecrypt => 0x0021,
            Op::Sign => 0x0022,
            Op::Verify => 0x0023,
            Op::KeyExport => 0x0030,
            Op::KeyImport => 0x0031,
            Op::Random => 0x0040,
        }
    }
}

impl TryFrom<u16> for Op {
    type Error = Error;

    fn try_from(v: u16) -> Result<Self, Error> {
        match v {
            0x0001 => Ok(Self::Hello),
            0x0002 => Ok(Self::Ping),
            0x0010 => Ok(Self::KeyGenerate),
            0x0011 => Ok(Self::KeyInspect),
            0x0020 => Ok(Self::AeadEncrypt),
            0x0021 => Ok(Self::AeadDecrypt),
            0x0022 => Ok(Self::Sign),
            0x0023 => Ok(Self::Verify),
            0x0030 => Ok(Self::KeyExport),
            0x0031 => Ok(Self::KeyImport),
            0x0040 => Ok(Self::Random),
            _ => Err(Error::UnknownOp),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: Kind,
    pub status: Status,
    pub op: u16,
    pub id: u32,
    pub len: u32,
}

impl Header {
    pub fn request(op: Op, id: u32, len: u32) -> Result<Self, Error> {
        if len > MAX_BODY {
            return Err(Error::BodyTooLarge);
        }
        Ok(Self {
            kind: Kind::Request,
            status: Status::Ok,
            op: u16::from(op),
            id,
            len,
        })
    }

    pub fn response(op: u16, id: u32, len: u32) -> Result<Self, Error> {
        if len > MAX_BODY {
            return Err(Error::BodyTooLarge);
        }
        Ok(Self {
            kind: Kind::Response,
            status: Status::Ok,
            op,
            id,
            len,
        })
    }

    #[must_use]
    pub const fn error(op: u16, id: u32, status: Status) -> Self {
        Self {
            kind: Kind::Response,
            status,
            op,
            id,
            len: 0,
        }
    }

    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        let (magic, rest) = out.split_at_mut(4);
        magic.copy_from_slice(&MAGIC);
        let (kind, rest) = rest.split_at_mut(1);
        kind.copy_from_slice(&[u8::from(self.kind)]);
        let (status, rest) = rest.split_at_mut(1);
        status.copy_from_slice(&[u8::from(self.status)]);
        let (op, rest) = rest.split_at_mut(2);
        op.copy_from_slice(&self.op.to_be_bytes());
        let (id, len) = rest.split_at_mut(4);
        id.copy_from_slice(&self.id.to_be_bytes());
        len.copy_from_slice(&self.len.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8; HEADER_LEN]) -> Result<Self, Error> {
        let (magic, rest) = buf.split_at(4);
        if magic != MAGIC {
            return Err(Error::BadMagic);
        }
        let (kind, rest) = rest.split_at(1);
        let kind = Kind::try_from(kind.first().copied().ok_or(Error::Truncated)?)?;
        let (status, rest) = rest.split_at(1);
        let status = Status::try_from(status.first().copied().ok_or(Error::Truncated)?)?;
        let (op, rest) = rest.split_at(2);
        let op = u16::from_be_bytes(<[u8; 2]>::try_from(op).map_err(|_| Error::Truncated)?);
        let (id, len) = rest.split_at(4);
        let id = u32::from_be_bytes(<[u8; 4]>::try_from(id).map_err(|_| Error::Truncated)?);
        let len = u32::from_be_bytes(<[u8; 4]>::try_from(len).map_err(|_| Error::Truncated)?);
        if len > MAX_BODY {
            return Err(Error::BodyTooLarge);
        }
        match kind {
            Kind::Request if status != Status::Ok => return Err(Error::BadStatus),
            Kind::Response if status != Status::Ok && len != 0 => return Err(Error::BadStatus),
            _ => {}
        }
        Ok(Self {
            kind,
            status,
            op,
            id,
            len,
        })
    }
}
