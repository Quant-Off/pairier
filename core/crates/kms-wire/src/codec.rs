use alloc::vec::Vec;

use crate::error::Error;
use crate::header::MAX_BODY;

#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(n).ok_or(Error::Overflow)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    pub fn read_u8(&mut self) -> Result<u8, Error> {
        self.take(1)?.first().copied().ok_or(Error::Truncated)
    }

    pub fn read_u16(&mut self) -> Result<u16, Error> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes(
            <[u8; 2]>::try_from(s).map_err(|_| Error::Truncated)?,
        ))
    }

    pub fn read_u32(&mut self) -> Result<u32, Error> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes(
            <[u8; 4]>::try_from(s).map_err(|_| Error::Truncated)?,
        ))
    }

    pub fn read_u64(&mut self) -> Result<u64, Error> {
        let s = self.take(8)?;
        Ok(u64::from_be_bytes(
            <[u8; 8]>::try_from(s).map_err(|_| Error::Truncated)?,
        ))
    }

    pub fn read_bool(&mut self) -> Result<bool, Error> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::BadBool),
        }
    }

    pub fn read_bytes(&mut self, max: usize) -> Result<&'a [u8], Error> {
        let n = usize::try_from(self.read_u32()?).map_err(|_| Error::TooLarge)?;
        if n > max {
            return Err(Error::TooLarge);
        }
        self.take(n)
    }

    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let s = self.read_bytes(N)?;
        <[u8; N]>::try_from(s).map_err(|_| Error::BadLength)
    }

    pub fn read_str(&mut self, max: usize) -> Result<&'a str, Error> {
        core::str::from_utf8(self.read_bytes(max)?).map_err(|_| Error::BadUtf8)
    }

    pub fn finish(self) -> Result<(), Error> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::TrailingBytes)
        }
    }
}

#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self {
            buf: Vec::with_capacity(n),
        }
    }

    fn push(&mut self, s: &[u8]) -> Result<(), Error> {
        let new_len = self.buf.len().checked_add(s.len()).ok_or(Error::Overflow)?;
        if u32::try_from(new_len).map_or(true, |n| n > MAX_BODY) {
            return Err(Error::BodyTooLarge);
        }
        self.buf.extend_from_slice(s);
        Ok(())
    }

    pub fn write_u8(&mut self, v: u8) -> Result<(), Error> {
        self.push(&[v])
    }

    pub fn write_u16(&mut self, v: u16) -> Result<(), Error> {
        self.push(&v.to_be_bytes())
    }

    pub fn write_u32(&mut self, v: u32) -> Result<(), Error> {
        self.push(&v.to_be_bytes())
    }

    pub fn write_u64(&mut self, v: u64) -> Result<(), Error> {
        self.push(&v.to_be_bytes())
    }

    pub fn write_bool(&mut self, v: bool) -> Result<(), Error> {
        self.write_u8(u8::from(v))
    }

    pub fn write_bytes(&mut self, s: &[u8]) -> Result<(), Error> {
        let n = u32::try_from(s.len()).map_err(|_| Error::TooLarge)?;
        self.write_u32(n)?;
        self.push(s)
    }

    pub fn write_str(&mut self, s: &str) -> Result<(), Error> {
        self.write_bytes(s.as_bytes())
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use alloc::vec;

    use super::{Reader, Writer};
    use crate::error::Error;
    use crate::header::MAX_BODY;

    #[test]
    fn writer_rejects_body_over_max() {
        let mut w = Writer::new();
        let chunk = vec![0u8; 1 << 16];
        for _ in 0..16 {
            w.write_bytes(&chunk[..(1 << 16) - 4]).unwrap();
        }
        assert_eq!(w.len(), usize::try_from(MAX_BODY).unwrap());
        assert_eq!(w.write_u8(0), Err(Error::BodyTooLarge));
    }

    #[test]
    fn reader_rejects_trailing_and_truncated() {
        let r = Reader::new(&[0, 0, 0, 1, 9]);
        let mut r2 = r;
        assert_eq!(r2.read_u32().unwrap(), 1);
        assert_eq!(r2.finish(), Err(Error::TrailingBytes));
        let mut r3 = Reader::new(&[0, 0, 0]);
        assert_eq!(r3.read_u32(), Err(Error::Truncated));
        assert_eq!(r3.remaining(), 3);
    }

    #[test]
    fn reader_checks_limit_before_taking() {
        let mut r = Reader::new(&[0, 0, 0, 5, 1, 2]);
        assert_eq!(r.read_bytes(4), Err(Error::TooLarge));
        let mut r = Reader::new(&[0, 0, 0, 5, 1, 2]);
        assert_eq!(r.read_bytes(5), Err(Error::Truncated));
        let mut r = Reader::new(&[0, 0, 0, 2, 1, 2]);
        assert_eq!(r.read_bytes(5).unwrap(), &[1, 2]);
        assert_eq!(r.read_bool(), Err(Error::Truncated));
    }

    #[test]
    fn bool_and_str_strictness() {
        let mut r = Reader::new(&[2]);
        assert_eq!(r.read_bool(), Err(Error::BadBool));
        let mut r = Reader::new(&[0, 0, 0, 1, 0xff]);
        assert_eq!(r.read_str(8), Err(Error::BadUtf8));
        let mut r = Reader::new(&[0, 0, 0, 2, 1]);
        assert_eq!(r.read_array::<2>(), Err(Error::Truncated));
        let mut r = Reader::new(&[0, 0, 0, 1, 1]);
        assert_eq!(r.read_array::<2>(), Err(Error::BadLength));
    }
}
