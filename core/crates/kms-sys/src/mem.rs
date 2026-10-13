use core::fmt;
use core::ptr::NonNull;

use zeroize::Zeroize;

use crate::error::Error;

pub struct LockedBuf {
    data: NonNull<u8>,
    len: usize,
    data_len: usize,
    map: NonNull<u8>,
    map_len: usize,
}

fn page_size() -> Result<usize, Error> {
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(v)
        .ok()
        .filter(|p| *p > 0 && p.is_power_of_two())
        .ok_or_else(|| Error::unsupported("sysconf(_SC_PAGESIZE)"))
}

impl LockedBuf {
    pub fn new(len: usize) -> Result<Self, Error> {
        if len == 0 {
            return Err(Error::invalid("LockedBuf::new", "zero length"));
        }
        let page = page_size()?;
        let data_len = len
            .div_ceil(page)
            .checked_mul(page)
            .ok_or_else(|| Error::invalid("LockedBuf::new", "length overflow"))?;
        let map_len = page
            .checked_mul(2)
            .and_then(|g| g.checked_add(data_len))
            .ok_or_else(|| Error::invalid("LockedBuf::new", "length overflow"))?;

        let raw = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(Error::last("mmap"));
        }
        let map =
            NonNull::new(raw.cast::<u8>()).ok_or_else(|| Error::invalid("mmap", "null map"))?;
        let guard = Self {
            data: map,
            len: 0,
            data_len: 0,
            map,
            map_len,
        };

        let data_ptr = unsafe { map.as_ptr().add(page) };
        let tail_ptr = unsafe { data_ptr.add(data_len) };
        if unsafe { libc::mprotect(map.as_ptr().cast(), page, libc::PROT_NONE) } != 0 {
            return Err(Error::last("mprotect(head guard)"));
        }
        if unsafe { libc::mprotect(tail_ptr.cast(), page, libc::PROT_NONE) } != 0 {
            return Err(Error::last("mprotect(tail guard)"));
        }
        if unsafe { libc::mlock(data_ptr.cast(), data_len) } != 0 {
            return Err(Error::last("mlock"));
        }
        #[cfg(target_os = "linux")]
        if unsafe { libc::madvise(data_ptr.cast(), data_len, libc::MADV_DONTDUMP) } != 0 {
            return Err(Error::last("madvise(MADV_DONTDUMP)"));
        }

        let data = NonNull::new(data_ptr).ok_or_else(|| Error::invalid("mmap", "null data"))?;
        let mut out = guard;
        out.data = data;
        out.len = len;
        out.data_len = data_len;
        Ok(out)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
    }
}

impl Drop for LockedBuf {
    fn drop(&mut self) {
        if self.data_len != 0 {
            let whole =
                unsafe { core::slice::from_raw_parts_mut(self.data.as_ptr(), self.data_len) };
            whole.zeroize();
            unsafe {
                libc::munlock(self.data.as_ptr().cast(), self.data_len);
            }
        }
        unsafe {
            libc::munmap(self.map.as_ptr().cast(), self.map_len);
        }
    }
}

unsafe impl Send for LockedBuf {}
unsafe impl Sync for LockedBuf {}

impl fmt::Debug for LockedBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedBuf")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::{LockedBuf, page_size};

    #[test]
    fn allocates_locks_and_zeroes() {
        let mut b = LockedBuf::new(5).unwrap();
        assert_eq!(b.len(), 5);
        assert!(!b.is_empty());
        assert_eq!(b.as_slice(), &[0, 0, 0, 0, 0]);
        b.as_mut_slice().copy_from_slice(b"hello");
        assert_eq!(b.as_slice(), b"hello");
        drop(b);
    }

    #[test]
    fn rejects_zero_length() {
        assert!(LockedBuf::new(0).is_err());
    }

    #[test]
    fn spans_multiple_pages() {
        let page = page_size().unwrap();
        let n = page.checked_mul(3).unwrap().checked_add(1).unwrap();
        let mut b = LockedBuf::new(n).unwrap();
        b.as_mut_slice()[n - 1] = 0xAA;
        b.as_mut_slice()[0] = 0x55;
        assert_eq!(b.as_slice()[n - 1], 0xAA);
        assert_eq!(b.as_slice()[0], 0x55);
    }

    #[test]
    fn debug_hides_contents() {
        let mut b = LockedBuf::new(4).unwrap();
        b.as_mut_slice().copy_from_slice(b"SECR");
        let s = format!("{b:?}");
        assert!(!s.contains("SECR"));
    }
}
