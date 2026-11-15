use std::fs::{File, OpenOptions};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;

use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT,
    GetFileInformationByHandle,
};

use crate::error::Error;
use crate::win;

pub(super) fn open_private(path: &Path) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| Error::new("open", e))?;
    let handle = file.as_raw_handle();
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { core::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &raw mut info) } == 0 {
        return Err(Error::last("GetFileInformationByHandle"));
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(Error::invalid("open", "not a regular file"));
    }
    if info.nNumberOfLinks != 1 {
        return Err(Error::invalid("open", "has additional hard links"));
    }
    let owner = win::current_user_sid()?;
    win::check_private_object(handle, SE_FILE_OBJECT, &owner)?;
    Ok(file)
}

pub(super) fn create_private(path: &Path) -> Result<File, Error> {
    let owner = win::current_user_sid()?;
    let attrs = win::Attributes::private(&owner)?;
    create_with(path, &attrs)
}

fn create_with(path: &Path, attrs: &win::Attributes) -> Result<File, Error> {
    let name: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(core::iter::once(0))
        .collect();
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            0,
            attrs.as_ptr(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            core::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(Error::last("CreateFileW"));
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::windows::io::AsRawHandle;
    use std::path::{Path, PathBuf};

    use windows_sys::Win32::Security::Authorization::SE_FILE_OBJECT;

    use super::{create_private, create_with, open_private};
    use crate::win;

    fn temp_path(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("kms-sys-fs-{}-{tag}", std::process::id()));
        let _ = fs::remove_file(&p);
        p
    }

    fn owner_of(p: &Path) -> win::Sid {
        let f = fs::File::open(p).unwrap();
        win::object_security(f.as_raw_handle(), SE_FILE_OBJECT)
            .unwrap()
            .owner
            .unwrap()
    }

    #[test]
    fn owner_is_set_explicitly_and_by_token_default() {
        let me = win::current_user_sid().unwrap();
        let p = temp_path("owner");
        drop(create_private(&p).unwrap());
        assert_eq!(owner_of(&p), me);
        fs::remove_file(&p).unwrap();
        crate::harden::restrict_umask().unwrap();
        let sddl = format!("D:P(A;;FA;;;SY)(A;;FA;;;{})", me.display().unwrap());
        let attrs = win::Attributes::from_sddl(&sddl).unwrap();
        drop(create_with(&p, &attrs).unwrap());
        assert_eq!(owner_of(&p), me);
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn creates_private_file_and_reopens() {
        let p = temp_path("ok");
        let mut f = create_private(&p).unwrap();
        f.write_all(b"secret").unwrap();
        drop(f);
        open_private(&p).unwrap();
        assert!(create_private(&p).is_err());
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn rejects_files_readable_by_others_and_directories() {
        let me = win::current_user_sid().unwrap();
        let sddl = format!(
            "D:P(A;;FA;;;SY)(A;;FA;;;{})(A;;FR;;;WD)",
            me.display().unwrap()
        );
        let attrs = win::Attributes::from_sddl(&sddl).unwrap();
        let p = temp_path("world");
        drop(create_with(&p, &attrs).unwrap());
        assert!(open_private(&p).is_err());
        fs::remove_file(&p).unwrap();
        assert!(open_private(&std::env::temp_dir()).is_err());
        assert!(open_private(&temp_path("missing")).is_err());
    }
}
