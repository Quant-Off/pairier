use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use crate::error::Error;

pub(super) fn open_private(path: &Path) -> Result<File, Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| Error::new("open", e))?;
    let md = file.metadata().map_err(|e| Error::new("fstat", e))?;
    if !md.is_file() {
        return Err(Error::invalid("open", "not a regular file"));
    }
    if md.uid() != unsafe { libc::getuid() } {
        return Err(Error::invalid("open", "not owned by the current user"));
    }
    if md.mode() & 0o077 != 0 {
        return Err(Error::invalid(
            "open",
            "must not be group or world accessible",
        ));
    }
    if md.nlink() != 1 {
        return Err(Error::invalid("open", "has additional hard links"));
    }
    Ok(file)
}

pub(super) fn create_private(path: &Path) -> Result<File, Error> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| Error::new("create", e))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::{create_private, open_private};

    fn temp_path(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("kms-sys-fs-{}-{tag}", std::process::id()));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn creates_read_only_and_reopens() {
        let p = temp_path("ok");
        let mut f = create_private(&p).unwrap();
        f.write_all(b"secret").unwrap();
        drop(f);
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert!(open_private(&p).is_ok());
        assert!(create_private(&p).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(open_private(&p).is_err());
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn rejects_symlink_and_directory() {
        let target = temp_path("target");
        drop(create_private(&target).unwrap());
        let link = temp_path("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(open_private(&link).is_err());
        assert!(open_private(&std::env::temp_dir()).is_err());
        fs::remove_file(&link).unwrap();
        fs::remove_file(&target).unwrap();
    }
}
