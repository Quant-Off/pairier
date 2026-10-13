use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use kms_engine::{ROOT_KEY_LEN, RootKey};
use zeroize::Zeroizing;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

fn check_metadata(file: &File) -> io::Result<()> {
    let md = file.metadata()?;
    if !md.is_file() {
        return Err(invalid("root key path is not a regular file"));
    }
    if md.uid() != kms_sys::peer::current_uid() {
        return Err(invalid("root key file is not owned by the current user"));
    }
    if md.mode() & 0o077 != 0 {
        return Err(invalid(
            "root key file must not be group or world accessible",
        ));
    }
    if md.nlink() != 1 {
        return Err(invalid("root key file must not have additional hard links"));
    }
    if md.len() != u64::try_from(ROOT_KEY_LEN).map_err(|_| invalid("length overflow"))? {
        return Err(invalid("root key file has wrong length"));
    }
    Ok(())
}

pub(crate) fn load(path: &Path) -> io::Result<RootKey> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc_nofollow())
        .open(path)?;
    check_metadata(&file)?;
    let mut buf = Zeroizing::new([0u8; ROOT_KEY_LEN]);
    file.read_exact(buf.as_mut_slice())?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(invalid("root key file has trailing data"));
    }
    RootKey::from_slice(buf.as_slice()).map_err(|e| invalid(&e.to_string()))
}

pub(crate) fn generate(path: &Path) -> io::Result<()> {
    let mut buf = Zeroizing::new([0u8; ROOT_KEY_LEN]);
    kms_engine::fill_random(buf.as_mut_slice()).map_err(|e| invalid(&e.to_string()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc_nofollow())
        .open(path)?;
    file.write_all(buf.as_slice())?;
    file.sync_all()?;
    Ok(())
}

const fn libc_nofollow() -> i32 {
    libc::O_NOFOLLOW
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::{generate, load};

    fn temp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("kms-core-test-{}-{tag}", std::process::id()));
        let _ = fs::remove_file(&p);
        p
    }

    #[test]
    fn generate_then_load() {
        let p = temp_path("ok");
        generate(&p).unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert!(load(&p).is_ok());
        assert!(generate(&p).is_err());
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn rejects_permissive_short_and_missing() {
        let p = temp_path("perm");
        generate(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load(&p).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&p).is_ok());
        fs::remove_file(&p).unwrap();

        let s = temp_path("short");
        fs::write(&s, [0u8; 31]).unwrap();
        fs::set_permissions(&s, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&s).is_err());
        fs::remove_file(&s).unwrap();

        assert!(load(&temp_path("missing")).is_err());
    }
}
