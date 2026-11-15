use std::io::{self, Read, Write};
use std::path::Path;

use kms_engine::{ROOT_KEY_LEN, RootKey};
use zeroize::Zeroizing;

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_owned())
}

fn sys(e: kms_sys::Error) -> io::Error {
    io::Error::new(e.kind(), e)
}

pub(crate) fn load(path: &Path) -> io::Result<RootKey> {
    let mut file = kms_sys::fs::open_private(path).map_err(sys)?;
    let len = file.metadata()?.len();
    if len != u64::try_from(ROOT_KEY_LEN).map_err(|_| invalid("length overflow"))? {
        return Err(invalid("root key file has wrong length"));
    }
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
    let mut file = kms_sys::fs::create_private(path).map_err(sys)?;
    file.write_all(buf.as_slice())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::fs;
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
        assert!(load(&p).is_ok());
        assert!(generate(&p).is_err());
        fs::remove_file(&p).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_permissive_file() {
        use std::os::unix::fs::PermissionsExt;
        let p = temp_path("perm");
        generate(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load(&p).is_err());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&p).is_ok());
        fs::remove_file(&p).unwrap();
    }

    #[test]
    fn rejects_short_and_missing() {
        let s = temp_path("short");
        let mut f = kms_sys::fs::create_private(&s).unwrap();
        std::io::Write::write_all(&mut f, &[0u8; 31]).unwrap();
        drop(f);
        assert!(load(&s).is_err());
        fs::remove_file(&s).unwrap();

        assert!(load(&temp_path("missing")).is_err());
    }
}
