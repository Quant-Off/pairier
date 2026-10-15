use std::os::fd::RawFd;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Transport {
    Fd(RawFd),
    Socket(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RootSource {
    File(PathBuf),
    Ephemeral,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Config {
    pub(crate) transport: Transport,
    pub(crate) root: RootSource,
    pub(crate) pqc: bool,
    pub(crate) allow_unlocked_memory: bool,
    pub(crate) peer_uid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    Serve(Config),
    GenerateRootKey(PathBuf),
    Version,
}

const USAGE: &str = "usage: kms-core (--fd N | --socket PATH) (--root-key-file PATH | --ephemeral-root) [--pqc] [--allow-unlocked-memory] [--peer-uid UID]\n       kms-core --generate-root-key PATH\n       kms-core --version";

pub(crate) fn parse(argv: &[String]) -> Result<Action, String> {
    let mut transport: Option<Transport> = None;
    let mut root: Option<RootSource> = None;
    let mut generate: Option<PathBuf> = None;
    let mut pqc = false;
    let mut allow_unlocked_memory = false;
    let mut peer_uid: Option<u32> = None;
    let mut version = false;

    let mut it = argv.iter();
    while let Some(flag) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{flag} requires a value\n{USAGE}"))
        };
        match flag.as_str() {
            "--fd" => {
                let v = value()?;
                let fd: RawFd = v.parse().map_err(|_| format!("invalid fd {v:?}"))?;
                if fd < 0 {
                    return Err(format!("invalid fd {v:?}"));
                }
                set_once(&mut transport, Transport::Fd(fd), "transport")?;
            }
            "--socket" => {
                let v = value()?;
                set_once(
                    &mut transport,
                    Transport::Socket(PathBuf::from(v)),
                    "transport",
                )?;
            }
            "--root-key-file" => {
                let v = value()?;
                set_once(
                    &mut root,
                    RootSource::File(PathBuf::from(v)),
                    "root key source",
                )?;
            }
            "--ephemeral-root" => set_once(&mut root, RootSource::Ephemeral, "root key source")?,
            "--generate-root-key" => {
                let v = value()?;
                set_once(&mut generate, PathBuf::from(v), "--generate-root-key")?;
            }
            "--pqc" => pqc = true,
            "--version" => version = true,
            "--allow-unlocked-memory" => allow_unlocked_memory = true,
            "--peer-uid" => {
                let v = value()?;
                let uid: u32 = v.parse().map_err(|_| format!("invalid uid {v:?}"))?;
                set_once(&mut peer_uid, uid, "--peer-uid")?;
            }
            other => return Err(format!("unknown argument {other:?}\n{USAGE}")),
        }
    }

    if version {
        if transport.is_some()
            || root.is_some()
            || generate.is_some()
            || pqc
            || allow_unlocked_memory
            || peer_uid.is_some()
        {
            return Err(format!("--version takes no other options\n{USAGE}"));
        }
        return Ok(Action::Version);
    }

    if let Some(path) = generate {
        if transport.is_some()
            || root.is_some()
            || pqc
            || allow_unlocked_memory
            || peer_uid.is_some()
        {
            return Err(format!(
                "--generate-root-key takes no other options\n{USAGE}"
            ));
        }
        return Ok(Action::GenerateRootKey(path));
    }

    let transport = transport.ok_or_else(|| format!("missing --fd or --socket\n{USAGE}"))?;
    let root =
        root.ok_or_else(|| format!("missing --root-key-file or --ephemeral-root\n{USAGE}"))?;
    Ok(Action::Serve(Config {
        transport,
        root,
        pqc,
        allow_unlocked_memory,
        peer_uid,
    }))
}

fn set_once<T>(slot: &mut Option<T>, value: T, what: &str) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{what} specified more than once\n{USAGE}"));
    }
    *slot = Some(value);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{Action, Config, RootSource, Transport, parse};
    use std::path::PathBuf;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn parses_serve_configuration() {
        let a = parse(&args(
            "--fd 3 --root-key-file /k --pqc --allow-unlocked-memory --peer-uid 42",
        ))
        .unwrap();
        assert_eq!(
            a,
            Action::Serve(Config {
                transport: Transport::Fd(3),
                root: RootSource::File(PathBuf::from("/k")),
                pqc: true,
                allow_unlocked_memory: true,
                peer_uid: Some(42),
            })
        );
        let b = parse(&args("--socket /tmp/s --ephemeral-root")).unwrap();
        assert_eq!(
            b,
            Action::Serve(Config {
                transport: Transport::Socket(PathBuf::from("/tmp/s")),
                root: RootSource::Ephemeral,
                pqc: false,
                allow_unlocked_memory: false,
                peer_uid: None,
            })
        );
    }

    #[test]
    fn parses_generate_and_rejects_bad_input() {
        assert_eq!(
            parse(&args("--generate-root-key /k")).unwrap(),
            Action::GenerateRootKey(PathBuf::from("/k"))
        );
        assert!(parse(&args("--generate-root-key /k --pqc")).is_err());
        assert_eq!(parse(&args("--version")).unwrap(), Action::Version);
        assert!(parse(&args("--version --fd 3")).is_err());
        assert!(parse(&args("--fd 3")).is_err());
        assert!(parse(&args("--ephemeral-root")).is_err());
        assert!(parse(&args("--fd -1 --ephemeral-root")).is_err());
        assert!(parse(&args("--fd x --ephemeral-root")).is_err());
        assert!(parse(&args("--fd 3 --socket /s --ephemeral-root")).is_err());
        assert!(parse(&args("--fd 3 --ephemeral-root --root-key-file /k")).is_err());
        assert!(parse(&args("--fd")).is_err());
        assert!(parse(&args("--bogus")).is_err());
        assert!(parse(&args("--fd 3 --ephemeral-root --peer-uid -5")).is_err());
    }
}
