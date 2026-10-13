#![forbid(unsafe_code)]
#![allow(clippy::print_stderr)]

mod args;
mod rootfile;
mod server;
mod transport;

use std::process::ExitCode;

use kms_engine::Engine;

use crate::args::{Action, Config, RootSource};

fn log(msg: &str) {
    eprintln!("kms-core: {msg}");
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match run(&argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log(&e);
            ExitCode::FAILURE
        }
    }
}

fn run(argv: &[String]) -> Result<(), String> {
    let action = args::parse(argv)?;
    match action {
        Action::GenerateRootKey(path) => {
            rootfile::generate(&path).map_err(|e| format!("generate root key: {e}"))?;
            log(&format!("root key written to {}", path.display()));
            Ok(())
        }
        Action::Serve(cfg) => serve(&cfg),
    }
}

fn harden(cfg: &Config) -> Result<(), String> {
    kms_sys::harden::restrict_umask();
    kms_sys::harden::disable_core_dumps().map_err(|e| e.to_string())?;
    kms_sys::harden::deny_ptrace().map_err(|e| e.to_string())?;
    kms_sys::harden::no_new_privs().map_err(|e| e.to_string())?;
    match kms_sys::harden::lock_all_memory() {
        Ok(()) => {}
        Err(e) if cfg.allow_unlocked_memory => log(&format!("memory not locked ({e})")),
        Err(e) => return Err(format!("{e} (pass --allow-unlocked-memory to proceed)")),
    }
    kms_sys::harden::scrub_environment(&[]);
    Ok(())
}

fn serve(cfg: &Config) -> Result<(), String> {
    harden(cfg)?;

    let mut stream = transport::acquire(&cfg.transport).map_err(|e| format!("transport: {e}"))?;

    let cred = kms_sys::peer::peer_credentials(&stream).map_err(|e| e.to_string())?;
    let expected_uid = cfg.peer_uid.unwrap_or_else(kms_sys::peer::current_uid);
    if cred.uid != expected_uid {
        return Err(format!(
            "peer uid {} does not match expected uid {expected_uid}",
            cred.uid
        ));
    }

    let root = match &cfg.root {
        RootSource::File(path) => {
            rootfile::load(path).map_err(|e| format!("root key file: {e}"))?
        }
        RootSource::Ephemeral => {
            log("using ephemeral root key; key blobs will not survive restart");
            kms_engine::RootKey::generate().map_err(|e| e.to_string())?
        }
    };

    let engine = Engine::new(root, cfg.pqc);
    log(&format!(
        "serving peer pid {} (fips={}, pqc={})",
        cred.pid.map_or_else(|| "?".to_owned(), |p| p.to_string()),
        Engine::fips_mode(),
        engine.pqc_available()
    ));
    let mut server = server::Server::new(engine);
    server
        .serve(&mut stream)
        .map_err(|e| format!("session ended: {e}"))
}
