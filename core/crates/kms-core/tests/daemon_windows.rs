#![cfg(windows)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use kms_wire::msg::{HelloRequest, HelloResponse, Message, PingRequest, PingResponse};
use kms_wire::{HEADER_LEN, Header, Kind, PROTOCOL_VERSION, Status};

fn scratch(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("kms-core-it-{}-{tag}", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

fn pipe_pair(tag: &str) -> (File, OwnedHandle) {
    kms_sys::testing::pipe_pair(tag).unwrap()
}

fn spawn(args: &[String]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_kms-core"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn spawn_with_pipe(tag: &str, extra: &[&str]) -> (File, Child) {
    let (server, client) = pipe_pair(tag);
    let value = client.as_raw_handle().expose_provenance().to_string();
    let mut args = vec!["--handle".to_owned(), value];
    args.extend(extra.iter().map(|s| (*s).to_owned()));
    let child = spawn(&args);
    drop(client);
    (server, child)
}

fn roundtrip<'a, Req: Message<'a>>(s: &mut File, id: u32, req: &Req) -> (Header, Vec<u8>) {
    let body = req.encode_body().unwrap();
    let h = Header::request(Req::OP, id, u32::try_from(body.len()).unwrap()).unwrap();
    s.write_all(&h.encode()).unwrap();
    s.write_all(&body).unwrap();
    let mut hb = [0u8; HEADER_LEN];
    s.read_exact(&mut hb).unwrap();
    let rh = Header::decode(&hb).unwrap();
    assert_eq!(rh.kind, Kind::Response);
    assert_eq!(rh.id, id);
    assert_eq!(rh.op, u16::from(Req::OP));
    let mut rb = vec![0u8; usize::try_from(rh.len).unwrap()];
    s.read_exact(&mut rb).unwrap();
    (rh, rb)
}

fn finish(mut child: Child) -> (bool, String) {
    let status = child.wait().unwrap();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    (status.success(), err)
}

fn hello(s: &mut File) {
    let (h, b) = roundtrip(
        s,
        1,
        &HelloRequest {
            protocol_version: PROTOCOL_VERSION,
        },
    );
    assert_eq!(h.status, Status::Ok);
    let hello = HelloResponse::decode_body(&b).unwrap();
    assert_eq!(hello.protocol_version, PROTOCOL_VERSION);
    assert_eq!(hello.capabilities & kms_wire::cap::FIPS, 0);
}

#[test]
fn daemon_serves_a_session_over_inherited_pipe() {
    let (mut s, child) = spawn_with_pipe(
        "session",
        &["--ephemeral-root", "--allow-unlocked-memory", "--pqc"],
    );
    hello(&mut s);
    let (h, b) = roundtrip(
        &mut s,
        1,
        &HelloRequest {
            protocol_version: PROTOCOL_VERSION,
        },
    );
    assert_eq!(h.status, Status::Ok);
    assert_eq!(
        HelloResponse::decode_body(&b).unwrap().capabilities & kms_wire::cap::PQC != 0,
        cfg!(feature = "pqc")
    );
    let (h, b) = roundtrip(&mut s, 2, &PingRequest);
    assert_eq!(h.status, Status::Ok);
    PingResponse::decode_body(&b).unwrap();
    drop(s);
    let (ok, err) = finish(child);
    assert!(ok, "daemon failed: {err}");
    assert!(err.contains("serving peer pid"), "stderr: {err}");
}

#[test]
fn root_key_file_is_generated_private_and_loaded() {
    let key = scratch("rootkey");
    let (ok, err) = finish(spawn(&[
        "--generate-root-key".to_owned(),
        key.to_str().unwrap().to_owned(),
    ]));
    assert!(ok, "generate failed: {err}");
    let (mut s, child) = spawn_with_pipe(
        "rootkey",
        &[
            "--root-key-file",
            key.to_str().unwrap(),
            "--allow-unlocked-memory",
        ],
    );
    hello(&mut s);
    drop(s);
    let (ok, err) = finish(child);
    assert!(ok, "daemon failed: {err}");
    fs::remove_file(&key).unwrap();
}

#[test]
fn unix_only_options_are_refused() {
    let (ok, err) = finish(spawn(&[
        "--fd".to_owned(),
        "3".to_owned(),
        "--ephemeral-root".to_owned(),
        "--allow-unlocked-memory".to_owned(),
    ]));
    assert!(!ok);
    assert!(err.contains("--fd"), "stderr: {err}");

    let (s, child) = spawn_with_pipe(
        "peer-uid",
        &[
            "--ephemeral-root",
            "--allow-unlocked-memory",
            "--peer-uid",
            "1",
        ],
    );
    drop(s);
    let (ok, err) = finish(child);
    assert!(!ok);
    assert!(err.contains("--peer-uid"), "stderr: {err}");

    let (s, child) = spawn_with_pipe("locked", &["--ephemeral-root"]);
    drop(s);
    let (ok, err) = finish(child);
    assert!(!ok);
    assert!(err.contains("--allow-unlocked-memory"), "stderr: {err}");
}
