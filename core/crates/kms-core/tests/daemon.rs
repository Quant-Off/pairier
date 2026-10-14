#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use kms_wire::msg::{
    AeadDecryptRequest, AeadDecryptResponse, AeadEncryptRequest, AeadEncryptResponse, HelloRequest,
    HelloResponse, KeyGenerateRequest, KeyGenerateResponse, Message, PingRequest, PingResponse,
};
use kms_wire::{HEADER_LEN, Header, Kind, PROTOCOL_VERSION, Status, alg, usage};

fn scratch(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("kms-core-it-{}-{tag}", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

fn spawn(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_kms-core"))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn connect(path: &PathBuf) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(s) = UnixStream::connect(path) {
            return s;
        }
        assert!(
            Instant::now() < deadline,
            "socket {} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn roundtrip<'a, Req: Message<'a>>(s: &mut UnixStream, id: u32, req: &Req) -> (Header, Vec<u8>) {
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

#[test]
fn daemon_serves_a_session_over_socket_path() {
    let sock = scratch("sock");
    let child = spawn(&[
        "--socket",
        sock.to_str().unwrap(),
        "--ephemeral-root",
        "--allow-unlocked-memory",
        "--pqc",
    ]);
    let mut s = connect(&sock);

    let (h, b) = roundtrip(
        &mut s,
        1,
        &HelloRequest {
            protocol_version: PROTOCOL_VERSION,
        },
    );
    assert_eq!(h.status, Status::Ok);
    let hello = HelloResponse::decode_body(&b).unwrap();
    assert_eq!(hello.protocol_version, PROTOCOL_VERSION);
    assert_eq!(
        hello.capabilities & kms_wire::cap::PQC != 0,
        cfg!(feature = "pqc")
    );

    let (h, b) = roundtrip(&mut s, 2, &PingRequest);
    assert_eq!(h.status, Status::Ok);
    PingResponse::decode_body(&b).unwrap();

    let (h, b) = roundtrip(
        &mut s,
        3,
        &KeyGenerateRequest {
            alg: alg::AES_256_GCM,
            usage: usage::ENCRYPT | usage::DECRYPT,
            label: "it",
        },
    );
    assert_eq!(h.status, Status::Ok);
    let blob = KeyGenerateResponse::decode_body(&b)
        .unwrap()
        .key_blob
        .to_vec();
    let (h, b) = roundtrip(
        &mut s,
        4,
        &AeadEncryptRequest {
            key_blob: &blob,
            plaintext: b"payload",
            aad: b"",
        },
    );
    assert_eq!(h.status, Status::Ok);
    let ct = AeadEncryptResponse::decode_body(&b)
        .unwrap()
        .ciphertext
        .to_vec();
    let (h, b) = roundtrip(
        &mut s,
        5,
        &AeadDecryptRequest {
            key_blob: &blob,
            ciphertext: &ct,
            aad: b"",
        },
    );
    assert_eq!(h.status, Status::Ok);
    assert_eq!(
        AeadDecryptResponse::decode_body(&b).unwrap().plaintext,
        b"payload"
    );

    assert!(
        !sock.exists(),
        "socket path should be unlinked after accept"
    );
    drop(s);
    let (ok, err) = finish(child);
    assert!(ok, "daemon failed: {err}");
}

#[test]
fn daemon_closes_on_protocol_violation() {
    let sock = scratch("violation");
    let child = spawn(&[
        "--socket",
        sock.to_str().unwrap(),
        "--ephemeral-root",
        "--allow-unlocked-memory",
    ]);
    let mut s = connect(&sock);
    let body = PingRequest.encode_body().unwrap();
    let h = Header::request(kms_wire::Op::Ping, 1, 0).unwrap();
    s.write_all(&h.encode()).unwrap();
    s.write_all(&body).unwrap();
    let mut buf = [0u8; HEADER_LEN];
    assert!(s.read_exact(&mut buf).is_err());
    let (ok, err) = finish(child);
    assert!(!ok);
    assert!(err.contains("HELLO"), "stderr: {err}");
}

#[test]
fn root_key_file_permissions_are_enforced() {
    let key = scratch("rootkey");
    let (ok, err) = finish(spawn(&["--generate-root-key", key.to_str().unwrap()]));
    assert!(ok, "generate failed: {err}");
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o777,
        0o400
    );

    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    let sock = scratch("rootkey-sock");
    let child = spawn(&[
        "--socket",
        sock.to_str().unwrap(),
        "--root-key-file",
        key.to_str().unwrap(),
        "--allow-unlocked-memory",
    ]);
    let s = connect(&sock);
    drop(s);
    let (ok, err) = finish(child);
    assert!(!ok);
    assert!(err.contains("group or world"), "stderr: {err}");

    fs::set_permissions(&key, fs::Permissions::from_mode(0o400)).unwrap();
    let sock = scratch("rootkey-sock2");
    let child = spawn(&[
        "--socket",
        sock.to_str().unwrap(),
        "--root-key-file",
        key.to_str().unwrap(),
        "--allow-unlocked-memory",
    ]);
    let mut s = connect(&sock);
    let (h, _) = roundtrip(
        &mut s,
        1,
        &HelloRequest {
            protocol_version: PROTOCOL_VERSION,
        },
    );
    assert_eq!(h.status, Status::Ok);
    drop(s);
    let (ok, err) = finish(child);
    assert!(ok, "daemon failed: {err}");
    fs::remove_file(&key).unwrap();
}

#[test]
fn bad_arguments_fail_fast() {
    let (ok, err) = finish(spawn(&["--fd", "3"]));
    assert!(!ok);
    assert!(err.contains("usage"), "stderr: {err}");
}

fn wait_for(path: &PathBuf) -> fs::Metadata {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(md) = fs::symlink_metadata(path) {
            return md;
        }
        assert!(
            Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn private_dir(tag: &str) -> PathBuf {
    let d = scratch(tag);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
    d
}

#[test]
fn same_uid_socket_is_owner_only() {
    let dir = private_dir("own-dir");
    let sock = dir.join("core.sock");
    let child = spawn(&[
        "--socket",
        sock.to_str().unwrap(),
        "--ephemeral-root",
        "--allow-unlocked-memory",
    ]);
    assert_eq!(wait_for(&sock).permissions().mode() & 0o077, 0);
    let mut s = connect(&sock);
    let (h, _) = roundtrip(
        &mut s,
        1,
        &HelloRequest {
            protocol_version: PROTOCOL_VERSION,
        },
    );
    assert_eq!(h.status, Status::Ok);
    drop(s);
    let _ = finish(child);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn foreign_uid_is_rejected_without_ending_the_daemon() {
    let dir = private_dir("foreign-dir");
    let sock = dir.join("core.sock");
    let other = kms_sys::peer::current_uid().wrapping_add(1).to_string();
    let mut child = spawn(&[
        "--socket",
        sock.to_str().unwrap(),
        "--ephemeral-root",
        "--allow-unlocked-memory",
        "--peer-uid",
        &other,
    ]);
    assert_eq!(wait_for(&sock).permissions().mode() & 0o777, 0o666);
    let mut s = connect(&sock);
    let mut buf = [0u8; 1];
    assert_eq!(s.read(&mut buf).unwrap_or(0), 0, "foreign peer was served");
    std::thread::sleep(Duration::from_millis(200));
    assert!(child.try_wait().unwrap().is_none(), "daemon exited");
    assert!(sock.exists(), "socket removed before an accepted peer");
    child.kill().unwrap();
    let (_, err) = finish(child);
    assert!(err.contains("rejected connection"), "{err}");
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn shared_socket_directory_is_refused() {
    let dir = private_dir("shared-dir");
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
    let sock = dir.join("core.sock");
    let child = spawn(&[
        "--socket",
        sock.to_str().unwrap(),
        "--ephemeral-root",
        "--allow-unlocked-memory",
    ]);
    let (ok, err) = finish(child);
    assert!(!ok);
    assert!(err.contains("writable by other users"), "{err}");
    assert!(!sock.exists());
    fs::remove_dir_all(&dir).unwrap();
}
