#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use kms_wire::msg::{
    AeadDecryptRequest, AeadDecryptResponse, AeadEncryptRequest, AeadEncryptResponse, HelloRequest,
    HelloResponse, KeyExportRequest, KeyExportResponse, KeyGenerateRequest, KeyGenerateResponse,
    KeyImportRequest, KeyImportResponse, KeyInspectRequest, KeyInspectResponse, Message,
    PingRequest, PingResponse, RandomRequest, RandomResponse, SignRequest, SignResponse,
    VerifyRequest, VerifyResponse,
};
use kms_wire::{Error, HEADER_LEN, Header, Kind, Op, Status};

const VECTORS: &str = include_str!("../../../../conformance/wire/v1.txt");

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
        .collect()
}

fn parse_op(s: &str) -> u16 {
    u16::from_str_radix(s.trim_start_matches("0x"), 16).expect("bad op")
}

fn parse_kind(s: &str) -> Kind {
    match s {
        "req" => Kind::Request,
        "rsp" => Kind::Response,
        other => panic!("bad kind {other}"),
    }
}

fn roundtrip(op: u16, kind: Kind, body: &[u8]) -> Result<Vec<u8>, Error> {
    let op = Op::try_from(op)?;
    match (op, kind) {
        (Op::Hello, Kind::Request) => HelloRequest::decode_body(body)?.encode_body(),
        (Op::Hello, Kind::Response) => HelloResponse::decode_body(body)?.encode_body(),
        (Op::Ping, Kind::Request) => PingRequest::decode_body(body)?.encode_body(),
        (Op::Ping, Kind::Response) => PingResponse::decode_body(body)?.encode_body(),
        (Op::KeyGenerate, Kind::Request) => KeyGenerateRequest::decode_body(body)?.encode_body(),
        (Op::KeyGenerate, Kind::Response) => KeyGenerateResponse::decode_body(body)?.encode_body(),
        (Op::KeyInspect, Kind::Request) => KeyInspectRequest::decode_body(body)?.encode_body(),
        (Op::KeyInspect, Kind::Response) => KeyInspectResponse::decode_body(body)?.encode_body(),
        (Op::KeyExport, Kind::Request) => KeyExportRequest::decode_body(body)?.encode_body(),
        (Op::KeyExport, Kind::Response) => KeyExportResponse::decode_body(body)?.encode_body(),
        (Op::KeyImport, Kind::Request) => KeyImportRequest::decode_body(body)?.encode_body(),
        (Op::KeyImport, Kind::Response) => KeyImportResponse::decode_body(body)?.encode_body(),
        (Op::AeadEncrypt, Kind::Request) => AeadEncryptRequest::decode_body(body)?.encode_body(),
        (Op::AeadEncrypt, Kind::Response) => AeadEncryptResponse::decode_body(body)?.encode_body(),
        (Op::AeadDecrypt, Kind::Request) => AeadDecryptRequest::decode_body(body)?.encode_body(),
        (Op::AeadDecrypt, Kind::Response) => AeadDecryptResponse::decode_body(body)?.encode_body(),
        (Op::Sign, Kind::Request) => SignRequest::decode_body(body)?.encode_body(),
        (Op::Sign, Kind::Response) => SignResponse::decode_body(body)?.encode_body(),
        (Op::Verify, Kind::Request) => VerifyRequest::decode_body(body)?.encode_body(),
        (Op::Verify, Kind::Response) => VerifyResponse::decode_body(body)?.encode_body(),
        (Op::Random, Kind::Request) => RandomRequest::decode_body(body)?.encode_body(),
        (Op::Random, Kind::Response) => RandomResponse::decode_body(body)?.encode_body(),
    }
}

#[test]
fn conformance_vectors() {
    let mut frames = 0;
    let mut reject_headers = 0;
    let mut reject_bodies = 0;
    for raw in VECTORS.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut t = line.split_whitespace();
        let tag = t.next().unwrap();
        let name = t.next().unwrap();
        match tag {
            "frame" => {
                let bytes = unhex(t.next().unwrap());
                let (h, body) = bytes.split_at(HEADER_LEN);
                let hdr = Header::decode(h.try_into().unwrap())
                    .unwrap_or_else(|e| panic!("{name}: header {e}"));
                assert_eq!(usize::try_from(hdr.len).unwrap(), body.len(), "{name}: len");
                assert_eq!(hdr.encode().as_slice(), h, "{name}: header re-encode");
                if hdr.status == Status::Ok {
                    let re = roundtrip(hdr.op, hdr.kind, body)
                        .unwrap_or_else(|e| panic!("{name}: body {e}"));
                    assert_eq!(re, body, "{name}: body re-encode");
                } else {
                    assert!(body.is_empty(), "{name}: error with body");
                }
                frames += 1;
            }
            "reject_header" => {
                let bytes = unhex(t.next().unwrap());
                let arr: &[u8; HEADER_LEN] = bytes.as_slice().try_into().unwrap();
                assert!(Header::decode(arr).is_err(), "{name}: header accepted");
                reject_headers += 1;
            }
            "reject_body" => {
                let op = parse_op(t.next().unwrap());
                let kind = parse_kind(t.next().unwrap());
                let bytes = unhex(t.next().unwrap_or(""));
                assert!(
                    roundtrip(op, kind, &bytes).is_err(),
                    "{name}: body accepted"
                );
                reject_bodies += 1;
            }
            other => panic!("unknown vector tag {other}"),
        }
    }
    assert!(frames >= 20, "frames={frames}");
    assert!(reject_headers >= 6, "reject_headers={reject_headers}");
    assert!(reject_bodies >= 10, "reject_bodies={reject_bodies}");
}

#[test]
fn header_layout_is_fixed() {
    let h = Header::request(Op::Hello, 0x0102_0304, 4).unwrap();
    assert_eq!(
        h.encode(),
        [b'K', b'W', b'P', b'1', 1, 0, 0, 1, 1, 2, 3, 4, 0, 0, 0, 4]
    );
    let e = Header::error(0x0020, 7, Status::CryptoFailure);
    assert_eq!(
        e.encode(),
        [
            b'K', b'W', b'P', b'1', 2, 6, 0, 0x20, 0, 0, 0, 7, 0, 0, 0, 0
        ]
    );
    assert_eq!(Header::decode(&e.encode()).unwrap(), e);
}

#[test]
fn header_constructors_cap_len() {
    assert_eq!(
        Header::request(Op::Ping, 1, kms_wire::MAX_BODY + 1),
        Err(Error::BodyTooLarge)
    );
    assert!(Header::response(0x0002, 1, kms_wire::MAX_BODY).is_ok());
}
