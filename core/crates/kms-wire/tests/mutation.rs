#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::as_conversions
)]

use kms_wire::msg::{
    AeadDecryptRequest, AeadDecryptResponse, AeadEncryptRequest, AeadEncryptResponse, HelloRequest,
    HelloResponse, KeyExportRequest, KeyExportResponse, KeyGenerateRequest, KeyGenerateResponse,
    KeyImportRequest, KeyImportResponse, KeyInspectRequest, KeyInspectResponse, Message,
    PingRequest, PingResponse, RandomRequest, RandomResponse, SignRequest, SignResponse,
    VerifyRequest, VerifyResponse,
};
use kms_wire::{Error, HEADER_LEN, Header, Kind, Op};

const VECTORS: &str = include_str!("../../../../conformance/wire/v1.txt");

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
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

fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut b = input.to_vec();
    for _ in 0..=rng.below(4) {
        match rng.below(6) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            1 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = rng.next() as u8;
            }
            2 if !b.is_empty() => {
                let n = rng.below(b.len());
                b.truncate(n);
            }
            3 => {
                let i = rng.below(b.len() + 1);
                b.insert(i, rng.next() as u8);
            }
            4 if b.len() >= 4 => {
                let i = rng.below(b.len() - 3);
                let v = [0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0];
                let o = rng.below(5);
                b[i..i + 4].copy_from_slice(&v[o..o + 4]);
            }
            _ => b.extend((0..rng.below(8)).map(|_| rng.next() as u8)),
        }
    }
    b
}

#[test]
fn mutated_frames_never_panic_and_accepted_bodies_are_canonical() {
    let frames: Vec<Vec<u8>> = VECTORS
        .lines()
        .filter_map(|l| l.strip_prefix("frame "))
        .map(|l| unhex(l.split_whitespace().nth(1).unwrap()))
        .collect();
    assert!(frames.len() >= 30);
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut accepted = 0usize;
    let mut rejected = 0usize;
    for round in 0..40_000 {
        let base = &frames[round % frames.len()];
        let (h, body) = base.split_at(HEADER_LEN);
        let mut hb: [u8; HEADER_LEN] = h.try_into().unwrap();
        if rng.below(8) == 0 {
            let i = rng.below(HEADER_LEN);
            hb[i] ^= 1 << rng.below(8);
        }
        let Ok(hdr) = Header::decode(&hb) else {
            rejected += 1;
            continue;
        };
        assert_eq!(hdr.encode(), hb, "accepted header is not canonical");
        let mutated = mutate(&mut rng, body);
        match roundtrip(hdr.op, hdr.kind, &mutated) {
            Ok(re) => {
                assert_eq!(re, mutated, "round {round}: accepted body is not canonical");
                accepted += 1;
            }
            Err(_) => rejected += 1,
        }
    }
    assert!(accepted > 1_000, "accepted={accepted}");
    assert!(rejected > 1_000, "rejected={rejected}");
}
