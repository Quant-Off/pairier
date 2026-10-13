use std::fmt;
use std::io::{self, Read, Write};

use kms_engine::{Alg, Engine, Usage};
use kms_wire::msg::{
    AeadDecryptRequest, AeadDecryptResponse, AeadEncryptRequest, AeadEncryptResponse, HelloRequest,
    HelloResponse, KeyGenerateRequest, KeyGenerateResponse, Message, PingRequest, PingResponse,
    RandomRequest, RandomResponse, SignRequest, SignResponse, VerifyRequest, VerifyResponse,
};
use kms_wire::{HEADER_LEN, Header, Kind, Op, PROTOCOL_VERSION, Status};

#[derive(Debug)]
pub(crate) enum Fatal {
    Io(io::Error),
    Frame(kms_wire::Error),
    UnexpectedKind,
    HelloRequired,
    DuplicateHello,
    VersionMismatch(u32),
}

impl fmt::Display for Fatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Frame(e) => write!(f, "frame: {e}"),
            Self::UnexpectedKind => f.write_str("received a non-request frame"),
            Self::HelloRequired => f.write_str("first request must be HELLO"),
            Self::DuplicateHello => f.write_str("HELLO sent twice"),
            Self::VersionMismatch(v) => write!(f, "unsupported protocol version {v}"),
        }
    }
}

impl From<io::Error> for Fatal {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<kms_wire::Error> for Fatal {
    fn from(e: kms_wire::Error) -> Self {
        Self::Frame(e)
    }
}

pub(crate) fn read_frame<R: Read>(r: &mut R) -> Result<Option<(Header, Vec<u8>)>, Fatal> {
    let mut hdr = [0u8; HEADER_LEN];
    match r.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(Fatal::Io(e)),
    }
    let h = Header::decode(&hdr)?;
    let len = usize::try_from(h.len).map_err(|_| Fatal::Frame(kms_wire::Error::BodyTooLarge))?;
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    Ok(Some((h, body)))
}

pub(crate) fn write_frame<W: Write>(w: &mut W, h: &Header, body: &[u8]) -> Result<(), Fatal> {
    w.write_all(&h.encode())?;
    if !body.is_empty() {
        w.write_all(body)?;
    }
    w.flush()?;
    Ok(())
}

pub(crate) struct Server {
    engine: Engine,
    hello_done: bool,
}

impl Server {
    pub(crate) fn new(engine: Engine) -> Self {
        Self {
            engine,
            hello_done: false,
        }
    }

    pub(crate) fn serve<S: Read + Write>(&mut self, stream: &mut S) -> Result<(), Fatal> {
        while let Some((h, body)) = read_frame(stream)? {
            if h.kind != Kind::Request {
                return Err(Fatal::UnexpectedKind);
            }
            let (rh, rbody) = self.handle(&h, &body)?;
            write_frame(stream, &rh, &rbody)?;
        }
        Ok(())
    }

    pub(crate) fn handle(&mut self, h: &Header, body: &[u8]) -> Result<(Header, Vec<u8>), Fatal> {
        let Ok(op) = Op::try_from(h.op) else {
            if !self.hello_done {
                return Err(Fatal::HelloRequired);
            }
            return Ok((Header::error(h.op, h.id, Status::UnsupportedOp), Vec::new()));
        };
        if !self.hello_done && op != Op::Hello {
            return Err(Fatal::HelloRequired);
        }
        if self.hello_done && op == Op::Hello {
            return Err(Fatal::DuplicateHello);
        }

        let result = match op {
            Op::Hello => self.hello(body)?,
            Op::Ping => ping(body),
            Op::KeyGenerate => self.key_generate(body),
            Op::AeadEncrypt => self.aead_encrypt(body),
            Op::AeadDecrypt => self.aead_decrypt(body),
            Op::Sign => self.sign(body),
            Op::Verify => self.verify(body),
            Op::Random => self.random(body),
        };

        Ok(match result {
            Ok(rbody) => {
                let len = u32::try_from(rbody.len()).map_err(|_| kms_wire::Error::BodyTooLarge);
                match len.and_then(|n| Header::response(h.op, h.id, n)) {
                    Ok(rh) => (rh, rbody),
                    Err(_) => (Header::error(h.op, h.id, Status::Internal), Vec::new()),
                }
            }
            Err(status) => (Header::error(h.op, h.id, status), Vec::new()),
        })
    }

    fn hello(&mut self, body: &[u8]) -> Result<Result<Vec<u8>, Status>, Fatal> {
        let Ok(req) = HelloRequest::decode_body(body) else {
            return Ok(Err(Status::Protocol));
        };
        if req.protocol_version != PROTOCOL_VERSION {
            return Err(Fatal::VersionMismatch(req.protocol_version));
        }
        self.hello_done = true;
        let rsp = HelloResponse {
            protocol_version: PROTOCOL_VERSION,
            capabilities: self.engine.capabilities(),
            engine_name: kms_engine::ENGINE_NAME,
            engine_version: kms_engine::ENGINE_VERSION,
        };
        Ok(encode(&rsp))
    }

    fn key_generate(&self, body: &[u8]) -> Result<Vec<u8>, Status> {
        let req = decode::<KeyGenerateRequest<'_>>(body)?;
        let alg = Alg::try_from(req.alg).map_err(Status::from)?;
        let usage = Usage::from_bits(req.usage).map_err(Status::from)?;
        let k = self
            .engine
            .generate_key(alg, usage, req.label)
            .map_err(Status::from)?;
        encode(&KeyGenerateResponse {
            key_id: k.key_id,
            key_blob: &k.blob,
            public_key: &k.public_key,
        })
    }

    fn aead_encrypt(&self, body: &[u8]) -> Result<Vec<u8>, Status> {
        let req = decode::<AeadEncryptRequest<'_>>(body)?;
        let ct = self
            .engine
            .aead_encrypt(req.key_blob, req.plaintext, req.aad)
            .map_err(Status::from)?;
        encode(&AeadEncryptResponse { ciphertext: &ct })
    }

    fn aead_decrypt(&self, body: &[u8]) -> Result<Vec<u8>, Status> {
        let req = decode::<AeadDecryptRequest<'_>>(body)?;
        let pt = self
            .engine
            .aead_decrypt(req.key_blob, req.ciphertext, req.aad)
            .map_err(Status::from)?;
        encode(&AeadDecryptResponse { plaintext: &pt })
    }

    fn sign(&self, body: &[u8]) -> Result<Vec<u8>, Status> {
        let req = decode::<SignRequest<'_>>(body)?;
        let sig = self
            .engine
            .sign(req.key_blob, req.message)
            .map_err(Status::from)?;
        encode(&SignResponse { signature: &sig })
    }

    fn verify(&self, body: &[u8]) -> Result<Vec<u8>, Status> {
        let req = decode::<VerifyRequest<'_>>(body)?;
        let alg = Alg::try_from(req.alg).map_err(Status::from)?;
        let valid = self
            .engine
            .verify(alg, req.public_key, req.message, req.signature)
            .map_err(Status::from)?;
        encode(&VerifyResponse { valid })
    }

    fn random(&self, body: &[u8]) -> Result<Vec<u8>, Status> {
        let req = decode::<RandomRequest>(body)?;
        let len = usize::try_from(req.len).map_err(|_| Status::LimitExceeded)?;
        let bytes = self.engine.random(len).map_err(Status::from)?;
        encode(&RandomResponse { bytes: &bytes })
    }
}

fn ping(body: &[u8]) -> Result<Vec<u8>, Status> {
    decode::<PingRequest>(body)?;
    encode(&PingResponse)
}

fn decode<'a, M: Message<'a>>(body: &'a [u8]) -> Result<M, Status> {
    M::decode_body(body).map_err(|_| Status::Protocol)
}

fn encode<'a, M: Message<'a>>(m: &M) -> Result<Vec<u8>, Status> {
    m.encode_body().map_err(|_| Status::Internal)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]
mod tests {
    use super::{Fatal, Server};
    use kms_engine::{Engine, RootKey};
    use kms_wire::msg::{
        AeadDecryptRequest, AeadDecryptResponse, AeadEncryptRequest, AeadEncryptResponse,
        HelloRequest, HelloResponse, KeyGenerateRequest, KeyGenerateResponse, Message, PingRequest,
        RandomRequest, RandomResponse, SignRequest, SignResponse, VerifyRequest, VerifyResponse,
    };
    use kms_wire::{Header, Kind, Op, PROTOCOL_VERSION, Status, alg, usage};

    fn server() -> Server {
        Server::new(Engine::new(RootKey::generate().unwrap(), true))
    }

    fn call<'a, M: Message<'a>>(
        s: &mut Server,
        id: u32,
        m: &M,
    ) -> Result<(Header, Vec<u8>), Fatal> {
        let body = m.encode_body().unwrap();
        let h = Header::request(M::OP, id, u32::try_from(body.len()).unwrap()).unwrap();
        s.handle(&h, &body)
    }

    fn hello(s: &mut Server) -> u64 {
        let (h, b) = call(
            s,
            1,
            &HelloRequest {
                protocol_version: PROTOCOL_VERSION,
            },
        )
        .unwrap();
        assert_eq!(h.status, Status::Ok);
        assert_eq!(h.kind, Kind::Response);
        assert_eq!(h.id, 1);
        let r = HelloResponse::decode_body(&b).unwrap();
        assert_eq!(r.protocol_version, PROTOCOL_VERSION);
        assert_eq!(r.engine_name, kms_engine::ENGINE_NAME);
        r.capabilities
    }

    #[test]
    fn hello_is_required_first_and_only_once() {
        let mut s = server();
        assert!(matches!(
            call(&mut s, 1, &PingRequest),
            Err(Fatal::HelloRequired)
        ));
        let mut s = server();
        let caps = hello(&mut s);
        assert_eq!(caps & kms_wire::cap::PQC != 0, cfg!(feature = "pqc"));
        assert!(matches!(
            call(
                &mut s,
                2,
                &HelloRequest {
                    protocol_version: PROTOCOL_VERSION
                }
            ),
            Err(Fatal::DuplicateHello)
        ));
        let mut s = server();
        assert!(matches!(
            call(
                &mut s,
                1,
                &HelloRequest {
                    protocol_version: 99
                }
            ),
            Err(Fatal::VersionMismatch(99))
        ));
    }

    #[test]
    fn unknown_op_and_bad_bodies_are_non_fatal_after_hello() {
        let mut s = server();
        let h = Header::request(Op::Ping, 5, 0).unwrap();
        let bogus = Header { op: 0x7777, ..h };
        assert!(matches!(s.handle(&bogus, &[]), Err(Fatal::HelloRequired)));
        hello(&mut s);
        let (rh, rb) = s.handle(&bogus, &[]).unwrap();
        assert_eq!(rh.status, Status::UnsupportedOp);
        assert_eq!(rh.op, 0x7777);
        assert_eq!(rh.id, 5);
        assert!(rb.is_empty());
        let (rh, _) = s
            .handle(&Header::request(Op::Ping, 6, 1).unwrap(), &[0])
            .unwrap();
        assert_eq!(rh.status, Status::Protocol);
        let (rh, _) = s
            .handle(&Header::request(Op::KeyGenerate, 7, 0).unwrap(), &[])
            .unwrap();
        assert_eq!(rh.status, Status::Protocol);
    }

    #[test]
    fn full_key_lifecycle_over_handle() {
        let mut s = server();
        hello(&mut s);
        let (h, b) = call(
            &mut s,
            2,
            &KeyGenerateRequest {
                alg: alg::AES_256_GCM,
                usage: usage::ENCRYPT | usage::DECRYPT,
                label: "t",
            },
        )
        .unwrap();
        assert_eq!(h.status, Status::Ok);
        let k = KeyGenerateResponse::decode_body(&b).unwrap();
        let blob = k.key_blob.to_vec();

        let (h, b) = call(
            &mut s,
            3,
            &AeadEncryptRequest {
                key_blob: &blob,
                plaintext: b"secret",
                aad: b"aad",
            },
        )
        .unwrap();
        assert_eq!(h.status, Status::Ok);
        let ct = AeadEncryptResponse::decode_body(&b)
            .unwrap()
            .ciphertext
            .to_vec();

        let (h, b) = call(
            &mut s,
            4,
            &AeadDecryptRequest {
                key_blob: &blob,
                ciphertext: &ct,
                aad: b"aad",
            },
        )
        .unwrap();
        assert_eq!(h.status, Status::Ok);
        assert_eq!(
            AeadDecryptResponse::decode_body(&b).unwrap().plaintext,
            b"secret"
        );

        let (h, b) = call(
            &mut s,
            5,
            &AeadDecryptRequest {
                key_blob: &blob,
                ciphertext: &ct,
                aad: b"wrong",
            },
        )
        .unwrap();
        assert_eq!(h.status, Status::CryptoFailure);
        assert!(b.is_empty());

        let (h, _) = call(
            &mut s,
            6,
            &KeyGenerateRequest {
                alg: 0x7fff,
                usage: usage::SIGN,
                label: "",
            },
        )
        .unwrap();
        assert_eq!(h.status, Status::InvalidArgument);

        let (h, b) = call(
            &mut s,
            7,
            &KeyGenerateRequest {
                alg: alg::ED25519,
                usage: usage::SIGN,
                label: "s",
            },
        )
        .unwrap();
        assert_eq!(h.status, Status::Ok);
        let sk = KeyGenerateResponse::decode_body(&b).unwrap();
        let sblob = sk.key_blob.to_vec();
        let pk = sk.public_key.to_vec();
        let (h, b) = call(
            &mut s,
            8,
            &SignRequest {
                key_blob: &sblob,
                message: b"m",
            },
        )
        .unwrap();
        assert_eq!(h.status, Status::Ok);
        let sig = SignResponse::decode_body(&b).unwrap().signature.to_vec();
        let (h, b) = call(
            &mut s,
            9,
            &VerifyRequest {
                alg: alg::ED25519,
                public_key: &pk,
                message: b"m",
                signature: &sig,
            },
        )
        .unwrap();
        assert_eq!(h.status, Status::Ok);
        assert!(VerifyResponse::decode_body(&b).unwrap().valid);

        let (h, _) = call(
            &mut s,
            10,
            &SignRequest {
                key_blob: &blob,
                message: b"m",
            },
        )
        .unwrap();
        assert_eq!(h.status, Status::InvalidArgument);

        let (h, b) = call(&mut s, 11, &RandomRequest { len: 16 }).unwrap();
        assert_eq!(h.status, Status::Ok);
        assert_eq!(RandomResponse::decode_body(&b).unwrap().bytes.len(), 16);

        let (h, _) = call(
            &mut s,
            12,
            &KeyGenerateRequest {
                alg: alg::ML_DSA_65,
                usage: usage::SIGN,
                label: "",
            },
        )
        .unwrap();
        let expect = if cfg!(feature = "pqc") {
            Status::Ok
        } else {
            Status::CapabilityDisabled
        };
        assert_eq!(h.status, expect);
    }
}
