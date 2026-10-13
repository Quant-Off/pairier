# pairier

<div align="center">

[한국어](README_KR.md) | English

</div>

A Zero-Trust hybrid Key Management System (KMS) built with Go and Rust. The Go host provides the network and management interfaces, and the Rust security core owns the cryptographic engine and key material.

## Layout

- `core/` Rust workspace (security core)
  - `kms-wire` dependency-free `no_std` wire protocol v1
  - `kms-sys` process hardening and secure memory, the only crate where `unsafe` is allowed
  - `kms-engine` cryptographic engine built on aws-lc-rs
  - `kms-core` security core daemon binary
- `host/` Go module (host)
  - `internal/wire` Go implementation of the wire protocol
  - `internal/core` core process launcher and client
  - `cmd/kmsd`, `cmd/kmsctl` daemon and management tool (API layer not yet implemented)
- `conformance/wire/` protocol conformance vectors that both Rust and Go must pass

## Features

The core (Rust) runs as a separate process and never shares an address space with the host (Go). The host creates a `socketpair` inside its own process, keeps one end for itself, and hands the other end to the child as `fd` 3 when it executes `kms-core`. No socket path appears on the filesystem and nothing listens, so there is no way for a third party to connect; only the host and the core share the channel. Because the host launches the core, both run under the same UID. For production, the core can instead be started first under a separate UID, with the host connecting through a `--socket` path; in that mode the core verifies the connecting peer with `--peer-uid`. Either way, TCP is never used, only local IPC on the same machine.

A stateless core is another key property. The core keeps only a 32-byte root key in memory. Individual keys are stored on the host as blobs sealed under the root key, and the host cannot open them. The blob header (algorithm, usage, key id, label) is fully authenticated.

The following features are also included.

- Validated cryptographic module: uses aws-lc-rs (AWS-LC); the `fips` feature selects the FIPS 140-3 validated module. The Go side uses the standard library only.
- Algorithms: AES-256-GCM, ECDSA P-256/P-384, Ed25519, ML-DSA-65/87, ML-KEM-768/1024
- Optional PQC: enabled only when both the compile-time `pqc` feature and the runtime `--pqc` flag are set, and advertised to the host through capability bits in the `HELLO` response.
- Key usage enforcement: the core rejects any operation outside the usage assigned at generation time (ENCRYPT, DECRYPT, SIGN, VERIFY, and so on).
- Core hardening: on startup the core disables core dumps, denies `ptrace`, sets `no_new_privs` and `umask 077`, scrubs environment variables, closes unneeded `fd`s, verifies the peer UID, and checks the root key file's permissions, owner, and links. On Linux, `mlockall` prevents memory from being swapped.
- Strict protocol: fixed 16-byte header, length-prefixed fields, 1 MiB body limit, and rejection of trailing bytes. `HELLO` must come first, and any framing violation terminates the session.
- Air-gapped build: Rust dependencies are vendored in `core/vendor` and built with `--frozen`. Go builds with `GOPROXY=off` and `-mod=vendor` and has no external dependencies.

## Build

Requirements are Rust `1.95.0` (pinned by `rust-toolchain.toml`) and Go `1.27.2`. A FIPS build additionally needs `cmake` and `perl`, and is statically linked only on Linux x86_64/aarch64.

```bash
$ make build # core (release, with pqc) + host
$ make build-core FIPS=1
$ make test # Rust tests with all features + Go tests (using the real core binary)
$ make lint
```

## Running the core

```bash
$ kms-core --generate-root-key /path/root.key
$ kms-core --socket /run/kms/core.sock --root-key-file /path/root.key --pqc
```

When the host launches the core directly, it uses the inherited socket via `--fd 3`. On platforms without `mlockall`, such as macOS, `--allow-unlocked-memory` is required.
