# Security policy

<div align="center">

[한국어](SECURITY_KR.md) | English

</div>

> [!WARNING]
> pairier has not had an external security review yet, and verifying the safety of its features may take additional time. Please use pairier for development or research purposes only.

## Reporting a vulnerability

**Do not open a public issue for a suspected vulnerability.** Instead, use one of the following private channels.

- Email: <qtfelix@qu4nt.space>
- GitHub: [Private vulnerability reporting](https://github.com/Quant-Off/pairier/security/advisories/new)

Please include the affected component and version (release or commit hash), steps to reproduce or a proof of concept, and the impact you expect. Reports in Korean or English are both welcome.

- You will receive an acknowledgement within 7 days at the latest.
- Confirmed issues are fixed in a patch release and credited in the advisory unless you ask otherwise.
- Please allow up to 90 days before public disclosure so that a fix can be released. If the fix ships earlier, disclosure can happen earlier.

## Supported versions

| Version            | Supported |
|--------------------|-----------|
| 1.0.x              | Yes       |
| Unreleased commits | No        |

Security fixes are released only for the latest 1.0.x release. To move off 1.0.0, follow [Upgrading from 1.0.0](USAGE.md#upgrading-from-100).

## Scope

In scope:

- `kms-core`, `kmsd` and `kmsctl`
- The KWP1 wire protocol, the KID1 identity card and the KXP1 envelope formats
- Node directory storage, the audit log and the mTLS layer
- The build, vendoring and release pipeline (`Makefile`, `scripts/`, `.github/workflows/`)

Out of scope, given the trust boundaries below:

- An attacker who already runs code as the node user. The node user can start the core and read the node directory by design.
- Vulnerabilities in vendored upstream projects (AWS-LC, aws-lc-rs, the Go toolchain). Please report those upstream, but a note to us is welcome so that the vendored copy can be updated.
- Resource exhaustion of a node by its own operator.
- Attacks that require a tampered build toolchain or a compromised operating system.

## Threat model

Assets:

- `root.key`, the 32-byte root key that seals every key blob of a node
- Key blobs: symmetric keys, received keys, and the identity, KEM, audit and TLS private keys
- Registered member cards and their fingerprints, which decide whom a node trusts
- Envelopes in transit and in the inbox, and the audit log with the heads witnessed by other members

Adversaries that pairier is designed to resist:

- A network attacker who can read, change, drop, replay or inject traffic between nodes
- Anyone whose card is not registered on the node and who connects to `kmsd`
- A registered member who acts maliciously, for example by impersonating another member, flooding the inbox, or rewriting its own audit history
- A thief of a disk or a backup that does not contain `root.key`
- A bug in the host's network or parsing code that does not let an attacker run arbitrary code as the node user

Adversaries outside the design are listed under Scope. Above all, code running as the node user can read `root.key` and open every blob without the core.

## Trust boundaries

pairier is designed under the Zero-Trust and Air-Gapped Ready principles.

- Key material exists in plaintext only inside `kms-core`, a separate process. The host process never handles an unsealed key.
- Every key is stored as a blob sealed under the node's root key. `root.key` is the only secret in the node directory.
- `root.key` itself is a plaintext file with no passphrase. `kmsd` and `kmsctl` start the core under the same user, so process separation protects keys against flaws in the host's network and parsing code, not against code that already runs as the node user.
- Trust between members comes only from identity card fingerprints verified over a separate channel. There is no CA and no trust on first use.
- Nothing listens on the network except `kmsd`, and `kmsd` accepts only mTLS clients whose certificate matches a registered member's card.
- Builds use vendored dependencies only and run without network access.

## Host and core channel

- The host creates a `socketpair` and passes one end to `kms-core` as fd 3. No socket path appears on the filesystem and nothing listens, so no other process can connect.
- The core is started with an empty environment, `/` as its working directory and no standard input or output. Only standard error and fd 3 are inherited, and the core closes every other fd itself.
- Before it accepts the channel or loads the root key, the core sets `umask 077`, disables core dumps, denies `ptrace`, sets `no_new_privs` and, on Linux, locks all memory with `mlockall`. If memory cannot be locked, the core refuses to start unless `--allow-unlocked-memory` is given.
- The core accepts the channel only if it is an `AF_UNIX` stream socket and the peer's UID matches its own, or the `--peer-uid` given in standalone socket mode.
- Every frame has a fixed 16-byte header, length-prefixed fields and a 1 MiB body limit. `HELLO` must come first with a matching protocol version, trailing bytes are rejected, and any framing violation ends the session.
- The host applies a fixed deadline to every core call (10 seconds by default). A cancelled request does not break the shared core session, and a core that does not exit in time is killed.

## Communication between members

pairier protects member-to-member traffic in two layers. mTLS authenticates the channel, and the envelope signature authenticates every key that is sent. A peer that passes the TLS layer still cannot deliver a key without the sender's identity key.

TLS layer:

- TLS 1.3 only. Go 1.27 offers the X25519MLKEM768 hybrid key exchange first, including in FIPS mode, so recorded traffic between pairier nodes resists later decryption by a quantum computer as long as ML-KEM holds. TLS authentication itself uses classical ECDSA P-256.
- Each node's TLS key is an ECDSA P-256 key held in the core. The core signs the TLS handshake. The private key never enters `kmsd` or `kmsctl`.
- The server requires a client certificate. It accepts the certificate only if its subject equals a registered member id and its public key equals the TLS key in that member's verified card. The TLS handshake then proves that the client holds the matching private key.
- The client pins the server in the same way, comparing the server key with the key in the recipient's card and the subject with the recipient's member id. It sends its own certificate only after the server passes this check, so an impostor server never learns which member is connecting.
- Every request is checked again against the registered card. Once a renewed card is registered with `member add`, the old TLS key no longer authenticates.
- `kmsctl` accepts only `https://` URLs and never uses a proxy. pairier clients speak HTTP/1.1.

HTTP service:

- Endpoints: `GET /v1/health`, `GET /v1/card`, `POST /v1/inbox`, `GET /v1/witness`. All of them require an authenticated member.
- Limits: 64 concurrent connections, 10 seconds each for the TLS handshake and the request header, 16 KiB of header, 15 seconds per request, and a request body no larger than the largest valid envelope.
- At most 64 pending envelopes per sender. Further envelopes are refused with `429`.
- Responses carry `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.

Envelope layer:

- A KXP1 envelope holds a context, a key package and a signature by the sender's identity key over both.
- The context names the sender and the recipient, and carries the creation time, a 16-byte random nonce and the sender's current audit log head. A context without an audit head is refused, which includes every envelope created by 1.0.0.
- The package is produced inside the sender's core. The key is sealed to the recipient's KEM key (DHKEM P-256, or MLKEM768-P256 in PQC mode), the context is bound to it, and the recipient's core compares the context in constant time before it opens the package.
- The sender can grant only a subset of the key's usage, and only from a key that has `export`. The recipient's core imports only 256-bit symmetric keys.
- The receiver checks that it is the recipient, that the sender is registered, that the signature algorithm matches the sender's card and that the signature verifies. `kmsd` also requires the TLS peer to be the sender named in the envelope, so one member cannot deliver an envelope in another's name.
- The receiver records the sender's audit head. If a head with the same sequence number but a different hash was seen earlier, the envelope is refused and the conflict is written to the audit log.
- No freshness window is enforced on the creation time. A replayed envelope is refused as a duplicate while it is pending, and once the key has been imported, importing it again fails because a key with the same id already exists.
- Envelopes, identity cards, audit checkpoints and TLS handshakes use distinct message formats, and identity, audit and TLS keys are separate keys, so a signature made for one purpose is not valid for another.

## Local key storage

- The node directory must be `0700` and owned by the current user, and files must have no group or other permissions. Symbolic links are never followed.
- Records are written through a temporary file, synced, and moved into place, followed by a sync of the directory. Key records are write-once and are never overwritten.
- `root.key` is created by the core with mode `0400`. The core opens it without following links and requires a regular file owned by the current user, without group or other permissions, with a single link and exactly 32 bytes.
- In the core the root key lives in a dedicated memory region with guard pages on both sides. The region is locked, excluded from core dumps, and zeroized when released.
- Each blob is sealed with AES-256-GCM under a key and nonce derived by HKDF-SHA256 from the root key and a fresh 32-byte salt. The blob header (version, algorithm, usage, key id, label) is fully authenticated as associated data.
- The core rejects every operation outside the usage assigned to a key. On every use, the host checks stored metadata and public keys against the values the core recomputes from the blob.
- Node start, key generation, encryption, decryption, member changes, sent and received envelopes, inbox decisions, card renewal and witness conflicts are written to the hash-chained audit log, and each entry is signed with the core's audit key.

## Known limitations

These are design choices or open items that are disclosed here rather than treated as vulnerabilities. Reports that go beyond them are welcome.

- The MLKEM768-P256 hybrid KEM follows draft-ietf-hpke-pq (HPKE KEM id 0x0050), which is still an Internet-Draft and may change before it becomes an RFC. The core keeps the private key in expanded form instead of the 32-byte seed the draft defines. This does not change the public key, the ciphertext or the shared secret.
- A member who receives a key with `export` can send it on to others. Omit `export` to prevent re-sharing.
- The audit log is a hash chain with a per-entry signature by the core's audit key. Anyone who can start the core as the node user can produce valid entries. Truncating the log tail or rolling the log back is detected only against heads that other members witnessed from the envelopes they received, or heads recorded outside the node. Entries after the last witnessed head are not protected, a member keeps at most 4096 heads per sender and drops the lowest sequence numbers first, and a dishonest witness can only cause a false alarm.
- `root.key` is not wrapped by a passphrase or an external key, so the node can start unattended. A backup of the node directory contains the root key and must be protected like it.
- `kmsd` and `kmsctl` always start the core themselves under the same user. The core already supports running under a separate user on a socket path (`--socket`, `--peer-uid`), but `kmsd` and `kmsctl` cannot connect to it yet.
- Key lifecycle is incomplete. There is no command to delete a key, `card renew` leaves the previous TLS key blob in `keys/`, the identity and audit keys cannot be rotated, the KEM key is replaced only when its algorithm is retired, and the root key cannot be rotated.
- There is no command to remove a member or revoke a card.
- Identity cards carry no generation number. `member add` accepts any validly signed card with the same identity key, including an older one, so verify the fingerprint of every renewed card.
- `kmsd` accepts TLS session resumption. A resumed connection skips the handshake-time certificate check and the proof of the TLS key, and only the per-request lookup of the certificate against the registered card remains. The session ticket key lives only in `kmsd` memory. pairier clients never resume, and pushing an envelope still requires the sender's identity signature.
- `kmsd` also offers HTTP/2 to clients that ask for it, although pairier clients use only HTTP/1.1.
- The client that `kmsctl` uses to reach a peer's `kmsd` follows HTTP redirects. Only a peer that has already passed the pin check can send one.
- Anyone who holds a member's card can make `kmsd` run one card signature check in the core per connection attempt before the handshake fails. Core calls are serialized, and the 64-connection limit bounds the load.
- The configuration file is checked for group and other write permission but not for its owner, and the core binary it names is not checked for owner or permissions. Keep both owned by the node user or root.
- The `fips` feature selects the AWS-LC FIPS 140-3 validated module, but whether every algorithm listed below is covered by the module's certificate has not been confirmed. Check the CMVP certificate of the exact module version before relying on FIPS for a given algorithm. CI does not yet assert that `kmsd` reports `go_fips=true`.
- On macOS the core runs without locked memory and the FIPS core is not statically linked. macOS is for development only.
- `make audit` uses a local RustSec advisory database that must be refreshed on a connected machine.
- The Rust wire decoder mutation test is seeded, not coverage guided.
- Linux x86_64 is covered by CI only. Offline verification has been done on Linux arm64.

## Verifying a release

Release tarballs are signed with [minisign](https://jedisct1.github.io/minisign/). The signing key is generated and kept offline and is never available to CI.

- Public key: `minisign.pub` in the repository root
- Key id: `5AE4F2AC05D840CA`
- Key: `RWTKQNgFrPLkWgNMj67g1XXR7A7IWAfeXYtnGZ1At0+QFEoUUqFZg7pP`
- Before trusting the key for the first time, compare the full key string with a copy obtained through a channel other than this repository.

```bash
$ minisign -Vm SHA256SUMS -p minisign.pub
$ minisign -Vm SHA256SUMS -P RWTKQNgFrPLkWgNMj67g1XXR7A7IWAfeXYtnGZ1At0+QFEoUUqFZg7pP
$ sha256sum --strict -c SHA256SUMS
```

Either form works. The first uses the key file, the second the key string itself. The repository's `scripts/verify.sh` (`make verify-dist`) also checks, beyond the signature and hashes, that every tarball and SBOM in the directory is listed in `SHA256SUMS` and that a tarball for the given version is present.

Releases are also reproducible. Running `make dist FIPS=1` in a git checkout of the release tag on Ubuntu 24.04 (GCC 13.3) with the pinned Rust and Go toolchains produces byte-identical tarballs, so you can rebuild and compare the matching lines of `SHA256SUMS` instead of, or in addition to, checking the signature. Build inside a git checkout rather than an exported source tree, because Go records the commit in `kmsd` and `kmsctl` and the commit time sets the archive timestamps. A different C compiler, such as GCC 12 on Debian 12, produces a different `kms-core`.

## Cryptography

- Core: aws-lc-rs. The `fips` feature selects the AWS-LC FIPS 140-3 validated module (static Linux builds).
- Host: Go standard library only, built with `GOFIPS140=certified` by default.
- Algorithms: AES-256-GCM, ECDSA P-256/P-384, Ed25519, DHKEM(P-256) per RFC 9180, ML-DSA-65/87, ML-KEM-768/1024, and the MLKEM768-P256 hybrid KEM from draft-ietf-hpke-pq.
- Key derivation: HKDF-SHA256 for key blobs and key packages, with a separate label for each.
- mTLS: TLS 1.3 with the X25519MLKEM768 key exchange preferred. The TLS key is an ECDSA P-256 key held in the core. `kmsd` and `kmsctl` pass the whole message to be signed, and the core hashes and signs it.
- Identity cards are self-signed by the identity key, and the fingerprint is the SHA-256 hash of the signed card content.
- The hybrid KEM of 1.0.0 (`0x0210`) is retired. The core opens such keys only so that a node created by 1.0.0 can start and run `card renew`. It no longer creates them, seals to them or imports keys with them.
