# Security policy

<div align="center">

[한국어](SECURITY_KR.md) | English

</div>

> [!WARNING]
> pairier has not had an external security review yet, and verifying the safety of its features may take additional time. Please use pairier for development or research purposes only.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use one of the following private channels.

- Email: qtfelix@qu4nt.space
- GitHub: [Report a vulnerability](https://github.com/Quant-Off/pairier/security/advisories/new) (private vulnerability reporting)

Please include the affected component and version (release or commit hash), steps to reproduce or a proof of concept, and the impact you expect. Reports in Korean or English are both welcome.

- You will receive an acknowledgement within 7 days.
- Confirmed issues are fixed in a patch release and credited in the advisory unless you ask otherwise.
- Please allow up to 90 days before public disclosure so that a fix can be released. If the fix ships earlier, disclosure can happen earlier.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | Yes |
| Unreleased commits | No |

Security fixes are released only for the latest 1.0.x release.

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

## Trust boundaries

pairier is designed around "Abandon trust. Choose isolation."

- Key material exists in plaintext only inside `kms-core`, a separate process. The host never sees an unsealed key.
- Every key is stored as a blob sealed under the node's root key. `root.key` is the only secret in the node directory.
- Trust between members comes only from identity card fingerprints verified over a separate channel. There is no CA and no trust on first use.
- Nothing listens on the network except `kmsd`, and `kmsd` accepts only mTLS clients whose certificate matches a registered member's card.
- Builds use vendored dependencies only and run without network access.

## Known limitations

These are design choices or open items that are disclosed here rather than treated as vulnerabilities. Reports that go beyond them are welcome.

- The MLKEM768-P256 hybrid KEM follows draft-ietf-hpke-pq (HPKE KEM id 0x0050), which is still an Internet-Draft and may change before it becomes an RFC. The core keeps the private key in expanded form instead of the 32-byte seed the draft defines. This does not change the public key, the ciphertext or the shared secret.
- A member who receives a key with `export` can send it on to others. Omit `export` to prevent re-sharing.
- The audit log is a hash chain with a per-entry signature by the core's audit key. Anyone who can start the core as the node user can produce valid entries. Truncating the log tail or rolling the log back is detected only against heads that other members witnessed from the envelopes they received, or heads recorded outside the node. Entries after the last witnessed head are not protected, a member keeps at most 4096 heads per sender and drops the lowest sequence numbers first, and a dishonest witness can only cause a false alarm.
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
- mTLS: the TLS key is an ECDSA P-256 key held in the core. `kmsd` and `kmsctl` pass the whole message to be signed, and the core hashes and signs it.
- The hybrid KEM of 1.0.0 (`0x0210`) is retired. The core still opens such keys so that pending envelopes can be received, but it no longer creates them or seals to them.
