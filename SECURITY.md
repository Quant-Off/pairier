# Security policy

<div align="center">

[한국어](SECURITY_KR.md) | English

</div>

> [!WARNING]
> pairier has not been released yet. Even after development is complete, verifying the safety of its features may take additional time. Please use pairier for development or research purposes only.

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
| 1.0.x   | Yes, once released |
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

- `kmsd` holds its TLS private key in process memory. Identity, KEM, audit and symmetric keys never leave the core, but the transport key does.
- The P-256 + ML-KEM-768 hybrid KEM combines the two shared secrets with an HKDF construction specific to pairier. It is not a standardized combiner.
- A member who receives a key with `export` can send it on to others. Omit `export` to prevent re-sharing.
- The audit log is a hash chain with a per-entry signature by the core's audit key. Anyone who can start the core as the node user can produce valid entries, and truncation of the log tail cannot be detected without an external reference.
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
$ sha256sum -c SHA256SUMS
```

Either form works. The first uses the key file, the second the key string itself.

Releases are also reproducible. `make dist FIPS=1` on Linux with the pinned toolchains produces a byte-identical tarball, so you can rebuild and compare `SHA256SUMS` instead of, or in addition to, checking the signature.

## Cryptography

- Core: aws-lc-rs. The `fips` feature selects the AWS-LC FIPS 140-3 validated module (static Linux builds).
- Host: Go standard library only, built with `GOFIPS140=certified` by default.
- Algorithms: AES-256-GCM, ECDSA P-256/P-384, Ed25519, DHKEM(P-256) per RFC 9180, ML-DSA-65/87, ML-KEM-768/1024, and the P-256 + ML-KEM-768 hybrid.
