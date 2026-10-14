# pairier usage

<div align="center">

[한국어](USAGE_KR.md) | English

</div>

pairier is a KMS for securely generating and exchanging symmetric keys between members. Each member keeps their own node directory, and key material exists in plaintext only inside each member's own security core (`kms-core`). To send a key to another member, the sender seals it to the recipient's KEM public key and delivers it in an envelope signed with the sender's identity key.

> [!WARNING]
> pairier has not been released yet. Even after development is complete, verifying the safety of its features may take additional time. Please use pairier for development or research purposes only.

## Components

| Binary     | Role                                                                                                                                 |
|------------|--------------------------------------------------------------------------------------------------------------------------------------|
| `kms-core` | The Rust security core. It owns the root key and all cryptographic operations, and the host launches it as a child process.          |
| `kmsctl`   | The command-line tool members use. It initializes nodes, registers members, generates and exchanges keys, and encrypts and decrypts. |
| `kmsd`     | A daemon that receives envelopes from other members over mTLS. It is needed only for online delivery.                                |

Every time `kmsctl` and `kmsd` run, they start `kms-core` as a child process and talk to it only over a single inherited socket, so **no socket is exposed on the filesystem.**

## Build

Requirements:

- Rust `1.95.0` (pinned by `core/rust-toolchain.toml`), Go `1.27.2`
- FIPS core build: `cmake`, `perl`, Go (static linking is supported only on Linux x86_64/aarch64)
- Distribution build: GNU tar (`brew install gnu-tar` on macOS), `python3`

All builds use only vendored dependencies and work without network access.

```bash
$ make build             # core (release, with pqc) + kmsd, kmsctl
$ make build-core FIPS=1 # build the core with the AWS-LC FIPS 140-3 module (Linux)
$ make test              # Rust tests with all features + Go race tests (using the real core)
$ make lint
$ make audit             # check vulnerabilities, licenses and sources with cargo-deny (local DB)
$ make dist FIPS=1       # write a reproducible tarball, SBOM and SHA256SUMS to dist/
```

Go binaries are built with the Go Cryptographic Module (`GOFIPS140=certified`) by default. To turn it off, run `GOFIPS140=off make build-host`. The current mode appears in the **version output**.

```bash
$ kms-core --version
kms-core 1.0.0 (kms-engine 1.0.0, fips=true, pqc=true)

$ kmsctl version
kmsctl 1.0.0 (go go1.27.2, go_fips=true)
```

## Installation

The distribution tarball contains `kms-core`, `kmsd`, `kmsctl`, `VERSION` and `sbom.cdx.json`. Verify the checksums before extracting it.

```bash
$ sha256sum -c SHA256SUMS
$ tar -xzf pairier-1.0.0-linux-amd64.tar.gz
```

> [!TIP]
> `kmsctl` and `kmsd` use the `kms-core` in their own directory by default. If it is located elsewhere, you can set it with the `--core` flag or the `KMS_CORE` environment variable. The node directory can be set with the `--dir` flag or the `KMS_DIR` environment variable.

## Quick start

The following example walks through `alice` creating a key and handing `bob` decrypt permission only. Run each command locally on the corresponding member's machine.

### 1. Initialize a node

```bash
alice$ export KMS_CORE=$PWD/core/target/release/kms-core
alice$ kmsctl --dir ~/.pairier init --id alice --pqc
member       alice
identity     ml-dsa-65
kem          hybrid-p256-ml-kem-768
core_fips    false
go_fips      true
pqc          true
fingerprint  664e-c20d-cced-8ac3-5422-d278-d9ad-107b-d225-0aea-1e45-ff50-cce1-c28e-0319-ed0f
```

Initialization creates the root key, the identity signing key, the KEM key, the audit signing key and the TLS key. With the `--pqc` flag, the node uses an ML-DSA-65 identity key and a P-256 + ML-KEM-768 hybrid KEM. Without it, the node uses ECDSA P-256 and DHKEM(P-256).

> [!TIP]
> All members of a group should use the same mode. A pqc node can register regular cards, but a node initialized without pqc cannot verify pqc cards and rejects them.

### 2. Exchange identity cards and verify fingerprints

```bash
alice$ kmsctl --dir ~/.pairier card --out alice.card
member       alice
fingerprint  664e-c20d-...-ed0f
```

The card file can be delivered by any route, such as email or USB. However, **the fingerprint must be verified over a channel separate from the card** (in person, by phone, through a signed message, and so on). The fingerprint is the sole basis of trust, and using a CA or TOFU (trust on first use) is not recommended.

### 3. Register members

```bash
alice$ kmsctl --dir ~/.pairier member add --card bob.card --fingerprint b567-baee-...-3d65
added  bob  b567-baee-...-3d65

bob$ kmsctl --dir ~/.pairier member add --card alice.card --fingerprint 664e-c20d-...-ed0f
```

Fingerprint comparison ignores case, whitespace, `-` and `:`. Registration is rejected if the card's self-signature does not verify or the fingerprint differs. Both sides must register each other before they can exchange keys.

### 4. Generate a key

```bash
alice$ kmsctl --dir ~/.pairier key gen --label project/db
af8477cc1076f219bfb047d846629eb8  aes-256-gcm  encrypt,decrypt,export  project/db
```

The generated key is an AES-256-GCM symmetric key. If the `--usage` flag is omitted, the default `encrypt,decrypt,export` applies. A key that will be sent to another member must include `export`.

### 5-a. Offline delivery (file)

```bash
alice$ kmsctl --dir ~/.pairier key send --id af8477cc1076f219bfb047d846629eb8 --to bob --out db.kxp
sent  af8477cc1076f219bfb047d846629eb8  to  bob  usage  decrypt

bob$ kmsctl --dir ~/.pairier key receive --in db.kxp
af8477cc1076f219bfb047d846629eb8  aes-256-gcm  decrypt  project/db  from alice
```

`--usage` sets the permissions granted to the recipient and defaults to `decrypt`. Only a subset of the original key's usage can be granted. The envelope opens only for `bob`, and `bob` imports the key only after verifying the signature, the recipient and the context. The same key cannot be imported twice.

### 5-b. Online delivery (kmsd)

If the recipient keeps `kmsd` running, the sender can push the envelope directly.

```bash
bob$ kmsd --dir ~/.pairier --listen 0.0.0.0:7443
kmsd 1.0.0 member bob listening on 0.0.0.0:7443 core_fips=false go_fips=true pqc=true

alice$ kmsctl --dir ~/.pairier peer health --member bob --url https://bob.example:7443
ok  bob
alice$ kmsctl --dir ~/.pairier key push --id af8477cc... --to bob --url https://bob.example:7443
pushed  af8477cc...  to  bob  envelope  854a37b90d476c1070be8c5449403071
```

A received envelope does not become a key right away. It is held in the inbox, and the recipient reviews it and then accepts or rejects it.

```bash
bob$ kmsctl --dir ~/.pairier inbox list
854a37b90d476c1070be8c5449403071  alice  2026-10-14T09:42:00Z  2026-10-14T09:42:00Z
bob$ kmsctl --dir ~/.pairier inbox accept --id 854a37b90d476c1070be8c5449403071
bob$ kmsctl --dir ~/.pairier inbox reject --id <ENVELOPEID>
```

The connection uses TLS 1.3 mutual authentication, and each side checks that the peer matches the TLS public key in the peer's card. Unregistered members are rejected during the TLS handshake.

### 6. Encrypt and decrypt

```bash
alice$ printf 'db password' | kmsctl --dir ~/.pairier encrypt --id af8477cc... --aad project/db --out secret.bin
bob$ kmsctl --dir ~/.pairier decrypt --id af8477cc... --aad project/db --in secret.bin
db password
```

The ciphertext is binary and exactly 48 bytes longer than the plaintext (salt 32 + tag 16). The `--aad` value must be identical for encryption and decryption. Because `bob` was granted only `decrypt`, an `encrypt` attempt is rejected with `usage denied`.

### 7. Verify the audit log

```bash
bob$ kmsctl --dir ~/.pairier audit verify
verified  13  entries
```

## kmsctl command reference

### Global options

| Option                    | Default                                          | Description                        |
|---------------------------|--------------------------------------------------|------------------------------------|
| `--dir DIR`               | `$KMS_DIR`                                       | Node directory                     |
| `--core PATH`             | `$KMS_CORE`, otherwise `kms-core` next to kmsctl | Core binary                        |
| `--allow-unlocked-memory` | `true` on macOS, `false` elsewhere               | Run the core without locked memory |
| `--timeout DUR`           | `10s`                                            | Core call timeout                  |

Global options must come before the command, for example `kmsctl --dir X key list`.

### Commands

| Command                                                       | Description                                                               |
|---------------------------------------------------------------|---------------------------------------------------------------------------|
| `init --id MEMBER [--pqc]`                                    | Creates a node in an empty directory.                                     |
| `card [--out FILE]`                                           | Prints the self-signed identity card. The fingerprint is shown on stderr. |
| `member add --card FILE --fingerprint FP`                     | Registers a member after checking the fingerprint.                        |
| `member list`                                                 | Shows registered members with their algorithms and fingerprints.          |
| `key gen --label LABEL [--usage LIST]`                        | Generates a symmetric key.                                                |
| `key list`                                                    | Lists keys. The last column is `local` or `from <sender>`.                |
| `key info --id KEYID`                                         | Shows key details and origin.                                             |
| `key send --id KEYID --to MEMBER [--usage LIST] [--out FILE]` | Creates an envelope file.                                                 |
| `key receive [--in FILE]`                                     | Verifies an envelope and imports the key.                                 |
| `key push --id KEYID --to MEMBER --url URL [--usage LIST]`    | Sends an envelope to the recipient's kmsd.                                |
| `inbox list`, `inbox accept --id ID`, `inbox reject --id ID`  | Handles envelopes received by kmsd.                                       |
| `peer health --member MEMBER --url URL`                       | Checks that mutual authentication with the peer's kmsd works.             |
| `encrypt --id KEYID [--in FILE] [--out FILE] [--aad STR]`     | Encrypts. Reads stdin when no input is given.                             |
| `decrypt --id KEYID [--in FILE] [--out FILE] [--aad STR]`     | Decrypts.                                                                 |
| `audit verify`                                                | Verifies the audit log chain and every checkpoint signature.              |
| `version`                                                     | Prints the version and the Go FIPS status.                                |

If the file given with `--out` already exists, the command fails instead of overwriting it, and new files are created with `0600` permissions. Exit codes are as follows.

- Success `0`
- Execution failure `1`
- Argument error `2`

## Key usage

| Usage                           | Meaning                                             |
|---------------------------------|-----------------------------------------------------|
| `encrypt`, `decrypt`            | AEAD encryption and decryption                      |
| `export`                        | Can be sent to other members                        |
| `wrap`, `unwrap`, `derive`      | Reserved symmetric key usages                       |
| `sign`, `verify`, `decapsulate` | Identity, audit and KEM keys only (used internally) |

- `key gen` accepts only symmetric key usages (`encrypt`, `decrypt`, `wrap`, `unwrap`, `derive`, `export`).
- The usage granted when sending must be a subset of the original key's usage. The core rejects privilege escalation.
- Granting `export` to a recipient lets them send the key on to other members. To prevent re-sharing, do not grant `export`.

## Operating kmsd

### Flags and configuration file

| Flag                      | Config field            | Default                            |
|---------------------------|-------------------------|------------------------------------|
| `--dir`                   | `dir`                   | None (required)                    |
| `--core`                  | `core`                  | `kms-core` next to kmsd            |
| `--listen`                | `listen`                | `127.0.0.1:7443`                   |
| `--allow-unlocked-memory` | `allow_unlocked_memory` | `true` on macOS, `false` elsewhere |
| `--timeout`               | `timeout`               | `10s`                              |
| `--config FILE`           |                         |                                    |
| `--version`               |                         |                                    |

```json
{
  "dir": "/var/lib/pairier/bob",
  "core": "/opt/pairier/kms-core",
  "listen": "0.0.0.0:7443",
  "allow_unlocked_memory": false,
  "timeout": "10s"
}
```

- Precedence is explicit flags -> configuration file -> defaults.
- The configuration file must be a regular file that the group and other users cannot access. kmsd refuses to start if the file contains unknown fields.
- The `listen` host must be an IP address.
- `kmsd` opens only nodes already initialized with `kmsctl init`.
- On `SIGINT` or `SIGTERM`, kmsd finishes in-flight requests and exits.
- `kmsctl` can be used on the same node while `kmsd` is running. Each starts its own core, and the store and audit log are safe for concurrent access.

### HTTP API

Every endpoint requires a client certificate of a registered member.

| Method and path  | Description                                                                                        |
|------------------|----------------------------------------------------------------------------------------------------|
| `GET /v1/health` | Member id, FIPS and PQC status                                                                     |
| `GET /v1/card`   | This node's identity card                                                                          |
| `POST /v1/inbox` | Submits an envelope (the body is the envelope bytes). Returns `201` and the envelope id on success |

An envelope is rejected with `400` if its sender differs from the authenticated peer, its recipient is not this node, or its signature does not verify. Submitting the same envelope again returns `409`.

### systemd example

```ini
[Service]
User=pairier
ExecStart=/opt/pairier/kmsd --config /etc/pairier/kmsd.json
LimitMEMLOCK=infinity
LimitCORE=0
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/pairier
PrivateTmp=yes
```

On Linux, the core locks all of its memory with the `mlockall` system call. If the memlock limit is too small the core refuses to start, so `LimitMEMLOCK=infinity` is required.

## Running kms-core standalone

Normally `kmsctl` and `kmsd` launch the core themselves. To run the core separately under its own user, use socket path mode as follows.

```bash
$ kms-core --generate-root-key /path/root.key
$ kms-core --socket /run/pairier/core.sock --root-key-file /path/root.key --pqc --peer-uid 1001
```

| Option                    | Description                                                                                                                                  |
|---------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `--fd N`                  | Use an inherited socket (`3` when the host launches the core)                                                                                |
| `--socket PATH`           | Accept a single connection on the socket path, then remove the path                                                                          |
| `--root-key-file PATH`    | Accepts only a 32-byte regular file owned by the current user, with no group or other permissions, no symbolic links and no extra hard links |
| `--ephemeral-root`        | Temporary root key held only in memory (blobs cannot be opened after a restart)                                                              |
| `--pqc`                   | Enable PQC algorithms (when built with the pqc feature)                                                                                      |
| `--allow-unlocked-memory` | Continue where `mlockall` is unavailable                                                                                                     |
| `--peer-uid UID`          | Verify the uid of the connecting peer (defaults to the core's own uid)                                                                       |

> [!NOTE]
> Currently `kmsctl` and `kmsd` support only launching the core directly with the root key in the node directory.

## Node directory

```text
<dir>/
  root.key     root key (0400) - the only secret that opens every key blob
  node.json    member id and the identity, KEM and audit key ids
  keys/        key records - key material is stored only as blobs sealed under the root key
  members/     registered member cards and fingerprints
  inbox/       envelopes received by kmsd
  tls.json     TLS certificate and the TLS private key encrypted by the core
  audit.log    hash-chained audit log (each entry signed with the audit key)
```

- The directory must be `0700` and owned by the current user, and files must have no group or other permissions. Symbolic links are never opened.
- On every use, stored metadata and public keys are checked against values the core recomputes from the blob.
- Backups include `root.key`, so **backup media must be protected at the same level as the root key**.

## Security operations notes

- **Verify fingerprints over a separate channel.** If the card and the fingerprint arrive by the same route, a man-in-the-middle attack cannot be prevented.
- **Understand the limits of the audit log.** Each entry is signed with the core's audit key, so an attacker who cannot use the core (a stolen disk, a tampered backup, and so on) cannot forge or recompute the log. However, anyone who can start the core with the node user's permissions can produce valid signatures. Truncating the end of the log also cannot be detected without an external reference point.
- **kmsd keeps its TLS private key in memory.** The symmetric keys being exchanged and the identity, KEM and audit keys never leave the core, but the transport TLS key is an exception.
- **Use macOS for development only.** Without `mlockall`, the core runs without memory locking, and the FIPS core is not statically linked. Run production deployments on Linux.
- **The audit log grows quickly in PQC mode.** ML-DSA signatures make each entry about 7KB, and every encryption and decryption also adds an entry.

> [!CAUTION]
> pairier has not been released yet. Even after development is complete, verifying the safety of its features may take additional time. Please use pairier for development or research purposes only.
>
> **The items above are provisional until a stable release is published. Security requirements may increase significantly as verification progresses.**

## Limits

| Item                         | Limit                                                                                                                          |
|------------------------------|--------------------------------------------------------------------------------------------------------------------------------|
| Member id                    | Up to 64 characters, starting with a lowercase letter or digit and containing only lowercase letters, digits, `.`, `_` and `-` |
| Key label                    | 256 bytes                                                                                                                      |
| Encryption plaintext, AAD    | 64KiB each                                                                                                                     |
| kmsctl input files and stdin | 1MiB                                                                                                                           |
| Envelope context             | 1KiB                                                                                                                           |

## Troubleshooting

| Message                                                                          | Cause and fix                                                                                      |
|----------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| `mlockall: Cannot allocate memory ... (pass --allow-unlocked-memory to proceed)` | The memlock limit is too small. Raise it with `ulimit -l unlimited` or `LimitMEMLOCK=infinity`.    |
| `node: fingerprint does not match the card`                                      | The fingerprint differs. Get the card again and re-verify the fingerprint over a separate channel. |
| `core: op 0x0023 failed: capability disabled`                                    | A pqc card was registered on a node initialized without pqc.                                       |
| `core: op 0x0030 failed: usage denied`                                           | The key lacks `export`, or the requested usage is broader than the original.                       |
| `node: envelope is addressed to another member`                                  | The envelope was sent to a different member.                                                       |
| `node: unknown member`                                                           | The sender or the recipient is not registered.                                                     |
| `store: object already exists`                                                   | The key was already imported or the envelope was already received.                                 |
| `node: stored metadata does not match the core`                                  | Records in the node directory have been tampered with. Check backups and the audit log.            |
| `audit: checkpoint signature is invalid`                                         | The audit log was modified without the core.                                                       |
