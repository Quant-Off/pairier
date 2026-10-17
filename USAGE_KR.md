# pairier 사용법

<div align="center">

한국어 | [English](USAGE.md)

</div>

pairier는 구성원 간에 대칭 키를 안전하게 생성하고 교환하기 위한 KMS입니다. 구성원마다 자기 노드 디렉토리를 두고, 키 재료는 항상 각자의 보안 코어(`kms-core`) 안에서만 평문으로 존재합니다. 다른 구성원에게 키를 보낼 때는 수신자의 KEM 공개키로 봉인하고 송신자의 신원 키로 서명한 봉투(envelope)를 전달합니다.

> [!WARNING]
> pairier는 아직 외부 보안 검토를 받지 않았으며, 기능의 안전성 검증을 위해 시간이 더 소요될 수 있습니다. pairier는 개발 또는 연구용으로만 사용해주시길 바랍니다.

## 구성 요소

| 바이너리       | 역할                                                            |
|------------|---------------------------------------------------------------|
| `kms-core` | Rust 보안 코어로, 루트 키와 모든 암호 연산을 담당하며 호스트가 자식 프로세스로 기동합니다.        |
| `kmsctl`   | 구성원이 쓰는 명령줄 도구입니다. 노드 초기화, 구성원 등록, 키 생성과 교환, 암/복호화를 수행합니다.    |
| `kmsd`     | 다른 구성원이 보낸 봉투를 mTLS로 받는 데몬(daemon)입니다. 온라인 전달을 사용할 때에만 필요합니다. |

`kmsctl`과 `kmsd`는 실행될 때마다 `kms-core`를 자식 프로세스로 띄우고 상속한 소켓 하나로만 통신하며, **파일 시스템에 소켓이 노출되지 않습니다.**

## 빌드

요구 사항은 다음과 같습니다.

- Rust `1.95.0` (`core/rust-toolchain.toml`로 고정), Go `1.27.2`
- FIPS 코어 빌드: `cmake`, `perl`, Go (정적 링크는 Linux x86_64/aarch64에서만 지원)
- 배포본 생성: GNU tar (macOS의 경우 `brew install gnu-tar`), `python3`

빌드는 Linux와 macOS에서 동작합니다. 코어의 격리가 상속 소켓, 피어 UID 검사, `ptrace` 거부, `0700` 권한 같은 Unix 프로세스와 파일 권한 기능에 의존하므로 Windows 네이티브 빌드는 지원하지 않습니다. Windows에서는 WSL2의 Ubuntu 24.04 안에 위 요구 사항을 설치해 빌드하세요. 저장소와 노드 디렉토리는 `~/` 아래처럼 WSL 파일 시스템에 두어야 합니다. `/mnt/c` 아래의 Windows 드라이브는 기본적으로 Unix 권한을 지정할 수 없어 노드 디렉토리 검사에서 거부됩니다.

모든 빌드는 벤더링된 의존성만 사용하며 네트워크 없이 동작합니다.

```bash
$ make build             # 코어(release, pqc 포함) + kmsd, kmsctl
$ make build-core FIPS=1 # AWS-LC FIPS 140-3 모듈로 코어 빌드 (Linux)
$ make test              # Rust 전체 feature 테스트 + Go race 테스트 (실제 코어 사용)
$ make lint
$ make audit             # cargo-deny로 취약점, 라이선스, 소스 점검 (로컬 DB 사용)
$ make dist FIPS=1       # 재현 가능한 배포 tarball, SBOM, SHA256SUMS를 dist/에 생성
```

Go 바이너리는 기본적으로 Go 인증 암호 모듈(`GOFIPS140=certified`)로 빌드됩니다. 해제하려면 `GOFIPS140=off make build-host`를 입력하세요. 현재 모드는 **버전 출력**에서 확인할 수 있습니다.

```bash
$ kms-core --version
kms-core 2.0.0 (kms-engine 2.0.0, fips=true, pqc=true)

$ kmsctl version
kmsctl 2.0.0 (go go1.27.2, go_fips=true)
```

## 설치

배포 tarball은 Linux amd64와 arm64용으로 제공되며 glibc 2.38 이상이 필요합니다(Ubuntu 24.04, Debian 13 등). `kmsd`와 `kmsctl`은 정적 바이너리이고, `kms-core`는 glibc를 동적 링크합니다. macOS 바이너리는 제공하지 않기 때문에 개발용으로는 소스에서 직접 빌드하세요([빌드](#빌드) 참고).

배포 tarball에는 `kms-core`, `kmsd`, `kmsctl`, `VERSION`, `sbom.cdx.json`, `LICENSE`, `NOTICE`가 들어 있습니다. 해제 전에 `SHA256SUMS`의 minisign 서명(signature)을 먼저 확인하고, 그다음 체크섬(checksum)을 확인하세요. 공개키는 저장소 루트의 `minisign.pub`이며, 확인 방법은 [SECURITY_KR.md](SECURITY_KR.md)를 참고하세요.

```bash
$ minisign -Vm SHA256SUMS -p minisign.pub
$ sha256sum --strict --ignore-missing -c SHA256SUMS
$ tar -xzf pairier-2.0.0-linux-amd64.tar.gz
```

`SHA256SUMS`에는 두 아키텍처의 파일이 모두 들어 있으며, `--ignore-missing`은 받지 않은 파일을 건너뜁니다.

> [!TIP]
> `kmsctl`과 `kmsd`는 같은 디렉토리에 있는 `kms-core`를 기본으로 사용합니다. 다른 위치에 둔 경우 `--core` 플래그 또는 `KMS_CORE` 환경 변수로 지정할 수 있습니다. 노드 디렉토리는 `--dir` 플래그 또는 `KMS_DIR` 환경 변수로 지정할 수 있습니다.

## 빠른 시작

다음은 예시로, `alice`가 키를 만들어 `bob`에게 복호화 권한만 넘기는 흐름을 따릅니다. 각 명령은 해당 구성원 로컬에서 실행합니다.

### 1. 노드 초기화

```bash
alice$ export KMS_CORE=$PWD/core/target/release/kms-core
alice$ kmsctl --dir ~/.pairier init --id alice --pqc
member       alice
identity     ml-dsa-65
kem          mlkem768-p256
core_fips    false
go_fips      true
pqc          true
fingerprint  664e-c20d-cced-8ac3-5422-d278-d9ad-107b-d225-0aea-1e45-ff50-cce1-c28e-0319-ed0f
```

초기화는 루트 키, 신원 서명 키, KEM 키, 감사 서명 키, TLS 키를 만들어냅니다. `--pqc` 플래그를 사용하면 ML-DSA-65 신원 키와, ML-KEM-768과 P-256을 draft-ietf-hpke-pq 방식으로 결합한 MLKEM768-P256 하이브리드 KEM을, 생략하면 ECDSA P-256과 DHKEM(P-256)을 사용합니다.

> [!TIP]
> 한 그룹 안에서는 모든 구성원이 같은 모드를 사용하는 것을 권장합니다. pqc 노드는 일반 카드를 등록할 수 있지만, pqc 없이 초기화한 노드는 pqc 카드를 검증할 수 없어 등록을 거부합니다.

### 2. 신원 카드 교환과 지문 확인

```bash
alice$ kmsctl --dir ~/.pairier card --out alice.card
member       alice
fingerprint  664e-c20d-...-ed0f
```

카드 파일은 이메일이나 USB 등 어떤 경로로 전달해도 됩니다. 단, **지문(fingerprint)은 반드시 카드와 다른 채널**(대면, 전화, 서명된 메시지 등)로 확인해야 합니다. 지문이 신뢰의 유일한 근거이며, CA나 TOFU(최초 접속 신뢰)는 사용하지 않는 것을 권장합니다.

### 3. 구성원 등록

```bash
alice$ kmsctl --dir ~/.pairier member add --card bob.card --fingerprint b567-baee-...-3d65
added  bob  b567-baee-...-3d65

bob$ kmsctl --dir ~/.pairier member add --card alice.card --fingerprint 664e-c20d-...-ed0f
```

지문 비교는 대소문자, 공백, `-`, `:`를 무시합니다. 카드의 자기 서명이 일치하지 않거나 지문이 다르면 등록이 거부됩니다. 키를 주고받기 위해선 양측 모두 상대방을 등록해야 합니다.

구성원이 카드를 갱신하면([카드 갱신](#카드-갱신) 참고) 새 카드를 같은 방법으로 새 지문과 함께 등록합니다. 이때 출력은 `updated`입니다. 같은 구성원 id라도 신원 키가 다른 카드는 거부됩니다.

### 4. 키 생성

```bash
alice$ kmsctl --dir ~/.pairier key gen --label project/db
af8477cc1076f219bfb047d846629eb8  aes-256-gcm  encrypt,decrypt,export  project/db
```

생성되는 키는 AES-256-GCM 대칭 키입니다. `--usage` 플래그를 생략하면 기본값으로 `encrypt,decrypt,export`가 적용됩니다. 다른 구성원에게 보낼 키에는 반드시 `export`가 포함되어 있어야 합니다. 라벨에는 줄바꿈 같은 제어 문자와 U+202E 같은 양방향 서식 문자를 쓸 수 없습니다.

### 5-a. 오프라인 전달 (파일)

```bash
alice$ kmsctl --dir ~/.pairier key send --id af8477cc1076f219bfb047d846629eb8 --to bob --out db.kxp
sent  af8477cc1076f219bfb047d846629eb8  to  bob  usage  decrypt

bob$ kmsctl --dir ~/.pairier key receive --in db.kxp
af8477cc1076f219bfb047d846629eb8  aes-256-gcm  decrypt  project/db  from alice
```

`--usage`로 수신자에게 줄 권한을 정할 수 있으며, 기본값은 `decrypt`입니다. 원래 키가 가진 용도의 부분집합만 정할 수 있습니다. 해당 봉투는 `bob`에게만 열리고, `bob` 쪽에서는 서명, 수신자, 컨텍스트를 모두 검증한 뒤에만 가져옵니다. 같은 키를 두 번 가져올 수는 없습니다.

### 5-b. 온라인 전달 (kmsd)

수신자가 `kmsd`를 실행해 둔다면 송신자가 직접 밀어(push) 넣을 수 있습니다.

```bash
bob$ kmsd --dir ~/.pairier --listen 0.0.0.0:7443
kmsd 2.0.0 member bob listening on 0.0.0.0:7443 core_fips=false go_fips=true pqc=true

alice$ kmsctl --dir ~/.pairier peer health --member bob --url https://bob.example:7443
ok  bob
alice$ kmsctl --dir ~/.pairier key push --id af8477cc... --to bob --url https://bob.example:7443
pushed  af8477cc...  to  bob  envelope  854a37b90d476c1070be8c5449403071
```

받은 봉투는 바로 키가 되지 않고 inbox에 보관됩니다. 수신자가 확인 후 수락하거나 거절할 수 있습니다. 송신자 한 명당 대기 중인 봉투는 64개까지 보관하며, 수락하거나 거절해 자리가 비어야 다음 봉투를 받습니다.

```bash
bob$ kmsctl --dir ~/.pairier inbox list
854a37b90d476c1070be8c5449403071  alice  2026-10-14T09:42:00Z  2026-10-14T09:42:00Z
bob$ kmsctl --dir ~/.pairier inbox accept --id 854a37b90d476c1070be8c5449403071
bob$ kmsctl --dir ~/.pairier inbox reject --id <ENVELOPEID>
```

연결은 TLS 1.3 상호 인증이며, 양쪽 모두 상대 카드에 들어 있는 TLS 공개키와 일치하는지 확인합니다. 등록되지 않은 구성원은 TLS 단계에서 거부됩니다.

### 6. 암/복호화

```bash
alice$ printf 'db password' | kmsctl --dir ~/.pairier encrypt --id af8477cc... --aad project/db --out secret.bin
bob$ kmsctl --dir ~/.pairier decrypt --id af8477cc... --aad project/db --in secret.bin
db password
```

암호문은 바이너리이며 평문보다 정확히 48바이트 깁니다(salt 32 + tag 16). `--aad` 플래그는 암호화와 복호화 과정에서 반드시 같아야 합니다. `bob`은 `decrypt` 권한만 받았기 때문에 `encrypt`를 시도하는 경우 `usage denied`로 거부됩니다.

### 7. 감사 로그 검증

```bash
bob$ kmsctl --dir ~/.pairier audit verify
verified  13  entries
head      13:9c1d...e4a0
bob$ kmsctl --dir ~/.pairier audit verify --anchor 13:9c1d...e4a0
```

`head`는 마지막 항목의 순번과 해시입니다. 키 전달이나 구성원 등록처럼 중요한 작업을 마친 뒤에는 이 값을 노드 밖(다른 기기, 출력물 등)에 기록해 두세요. 나중에 `--anchor`로 넘기면 로그가 그 항목을 그대로 담고 있는지 확인합니다. 로그 끝부분이 잘렸거나, 이전 로그로 되돌린 뒤 이어 쓴 경우에는 실패합니다.

모든 봉투에는 송신자의 현재 head도 담기며, 수신자는 이를 그 구성원에 대해 증인으로 본 head로 구성원마다 최대 4096개까지 보관합니다. 이 head들을 쓰면 직접 기록해 두지 않아도 로그를 확인할 수 있습니다.

```bash
bob$ kmsctl --dir ~/.pairier member witness --member alice --out alice.heads
witnessed  3  heads  for  alice
alice$ kmsctl --dir ~/.pairier audit verify --anchor-file alice.heads
alice$ kmsctl --dir ~/.pairier audit verify --peer bob --url https://bob.example:7443
```

`--anchor`는 여러 번 줄 수 있고, `--anchor-file`은 한 줄에 하나씩 `SEQ:HASH`를 읽습니다. `--peer`는 그 구성원의 kmsd에 내 로그에 대해 증인으로 본 head를 요청합니다. 주어진 head가 하나라도 로그와 다르면 실패합니다. 이미 증인으로 본 순번에 다른 해시를 보낸 구성원의 봉투는 거부되고, 수신 측 감사 로그에 `witness.conflict`가 기록됩니다.

## 카드 갱신

```bash
alice$ kmsctl --dir ~/.pairier card renew --out alice.card
member       alice
kem          mlkem768-p256
fingerprint  1d0a-...-77c2
send the new card and fingerprint to every member and restart kmsd
```

`card renew`는 코어 안에서 새 TLS 키를 만들고 그 키로 새 인증서를 발급합니다. KEM 키가 폐기된 하이브리드 KEM(1.0.0에서 `--pqc`로 만든 `hybrid-p256-ml-kem-768`)이면 `mlkem768-p256` 키로 교체합니다. 신원 키와 감사 키는 그대로이므로, 구성원은 새 지문을 이전과 같이 별도 채널로 확인한 뒤 `member add`로 카드를 갱신합니다.

### 1.0.0에서 업그레이드

이 버전은 1.0.0과 어느 방향으로도 봉투를 주고받을 수 없고, 1.0.0에서 만든 노드는 카드를 갱신해야 합니다. 그룹은 다음 순서로 업그레이드하세요.

1. 키 전송을 멈춥니다. 모든 노드가 아직 1.0.0일 때 대기 중인 봉투를 `inbox accept`와 `inbox reject`로 모두 처리하고, 오프라인 봉투 파일도 모두 `key receive`로 가져옵니다. 1.0.0이 만든 봉투에는 감사 head가 없으므로 이 버전은 그런 봉투를 모두 거부합니다.
2. 그룹의 모든 구성원을 함께 업그레이드합니다. 봉투에 송신자의 감사 로그 head가 담기며 1.0.0은 이를 읽지 못합니다.
3. 모든 노드에서 `card renew`를 실행합니다. 1.0.0에서 만든 노드는 TLS 개인키를 코어 밖에 두었으므로, 갱신해야 `kmsd`, `key push`, `peer health`, `audit verify --peer`를 쓸 수 있습니다.
4. 새 카드와 지문을 모든 구성원에게 보냅니다. 구성원은 별도 채널로 지문을 확인한 뒤 `member add`로 등록합니다. 그다음 `kmsd`를 다시 시작합니다.

폐기된 하이브리드 KEM을 쓰는 카드로는 키를 보낼 수 없고, 그 카드의 노드도 `card renew`를 실행하기 전에는 키를 받을 수 없습니다.

## kmsctl 명령 참조

### 전역 옵션

| 옵션                        | 기본값                                   | 설명              |
|---------------------------|---------------------------------------|-----------------|
| `--dir DIR`               | `$KMS_DIR`                            | 노드 디렉토리         |
| `--core PATH`             | `$KMS_CORE`, 없으면 kmsctl 옆의 `kms-core` | 코어 바이너리         |
| `--allow-unlocked-memory` | macOS `true`, 그 외 `false`             | 메모리 잠금 없이 코어 실행 |
| `--timeout DUR`           | `10s`                                 | 코어 호출 제한 시간     |

전역 옵션은 명령 앞/뒤 어디에 두어도 됩니다. `kmsctl --dir X key list`와 `kmsctl key list --dir X`는 같으며, 양쪽에 모두 설정하면 명령 뒤의 값이 적용됩니다.

### 명령

| 명령                                                                                   | 설명                                                                                                               |
|--------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| `init --id MEMBER [--pqc]`                                                           | 빈 디렉토리에 노드를 만듭니다.                                                                                                |
| `card [--out FILE]`                                                                  | 자기 서명된 신원 카드를 출력합니다. 지문은 stderr에 표시됩니다.                                                                          |
| `card renew [--out FILE]`                                                            | 코어 안에서 새 TLS 키와 인증서를 발급하고 폐기된 KEM 키를 교체합니다. 새 카드를 출력합니다.                                                         |
| `member add --card FILE --fingerprint FP`                                            | 지문을 확인한 뒤 구성원을 등록하거나, 갱신된 카드로 교체합니다.                                                                             |
| `member list`                                                                        | 등록된 구성원과 알고리즘, 지문을 표시합니다.                                                                                        |
| `member witness --member MEMBER [--out FILE]`                                        | 그 구성원에 대해 증인으로 본 감사 로그 head를 한 줄에 하나씩 `SEQ:HASH`로 출력합니다.                                                         |
| `key gen --label LABEL [--usage LIST]`                                               | 대칭 키를 생성합니다.                                                                                                     |
| `key list`                                                                           | 키 목록을 표시합니다. 마지막 열은 `local` 또는 `from <송신자>`입니다.                                                                  |
| `key info --id KEYID`                                                                | 키 상세와 출처를 표시합니다.                                                                                                 |
| `key send --id KEYID --to MEMBER [--usage LIST] [--out FILE]`                        | 봉투 파일을 만듭니다.                                                                                                     |
| `key receive [--in FILE]`                                                            | 봉투를 검증하고 키를 가져옵니다.                                                                                               |
| `key push --id KEYID --to MEMBER --url URL [--usage LIST]`                           | 수신자의 kmsd로 봉투를 보냅니다.                                                                                             |
| `inbox list`, `inbox accept --id ID`, `inbox reject --id ID`                         | kmsd가 받은 봉투를 처리합니다.                                                                                              |
| `peer health --member MEMBER --url URL`                                              | 상대 kmsd와 상호 인증이 되는지 확인합니다.                                                                                       |
| `encrypt --id KEYID [--in FILE] [--out FILE] [--aad STR]`                            | 암호화합니다. 입력이 없으면 stdin을 씁니다.                                                                                      |
| `decrypt --id KEYID [--in FILE] [--out FILE] [--aad STR]`                            | 복호화합니다.                                                                                                          |
| `audit verify [--anchor SEQ:HASH]... [--anchor-file FILE] [--peer MEMBER --url URL]` | 감사 로그 체인과 모든 체크포인트 서명을 검증하고 head를 출력합니다. 주어진 head(`--anchor`, `--anchor-file`, `--peer`)가 모두 로그에 그대로 있는지도 확인합니다. |
| `version`                                                                            | 버전과 Go FIPS 상태를 출력합니다.                                                                                           |

`--out`으로 지정한 파일이 이미 있으면 덮어쓰지 않고 실패하며, 새 파일은 `0600` 권한으로 만들어집니다. 종료 코드는 다음과 같습니다.

- 성공 `0`
- 실행 실패 `1`
- 인자 오류 `2`

## 키 용도

| 용도                              | 의미                         |
|---------------------------------|----------------------------|
| `encrypt`, `decrypt`            | AEAD 암호화, 복호화              |
| `export`                        | 다른 구성원에게 보낼 수 있음           |
| `wrap`, `unwrap`, `derive`      | 예약된 대칭 키 용도                |
| `sign`, `verify`, `decapsulate` | 신원, 감사, KEM 키 전용 (내부에서 사용) |

- `key gen`으로는 대칭 키 용도(`encrypt`, `decrypt`, `wrap`, `unwrap`, `derive`, `export`)만 지정할 수 있습니다.
- 보낼 때 주는 용도는 원래 키 용도의 부분집합이어야 합니다. 권한 상승은 코어가 거부합니다.
- 수신자에게 `export`를 주면 수신자가 그 키를 다시 다른 구성원에게 보낼 수 있습니다. 재공유를 막으려면 `export`를 설정하지 마세요.

## kmsd 운영

### 플래그와 설정 파일

| 플래그                       | 설정 파일 필드                | 기본값                                   |
|---------------------------|-------------------------|---------------------------------------|
| `--dir`                   | `dir`                   | `$KMS_DIR`, 없는 경우 필수                  |
| `--core`                  | `core`                  | `$KMS_CORE`, 없는 경우 kmsd 옆의 `kms-core` |
| `--listen`                | `listen`                | `127.0.0.1:7443`                      |
| `--allow-unlocked-memory` | `allow_unlocked_memory` | macOS `true`, 그 외 `false`             |
| `--timeout`               | `timeout`               | `10s`                                 |
| `--config FILE`           |                         |                                       |
| `--version`               |                         |                                       |

```json
{
  "dir": "/var/lib/pairier/bob",
  "core": "/opt/pairier/kms-core",
  "listen": "0.0.0.0:7443",
  "allow_unlocked_memory": false,
  "timeout": "10s"
}
```

- 우선순위는 명시한 플래그 -> 설정 파일 -> 환경 변수 -> 기본값 순입니다.
- 설정 파일은 일반 파일이어야 하며, 그룹 또는 다른 사용자가 사용할 수 없어야 합니다. 알 수 없는 필드가 있다면 기동하지 않습니다.
- `listen`의 호스트는 IP 주소만 허용합니다.
- `kmsd`는 `kmsctl init`으로 이미 초기화한 노드만 엽니다.
- `SIGINT`나 `SIGTERM`을 받으면 진행 중인 요청을 마무리하고 종료합니다.
- `kmsd`가 실행 중이어도 같은 노드에서 `kmsctl`을 쓸 수 있습니다. 각자 별도의 코어를 띄우며, 저장소와 감사 로그는 동시 접근에 안전합니다.

### HTTP API

모든 엔드포인트는 등록된 구성원의 클라이언트 인증서를 요구합니다.

| 메서드와 경로           | 설명                                    |
|-------------------|---------------------------------------|
| `GET /v1/health`  | 구성원 id, FIPS, PQC 상태                  |
| `GET /v1/card`    | 이 노드의 신원 카드                           |
| `POST /v1/inbox`  | 봉투 제출 (본문은 봉투 바이트). 성공 시 `201`과 봉투 id |
| `GET /v1/witness` | 이 노드가 요청한 구성원에 대해 증인으로 본 감사 로그 head   |

봉투의 송신자가 인증된 피어와 다르거나, 수신자가 이 노드가 아니거나, 서명이 일치하지 않으면 `400`으로 거부됩니다. 같은 봉투를 다시 보내면 `409`로, 같은 송신자의 대기 봉투가 64개에 이르면 `429`로 응답합니다. kmsd는 동시에 64개 연결까지 처리하고, 그 이상은 앞선 연결이 끝날 때까지 대기시킵니다.

### systemd 예시

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

Linux에서 코어는 `mlockall` 시스템 콜로 모든 메모리를 잠급니다. memlock 한도가 작으면 코어가 기동을 거부하기 때문에 `LimitMEMLOCK=infinity`가 필요합니다.

## kms-core 단독 실행

보통은 `kmsctl`과 `kmsd`가 코어를 직접 띄웁니다. 코어를 별도 사용자로 분리해 운영하려면 다음과 같이 소켓 경로 모드를 사용해야 합니다.

```bash
$ kms-core --generate-root-key /path/root.key
$ kms-core --socket /run/pairier/core.sock --root-key-file /path/root.key --pqc --peer-uid 1001
```

| 옵션                        | 설명                                                            |
|---------------------------|---------------------------------------------------------------|
| `--fd N`                  | 상속받은 소켓 사용 (호스트가 기동할 때 `3`)                                   |
| `--socket PATH`           | 소켓 경로에서 uid가 맞는 연결 하나만 받은 뒤 경로를 삭제. 다른 uid의 연결은 기록 후 끊고 계속 대기 |
| `--root-key-file PATH`    | 32바이트 일반 파일만 허용. 현재 사용자 소유, 그룹과 기타 권한 없음, 심볼릭 링크와 추가 하드 링크 없음 |
| `--ephemeral-root`        | 메모리에만 있는 임시 루트 키 (재시작하면 blob을 열 수 없음)                         |
| `--pqc`                   | PQC 알고리즘 활성화 (pqc feature로 빌드한 경우)                            |
| `--allow-unlocked-memory` | `mlockall`을 쓸 수 없는 환경에서 계속 진행                                 |
| `--peer-uid UID`          | 받을 피어의 uid (기본은 자신의 uid). 자신과 다르면 소켓을 `0666`으로 열어 둠           |

소켓을 만드는 디렉토리는 코어 사용자나 root 소유여야 합니다. 그룹이나 기타 사용자가 쓸 수 있는 디렉토리는 sticky 비트가 없으면 기동을 거부합니다. `--peer-uid`가 코어 자신과 다르면 소켓 파일이 `0666`이 되므로, 디렉토리 권한으로 접근을 좁혀야 합니다. 예를 들어 코어가 uid 1001, 호스트가 uid 1002라면 호스트 그룹만 디렉토리를 지날 수 있게 만듭니다.

```bash
# install -d -o 1001 -g 1002 -m 0710 /run/pairier
```

> [!NOTE]
> 현재 `kmsctl`과 `kmsd`는 노드 디렉토리의 루트 키로 코어를 직접 기동하는 방식만 지원합니다.

## 노드 디렉토리

```text
<dir>/
  root.key     루트 키 (0400) - 모든 키 blob을 여는 유일한 비밀(secret)
  node.json    구성원 id와 신원, KEM, 감사 키 id
  keys/        키 레코드 - 키 재료는 루트 키로 봉인된 blob으로만 저장
  members/     등록된 구성원 카드와 지문
  inbox/       kmsd가 받은 봉투
  witness/     구성원별로 증인으로 본 감사 로그 head (구성원당 최대 4096개)
  tls.json     TLS 인증서와 코어 안 TLS 키의 id
  audit.log    해시 체인 감사 로그 (항목마다 감사 키 서명)
```

- 디렉토리는 `0700`이고 현재 사용자 소유여야 하며, 파일에는 그룹과 기타 권한이 없어야 합니다. 심볼릭 링크는 열지 않습니다.
- 저장된 메타데이터와 공개키는 사용할 때마다 코어가 blob에서 다시 계산한 값과 대조합니다.
- 백업에는 `root.key`가 포함되기 때문에 **백업 매체도 루트 키와 같은 수준으로 보호**해야 합니다.

## 보안 운영 주의 사항

- **지문은 별도 채널로 확인하세요.** 카드와 지문을 같은 경로로 받으면 중간자 공격을 막을 수 없습니다.
- **감사 로그의 한계를 이해해야 합니다.** 각 항목은 코어의 감사 키로 서명되므로, 코어를 쓸 수 없는 공격자(디스크 탈취, 변조된 백업 등)는 로그를 위조하거나 재계산할 수 없습니다. 반면 노드 사용자 권한으로 코어를 기동할 수 있으면 유효한 서명을 만들 수 있습니다. 또 로그 끝부분을 잘라 내거나 이전 로그로 되돌리는 것은, 다른 구성원이 증인으로 본 head나 노드 밖에 기록해 둔 head와 대조해야 탐지할 수 있습니다. 마지막으로 증인이 본 head 이후의 항목은 보호되지 않으므로 여러 구성원과 대조하세요.
- **macOS는 개발용으로 사용하세요.** `mlockall`이 없어 메모리 잠금 없이 실행되고, FIPS 코어도 정적 링크되지 않습니다. 운영은 Linux에서 하십시오.
- **PQC 모드 감사 로깅은 빠른 속도로 증가합니다.** ML-DSA 서명으로 인해 항목 하나가 약 7KB입니다. 암/복호화도 한 번마다 항목이 추가됩니다.

> [!CAUTION]
> pairier는 아직 외부 보안 검토를 받지 않았으며, 기능의 안전성 검증을 위해 시간이 더 소요될 수 있습니다. pairier는 개발 또는 연구용으로만 사용해주시길 바랍니다.
>
> **위 항목들은 검증이 진행됨에 따라 언제든 바뀔 수 있으며, 필요한 보안 요구사항이 충분히 증가될 수 있습니다.**

## 한도

| 항목                  | 한도                                              |
|---------------------|-------------------------------------------------|
| 구성원 id              | 영문 소문자, 숫자로 시작하고 소문자, 숫자, `.`, `_`, `-`로 최대 64자 |
| 키 label             | 256바이트, 제어 문자와 양방향 서식 문자 불가                     |
| 암호화 평문, AAD         | 각각 64KiB                                        |
| kmsctl 입력 파일과 stdin | 1MiB                                            |
| 봉투 컨텍스트             | 1KiB                                            |
| 송신자별 대기 봉투          | 64개                                             |
| kmsd 동시 연결          | 64개                                             |
| 구성원별 증인 head        | 4096개 (순번이 가장 낮은 것부터 버림)                        |

## 문제 해결

| 메시지                                                                              | 원인 및 조치                                                                                             |
|----------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `mlockall: Cannot allocate memory ... (pass --allow-unlocked-memory to proceed)` | memlock 한도가 작습니다. `ulimit -l unlimited` 또는 `LimitMEMLOCK=infinity`로 늘려야 합니다.                        |
| `node: fingerprint does not match the card`                                      | 지문이 다릅니다. 카드를 다시 받아 별도 채널로 지문을 재확인해야 합니다.                                                           |
| `core: op 0x0023 failed: capability disabled`                                    | pqc 없이 초기화한 노드에 pqc 카드를 등록하려 했습니다.                                                                  |
| `core: op 0x0030 failed: usage denied`                                           | 키에 `export`가 없거나, 원래 용도보다 넓은 용도를 주려 했습니다.                                                           |
| `node: envelope is addressed to another member`                                  | 다른 구성원에게 보낸 봉투입니다.                                                                                  |
| `node: unknown member`                                                           | 송신자 또는 수신자가 등록되지 않았습니다.                                                                             |
| `store: object already exists`                                                   | 이미 가져온 키이거나 이미 받은 봉투입니다.                                                                            |
| `node: stored metadata does not match the core`                                  | 노드 디렉토리의 레코드가 변조되었습니다. 백업과 감사 로그를 확인해야 합니다.                                                         |
| `audit: checkpoint signature is invalid`                                         | 감사 로그가 코어 없이 수정되었습니다.                                                                               |
| `audit: log does not contain the anchored entry`                                 | 기록해 두었거나 증인이 본 head 이후 로그가 잘렸거나 이전 로그로 되돌려졌습니다. 백업과 노드 접근 기록을 확인해야 합니다.                             |
| `node: label contains control or bidirectional formatting characters`            | 라벨에서 제어 문자와 양방향 서식 문자를 빼야 합니다.                                                                      |
| `api: push rejected: 429 inbox full for this sender`                             | 수신자 inbox에 내가 보낸 대기 봉투가 64개 쌓였습니다. 수신자가 수락하거나 거절해야 합니다.                                             |
| `transport: socket directory ... is writable by other users`                     | 소켓 디렉토리에서 그룹과 기타 사용자의 쓰기 권한을 빼야 합니다.                                                                |
| `node: tls key is held outside the core, ...`                                    | 1.0.0에서 만든 노드입니다. `card renew`를 실행하고 새 카드와 지문을 구성원에게 보낸 뒤 kmsd를 다시 시작해야 합니다.                        |
| `node: member card uses a retired kem, ...`                                      | 구성원에게 `card renew`를 요청한 뒤 새 카드를 등록해야 합니다.                                                           |
| `exchange: malformed object: envelope from pairier 1.0.0 ...`                    | 1.0.0이 만든 봉투이며 이 버전은 받지 않습니다. 송신자가 업그레이드한 뒤 키를 다시 보내야 합니다.                         |
| `node: member identity key differs from the registered card`                     | 등록된 구성원의 갱신 카드가 아닙니다. 별도 채널로 지문을 확인해야 합니다.                                                          |
| `node: member audit head conflicts with a head witnessed earlier`                | 송신자의 감사 로그가 분기했거나 되돌려졌습니다. 송신자 노드를 조사해야 합니다. 백업 복원임을 별도 채널로 확인한 경우에만 `witness/<member>.json`을 지웁니다. |
| `` linker `link.exe` not found ``                                                | Windows 네이티브 빌드는 지원하지 않습니다. WSL2 안에서 빌드해야 합니다([빌드](#빌드) 참고).                                        |
| `undefined: syscall.Socketpair`, `undefined: syscall.Stat_t`                     | 원인이 위와 같습니다. 호스트가 Unix 시스템 콜을 사용하므로 WSL2 안에서 빌드해야 합니다.                                              |
