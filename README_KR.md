# pairier

<div align="center">

한국어 | [English](README.md)

</div>

제로 트러스트(Zero-Trust) 기반 Go 및 Rust의 하이브리드 키 관리 체계(Key Management System, KMS)입니다. Go 호스트가 네트워크와 관리 인터페이스를 맡고, Rust 보안 코어가 암호 엔진과 키 재료(material)를 맡습니다.

## 구조

- `core/` Rust 워크스페이스 (보안 코어)
  - `kms-wire` 의존성 없는 `no_std` 와이어 프로토콜 v1
  - `kms-sys` 프로세스 하드닝과 보안 메모리, 유일하게 `unsafe`가 허용된 crate
  - `kms-engine` aws-lc-rs 기반 암호 엔진
  - `kms-core` 보안 코어 데몬(daemon) 바이너리
- `host/` Go 모듈 (호스트)
  - `internal/wire` 와이어 프로토콜 Go 구현
  - `internal/core` 코어 프로세스 기동과 클라이언트
  - `cmd/kmsd`, `cmd/kmsctl` 데몬과 관리 도구 (API 계층은 구현 예정)
- `conformance/wire/` Rust와 Go가 함께 통과해야 하는 프로토콜 적합성 벡터

## 기능

코어(Rust)는 별도 프로세스로 동작하며, 호스트(Go)와 같은 주소 공간을 공유하지 않습니다. 호스트가 자기 프로세스 안에서 `socketpair`를 만들어 한쪽 끝은 자신이 갖고, 다른 쪽 끝을 자식 프로세스의 `fd` 3번으로 넘기며 `kms-core`를 실행합니다. 이 방식에서는 파일시스템(fs)에 소켓 경로가 생기지 않고 listen도 하지 않으므로 제3자가 접속할 방법이 없고, 호스트와 코어만 해당 통로를 공유합니다. 다만 호스트가 코어를 띄우기 때문에 같은 UID로 동작합니다. 운영 환경에서는 코어를 별도 UID로 먼저 띄우고 호스트가 `--socket` 경로로 접속하는 방식도 지원하며, 이때 코어는 `--peer-uid`로 접속자를 검증합니다. 어느 방식이든 TCP는 쓰지 않고 같은 머신 안의 로컬 IPC만 사용합니다.

상태 없는(stateless) 코어도 핵심 기능입니다. 코어는 32바이트 루트 키(root key)만 메모리에 두고, 개별 키는 루트 키로 봉인된(sealed) blob으로 호스트에 저장되며, 호스트는 해당 blob을 열 수 없습니다. blob 헤더(알고리즘, 용도, 키 id, 라벨)는 모두 인증됩니다.

이 외에도 다음과 같은 중요한 기능이 포함됩니다.

- 검인증 암호 모듈: aws-lc-rs(AWS-LC)를 사용하며, `fips` feature로 FIPS 140-3 검증 모듈을 선택합니다. Go 쪽은 표준 라이브러리만 사용합니다.
- 알고리즘: AES-256-GCM, ECDSA P-256/P-384, Ed25519, ML-DSA-65/87, ML-KEM-768/1024
- 선택적 PQC: 컴파일 타임 `pqc` feature와 런타임 `--pqc` 플래그를 모두 설정해야 활성화되며, `HELLO` 응답의 capability 비트를 통해 호스트에 알립니다.
- 키 용도 강제: 생성 시 지정한 용도(ENCRYPT, DECRYPT, SIGN, VERIFY 등) 외의 연산은 코어 측에서 거부합니다.
- 코어 하드닝: 시작 시 코어 덤프 차단, `ptrace` 거부, `no_new_privs`, `umask 077`, 환경 변수 제거, 불필요 `fd` 정리, 피어(peer) UID 검증, 루트 키 파일 권한·소유자·링크 검증을 수행합니다. Linux에서는 `mlockall`로 메모리 스와핑(swap)을 막습니다.
- 엄격한 프로토콜: 고정 16바이트 헤더와 길이 접두 필드, 1MiB 본문 상한, 후행 바이트를 거부합니다. `HELLO` 선행을 강제하며 프레이밍(framing) 위반 시 세션을 끊어냅니다.
- 폐쇄 빌드: Rust 의존성은 `core/vendor`에 벤더링되고 `--frozen`으로 빌드합니다. Go는 `GOPROXY=off`, `-mod=vendor`로 빌드하며 외부 의존성이 없습니다.

## 빌드

요구 사항은 Rust `1.95.0`(`rust-toolchain.toml`로 고정)과 Go `1.27.2`입니다. FIPS 빌드는 `cmake`, `perl`이 추가로 필요하며 Linux x86_64/aarch64에서만 정적 링크됩니다.

```bash
$ make build # 코어(release, pqc 포함) + 호스트
$ make build-core FIPS=1
$ make test # Rust 전체 feature 테스트 + Go 테스트(실제 코어 바이너리 사용)
$ make lint
```

## 코어 실행

```bash
$ kms-core --generate-root-key /path/root.key
$ kms-core --socket /run/kms/core.sock --root-key-file /path/root.key --pqc
```

호스트가 직접 기동할 때는 `--fd 3`으로 상속 소켓을 사용합니다. macOS처럼 `mlockall`이 없는 환경에서는 `--allow-unlocked-memory`가 필요합니다.
