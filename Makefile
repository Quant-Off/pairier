GO    ?= go
CARGO ?= cargo

CORE_DIR := core
HOST_DIR := host

CORE_FEATURES ?= pqc
FIPS          ?= 0
ifeq ($(FIPS),1)
CORE_FLAGS := --no-default-features --features fips,$(CORE_FEATURES)
else
CORE_FLAGS := --features $(CORE_FEATURES)
endif
KMS_CORE_BIN  := $(abspath $(CORE_DIR)/target/debug/kms-core)

export GOTOOLCHAIN := local
export GOPROXY     := off
export GOFLAGS     := -mod=vendor -trimpath
export CGO_ENABLED := 0
GOFIPS140 ?= certified
export GOFIPS140

RUST_TOOLCHAIN := $(shell sed -n 's/^channel = "\(.*\)"/\1/p' $(CORE_DIR)/rust-toolchain.toml)
VERSION        := $(shell sed -n 's/^version = "\(.*\)"/\1/p' $(CORE_DIR)/Cargo.toml | head -1)
GO_LDFLAGS     := -s -w -X main.version=$(VERSION)
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH
DIST_DIR       := dist
CORE_RELEASE   := $(abspath $(CORE_DIR)/target/release/kms-core)
CARGO_NET      := $(CARGO) +$(RUST_TOOLCHAIN)
CORE_MANIFEST  := --manifest-path $(CORE_DIR)/Cargo.toml
GO_NET         := GOPROXY=https://proxy.golang.org,direct GOFLAGS=-trimpath $(GO)

.PHONY: all build build-core build-host test test-core test-host lint lint-core lint-host fmt vendor update clean dist sign verify-dist audit

all: build

build: build-core build-host

build-core:
	cd $(CORE_DIR) && RUSTFLAGS="--remap-path-prefix=$(abspath .)=/pairier $(RUSTFLAGS)" $(CARGO) build --release --frozen -p kms-core $(CORE_FLAGS)

build-host:
	cd $(HOST_DIR) && $(GO) build -ldflags "$(GO_LDFLAGS)" -o bin/ ./cmd/...

test: test-core test-host

test-core:
	cd $(CORE_DIR) && $(CARGO) test --frozen --all-features

test-host:
	cd $(CORE_DIR) && $(CARGO) build --frozen -p kms-core --features pqc
	cd $(HOST_DIR) && CGO_ENABLED=1 KMS_CORE_BIN=$(KMS_CORE_BIN) $(GO) test -race ./...

lint: lint-core lint-host

lint-core:
	cd $(CORE_DIR) && $(CARGO) fmt --all --check
	cd $(CORE_DIR) && $(CARGO) clippy --frozen --all-targets --all-features -- -D warnings

lint-host:
	cd $(HOST_DIR) && test -z "$$(gofmt -l .)"
	cd $(HOST_DIR) && $(GO) vet ./...

fmt:
	cd $(CORE_DIR) && $(CARGO) fmt --all
	cd $(HOST_DIR) && gofmt -w .

vendor:
	$(CARGO_NET) vendor $(CORE_MANIFEST) --locked $(CORE_DIR)/vendor
	cd $(HOST_DIR) && $(GO_NET) mod vendor

update:
	$(CARGO_NET) update $(CORE_MANIFEST)
	cd $(HOST_DIR) && $(GO_NET) get -u ./... && $(GO_NET) mod tidy

dist: build
	mkdir -p $(DIST_DIR)
	python3 -I scripts/sbom.py --version $(VERSION) --cargo "$(CARGO)" --core-flags "$(CORE_FLAGS)" \
		--go-binary $(HOST_DIR)/bin/kmsd --go-binary $(HOST_DIR)/bin/kmsctl \
		--epoch $(SOURCE_DATE_EPOCH) --out $(DIST_DIR)/sbom.cdx.json
	./scripts/dist.sh $(VERSION) $(CORE_RELEASE) $(HOST_DIR)/bin/kmsd $(HOST_DIR)/bin/kmsctl $(DIST_DIR) $(DIST_DIR)/sbom.cdx.json
	rm -f $(DIST_DIR)/sbom.cdx.json

sign:
	./scripts/sign.sh $(DIST_DIR) $(VERSION)

verify-dist:
	./scripts/verify.sh $(DIST_DIR) minisign.pub $(VERSION)

audit:
	cd $(CORE_DIR) && $(CARGO) deny check --disable-fetch advisories licenses bans sources
	@command -v govulncheck >/dev/null && (cd $(HOST_DIR) && govulncheck ./...) || echo "govulncheck not installed, skipping"

clean:
	cd $(CORE_DIR) && $(CARGO) clean
	rm -rf $(HOST_DIR)/bin $(DIST_DIR)
