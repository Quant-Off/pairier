GO    ?= go
CARGO ?= cargo

CORE_DIR := core
HOST_DIR := host

export GOTOOLCHAIN := local
export GOPROXY     := off
export GOFLAGS     := -mod=vendor -trimpath
export CGO_ENABLED := 0

RUST_TOOLCHAIN := $(shell sed -n 's/^channel = "\(.*\)"/\1/p' $(CORE_DIR)/rust-toolchain.toml)
CARGO_NET      := $(CARGO) +$(RUST_TOOLCHAIN)
CORE_MANIFEST  := --manifest-path $(CORE_DIR)/Cargo.toml
GO_NET         := GOPROXY=https://proxy.golang.org,direct GOFLAGS=-trimpath $(GO)

.PHONY: all build build-core build-host test test-core test-host lint lint-core lint-host fmt vendor update clean

all: build

build: build-core build-host

build-core:
	cd $(CORE_DIR) && $(CARGO) build --release --frozen

build-host:
	cd $(HOST_DIR) && $(GO) build -o bin/ ./cmd/...

test: test-core test-host

test-core:
	cd $(CORE_DIR) && $(CARGO) test --frozen --all-features

test-host:
	cd $(HOST_DIR) && $(GO) test ./...

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

clean:
	cd $(CORE_DIR) && $(CARGO) clean
	rm -rf $(HOST_DIR)/bin
