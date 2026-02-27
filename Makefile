# NovaNet Makefile
# Build automation for novanet-agent, novanet-cni, novanetctl, and novanet-dataplane.

BINARY_DIR    := bin
AGENT_BINARY  := $(BINARY_DIR)/novanet-agent
CNI_BINARY    := $(BINARY_DIR)/novanet-cni
CTL_BINARY    := $(BINARY_DIR)/novanetctl
DP_BINARY     := $(BINARY_DIR)/novanet-dataplane

DOCKER_IMAGE_AGENT := ghcr.io/piwi3910/novanet-agent
DOCKER_IMAGE_DP    := ghcr.io/piwi3910/novanet-dataplane
DOCKER_TAG         := latest

GO       := go
GOFLAGS  := -ldflags="-s -w"
CARGO    := cargo
PROTOC   := protoc

.PHONY: all build build-go build-rust build-ebpf build-docker test test-go test-rust lint proto docker-build docker-push clean help

## build: Build Go binaries (agent, CNI, CLI). Use build-docker for Rust/eBPF.
build: build-go

## build-all: Build everything using Docker for Rust/eBPF
build-all: build-go build-docker-rust

## build-go: Build all Go binaries
build-go: build-agent build-cni build-ctl

build-agent:
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -o $(AGENT_BINARY) ./cmd/novanet-agent/

build-cni:
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -o $(CNI_BINARY) ./cmd/novanet-cni/

build-ctl:
	@mkdir -p $(BINARY_DIR)
	$(GO) build $(GOFLAGS) -o $(CTL_BINARY) ./cmd/novanetctl/

## build-docker-rust: Build Rust/eBPF in Docker (required on macOS)
build-docker-rust:
	docker build -f Dockerfile.build -t novanet-builder .
	docker create --name novanet-extract novanet-builder /bin/true
	@mkdir -p $(BINARY_DIR)
	docker cp novanet-extract:/build/dataplane/target/release/novanet-dataplane $(DP_BINARY)
	# eBPF object may not exist if the eBPF build was skipped (e.g. missing nightly).
	docker cp novanet-extract:/build/dataplane/target/bpfel-unknown-none/release/novanet-ebpf $(BINARY_DIR)/novanet-ebpf.bpf.o 2>/dev/null \
		&& echo "Copied eBPF object file" || echo "Warning: eBPF object file not found (nightly toolchain may be required)"
	docker rm novanet-extract

## build-rust-native: Build Rust locally (Linux only)
build-rust-native: build-ebpf-native
	cd dataplane && $(CARGO) build --package novanet-dataplane --release
	@mkdir -p $(BINARY_DIR)
	cp dataplane/target/release/novanet-dataplane $(DP_BINARY)

build-ebpf-native:
	cd dataplane && $(CARGO) +nightly build --package novanet-ebpf \
		--target bpfel-unknown-none -Z build-std=core --release

## test: Run all tests
test: test-go test-rust

## test-go: Run Go unit tests with race detection
test-go:
	$(GO) test -race -count=1 ./...

## test-rust: Run Rust tests (dataplane + common only, not eBPF)
test-rust:
	cd dataplane && $(CARGO) test --package novanet-dataplane
	cd dataplane && $(CARGO) test --package novanet-common

## lint: Run linters
lint: lint-go lint-rust

lint-go:
	$(GO) vet ./...
	@if [ "$$(gofmt -s -l . | wc -l)" -gt 0 ]; then \
		echo "Code is not formatted:"; gofmt -s -l .; exit 1; \
	fi

## lint-rust: Run Rust linters (clippy + fmt check)
lint-rust:
	cd dataplane && $(CARGO) fmt --all -- --check
	cd dataplane && $(CARGO) clippy --package novanet-common --package novanet-dataplane -- -D warnings

## proto: Generate protobuf Go code
proto:
	$(PROTOC) --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/v1/novanet.proto

## docker-build: Build production Docker images
docker-build:
	docker build -t $(DOCKER_IMAGE_AGENT):$(DOCKER_TAG) -f Dockerfile.agent .
	docker build -t $(DOCKER_IMAGE_DP):$(DOCKER_TAG) -f Dockerfile.dataplane .

## docker-push: Push Docker images to registry
docker-push:
	docker push $(DOCKER_IMAGE_AGENT):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE_DP):$(DOCKER_TAG)

## clean: Remove build artifacts
clean:
	rm -rf $(BINARY_DIR)
	cd dataplane && $(CARGO) clean 2>/dev/null || true
	@echo "Cleaned build artifacts"

## help: Show this help message
help:
	@echo "Available targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
