# NovaNet Development Guide

This guide covers building NovaNet from source, running tests, and contributing.

---

## Prerequisites

### Go Development

- **Go 1.26+** ([install](https://go.dev/dl/))
- **protoc** (Protocol Buffers compiler) with Go plugins:

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
```

### Rust/eBPF Development

Building the eBPF dataplane requires a Linux environment. On macOS, use Docker.

**Native Linux requirements:**
- Rust stable + nightly (`rustup toolchain install nightly`)
- `bpf-linker` (`cargo install bpf-linker`)
- `clang`, `llvm`, `libelf-dev`, `linux-headers`

**macOS/Windows:** Use `make build-docker-rust` which builds inside Docker.

### Helm

- **Helm 3.x** ([install](https://helm.sh/docs/intro/install/))

---

## Repository Layout

```
cmd/
  novanet-agent/         Main agent binary (Go)
  novanet-cni/           CNI plugin binary (Go)
  novanetctl/            CLI tool (Go)
internal/
  cni/                   Veth/namespace setup (Linux-only)
  config/                Config loading and validation
  dataplane/             Dataplane gRPC client interface
  egress/                Egress policy management
  identity/              Label-based identity allocation
  ipam/                  Bitmap IP allocator with disk persistence
  k8s/                   Kubernetes API helpers
  masquerade/            iptables SNAT rules
  metrics/               Prometheus metric definitions
  node/                  Node management
  novaroute/             NovaRoute gRPC client
  policy/                NetworkPolicy compiler and watcher
  routing/               Routing mode manager
  tunnel/                Geneve/VXLAN tunnel creation
dataplane/
  novanet-common/        Shared types between eBPF and userspace (Rust)
  novanet-dataplane/     Userspace daemon: gRPC server, eBPF loader (Rust)
  novanet-ebpf/          eBPF TC programs (Rust, no_std)
api/v1/                  Protobuf definitions and generated code
deploy/helm/novanet/     Kubernetes Helm chart
tests/
  integration/           Live cluster integration tests (shell scripts)
  benchmark/             Performance benchmarks
docs/                    Documentation
```

---

## Building

### Go Binaries

```bash
# Build all Go binaries (agent, CNI, CLI)
make build

# Build individually
make build-agent
make build-cni
make build-ctl
```

Binaries are written to `bin/`.

### Rust Dataplane (via Docker -- macOS or Linux)

```bash
make build-docker-rust
```

This builds inside a Docker container and extracts the binaries to `bin/`.

### Rust Dataplane (Native -- Linux Only)

```bash
make build-rust-native
```

Requires nightly Rust toolchain and system dependencies (clang, llvm, libelf-dev).

### Docker Images

```bash
# Build production images
make docker-build

# Build and push
make docker-push

# Build with a specific tag
make docker-build DOCKER_TAG=v0.2.0
```

### Protobuf Regeneration

If you modify `api/v1/novanet.proto`:

```bash
make proto
```

---

## Testing

### Go Unit Tests

```bash
make test-go
# or directly:
go test -race -count=1 ./...
```

### Rust Unit Tests

```bash
make test-rust
# or directly:
cd dataplane && cargo test --package novanet-dataplane
cd dataplane && cargo test --package novanet-common
```

Note: `novanet-ebpf` cannot be unit-tested (eBPF bytecode runs in kernel only). It is validated via integration tests.

### Linting

```bash
# All linters
make lint

# Go only
make lint-go

# Rust only
make lint-rust
```

### Integration Tests

Requires a running K3s cluster with NovaNet installed:

```bash
# Run all integration tests
tests/integration/run-all.sh

# Run a specific test
tests/integration/01-same-node.sh
```

Test scenarios:

| Test | Description |
|------|-------------|
| `01-same-node.sh` | Same-node pod connectivity |
| `02-cross-node-native.sh` | Cross-node native routing |
| `03-cross-node-geneve.sh` | Cross-node Geneve overlay |
| `04-cross-node-vxlan.sh` | Cross-node VXLAN overlay |
| `05-network-policy.sh` | NetworkPolicy enforcement |
| `06-egress.sh` | Egress policy and masquerade |
| `07-dns.sh` | DNS resolution |
| `08-external.sh` | External connectivity |
| `09-graceful-restart.sh` | Rolling restart resilience |

### Benchmarks

```bash
tests/benchmark/run-all.sh
```

---

## CI/CD

### CI Pipeline (`.github/workflows/ci.yml`)

Runs on every push to `main` and on pull requests:

- Go lint (vet, fmt)
- Rust lint (clippy, fmt)
- Helm lint
- Go unit tests with race detection and coverage
- Rust unit tests
- Go binary builds
- Rust/eBPF Docker build
- Security scan (govulncheck)

### Release Pipeline (`.github/workflows/release.yml`)

Triggered by pushing a version tag (`v*`):

1. Builds Go binaries for `linux/amd64` and `linux/arm64`
2. Builds multi-arch Docker images (amd64 + arm64) for both agent and dataplane
3. Pushes images to `ghcr.io/piwi3910/novanet/novanet-agent` and `ghcr.io/piwi3910/novanet/novanet-dataplane`
4. Runs Trivy vulnerability scans on published images
5. Creates a GitHub Release with tarballs attached

To create a release:

```bash
git tag v0.2.0
git push origin v0.2.0
```

---

## Makefile Targets

| Target | Description |
|--------|-------------|
| `build` | Build Go binaries (alias for `build-go`) |
| `build-all` | Build Go + Rust/eBPF via Docker |
| `build-go` | Build all Go binaries |
| `build-agent` | Build novanet-agent |
| `build-cni` | Build novanet-cni |
| `build-ctl` | Build novanetctl |
| `build-docker-rust` | Build Rust/eBPF in Docker (works on macOS) |
| `build-rust-native` | Build Rust natively (Linux only) |
| `test` | Run all tests (Go + Rust) |
| `test-go` | Run Go tests with `-race` |
| `test-rust` | Run Rust tests |
| `lint` | Run all linters |
| `lint-go` | Run Go linters |
| `lint-rust` | Run Rust linters (clippy + fmt) |
| `proto` | Regenerate protobuf Go code |
| `docker-build` | Build Docker images |
| `docker-push` | Push Docker images |
| `clean` | Remove build artifacts |
| `help` | Show available targets |

---

## Architecture Notes for Contributors

### Adding a New eBPF Map

1. Define the key/value types in `dataplane/novanet-common/src/lib.rs` (shared between kernel and userspace)
2. Add the map declaration in `dataplane/novanet-ebpf/src/main.rs`
3. Add management methods in `dataplane/novanet-dataplane/src/maps.rs` (both `MockMaps` and `RealMaps`)
4. Add gRPC RPCs in `api/v1/novanet.proto`
5. Regenerate proto: `make proto`
6. Implement the server-side handler in `dataplane/novanet-dataplane/src/server.rs`
7. Implement the agent-side caller in `cmd/novanet-agent/main.go`

### Adding a New CLI Command

1. Create a new file in `cmd/novanetctl/` (e.g., `newcmd.go`)
2. Define a Cobra command and register it in `main.go`
3. Add the corresponding gRPC RPC if needed

### Adding a New Helm Value

1. Add the default to `deploy/helm/novanet/values.yaml`
2. Reference it in the appropriate template (usually `configmap.yaml` or `daemonset.yaml`)
3. Document it in `docs/configuration.md`

---

## Next Steps

- [Architecture](architecture.md) -- Internal design details
- [API Reference](api-reference.md) -- gRPC protocol
- [Troubleshooting](troubleshooting.md) -- Debugging
