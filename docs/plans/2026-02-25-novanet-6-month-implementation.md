# NovaNet 6-Month Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build NovaNet from an empty repo to a production-ready eBPF-based Kubernetes CNI with identity-based policy, dual overlay support (Geneve/VXLAN), native routing via NovaRoute (BGP/OSPF), and deep observability. NovaNet provides L4 load balancing (ClusterIP/NodePort DNAT) as a kube-proxy replacement. When NovaEdge is installed, it supersedes NovaNet's L4 LB with full L7 capabilities.

**Architecture:** Go management plane (Kubernetes watchers, policy compiler, IPAM, state reconciler, NovaRoute gRPC client) communicates with a Rust+eBPF dataplane (TC hooks, eBPF maps, ring buffer) via gRPC over Unix socket. CNI binary handles pod setup. Follows NovaRoute's patterns: structured logging (zap), Prometheus metrics, cobra CLI, protobuf API.

**Tech Stack:** Go 1.26 (management plane, CNI binary, CLI), Rust (dataplane, Aya framework for eBPF), Protobuf/gRPC (agent ↔ dataplane IPC), eBPF (TC ingress/egress hooks), Kubernetes client-go (watchers), Prometheus (metrics).

**Reference:** NovaRoute repo at github.com/azrtydxb/NovaRoute — match its Go conventions (package layout, zap logging, cobra CLI, protobuf API, Makefile structure, CI pipeline, config pattern).

---

## Month 1: Foundation & Same-Node Networking

### Task 1: Go Module & Project Structure

**Files:**
- Create: `go.mod`
- Create: `go.sum`
- Create: `cmd/novanet-agent/main.go`
- Create: `cmd/novanet-cni/main.go`
- Create: `cmd/novanetctl/main.go`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `.gitignore`
- Create: `LICENSE`

**Step 1: Initialize Go module**

```bash
cd /Users/pascal/Development/novanet
go mod init github.com/azrtydxb/novanet
```

**Step 2: Create .gitignore**

```gitignore
bin/
*.o
*.d
target/
*.bpf.o
```

**Step 3: Create LICENSE (Apache-2.0)**

Use the standard Apache-2.0 license text matching NovaRoute.

**Step 4: Create config package**

`internal/config/config.go` — match NovaRoute's config pattern (LoadFromFile, Validate, ExpandEnvVars, DefaultConfig):

```go
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

type Config struct {
	ListenSocket    string          `json:"listen_socket"`
	CNISocket       string          `json:"cni_socket"`
	DataplaneSocket string          `json:"dataplane_socket"`
	ClusterCIDR     string          `json:"cluster_cidr"`
	TunnelProtocol  string          `json:"tunnel_protocol"`
	RoutingMode     string          `json:"routing_mode"`
	NovaRoute       NovaRouteConfig `json:"novaroute"`
	LogLevel        string          `json:"log_level"`
	MetricsAddress  string          `json:"metrics_address"`
}

type NovaRouteConfig struct {
	Socket string `json:"socket"`
	Token  string `json:"token"`
}

func DefaultConfig() *Config {
	return &Config{
		ListenSocket:    "/run/novanet/novanet.sock",
		CNISocket:       "/run/novanet/cni.sock",
		DataplaneSocket: "/run/novanet/dataplane.sock",
		ClusterCIDR:     "10.244.0.0/16",
		TunnelProtocol:  "geneve",
		RoutingMode:     "overlay",
		NovaRoute: NovaRouteConfig{
			Socket: "/run/novaroute/novaroute.sock",
		},
		LogLevel:       "info",
		MetricsAddress: ":9103",
	}
}

func LoadFromFile(path string) (*Config, error) { /* ... */ }
func Validate(cfg *Config) error { /* ... */ }
func ExpandEnvVars(cfg *Config) { /* ... */ }
```

Validate must check:
- `cluster_cidr` is valid CIDR
- `tunnel_protocol` is `geneve` or `vxlan`
- `routing_mode` is `overlay` or `native`
- If `routing_mode` is `native`, `novaroute.socket` must be set and `novaroute.token` must be non-empty

**Step 5: Write config_test.go**

Test: LoadFromFile, Validate (happy path + all error cases), DefaultConfig, ExpandEnvVars.

Run: `go test -v -race ./internal/config/`

**Step 6: Create stub main.go files**

`cmd/novanet-agent/main.go` — minimal main that loads config and starts logger (match NovaRoute's main.go pattern: flag parsing, config load, zap logger, signal handling).

`cmd/novanet-cni/main.go` — stub that reads CNI stdin and returns a placeholder result.

`cmd/novanetctl/main.go` — cobra root command with `status` subcommand stub.

**Step 7: Verify build**

```bash
go build ./cmd/novanet-agent/
go build ./cmd/novanet-cni/
go build ./cmd/novanetctl/
go test -race ./...
```

**Step 8: Commit**

```bash
git add -A
git commit -m "feat: initialize Go project structure with config, agent, CNI, and CLI stubs"
```

---

### Task 2: Rust Workspace & Aya eBPF Setup

**Files:**
- Create: `dataplane/Cargo.toml` (workspace root)
- Create: `dataplane/novanet-dataplane/Cargo.toml`
- Create: `dataplane/novanet-dataplane/src/main.rs`
- Create: `dataplane/novanet-ebpf/Cargo.toml`
- Create: `dataplane/novanet-ebpf/src/main.rs`
- Create: `dataplane/novanet-common/Cargo.toml`
- Create: `dataplane/novanet-common/src/lib.rs`
- Create: `dataplane/rust-toolchain.toml`

**Step 1: Create Rust workspace**

`dataplane/Cargo.toml`:
```toml
[workspace]
resolver = "2"
members = [
    "novanet-dataplane",
    "novanet-ebpf",
    "novanet-common",
]
```

**Step 2: Create shared types crate**

`dataplane/novanet-common/` — shared types between userspace and eBPF (endpoint key/value, policy key/value, config keys). Uses `#![no_std]` for eBPF compatibility.

```rust
// dataplane/novanet-common/src/lib.rs
#![no_std]

// Endpoint map: Pod IP -> metadata
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EndpointKey {
    pub ip: u32, // network byte order
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EndpointValue {
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub _pad: [u8; 2],
    pub identity: u32,
}

// Policy map: (src_id, dst_id, proto, port) -> verdict
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PolicyKey {
    pub src_identity: u32,
    pub dst_identity: u32,
    pub protocol: u8,
    pub _pad: [u8; 1],
    pub dst_port: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PolicyValue {
    pub action: u8, // 0 = deny, 1 = allow
    pub _pad: [u8; 3],
}

// Config map keys
pub const CONFIG_KEY_MODE: u32 = 0;        // 0 = overlay, 1 = native
pub const CONFIG_KEY_TUNNEL_TYPE: u32 = 1;  // 0 = geneve, 1 = vxlan
pub const CONFIG_KEY_NODE_IP: u32 = 2;

// Mode values
pub const MODE_OVERLAY: u64 = 0;
pub const MODE_NATIVE: u64 = 1;

// Tunnel type values
pub const TUNNEL_GENEVE: u64 = 0;
pub const TUNNEL_VXLAN: u64 = 1;

// Policy actions
pub const ACTION_DENY: u8 = 0;
pub const ACTION_ALLOW: u8 = 1;
```

**Step 3: Create eBPF crate**

`dataplane/novanet-ebpf/` — eBPF programs using aya-ebpf. Initial TC program that passes all traffic (no-op baseline).

```rust
// dataplane/novanet-ebpf/src/main.rs
#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use novanet_common::*;

#[map]
static ENDPOINTS: HashMap<EndpointKey, EndpointValue> = HashMap::with_max_entries(65536, 0);

#[map]
static CONFIG: HashMap<u32, u64> = HashMap::with_max_entries(16, 0);

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    TC_ACT_OK
}

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    TC_ACT_OK
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

Cargo.toml for novanet-ebpf must target `bpfel-unknown-none` and depend on `aya-ebpf` and `novanet-common`.

**Step 4: Create userspace dataplane crate**

`dataplane/novanet-dataplane/` — Rust binary that loads eBPF programs, manages maps, exposes gRPC server for Go agent.

Dependencies: `aya`, `tonic` (gRPC), `tokio`, `novanet-common`.

Initial main.rs: load eBPF object file, attach TC programs to a specified interface, log success.

**Step 5: Create rust-toolchain.toml**

```toml
[toolchain]
channel = "nightly"
components = ["rust-src"]
```

Nightly is required for eBPF target compilation with Aya.

**Step 6: Verify build**

```bash
cd dataplane
cargo build --package novanet-common
cargo build --package novanet-dataplane
# eBPF build requires:
cargo +nightly build --package novanet-ebpf --target bpfel-unknown-none -Z build-std=core
```

**Step 7: Commit**

```bash
git add dataplane/
git commit -m "feat: initialize Rust workspace with eBPF, dataplane, and common crates"
```

---

### Task 3: Makefile & Build System

**Files:**
- Create: `Makefile`

**Step 1: Write Makefile**

Match NovaRoute's Makefile pattern. Targets:

```makefile
BINARY_DIR    := bin
AGENT_BINARY  := $(BINARY_DIR)/novanet-agent
CNI_BINARY    := $(BINARY_DIR)/novanet-cni
CTL_BINARY    := $(BINARY_DIR)/novanetctl
DP_BINARY     := $(BINARY_DIR)/novanet-dataplane

GO       := go
GOFLAGS  := -ldflags="-s -w"
CARGO    := cargo
PROTOC   := protoc

.PHONY: all build build-go build-rust build-ebpf test test-go test-rust lint proto clean help

build: build-go build-rust

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

build-ebpf:
	cd dataplane && $(CARGO) +nightly build --package novanet-ebpf \
		--target bpfel-unknown-none -Z build-std=core --release

build-rust: build-ebpf
	cd dataplane && $(CARGO) build --package novanet-dataplane --release
	@mkdir -p $(BINARY_DIR)
	cp dataplane/target/release/novanet-dataplane $(DP_BINARY)

test: test-go test-rust

test-go:
	$(GO) test -race -count=1 ./...

test-rust:
	cd dataplane && $(CARGO) test --package novanet-dataplane
	cd dataplane && $(CARGO) test --package novanet-common

lint:
	$(GO) vet ./...
	gofmt -s -l .
	cd dataplane && $(CARGO) clippy --all-targets

proto:
	$(PROTOC) --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/v1/novanet.proto

clean:
	rm -rf $(BINARY_DIR)
	cd dataplane && $(CARGO) clean
```

**Step 2: Verify**

```bash
make build-go
make test-go
make lint
```

**Step 3: Commit**

```bash
git add Makefile
git commit -m "feat: add Makefile with Go + Rust build targets"
```

---

### Task 4: gRPC API Definition (Agent ↔ Dataplane)

**Files:**
- Create: `api/v1/novanet.proto`
- Create: `api/v1/novanet.pb.go` (generated)
- Create: `api/v1/novanet_grpc.pb.go` (generated)
- Create: `dataplane/proto/novanet.proto` (copy or symlink for Rust tonic)

**Step 1: Write novanet.proto**

This is the internal API between Go agent and Rust dataplane. NOT the user-facing API.

```protobuf
syntax = "proto3";

package novanet.v1;

option go_package = "github.com/azrtydxb/novanet/api/v1";

// DataplaneControl is the internal API between the Go management plane
// and the Rust eBPF dataplane. The Rust dataplane runs the gRPC server,
// the Go agent is the client.
service DataplaneControl {
  // Endpoint management
  rpc UpsertEndpoint(UpsertEndpointRequest) returns (UpsertEndpointResponse);
  rpc DeleteEndpoint(DeleteEndpointRequest) returns (DeleteEndpointResponse);

  // Policy management
  rpc UpsertPolicy(UpsertPolicyRequest) returns (UpsertPolicyResponse);
  rpc DeletePolicy(DeletePolicyRequest) returns (DeletePolicyResponse);
  rpc SyncPolicies(SyncPoliciesRequest) returns (SyncPoliciesResponse);

  // Tunnel management (overlay mode)
  rpc UpsertTunnel(UpsertTunnelRequest) returns (UpsertTunnelResponse);
  rpc DeleteTunnel(DeleteTunnelRequest) returns (DeleteTunnelResponse);

  // Configuration
  rpc UpdateConfig(UpdateConfigRequest) returns (UpdateConfigResponse);

  // TC program lifecycle
  rpc AttachProgram(AttachProgramRequest) returns (AttachProgramResponse);
  rpc DetachProgram(DetachProgramRequest) returns (DetachProgramResponse);

  // Observability
  rpc StreamFlows(StreamFlowsRequest) returns (stream FlowEvent);
  rpc GetDataplaneStatus(GetDataplaneStatusRequest) returns (GetDataplaneStatusResponse);
}

// --- Endpoints ---

message UpsertEndpointRequest {
  uint32 ip = 1;          // network byte order
  uint32 ifindex = 2;
  bytes mac = 3;          // 6 bytes
  uint32 identity_id = 4;
  string pod_name = 5;
  string namespace = 6;
}
message UpsertEndpointResponse {}

message DeleteEndpointRequest {
  uint32 ip = 1;
}
message DeleteEndpointResponse {}

// --- Policies ---

message UpsertPolicyRequest {
  uint32 src_identity = 1;
  uint32 dst_identity = 2;
  uint32 protocol = 3;
  uint32 dst_port = 4;
  PolicyAction action = 5;
}
message UpsertPolicyResponse {}

message DeletePolicyRequest {
  uint32 src_identity = 1;
  uint32 dst_identity = 2;
  uint32 protocol = 3;
  uint32 dst_port = 4;
}
message DeletePolicyResponse {}

message SyncPoliciesRequest {
  repeated PolicyEntry policies = 1;
}
message PolicyEntry {
  uint32 src_identity = 1;
  uint32 dst_identity = 2;
  uint32 protocol = 3;
  uint32 dst_port = 4;
  PolicyAction action = 5;
}
message SyncPoliciesResponse {
  uint32 added = 1;
  uint32 removed = 2;
  uint32 updated = 3;
}

enum PolicyAction {
  POLICY_ACTION_DENY = 0;
  POLICY_ACTION_ALLOW = 1;
}

// --- Tunnels ---

message UpsertTunnelRequest {
  uint32 node_ip = 1;        // remote node IP
  uint32 tunnel_ifindex = 2;  // local tunnel interface index
  uint32 vni = 3;
}
message UpsertTunnelResponse {}

message DeleteTunnelRequest {
  uint32 node_ip = 1;
}
message DeleteTunnelResponse {}

// --- Config ---

message UpdateConfigRequest {
  map<uint32, uint64> entries = 1;
}
message UpdateConfigResponse {}

// --- TC Programs ---

message AttachProgramRequest {
  string interface_name = 1;
  AttachType attach_type = 2;
}
enum AttachType {
  ATTACH_TC_INGRESS = 0;
  ATTACH_TC_EGRESS = 1;
}
message AttachProgramResponse {}

message DetachProgramRequest {
  string interface_name = 1;
  AttachType attach_type = 2;
}
message DetachProgramResponse {}

// --- Observability ---

message StreamFlowsRequest {
  uint32 identity_filter = 1;  // 0 = all
}

message FlowEvent {
  uint32 src_ip = 1;
  uint32 dst_ip = 2;
  uint32 src_identity = 3;
  uint32 dst_identity = 4;
  uint32 protocol = 5;
  uint32 src_port = 6;
  uint32 dst_port = 7;
  PolicyAction verdict = 8;
  uint64 bytes = 9;
  uint64 packets = 10;
  int64 timestamp_ns = 11;
  DropReason drop_reason = 12;
}

enum DropReason {
  DROP_REASON_NONE = 0;
  DROP_REASON_POLICY_DENIED = 1;
  DROP_REASON_NO_IDENTITY = 2;
  DROP_REASON_NO_ROUTE = 3;
  DROP_REASON_NO_TUNNEL = 4;
  DROP_REASON_TTL_EXCEEDED = 5;
}

message GetDataplaneStatusRequest {}
message GetDataplaneStatusResponse {
  uint32 endpoint_count = 1;
  uint32 policy_count = 2;
  uint32 tunnel_count = 3;
  repeated AttachedProgram programs = 4;
  string mode = 5;           // "overlay" or "native"
  string tunnel_protocol = 6; // "geneve" or "vxlan"
}

message AttachedProgram {
  string interface_name = 1;
  string attach_type = 2;
  uint32 program_id = 3;
}
```

**Step 2: Generate Go code**

```bash
make proto
```

**Step 3: Set up tonic build for Rust**

Add `build.rs` to `novanet-dataplane` that compiles the proto with tonic-build.

**Step 4: Verify both Go and Rust compile with generated code**

```bash
make build-go
cd dataplane && cargo build --package novanet-dataplane
```

**Step 5: Commit**

```bash
git add api/ dataplane/
git commit -m "feat: define agent-dataplane gRPC API with protobuf"
```

---

### Task 5: IPAM Allocator

**Files:**
- Create: `internal/ipam/allocator.go`
- Create: `internal/ipam/allocator_test.go`

**Step 1: Write failing tests**

Test: Allocate returns sequential IPs within PodCIDR, Release frees IPs for reuse, Allocate returns error when exhausted, AllocateSpecific claims a specific IP.

**Step 2: Implement bitmap-based allocator**

```go
package ipam

import (
	"fmt"
	"net"
	"sync"
)

type Allocator struct {
	mu       sync.Mutex
	podCIDR  *net.IPNet
	base     uint32
	size     uint32
	bitmap   []uint64
}

func NewAllocator(podCIDR string) (*Allocator, error) { /* ... */ }
func (a *Allocator) Allocate() (net.IP, error) { /* ... */ }
func (a *Allocator) AllocateSpecific(ip net.IP) error { /* ... */ }
func (a *Allocator) Release(ip net.IP) error { /* ... */ }
func (a *Allocator) Used() int { /* ... */ }
func (a *Allocator) Available() int { /* ... */ }
```

Reserve .0 (network) and .1 (gateway) automatically.

**Step 3: Run tests**

```bash
go test -v -race ./internal/ipam/
```

**Step 4: Commit**

```bash
git add internal/ipam/
git commit -m "feat: implement bitmap-based IPAM allocator"
```

---

### Task 6: CNI Binary

**Files:**
- Modify: `cmd/novanet-cni/main.go`
- Create: `internal/cni/cni.go`
- Create: `internal/cni/cni_test.go`

**Step 1: Implement CNI ADD/DEL/CHECK**

The CNI binary is invoked by the kubelet. It:

1. Reads CNI config from stdin
2. Connects to novanet-agent via Unix socket (`/run/novanet/cni.sock`)
3. Requests IP allocation and pod setup
4. Returns CNI result to kubelet

For now (Month 1), the agent handles the actual netns setup:

- Create veth pair
- Move one end into pod netns
- Assign IP from IPAM
- Set up routes (default route via veth)
- Return IP to CNI binary

**Step 2: Implement agent-side CNI handler**

```go
// internal/cni/cni.go
package cni

type PodSetupRequest struct {
	PodName      string
	PodNamespace string
	ContainerID  string
	Netns        string
	IfName       string
}

type PodSetupResult struct {
	IP      net.IP
	Gateway net.IP
	Mac     net.HardwareAddr
	Ifindex int
}

type Handler struct {
	ipam       *ipam.Allocator
	dataplane  DataplaneClient  // gRPC client to Rust dataplane
	logger     *zap.Logger
}

func (h *Handler) Add(req *PodSetupRequest) (*PodSetupResult, error) { /* ... */ }
func (h *Handler) Del(req *PodSetupRequest) error { /* ... */ }
```

Add creates veth, configures netns, allocates IP, updates endpoint map via dataplane gRPC.
Del releases IP, removes endpoint, cleans up veth.

**Step 3: Write tests**

Test with mock netns (or skip netns tests on non-Linux). Test IPAM integration, error handling.

**Step 4: Commit**

```bash
git add cmd/novanet-cni/ internal/cni/
git commit -m "feat: implement CNI binary with pod veth setup and IPAM"
```

---

### Task 7: Kubernetes Watchers

**Files:**
- Create: `internal/k8s/watchers.go`
- Create: `internal/k8s/watchers_test.go`

**Step 1: Implement watchers using client-go informers**

```go
package k8s

type Watchers struct {
	nodeInformer      cache.SharedIndexInformer
	podInformer       cache.SharedIndexInformer
	namespaceInformer cache.SharedIndexInformer
	callbacks         WatcherCallbacks
	logger            *zap.Logger
}

type WatcherCallbacks struct {
	OnNodeAdd    func(node *v1.Node)
	OnNodeUpdate func(old, new *v1.Node)
	OnNodeDelete func(node *v1.Node)
	OnPodAdd     func(pod *v1.Pod)
	OnPodUpdate  func(old, new *v1.Pod)
	OnPodDelete  func(pod *v1.Pod)
}
```

Month 1 needs: Node watcher (for node discovery), Pod watcher (for endpoint tracking).

NetworkPolicy watcher comes in Month 3.

**Step 2: Add client-go dependency**

```bash
go get k8s.io/client-go@latest
go get k8s.io/api@latest
go get k8s.io/apimachinery@latest
```

**Step 3: Write tests with fake clientset**

**Step 4: Commit**

```bash
git add internal/k8s/ go.mod go.sum
git commit -m "feat: implement Kubernetes node and pod watchers"
```

---

### Task 8: Dataplane gRPC Server & Map Management

**Files:**
- Modify: `dataplane/novanet-dataplane/src/main.rs`
- Create: `dataplane/novanet-dataplane/src/server.rs`
- Create: `dataplane/novanet-dataplane/src/maps.rs`
- Create: `dataplane/novanet-dataplane/src/loader.rs`

**Step 1: Implement eBPF program loader**

`loader.rs` — loads compiled eBPF object, returns handles to maps and programs.

**Step 2: Implement map manager**

`maps.rs` — wraps Aya map handles, provides typed insert/delete/get for endpoint, policy, config, tunnel maps.

**Step 3: Implement gRPC server**

`server.rs` — implements `DataplaneControl` service using tonic. Each RPC translates to map operations.

**Step 4: Wire up main.rs**

Load eBPF → create map manager → start gRPC server on Unix socket → wait for signals.

**Step 5: Verify**

```bash
cd dataplane && cargo build --package novanet-dataplane
```

**Step 6: Commit**

```bash
git add dataplane/
git commit -m "feat: implement dataplane gRPC server with eBPF map management"
```

---

### Task 9: Agent ↔ Dataplane Integration

**Files:**
- Create: `internal/dataplane/client.go`
- Create: `internal/dataplane/client_test.go`
- Modify: `cmd/novanet-agent/main.go`

**Step 1: Implement Go gRPC client for dataplane**

```go
package dataplane

type Client struct {
	conn   *grpc.ClientConn
	client pb.DataplaneControlClient
	logger *zap.Logger
}

func NewClient(socketPath string, logger *zap.Logger) (*Client, error) { /* ... */ }
func (c *Client) UpsertEndpoint(ctx context.Context, ep *Endpoint) error { /* ... */ }
func (c *Client) DeleteEndpoint(ctx context.Context, ip uint32) error { /* ... */ }
func (c *Client) AttachProgram(ctx context.Context, iface string, typ AttachType) error { /* ... */ }
func (c *Client) UpdateConfig(ctx context.Context, entries map[uint32]uint64) error { /* ... */ }
```

**Step 2: Wire agent main.go**

On startup:
1. Load config
2. Connect to dataplane via gRPC
3. Set config (mode, tunnel type, node IP)
4. Start Kubernetes watchers
5. Start CNI handler (listens on cni.sock)
6. On pod events: upsert/delete endpoints via dataplane client

**Step 3: Test end-to-end (manual)**

Deploy agent + dataplane on a node, create a pod, verify endpoint appears in eBPF map.

**Step 4: Commit**

```bash
git add internal/dataplane/ cmd/novanet-agent/
git commit -m "feat: integrate agent with dataplane via gRPC client"
```

---

### Task 10: Same-Node Pod-to-Pod Forwarding

**Files:**
- Modify: `dataplane/novanet-ebpf/src/main.rs`
- Create: `internal/cni/netns.go` (veth + netns helpers)

**Step 1: Implement TC forwarding in eBPF**

TC egress on pod veth:
1. Read destination IP from packet
2. Lookup endpoint map
3. If found (local pod): `bpf_redirect` to destination ifindex
4. If not found: pass to kernel stack (for cross-node or external)

TC ingress on pod veth:
1. Pass all traffic (policy enforcement comes in Month 3)

**Step 2: Ensure veth setup creates correct interface pairs**

CNI Add must:
1. Create veth pair (host side: `nova<short-id>`, pod side: `eth0`)
2. Attach TC ingress + egress to host-side veth via dataplane AttachProgram RPC
3. Populate endpoint map with pod IP → ifindex of host-side veth + MAC + identity

**Step 3: Test same-node connectivity**

Two pods on same node should be able to ping each other through eBPF redirect.

**Step 4: Commit**

```bash
git add dataplane/novanet-ebpf/ internal/cni/
git commit -m "feat: implement same-node pod-to-pod forwarding via eBPF TC redirect"
```

---

### Task 11: novanetctl Status Command

**Files:**
- Modify: `cmd/novanetctl/main.go`
- Create: `cmd/novanetctl/status.go`

**Step 1: Implement status command**

Connect to dataplane gRPC → call GetDataplaneStatus → display:
- Mode (overlay/native)
- Tunnel protocol (geneve/vxlan)
- Endpoint count
- Policy count
- Attached programs

Connect to agent gRPC (future) → for now just dataplane status.

**Step 2: Commit**

```bash
git add cmd/novanetctl/
git commit -m "feat: implement novanetctl status command"
```

---

### Task 12: CI Pipeline

**Files:**
- Create: `.github/workflows/ci.yml`

**Step 1: Write CI pipeline matching NovaRoute's pattern**

Jobs:
- **lint**: gofmt, go vet, go mod tidy, cargo clippy
- **test-go**: `go test -v -race -coverprofile=coverage.out ./...`
- **test-rust**: `cargo test --package novanet-dataplane --package novanet-common`
- **build-go**: build all three Go binaries
- **build-rust**: build eBPF + dataplane (requires nightly toolchain + bpf target)
- **security**: govulncheck, cargo audit
- **status-check**: gate job

Note: eBPF build in CI requires `bpfel-unknown-none` target. Use `rustup target add` in CI.

**Step 2: Commit**

```bash
git add .github/
git commit -m "feat: add CI pipeline for Go + Rust builds and tests"
```

---

### Month 1 Deliverable Checklist

- [ ] Go project compiles: agent, CNI binary, CLI
- [ ] Rust workspace compiles: eBPF programs, dataplane binary
- [ ] Config loading + validation with tests
- [ ] IPAM allocator with tests
- [ ] CNI ADD/DEL creates veth pairs and assigns IPs
- [ ] Kubernetes Node + Pod watchers running
- [ ] Agent ↔ Dataplane gRPC communication working
- [ ] eBPF endpoint map populated on pod creation
- [ ] Same-node pod-to-pod ping works via TC redirect
- [ ] `novanetctl status` shows endpoint count
- [ ] CI pipeline green

---

## Month 2: Cross-Node Overlay Networking

### Task 13: Node Registry & Discovery

**Files:**
- Create: `internal/node/registry.go`
- Create: `internal/node/registry_test.go`

Node watcher events feed into a node registry that tracks: node name, node IP, PodCIDR, health state. Registry changes trigger tunnel creation/teardown.

---

### Task 14: Geneve Tunnel Management

**Files:**
- Create: `internal/tunnel/manager.go`
- Create: `internal/tunnel/geneve.go`
- Create: `internal/tunnel/manager_test.go`

Tunnel manager creates/deletes Geneve interfaces via netlink:
- One Geneve tunnel per remote node
- `ip link add geneve<N> type geneve id <VNI> remote <nodeIP> dstport 6081`
- Attach TC ingress + egress to tunnel interface
- Update tunnel eBPF map: remote node IP → tunnel ifindex

---

### Task 15: VXLAN Tunnel Support

**Files:**
- Create: `internal/tunnel/vxlan.go`

Same as Geneve but using VXLAN:
- `ip link add vxlan<N> type vxlan id <VNI> remote <nodeIP> dstport 4789`
- No TLV support — identity via endpoint map lookup

Tunnel manager selects implementation based on `tunnel_protocol` config.

---

### Task 16: TC Encap/Decap Programs

**Files:**
- Modify: `dataplane/novanet-ebpf/src/main.rs`
- Create: `dataplane/novanet-ebpf/src/encap.rs`
- Create: `dataplane/novanet-ebpf/src/decap.rs`

TC egress on pod veth (cross-node path):
1. Destination IP not in local endpoint map
2. Lookup tunnel map for destination node
3. Geneve: encapsulate with identity TLV in option header
4. VXLAN: encapsulate (no identity metadata)
5. Redirect to tunnel interface

TC ingress on tunnel interface:
1. Geneve: decapsulate, extract identity from TLV
2. VXLAN: decapsulate, lookup source IP in endpoint map for identity
3. Forward to destination pod veth

---

### Task 17: Tunnel Map & Cross-Node E2E

**Files:**
- Modify: `dataplane/novanet-common/src/lib.rs` (add TunnelKey/TunnelValue)

Add tunnel map types. Agent populates tunnel map when nodes join. End-to-end test: pod on node A pings pod on node B over Geneve tunnel.

---

### Month 2 Deliverable Checklist

- [ ] Geneve tunnels created automatically when nodes join
- [ ] VXLAN tunnels work with config flag switch
- [ ] TC encap/decap working for cross-node traffic
- [ ] Identity carried in Geneve TLV header
- [ ] Cross-node pod-to-pod ping works
- [ ] `novanetctl tunnels` shows active tunnels
- [ ] Multi-node e2e tests passing

---

## Month 3: Identity-Based L3/L4 Policy

### Task 18: Identity Allocator

**Files:**
- Create: `internal/identity/allocator.go`
- Create: `internal/identity/allocator_test.go`

Label set → deterministic 32-bit identity ID via hash. Pods with identical security-relevant labels share identity. Identity assigned at CNI ADD, written to endpoint map.

---

### Task 19: NetworkPolicy Watcher & Compiler

**Files:**
- Create: `internal/policy/watcher.go`
- Create: `internal/policy/compiler.go`
- Create: `internal/policy/compiler_test.go`

Watch Kubernetes NetworkPolicy objects. Compile each policy into identity-based rules:
- Resolve podSelector → identity ID
- Resolve namespaceSelector → set of identity IDs
- Generate (src_id, dst_id, proto, port) → ALLOW entries
- Handle default deny (when any policy selects a pod)

Compiler outputs a full policy map that is synced to dataplane via `SyncPolicies` RPC.

---

### Task 20: TC Policy Enforcement

**Files:**
- Modify: `dataplane/novanet-ebpf/src/main.rs`

TC ingress: after identity resolution → lookup policy map → allow or drop.
TC egress: lookup egress policy map → allow or drop.
Store drop reason in per-CPU array map for observability.

---

### Task 21: Policy Conformance Tests

Run upstream Kubernetes NetworkPolicy conformance test suite. Fix any gaps.

---

### Month 3 Deliverable Checklist

- [ ] Identity allocator with deterministic hashing
- [ ] NetworkPolicy watcher and compiler
- [ ] Policy map synced to eBPF
- [ ] TC ingress/egress enforce policy
- [ ] Drop reason codes tracked
- [ ] `novanetctl policy` shows compiled rules
- [ ] `novanetctl identity` shows mappings
- [ ] NetworkPolicy conformance tests passing

---

## Month 4: Native Routing & Egress Control

### Task 22: NovaRoute gRPC Client

**Files:**
- Create: `internal/novaroute/client.go`
- Create: `internal/novaroute/client_test.go`

gRPC client connecting to `/run/novaroute/novaroute.sock`. Implements:
- `Register` as owner `"novanet"` with token auth
- `AdvertisePrefix` for PodCIDR (BGP or OSPF via protocol field)
- `WithdrawPrefix` on shutdown
- `StreamEvents` for routing state visibility
- Retry loop with backoff (match NovaRoute's FRR client pattern)

---

### Task 23: Native Routing Mode

**Files:**
- Modify: `cmd/novanet-agent/main.go`
- Create: `internal/routing/mode.go`

When `routing_mode: native`:
- Skip tunnel manager entirely
- Start NovaRoute client instead
- Advertise PodCIDR on startup
- TC programs skip encap/decap (read config map flag)
- Identity resolved via endpoint map lookup only

---

### Task 24: SNAT / Masquerade

**Files:**
- Modify: `dataplane/novanet-ebpf/src/main.rs`
- Create: `internal/egress/manager.go`

TC egress: if destination is not in endpoint map and not in cluster CIDR → SNAT source IP to node IP (masquerade). Configurable per namespace.

---

### Task 25: Egress Policy

**Files:**
- Create: `internal/egress/policy.go`
- Modify: `dataplane/novanet-common/src/lib.rs` (add EgressPolicyKey/Value)

Egress policy map: (src_identity, dst_cidr, proto, port) → ALLOW | DENY | SNAT.
Agent compiles namespace-level egress rules into this map.

---

### Month 4 Deliverable Checklist

- [ ] NovaRoute client connects and registers
- [ ] PodCIDR advertised via BGP (through NovaRoute)
- [ ] OSPF advertisement works
- [ ] Native routing mode: no tunnels, packets routed by underlay
- [ ] SNAT/masquerade for pod → external traffic
- [ ] Namespace egress policies enforced
- [ ] `novanetctl egress` shows rules and counters

---

## Month 5: Observability & CLI Tooling

### Task 26: Ring Buffer Flow Export

**Files:**
- Modify: `dataplane/novanet-ebpf/src/main.rs` (add ring buffer writes)
- Modify: `dataplane/novanet-dataplane/src/main.rs` (add ring buffer reader)

eBPF programs write flow events to BPF ring buffer on policy decisions. Rust dataplane reads ring buffer, exposes via `StreamFlows` gRPC.

---

### Task 27: Prometheus Metrics

**Files:**
- Create: `internal/metrics/metrics.go`

Match NovaRoute's metrics pattern. Expose:
- `novanet_endpoint_count` (gauge)
- `novanet_policy_count` (gauge)
- `novanet_flow_total` (counter, labels: src_identity, dst_identity, verdict)
- `novanet_drops_total` (counter, labels: reason)
- `novanet_policy_verdict_total` (counter, labels: action)
- `novanet_tunnel_count` (gauge)
- `novanet_latency_seconds` (histogram)

---

### Task 28: CLI Flow & Drop Inspection

**Files:**
- Create: `cmd/novanetctl/flows.go`
- Create: `cmd/novanetctl/drops.go`

`novanetctl flows` — connects to dataplane StreamFlows, displays real-time flow table.
`novanetctl drops` — filters flow stream for denied verdicts, shows drop reason.

---

### Task 29: TCP Metrics & Latency Histograms

**Files:**
- Modify: `dataplane/novanet-ebpf/src/main.rs` (add timestamp tracking)
- Modify: `internal/metrics/metrics.go` (add latency histograms)

Optional TCP state tracking via eBPF: SYN/FIN/RST counts, retransmits. Per-flow latency measured at TC hook timestamps. Exposed as Prometheus histograms.

---

### Task 30: Full novanetctl CLI

**Files:**
- Create: `cmd/novanetctl/tunnels.go`
- Create: `cmd/novanetctl/policy.go`
- Create: `cmd/novanetctl/identity.go`
- Create: `cmd/novanetctl/egress.go`
- Create: `cmd/novanetctl/metrics.go`

Complete the CLI with all inspection commands:
- `novanetctl tunnels` — tunnel state (overlay mode)
- `novanetctl policy` — compiled policy rules
- `novanetctl identity` — pod → identity mappings
- `novanetctl egress` — egress rules and counters
- `novanetctl metrics` — summary statistics

---

### Month 5 Deliverable Checklist

- [ ] Flow events exported via ring buffer
- [ ] Prometheus metrics endpoint working
- [ ] `novanetctl flows` shows real-time traffic
- [ ] `novanetctl drops` shows drops with reasons
- [ ] Latency histograms and TCP metrics available
- [ ] Full CLI tool with all subcommands
- [ ] Grafana dashboard template

---

## Month 6: Hardening & Production Readiness

### Task 31: Integration Test Framework

**Files:**
- Create: `tests/integration/` (Go test files using Kind or k3s)

Multi-node Kind cluster in CI:
- Deploy NovaNet DaemonSet
- Create pods, verify connectivity (same-node, cross-node)
- Apply NetworkPolicy, verify enforcement
- Test overlay and native modes

---

### Task 32: Performance Benchmarks

**Files:**
- Create: `tests/benchmark/` (scripts using iperf3, netperf)

Benchmark:
- iperf3 throughput: overlay vs native vs vanilla
- netperf latency: pod-to-pod, pod-to-service
- Policy lookup overhead: with/without policies loaded

---

### Task 33: Graceful Lifecycle

**Files:**
- Modify: `cmd/novanet-agent/main.go`
- Modify: `dataplane/novanet-dataplane/src/main.rs`

- eBPF programs pinned to `/sys/fs/bpf/novanet/` — survive agent/dataplane restarts
- Agent restart: reconnects to dataplane, re-syncs state from Kubernetes
- Dataplane restart: re-attaches to pinned programs, no traffic interruption
- CNI binary: stateless, always queries agent

---

### Task 34: Helm Chart

**Files:**
- Create: `deploy/helm/novanet/Chart.yaml`
- Create: `deploy/helm/novanet/values.yaml`
- Create: `deploy/helm/novanet/templates/daemonset.yaml`
- Create: `deploy/helm/novanet/templates/configmap.yaml`
- Create: `deploy/helm/novanet/templates/rbac.yaml`

Configurable values:
- `tunnelProtocol: geneve | vxlan`
- `routingMode: overlay | native`
- `novaroute.enabled: true | false`
- `novaroute.token: "..."`
- `metrics.enabled: true`
- `image.tag: latest`

---

### Task 35: Dockerfiles & Release Pipeline

**Files:**
- Create: `Dockerfile` (multi-stage: Go build + Rust build → minimal runtime)
- Create: `.github/workflows/release.yml`

Multi-arch (amd64, arm64). Publish to `ghcr.io/azrtydxb/novanet/novanet-agent` and `ghcr.io/azrtydxb/novanet/novanet-dataplane`.

---

### Task 36: Documentation

**Files:**
- Create: `docs/architecture.md`
- Create: `docs/installation.md`
- Create: `docs/configuration.md`
- Create: `docs/troubleshooting.md`
- Create: `docs/novaroute-integration.md`

---

### Month 6 Deliverable Checklist

- [ ] Integration tests passing in CI (multi-node Kind)
- [ ] Performance benchmarks published
- [ ] Graceful restart: zero traffic disruption
- [ ] Helm chart installable in < 5 minutes
- [ ] Multi-arch Docker images building
- [ ] Release pipeline automated
- [ ] Documentation complete
- [ ] v1.0 release tagged

---

## Repository Structure (Final)

```
novanet/
├── .github/workflows/
│   ├── ci.yml
│   └── release.yml
├── api/v1/
│   ├── novanet.proto
│   ├── novanet.pb.go
│   └── novanet_grpc.pb.go
├── cmd/
│   ├── novanet-agent/main.go
│   ├── novanet-cni/main.go
│   └── novanetctl/
│       ├── main.go
│       ├── status.go
│       ├── flows.go
│       └── drops.go
├── dataplane/
│   ├── Cargo.toml
│   ├── rust-toolchain.toml
│   ├── novanet-common/src/lib.rs
│   ├── novanet-ebpf/src/main.rs
│   └── novanet-dataplane/
│       ├── src/main.rs
│       ├── src/server.rs
│       ├── src/maps.rs
│       ├── src/loader.rs
│       └── build.rs
├── internal/
│   ├── cni/
│   ├── config/
│   ├── dataplane/
│   ├── egress/
│   ├── identity/
│   ├── ipam/
│   ├── k8s/
│   ├── metrics/
│   ├── node/
│   ├── novaroute/
│   ├── policy/
│   ├── routing/
│   └── tunnel/
├── deploy/
│   └── helm/novanet/
├── tests/
│   ├── integration/
│   └── benchmark/
├── docs/
│   ├── plans/
│   ├── architecture.md
│   ├── installation.md
│   ├── configuration.md
│   └── troubleshooting.md
├── Dockerfile
├── Makefile
├── LICENSE
└── README.md
```
