# eBPF Services API Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a gRPC eBPF Services API to NovaNet so external consumers (NovaEdge) can request kernel-level eBPF services without loading their own programs.

**Architecture:** New `EBPFServices` gRPC service on `/run/novanet/ebpf-services.sock`, backed by 4 new eBPF program types (SOCKMAP, SK_LOOKUP, rate limiting, health monitoring) managed through the existing Rust dataplane MapManager pattern.

**Tech Stack:** Go 1.26+, Rust (aya 0.13), protobuf/gRPC (tonic 0.12), eBPF (SOCK_OPS, SK_MSG, SK_LOOKUP, TC extensions)

**Design Doc:** `docs/plans/2026-03-09-ebpf-services-api-design.md`

---

## Phase 1: Proto & Go gRPC Scaffolding

### Task 1: Add EBPFServices proto definition

**Files:**
- Create: `api/v1/ebpf_services.proto`

**Step 1: Write the proto file**

Create `api/v1/ebpf_services.proto` with the full service definition from the design doc. Use `package novanet.ebpfservices.v1;` and `go_package = "github.com/azrtydxb/novanet/api/v1/ebpfservices";`.

Include all 11 RPCs and message types:
- SOCKMAP: EnableSockmap, DisableSockmap, GetSockmapStats
- Mesh: AddMeshRedirect, RemoveMeshRedirect, ListMeshRedirects
- Rate limit: ConfigureRateLimit, RemoveRateLimit, GetRateLimitStats
- Health: GetBackendHealth, StreamBackendHealth

**Step 2: Generate Go code**

Run: `protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative api/v1/ebpf_services.proto`

Verify generated files exist:
- `api/v1/ebpfservices/ebpf_services.pb.go`
- `api/v1/ebpfservices/ebpf_services_grpc.pb.go`

**Step 3: Commit**

```bash
git add api/v1/ebpf_services.proto api/v1/ebpfservices/
git commit -m "proto: add EBPFServices gRPC service definition"
```

---

### Task 2: Implement Go gRPC server scaffold

**Files:**
- Create: `internal/ebpfservices/server.go`
- Create: `internal/ebpfservices/server_test.go`

**Step 1: Write the test**

Create `internal/ebpfservices/server_test.go`:
- Test that `NewServer()` returns a non-nil server
- Test that the server implements the `EBPFServicesServer` interface
- Test that each RPC method returns `codes.Unimplemented` initially (scaffold)

Use the project's test pattern:
```go
package ebpfservices

import (
    "context"
    "testing"
    pb "github.com/azrtydxb/novanet/api/v1/ebpfservices"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

func TestNewServer(t *testing.T) {
    s := NewServer(testLogger())
    if s == nil {
        t.Fatal("expected non-nil server")
    }
}
```

**Step 2: Run test, verify it fails**

Run: `go test -race -count=1 ./internal/ebpfservices/`
Expected: FAIL (NewServer not defined)

**Step 3: Write the server scaffold**

Create `internal/ebpfservices/server.go`:
```go
package ebpfservices

import (
    "context"
    pb "github.com/azrtydxb/novanet/api/v1/ebpfservices"
    "go.uber.org/zap"
    "google.golang.org/grpc/codes"
    "google.golang.org/grpc/status"
)

type Server struct {
    pb.UnimplementedEBPFServicesServer
    logger *zap.Logger
}

func NewServer(logger *zap.Logger) *Server {
    return &Server{logger: logger}
}
```

All RPC methods return `status.Errorf(codes.Unimplemented, "not implemented")` initially.

**Step 4: Run test, verify it passes**

Run: `go test -race -count=1 ./internal/ebpfservices/`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/ebpfservices/
git commit -m "feat: add EBPFServices gRPC server scaffold"
```

---

### Task 3: Wire gRPC server into agent startup

**Files:**
- Modify: `cmd/novanet-agent/main.go`
- Modify: `internal/config/config.go` (add `ebpf_services` config fields)
- Modify: `deploy/helm/novanet/templates/configmap.yaml` (add socket path)
- Modify: `deploy/helm/novanet/values.yaml` (add `ebpfServices` section)

**Step 1: Add config fields**

Add to the config struct:
```go
type EBPFServicesConfig struct {
    Enabled    bool   `json:"enabled"`
    SocketPath string `json:"socket_path"`
}
```

Default: `enabled: true`, `socket_path: "/run/novanet/ebpf-services.sock"`

**Step 2: Start gRPC listener in main.go**

In the agent startup flow, after the existing gRPC servers:
- Create `ebpfservices.NewServer(logger)`
- Listen on the configured Unix socket path
- Register with a new `grpc.Server`
- Add graceful shutdown

**Step 3: Add Helm values**

```yaml
ebpfServices:
  enabled: true
  socketPath: "/run/novanet/ebpf-services.sock"
```

**Step 4: Run tests and lint**

Run: `make test-go && make lint-go`
Expected: PASS

**Step 5: Commit**

```bash
git add cmd/novanet-agent/main.go internal/config/ deploy/helm/
git commit -m "feat: wire EBPFServices gRPC server into agent startup"
```

---

## Phase 2: Rust Dataplane — New Maps & Programs

### Task 4: Add new map types to novanet-common

**Files:**
- Modify: `dataplane/novanet-common/src/lib.rs`

**Step 1: Write tests for new types**

Add tests at the bottom of `lib.rs` verifying size and alignment of new types:
```rust
#[test]
fn test_sock_key_size() {
    assert_eq!(core::mem::size_of::<SockKey>(), 20);
}
#[test]
fn test_mesh_service_key_size() {
    assert_eq!(core::mem::size_of::<MeshServiceKey>(), 8);
}
// ... for all new types
```

**Step 2: Run tests, verify they fail**

Run: `cd dataplane && cargo test --package novanet-common`
Expected: FAIL (types not defined)

**Step 3: Add the types**

Add `#[repr(C)]` structs with `unsafe impl Pod`:
- `SockKey` (src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, family: u32) — 20 bytes
- `MeshServiceKey` (ip: u32, port: u32) — 8 bytes
- `MeshRedirectValue` (redirect_port: u32) — 4 bytes
- `RateLimitKey` (addr: [u8; 16]) — 16 bytes (IPv4-mapped IPv6)
- `TokenBucketState` (tokens: u64, last_refill_ns: u64) — 16 bytes
- `RateLimitConfig` (rate: u32, burst: u32, window_ns: u64) — 16 bytes
- `BackendHealthKey` (ip: u32, port: u32) — 8 bytes
- `BackendHealthCounters` (total_conns: u64, failed_conns: u64, timeout_conns: u64, success_conns: u64, last_success_ns: u64, last_failure_ns: u64, total_rtt_ns: u64) — 56 bytes

**Step 4: Run tests, verify they pass**

Run: `cd dataplane && cargo test --package novanet-common`
Expected: PASS

**Step 5: Commit**

```bash
git add dataplane/novanet-common/
git commit -m "feat: add SOCKMAP, mesh redirect, rate limit, health map types"
```

---

### Task 5: Add new maps to MapManager

**Files:**
- Modify: `dataplane/novanet-dataplane/src/maps.rs`

**Step 1: Write tests**

Add tests to `maps.rs` verifying new map operations on MockMaps:
```rust
#[test]
fn test_mesh_service_upsert_delete() {
    let mgr = MapManager::new_mock();
    let key = MeshServiceKey { ip: 0x0A2A0105, port: 8080 };
    let val = MeshRedirectValue { redirect_port: 15001 };
    mgr.upsert_mesh_service(key, val).unwrap();
    mgr.delete_mesh_service(key).unwrap();
}
```

Write similar tests for: sockmap_endpoint, rate_limit_config, backend_health operations.

**Step 2: Run tests, verify they fail**

Run: `cd dataplane && cargo test --package novanet-dataplane`
Expected: FAIL

**Step 3: Implement MockMaps and RealMaps**

Follow the existing pattern in `maps.rs`:
- Add fields to `MockMaps` struct (RwLock<HashMap<...>> for each new map)
- Add fields to `RealMaps` struct (aya HashMap/Array/PerCpuHashMap handles)
- Add methods to `MapManager` that dispatch to Mock/Real via match
- New methods: `upsert_mesh_service`, `delete_mesh_service`, `list_mesh_services`, `upsert_sockmap_endpoint`, `delete_sockmap_endpoint`, `get_sockmap_stats`, `update_rate_limit_config`, `get_rate_limit_stats`, `get_backend_health`, `get_all_backend_health`

**Step 4: Run tests, verify they pass**

Run: `cd dataplane && cargo test --package novanet-dataplane`
Expected: PASS

**Step 5: Commit**

```bash
git add dataplane/novanet-dataplane/src/maps.rs
git commit -m "feat: add SOCKMAP, mesh, rate limit, health maps to MapManager"
```

---

### Task 6: Add new gRPC RPCs to DataplaneControl proto

**Files:**
- Modify: `api/v1/novanet.proto`

**Step 1: Add new RPCs to DataplaneControl service**

These are internal RPCs between Go agent and Rust dataplane (separate from the external EBPFServices API). Add:

```protobuf
// SOCKMAP
rpc UpsertSockmapEndpoint(UpsertSockmapEndpointRequest) returns (UpsertSockmapEndpointResponse);
rpc DeleteSockmapEndpoint(DeleteSockmapEndpointRequest) returns (DeleteSockmapEndpointResponse);
rpc GetSockmapStats(GetSockmapStatsRequest) returns (GetSockmapStatsResponse);

// Mesh redirect
rpc UpsertMeshService(UpsertMeshServiceRequest) returns (UpsertMeshServiceResponse);
rpc DeleteMeshService(DeleteMeshServiceRequest) returns (DeleteMeshServiceResponse);
rpc ListMeshServices(ListMeshServicesRequest) returns (ListMeshServicesResponse);

// Rate limiting
rpc UpdateRateLimitConfig(UpdateRateLimitConfigRequest) returns (UpdateRateLimitConfigResponse);
rpc GetRateLimitStats(GetInternalRateLimitStatsRequest) returns (GetInternalRateLimitStatsResponse);

// Health monitoring
rpc GetBackendHealthStats(GetBackendHealthStatsRequest) returns (GetBackendHealthStatsResponse);
```

Add corresponding message types.

**Step 2: Regenerate Go and rebuild Rust proto**

Run: `make proto`
Verify: `go build ./...` passes

**Step 3: Commit**

```bash
git add api/v1/novanet.proto api/v1/*.pb.go
git commit -m "proto: add SOCKMAP, mesh, rate limit, health RPCs to DataplaneControl"
```

---

### Task 7: Implement Rust gRPC handlers for new RPCs

**Files:**
- Modify: `dataplane/novanet-dataplane/src/server.rs`

**Step 1: Implement handlers**

Follow the existing pattern in `server.rs`. Each handler:
1. Parse request fields
2. Call MapManager method
3. Return response or error

Example for `upsert_mesh_service`:
```rust
async fn upsert_mesh_service(
    &self,
    request: Request<UpsertMeshServiceRequest>,
) -> Result<Response<UpsertMeshServiceResponse>, Status> {
    let req = request.into_inner();
    let ip = parse_ip(&req.ip)?;
    let key = MeshServiceKey {
        ip: match ip { IpAddr::V4(v4) => u32::from(v4), _ => return Err(Status::invalid_argument("IPv6 not yet supported")) },
        port: req.port,
    };
    let val = MeshRedirectValue { redirect_port: req.redirect_port };
    self.maps.upsert_mesh_service(key, val)
        .map_err(|e| Status::internal(format!("map update failed: {e}")))?;
    Ok(Response::new(UpsertMeshServiceResponse {}))
}
```

Implement all 9 new handlers following this pattern.

**Step 2: Build and test**

Run: `cd dataplane && cargo build --package novanet-dataplane && cargo test --package novanet-dataplane`
Expected: PASS

**Step 3: Commit**

```bash
git add dataplane/novanet-dataplane/src/server.rs
git commit -m "feat: implement gRPC handlers for SOCKMAP, mesh, rate limit, health"
```

---

### Task 8: Add Go dataplane client methods

**Files:**
- Modify: `internal/dataplane/client.go`
- Create: `internal/dataplane/client_ebpfservices_test.go`

**Step 1: Write tests**

Test the new client methods using a mock gRPC server or by verifying method signatures compile.

**Step 2: Add client methods**

Follow the existing pattern in `client.go`. Add methods that wrap the new DataplaneControl RPCs:
```go
func (c *Client) UpsertSockmapEndpoint(ctx context.Context, ip string, port uint32) error
func (c *Client) DeleteSockmapEndpoint(ctx context.Context, ip string, port uint32) error
func (c *Client) GetSockmapStats(ctx context.Context) (redirected, fallback uint64, active uint32, err error)
func (c *Client) UpsertMeshService(ctx context.Context, ip string, port, redirectPort uint32) error
func (c *Client) DeleteMeshService(ctx context.Context, ip string, port uint32) error
func (c *Client) ListMeshServices(ctx context.Context) ([]MeshServiceEntry, error)
func (c *Client) UpdateRateLimitConfig(ctx context.Context, rate, burst uint32) error
func (c *Client) GetRateLimitStats(ctx context.Context) (allowed, denied uint64, err error)
func (c *Client) GetBackendHealthStats(ctx context.Context, ip string, port uint32) (*BackendHealthInfo, error)
```

**Step 3: Run tests**

Run: `go test -race -count=1 ./internal/dataplane/`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/dataplane/
git commit -m "feat: add Go dataplane client methods for eBPF services"
```

---

## Phase 3: Implement EBPFServices Server Logic

### Task 9: Implement SOCKMAP RPCs

**Files:**
- Modify: `internal/ebpfservices/server.go`
- Create: `internal/ebpfservices/sockmap.go`
- Modify: `internal/ebpfservices/server_test.go`

**Step 1: Write tests**

Test EnableSockmap:
- Call with valid pod namespace/name → server resolves pod IP from endpoint store → calls dataplane client → returns success
- Call with unknown pod → returns NotFound error

Test DisableSockmap:
- Call for enabled pod → removes from dataplane → returns success

Test GetSockmapStats:
- Returns aggregated stats from dataplane

**Step 2: Run tests, verify they fail**

**Step 3: Implement**

`sockmap.go` contains the logic:
- `EnableSockmap`: Look up pod in the agent's endpoint store (by namespace/name), get IP/port, call `dataplaneClient.UpsertSockmapEndpoint()`
- `DisableSockmap`: Reverse lookup, call `dataplaneClient.DeleteSockmapEndpoint()`
- `GetSockmapStats`: Call `dataplaneClient.GetSockmapStats()`, return as proto

The Server struct needs a reference to the endpoint store and dataplane client:
```go
type Server struct {
    pb.UnimplementedEBPFServicesServer
    logger    *zap.Logger
    dataplane dataplane.ClientInterface
    endpoints EndpointStore // interface for pod IP lookup
}
```

**Step 4: Run tests, verify they pass**

**Step 5: Commit**

```bash
git add internal/ebpfservices/
git commit -m "feat: implement SOCKMAP enable/disable/stats RPCs"
```

---

### Task 10: Implement mesh redirect RPCs

**Files:**
- Create: `internal/ebpfservices/mesh.go`
- Modify: `internal/ebpfservices/server_test.go`

**Step 1: Write tests**

- AddMeshRedirect with valid IP/port → calls dataplane → success
- AddMeshRedirect with invalid IP → InvalidArgument error
- RemoveMeshRedirect → calls dataplane → success
- ListMeshRedirects → returns all entries from dataplane

**Step 2: Run tests, verify they fail**

**Step 3: Implement**

`mesh.go`:
- `AddMeshRedirect`: Validate IP, call `dataplaneClient.UpsertMeshService(ip, port, redirectPort)`
- `RemoveMeshRedirect`: Call `dataplaneClient.DeleteMeshService(ip, port)`
- `ListMeshRedirects`: Call `dataplaneClient.ListMeshServices()`, convert to proto

**Step 4: Run tests, verify they pass**

**Step 5: Commit**

```bash
git add internal/ebpfservices/
git commit -m "feat: implement mesh redirect RPCs"
```

---

### Task 11: Implement rate limiting RPCs

**Files:**
- Create: `internal/ebpfservices/ratelimit.go`
- Modify: `internal/ebpfservices/server_test.go`

**Step 1: Write tests**

- ConfigureRateLimit with valid CIDR/rate/burst → success
- ConfigureRateLimit with invalid CIDR → InvalidArgument
- RemoveRateLimit → success
- GetRateLimitStats → returns allowed/denied counts

**Step 2: Run tests, verify they fail**

**Step 3: Implement**

`ratelimit.go`:
- `ConfigureRateLimit`: Parse CIDR, call `dataplaneClient.UpdateRateLimitConfig()`
- `RemoveRateLimit`: Call dataplane to clear config for CIDR
- `GetRateLimitStats`: Call `dataplaneClient.GetRateLimitStats()`, return as proto

**Step 4: Run tests, verify they pass**

**Step 5: Commit**

```bash
git add internal/ebpfservices/
git commit -m "feat: implement rate limiting RPCs"
```

---

### Task 12: Implement health monitoring RPCs

**Files:**
- Create: `internal/ebpfservices/health.go`
- Modify: `internal/ebpfservices/server_test.go`

**Step 1: Write tests**

- GetBackendHealth with specific IP/port → returns health counters
- GetBackendHealth with empty IP → returns all backends
- StreamBackendHealth → returns periodic events

**Step 2: Run tests, verify they fail**

**Step 3: Implement**

`health.go`:
- `GetBackendHealth`: Call `dataplaneClient.GetBackendHealthStats()`, aggregate per-CPU counters, calculate failure rate and avg RTT
- `StreamBackendHealth`: Start polling loop at requested interval, send events on stream

**Step 4: Run tests, verify they pass**

**Step 5: Commit**

```bash
git add internal/ebpfservices/
git commit -m "feat: implement health monitoring RPCs"
```

---

## Phase 4: eBPF Programs (Rust/Kernel)

### Task 13: Write SOCKMAP eBPF programs

**Files:**
- Modify: `dataplane/novanet-ebpf/src/main.rs`

**Step 1: Add map declarations**

```rust
#[map]
static SOCK_HASH: SockHash<SockKey> = SockHash::with_max_entries(65536, 0);

#[map]
static SOCKMAP_ENDPOINTS: HashMap<EndpointKey, u32> = HashMap::with_max_entries(4096, 0);

#[map]
static SOCKMAP_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);
```

**Step 2: Write sockops_sockmap program**

```rust
#[sock_ops]
pub fn sockops_sockmap(ctx: SockOpsContext) -> u32 {
    // On BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB and BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    // 1. Check if both src and dst IP are in SOCKMAP_ENDPOINTS
    // 2. If yes, insert socket into SOCK_HASH
    // 3. Increment stats counter
}
```

**Step 3: Write sk_msg_sockmap program**

```rust
#[sk_msg]
pub fn sk_msg_sockmap(ctx: SkMsgContext) -> u32 {
    // Build reverse key (swap src/dst)
    // bpf_msg_redirect_hash to SOCK_HASH
    // Increment redirect counter on success, fallback counter on failure
}
```

**Step 4: Build**

Run: `make build-ebpf-native` (on Linux) or `make build-docker-rust` (on macOS)
Expected: Compiles without errors

**Step 5: Commit**

```bash
git add dataplane/novanet-ebpf/
git commit -m "feat: add SOCKMAP eBPF programs (sock_ops + sk_msg)"
```

---

### Task 14: Write SK_LOOKUP mesh redirect eBPF program

**Files:**
- Modify: `dataplane/novanet-ebpf/src/main.rs`

**Step 1: Add map declarations**

```rust
#[map]
static MESH_SERVICES: HashMap<MeshServiceKey, MeshRedirectValue> = HashMap::with_max_entries(4096, 0);
```

**Step 2: Write sk_lookup_mesh program**

```rust
#[sk_lookup]
pub fn sk_lookup_mesh(ctx: SkLookupContext) -> u32 {
    // 1. Extract destination IP and port from context
    // 2. Look up in MESH_SERVICES map
    // 3. If found, redirect to the redirect_port
    // 4. If not found, let kernel handle normally
}
```

Note: SK_LOOKUP redirect uses `bpf_sk_assign()` to redirect to a listening socket on the redirect port. The program needs access to the socket via a SOCKMAP or by looking up the listening socket.

**Step 3: Build**

Run: `make build-docker-rust`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add dataplane/novanet-ebpf/
git commit -m "feat: add SK_LOOKUP mesh redirect eBPF program"
```

---

### Task 15: Add rate limiting to tc_ingress

**Files:**
- Modify: `dataplane/novanet-ebpf/src/main.rs`

**Step 1: Add map declarations**

```rust
#[map]
static RL_TOKENS: LruPerCpuHashMap<RateLimitKey, TokenBucketState> =
    LruPerCpuHashMap::with_max_entries(100000, 0);

#[map]
static RL_CONFIG: Array<RateLimitConfig> = Array::with_max_entries(1, 0);
```

**Step 2: Add rate limit check to tc_ingress**

In the existing `tc_ingress` function, before policy evaluation:
```rust
// Rate limiting check
if let Some(config) = unsafe { RL_CONFIG.get(0) } {
    if config.rate > 0 {
        let src_key = RateLimitKey { addr: ipv4_to_mapped_v6(src_ip) };
        if !check_rate_limit(&src_key, config) {
            increment_drop_counter(DROP_REASON_RATE_LIMITED);
            return TC_ACT_SHOT;
        }
    }
}
```

Write `check_rate_limit()` helper that implements token bucket:
- Look up `RL_TOKENS` for source IP
- If not found, create entry with full bucket
- Check if enough time has passed to refill tokens
- Consume one token or deny

**Step 3: Build**

Run: `make build-docker-rust`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add dataplane/novanet-ebpf/
git commit -m "feat: add per-source-IP rate limiting to tc_ingress"
```

---

### Task 16: Add passive health monitoring to tc_ingress

**Files:**
- Modify: `dataplane/novanet-ebpf/src/main.rs`

**Step 1: Add map declaration**

```rust
#[map]
static BACKEND_HEALTH: PerCpuHashMap<BackendHealthKey, BackendHealthCounters> =
    PerCpuHashMap::with_max_entries(4096, 0);
```

**Step 2: Add health tracking to tc_ingress**

After the existing packet processing in `tc_ingress`, add TCP event tracking:
```rust
// Passive health monitoring
if protocol == IPPROTO_TCP {
    let health_key = BackendHealthKey { ip: dst_ip, port: dst_port };
    if let Some(counters) = unsafe { BACKEND_HEALTH.get_ptr_mut(&health_key) } {
        let now = unsafe { bpf_ktime_get_ns() };
        if tcp_flags & TCP_SYN != 0 && tcp_flags & TCP_ACK == 0 {
            (*counters).total_conns += 1;
        } else if tcp_flags & TCP_RST != 0 {
            (*counters).failed_conns += 1;
            (*counters).last_failure_ns = now;
        } else if tcp_flags & TCP_SYN != 0 && tcp_flags & TCP_ACK != 0 {
            (*counters).success_conns += 1;
            (*counters).last_success_ns = now;
        }
    }
}
```

**Step 3: Build**

Run: `make build-docker-rust`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add dataplane/novanet-ebpf/
git commit -m "feat: add passive TCP health monitoring to tc_ingress"
```

---

## Phase 5: Map Extraction & Program Attachment

### Task 17: Load new maps in Rust loader

**Files:**
- Modify: `dataplane/novanet-dataplane/src/loader.rs`

**Step 1: Extract new map handles in load_ebpf()**

Follow the existing pattern for extracting maps from the loaded eBPF object:
```rust
let sock_hash = ebpf.take_map("SOCK_HASH")...;
let sockmap_endpoints = ebpf.take_map("SOCKMAP_ENDPOINTS")...;
let mesh_services = ebpf.take_map("MESH_SERVICES")...;
let rl_tokens = ebpf.take_map("RL_TOKENS")...;
let rl_config = ebpf.take_map("RL_CONFIG")...;
let backend_health = ebpf.take_map("BACKEND_HEALTH")...;
let sockmap_stats = ebpf.take_map("SOCKMAP_STATS")...;
```

Add new fields to `RealMaps` struct. Pass them to `MapManager::new_real()`.

**Step 2: Add program attachment methods**

Add methods to attach SOCKMAP and SK_LOOKUP programs:
```rust
pub fn attach_sockops(&self, cgroup_path: &str) -> anyhow::Result<()>
pub fn attach_sk_msg(&self) -> anyhow::Result<()>
pub fn attach_sk_lookup(&self, netns_path: &str) -> anyhow::Result<()>
```

These are called from the gRPC server when the programs need to be activated.

**Step 3: Build and test**

Run: `cd dataplane && cargo build --package novanet-dataplane && cargo test --package novanet-dataplane`
Expected: PASS

**Step 4: Commit**

```bash
git add dataplane/novanet-dataplane/src/loader.rs dataplane/novanet-dataplane/src/maps.rs
git commit -m "feat: load and attach SOCKMAP, SK_LOOKUP, rate limit, health maps"
```

---

## Phase 6: Integration & Helm

### Task 18: Add novanetctl commands for eBPF services

**Files:**
- Create: `cmd/novanetctl/ebpfservices.go`

**Step 1: Add CLI commands**

Add subcommands under `novanetctl ebpf`:
- `novanetctl ebpf sockmap status` — show SOCKMAP stats
- `novanetctl ebpf mesh list` — list mesh redirect entries
- `novanetctl ebpf ratelimit stats` — show rate limit stats
- `novanetctl ebpf health list` — show backend health

These call the agent's existing AgentControl service, which needs new RPCs forwarding to the EBPFServices server internally.

**Step 2: Build and test**

Run: `make build-ctl`
Expected: Binary builds successfully

**Step 3: Commit**

```bash
git add cmd/novanetctl/
git commit -m "feat: add novanetctl ebpf subcommands for service management"
```

---

### Task 19: Update Helm chart

**Files:**
- Modify: `deploy/helm/novanet/values.yaml`
- Modify: `deploy/helm/novanet/templates/configmap.yaml`
- Modify: `deploy/helm/novanet/templates/daemonset.yaml`

**Step 1: Add values**

```yaml
ebpfServices:
  enabled: true
  socketPath: "/run/novanet/ebpf-services.sock"
```

**Step 2: Update configmap template**

Add `ebpf_services` section to the generated `novanet.json`:
```json
"ebpf_services": {
  "enabled": {{ .Values.ebpfServices.enabled }},
  "socket_path": "{{ .Values.ebpfServices.socketPath }}"
}
```

**Step 3: Update daemonset template**

No new volumes needed — `/run/novanet/` is already the socket directory. The agent creates the new socket alongside the existing ones.

**Step 4: Lint**

Run: `helm lint deploy/helm/novanet/`
Expected: PASS

**Step 5: Commit**

```bash
git add deploy/helm/novanet/
git commit -m "feat: add ebpfServices Helm configuration"
```

---

### Task 20: Update documentation

**Files:**
- Modify: `docs/configuration.md`
- Modify: `docs/api-reference.md`
- Modify: `docs/cli-reference.md`

**Step 1: Add eBPF Services section to configuration.md**

Document the new Helm values (`ebpfServices.enabled`, `ebpfServices.socketPath`).

**Step 2: Add EBPFServices API to api-reference.md**

Document all 11 RPCs with request/response message schemas.

**Step 3: Add novanetctl ebpf commands to cli-reference.md**

Document the new `novanetctl ebpf` subcommands.

**Step 4: Build docs**

Run: `pip install mkdocs-material && mkdocs build --strict`
Expected: PASS

**Step 5: Commit**

```bash
git add docs/
git commit -m "docs: add eBPF Services API documentation"
```

---

## Phase 7: End-to-End Testing

### Task 21: Integration test

**Files:**
- Create: `tests/integration/10-ebpf-services.sh`

**Step 1: Write integration test**

Test script that:
1. Verifies `ebpf-services.sock` exists on a running node
2. Deploys a test pod with NovaEdge-like gRPC client
3. Calls EnableSockmap, AddMeshRedirect, ConfigureRateLimit
4. Verifies via `novanetctl ebpf` commands that entries exist
5. Cleans up

**Step 2: Commit**

```bash
git add tests/integration/
git commit -m "test: add eBPF services integration test"
```

---

## Summary

| Phase | Tasks | Description |
|-------|-------|-------------|
| 1 | 1-3 | Proto definition, Go gRPC scaffold, agent wiring |
| 2 | 4-8 | Rust map types, MapManager, DataplaneControl RPCs, Go client |
| 3 | 9-12 | EBPFServices server logic (SOCKMAP, mesh, rate limit, health) |
| 4 | 13-16 | eBPF programs (SOCKMAP, SK_LOOKUP, TC rate limit, TC health) |
| 5 | 17 | Rust loader integration |
| 6 | 18-20 | CLI, Helm, documentation |
| 7 | 21 | Integration testing |

**Total: 21 tasks across 7 phases**
