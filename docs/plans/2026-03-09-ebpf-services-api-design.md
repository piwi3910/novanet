# Design: eBPF Services API for NovaEdge Integration

**Date**: 2026-03-09
**Status**: Approved
**Scope**: NovaNet becomes the single eBPF owner on each node. NovaEdge requests kernel-level eBPF services from NovaNet via a node-local gRPC API.

---

## Context

NovaEdge currently loads its own eBPF programs (SOCKMAP, SK_LOOKUP, AF_XDP, rate limiting, health monitoring) alongside NovaNet's eBPF programs on the same node. Two DaemonSets managing eBPF attach points on the same interfaces causes program ordering conflicts, map pinning collisions in `/sys/fs/bpf/`, and maintenance burden.

NovaNet already owns the critical eBPF path (TC ingress/egress, cgroup socket-LB, tunnels, policy). Consolidating all eBPF into NovaNet eliminates conflicts and lets NovaEdge drop `privileged: true`.

## Decision

**Approach A: gRPC API on NovaNet Agent** — NovaNet agent exposes a new Unix socket (`/run/novanet/ebpf-services.sock`) with a gRPC service. NovaEdge calls it for all eBPF operations.

Rejected alternatives:
- **CRD API**: Too slow (Kubernetes API roundtrip per pod), too heavy (thousands of CRs for per-pod SOCKMAP entries).
- **Shared BPF filesystem + gRPC hybrid**: Keeps eBPF map reading in NovaEdge, defeating the goal of removing all eBPF code.

---

## What NovaNet Gains

### New eBPF Programs

| Program | Type | Attach Point | Purpose |
|---|---|---|---|
| `sockops_sockmap` | SOCK_OPS | Root cgroup | Captures socket connections, inserts into sock_hash if both endpoints are local |
| `sk_msg_sockmap` | SK_MSG | sock_hash map | Redirects sendmsg() between paired sockets, bypasses TCP/IP stack |
| `sk_lookup_mesh` | SK_LOOKUP | Network namespace | Redirects connections matching mesh_services map to TPROXY port |
| *(tc_ingress additions)* | — | Already attached | Per-source-IP rate limit check + passive TCP health counters |

Rate limiting and health monitoring are additions to the existing `tc_ingress` program, not new programs. This avoids attaching more programs to the same interface.

### New Maps

| Map | Type | Key | Value | Max Entries |
|---|---|---|---|---|
| `SOCK_HASH` | SOCKHASH | SockKey (src_ip, dst_ip, src_port, dst_port, family) | socket FD | 65,536 |
| `SOCKMAP_ENDPOINTS` | HASH | EndpointKey (ip, port) | u32 (eligible flag) | 4,096 |
| `MESH_SERVICES` | HASH | MeshServiceKey (ip, port) | MeshRedirectValue (redirect_port) | 4,096 |
| `RL_TOKENS` | LRU_PERCPU_HASH | RateLimitKey ([u8; 16]) | TokenBucketState | 100,000 |
| `RL_CONFIG` | ARRAY | u32 (index 0) | RateLimitConfig (rate, burst, window_ns) | 1 |
| `BACKEND_HEALTH` | PERCPU_HASH | BackendKey (ip, port) | BackendHealthCounters (7 × u64) | 4,096 |

### New Go Packages

```
internal/ebpfservices/
  server.go       -- gRPC server implementing EBPFServices
  sockmap.go      -- SOCKMAP lifecycle (enable/disable per pod)
  mesh.go         -- SK_LOOKUP mesh redirect management
  ratelimit.go    -- Rate limit config + stats aggregation
  health.go       -- Backend health polling + streaming
```

### gRPC Service Definition

```protobuf
syntax = "proto3";
package novanet.ebpfservices.v1;

service EBPFServices {
  // SOCKMAP - same-node pod-to-pod acceleration
  rpc EnableSockmap(EnableSockmapRequest) returns (EnableSockmapResponse);
  rpc DisableSockmap(DisableSockmapRequest) returns (DisableSockmapResponse);
  rpc GetSockmapStats(GetSockmapStatsRequest) returns (GetSockmapStatsResponse);

  // SK_LOOKUP - mesh traffic redirection
  rpc AddMeshRedirect(AddMeshRedirectRequest) returns (AddMeshRedirectResponse);
  rpc RemoveMeshRedirect(RemoveMeshRedirectRequest) returns (RemoveMeshRedirectResponse);
  rpc ListMeshRedirects(ListMeshRedirectsRequest) returns (ListMeshRedirectsResponse);

  // Rate limiting - kernel-level per-source-IP
  rpc ConfigureRateLimit(ConfigureRateLimitRequest) returns (ConfigureRateLimitResponse);
  rpc RemoveRateLimit(RemoveRateLimitRequest) returns (RemoveRateLimitResponse);
  rpc GetRateLimitStats(GetRateLimitStatsRequest) returns (GetRateLimitStatsResponse);

  // Health monitoring - passive TCP counters
  rpc GetBackendHealth(GetBackendHealthRequest) returns (GetBackendHealthResponse);
  rpc StreamBackendHealth(StreamBackendHealthRequest) returns (stream BackendHealthEvent);
}

// ── SOCKMAP ─────────────────────────────────────────────

message EnableSockmapRequest {
  string pod_namespace = 1;
  string pod_name = 2;
}
message EnableSockmapResponse {}

message DisableSockmapRequest {
  string pod_namespace = 1;
  string pod_name = 2;
}
message DisableSockmapResponse {}

message GetSockmapStatsRequest {}
message GetSockmapStatsResponse {
  uint64 redirected = 1;
  uint64 fallback = 2;
  uint32 active_sockets = 3;
}

// ── MESH REDIRECT ───────────────────────────────────────

message AddMeshRedirectRequest {
  string ip = 1;            // destination IP to intercept
  uint32 port = 2;          // destination port to intercept
  uint32 redirect_port = 3; // port to redirect to (e.g., 15001)
}
message AddMeshRedirectResponse {}

message RemoveMeshRedirectRequest {
  string ip = 1;
  uint32 port = 2;
}
message RemoveMeshRedirectResponse {}

message ListMeshRedirectsRequest {}
message ListMeshRedirectsResponse {
  repeated MeshRedirectEntry entries = 1;
}
message MeshRedirectEntry {
  string ip = 1;
  uint32 port = 2;
  uint32 redirect_port = 3;
}

// ── RATE LIMITING ───────────────────────────────────────

message ConfigureRateLimitRequest {
  string cidr = 1;          // source CIDR to rate limit
  uint32 rate = 2;          // tokens per second
  uint32 burst = 3;         // max burst size
}
message ConfigureRateLimitResponse {}

message RemoveRateLimitRequest {
  string cidr = 1;
}
message RemoveRateLimitResponse {}

message GetRateLimitStatsRequest {
  string cidr = 1;          // empty = all
}
message GetRateLimitStatsResponse {
  uint64 allowed = 1;
  uint64 denied = 2;
}

// ── HEALTH MONITORING ───────────────────────────────────

message GetBackendHealthRequest {
  string ip = 1;            // empty = all backends
  uint32 port = 2;
}
message GetBackendHealthResponse {
  repeated BackendHealthInfo backends = 1;
}
message BackendHealthInfo {
  string ip = 1;
  uint32 port = 2;
  uint64 total_conns = 3;
  uint64 failed_conns = 4;
  uint64 timeout_conns = 5;
  uint64 success_conns = 6;
  uint64 avg_rtt_ns = 7;
  double failure_rate = 8;
}

message StreamBackendHealthRequest {
  uint32 poll_interval_ms = 1;  // how often to poll (default 10000)
}
message BackendHealthEvent {
  BackendHealthInfo backend = 1;
  uint64 timestamp_ns = 2;
}
```

### Data Flow

```
NovaEdge agent
    │ gRPC (Unix socket: /run/novanet/ebpf-services.sock)
    ▼
NovaNet agent (ebpfservices server)
    │ gRPC (Unix socket: /run/novanet/dataplane.sock)
    ▼
NovaNet dataplane (Rust, aya map operations)
    │ kernel map read/write
    ▼
Kernel eBPF programs (SOCKMAP, SK_LOOKUP, TC)
```

### Authentication

Unix socket peer credentials via `SO_PEERCRED`. NovaNet validates the calling process is on the same node. No tokens needed.

### Helm Chart Changes

```yaml
# values.yaml additions
ebpfServices:
  enabled: true
  socketPath: "/run/novanet/ebpf-services.sock"
```

New socket path added to the DaemonSet container args. No new volumes needed — `/run/novanet/` is already mounted.

---

## Deployment & Dependency Model

### Startup Order

1. NovaNet DaemonSet starts → CNI ready → `ebpf-services.sock` created
2. NovaEdge DaemonSet starts → connects to `ebpf-services.sock`
3. If socket unavailable → NovaEdge retries with backoff, operates in degraded mode

### Degraded Mode (NovaNet unavailable)

All features have userspace fallbacks in NovaEdge:
- **SOCKMAP unavailable**: Traffic flows through normal TCP/IP stack (slower, still works)
- **SK_LOOKUP unavailable**: Mesh falls back to iptables TPROXY rules
- **Rate limiting unavailable**: L7 middleware rate limiting in Rust dataplane
- **Health unavailable**: Active health checks in Rust dataplane

NovaEdge never hard-fails if NovaNet eBPF services are unavailable.

### Upgrade Ordering

1. Upgrade NovaNet first (new eBPF programs + gRPC service, backward-compatible)
2. Upgrade NovaEdge second (starts using new API, old eBPF code removed)

### Standalone Mode

```yaml
# NovaEdge values.yaml
novanet:
  enabled: false  # skip all eBPF service calls, pure userspace mode
```

Allows NovaEdge to work with other CNIs (Cilium, Calico) without NovaNet.
