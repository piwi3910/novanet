# Socket-Level Load Balancing Design

**Goal:** Replace TC-based ClusterIP DNAT with cgroup socket hooks (like Cilium's socket-LB), fixing the broken east-west service translation.

**Motivation:** The current TC-based approach rewrites packets on pod veths after routing decisions are made. BPF link TC attachments on kernel 6.12 aren't processing pod traffic, and even if fixed, TC-based ClusterIP DNAT has fundamental issues with conntrack conflicts and reply-path complexity. Cilium and Calico both solved this by intercepting at the socket layer instead.

**Architecture:** Attach `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` programs to the root cgroup v2. These intercept `connect()`/`sendmsg()` syscalls and rewrite the destination address *before* the kernel creates any packet — no packet rewriting, no conntrack, no SNAT needed.

---

## Scope

### Socket-LB handles (east-west)

- **ClusterIP** — pod calls `connect(ClusterIP:port)` or `sendmsg(ClusterIP:port)`, socket hook rewrites to backend pod IP:port before the kernel acts.

### TC handles (north-south, unchanged)

- **NodePort** (external origin) — packet arrives on bond0, `tc_host_ingress` does DNAT. Already working.
- **ExternalIP** — same as NodePort, packet-level DNAT on host interface.
- **LoadBalancer** — same path via host interface.

### Why socket-LB can't handle north-south

External traffic has no local socket to intercept. Packets arrive on the wire from remote clients — only packet-level hooks (TC/XDP) can DNAT them.

---

## eBPF Programs

Four new cgroup programs, all in `novanet-ebpf/src/main.rs`:

| Program | Macro | Fires on | Action |
|---------|-------|----------|--------|
| `sock_connect4` | `#[cgroup_sock_addr(connect4)]` | TCP `connect()` with IPv4 | Lookup service, select backend, store original dst, rewrite `user_ip4`/`user_port` |
| `sock_sendmsg4` | `#[cgroup_sock_addr(sendmsg4)]` | UDP `sendmsg()` with IPv4 | Same as connect4 but per-datagram |
| `sock_recvmsg4` | `#[cgroup_sock_addr(recvmsg4)]` | UDP `recvmsg()` reply | Reverse-translate: set `user_ip4`/`user_port` back to original ClusterIP |
| `sock_getpeername4` | `#[cgroup_sock_addr(getpeername4)]` | `getpeername()` call | Return original ClusterIP instead of backend IP |

### Program Logic

**connect4 / sendmsg4:**
```
1. Read user_ip4, user_port from bpf_sock_addr
2. Build ServiceKey { ip: user_ip4, port: user_port, protocol, scope: ClusterIP }
3. Lookup SERVICES map → if miss, return OK (not a service, pass through)
4. Select backend via algorithm (random/round-robin/maglev) from BACKENDS
5. Get socket cookie via bpf_get_socket_cookie()
6. Store in SOCK_LB_ORIGINS: cookie → { original_ip, original_port, protocol }
7. Overwrite user_ip4 = backend.ip, user_port = backend.port
8. Return OK
```

**recvmsg4 / getpeername4:**
```
1. Get socket cookie via bpf_get_socket_cookie()
2. Lookup SOCK_LB_ORIGINS by cookie → if miss, return OK (not a translated socket)
3. Overwrite user_ip4 = origin.original_ip, user_port = origin.original_port
4. Return OK
```

---

## New Map

```rust
#[map]
static SOCK_LB_ORIGINS: LruHashMap<u64, SockLbOrigin> = LruHashMap::with_max_entries(131072, 0);
```

| Field | Type | Description |
|-------|------|-------------|
| Key | `u64` | Socket cookie from `bpf_get_socket_cookie()` |
| `original_ip` | `u32` | Original ClusterIP (network byte order) |
| `original_port` | `u16` | Original service port |
| `protocol` | `u8` | TCP=6, UDP=17 |
| `_pad` | `u8` | Alignment |

131,072 entries supports ~131K concurrent service connections with LRU eviction for stale entries.

---

## Shared Maps (no changes)

Socket-LB programs share existing maps with TC programs:

- **SERVICES** — same service lookup (ClusterIP scope = 0)
- **BACKENDS** — same backend array
- **MAGLEV** — same consistent hashing tables
- **RR_COUNTERS** — same round-robin counters

No changes to the Go agent, gRPC service watcher, or map population logic.

---

## Data Flow Examples

### TCP: Pod → ClusterIP (e.g., app → database service)

```
Pod calls connect(10.43.0.100:5432)
  → cgroup/connect4 hook fires
  → SERVICES lookup: {ip=10.43.0.100, port=5432, proto=TCP, scope=0} → hit
  → Backend selection (round-robin): 10.42.3.15:5432
  → SOCK_LB_ORIGINS[cookie] = {ip=10.43.0.100, port=5432}
  → Rewrite: user_ip4=10.42.3.15, user_port=5432
  → Kernel connects directly to 10.42.3.15:5432
  → TCP handshake with real backend IP — no DNAT, no SNAT
  → Data flows directly between pod and backend
```

### UDP: Pod → ClusterIP (e.g., DNS)

```
Pod calls sendmsg(10.43.0.10:53, dns_query)
  → cgroup/sendmsg4 hook fires
  → SERVICES lookup: hit → backend 10.42.1.8:53
  → SOCK_LB_ORIGINS[cookie] = {ip=10.43.0.10, port=53}
  → Rewrite dst to 10.42.1.8:53
  → Kernel sends UDP packet directly to backend

Backend replies:
  → cgroup/recvmsg4 hook fires
  → SOCK_LB_ORIGINS[cookie] → {ip=10.43.0.10, port=53}
  → Rewrite msg_src_ip4=10.43.0.10, msg_src_port=53
  → App sees reply from 10.43.0.10:53 (the ClusterIP)
```

### NodePort from external (unchanged)

```
External client → node:30080
  → tc_host_ingress on bond0 (existing, working)
  → SERVICES lookup with scope=NodePort
  → Packet-level DNAT to backend
  → Reply via reverse conntrack SNAT
```

---

## Userspace Changes

### Loader (`novanet-dataplane/src/loader.rs`)

Load cgroup programs alongside TC programs:

```rust
// After loading TC programs...
for name in ["sock_connect4", "sock_sendmsg4", "sock_recvmsg4", "sock_getpeername4"] {
    let prog: &mut CgroupSockAddr = ebpf.program_mut(name)?.try_into()?;
    prog.load()?;
}
```

### Map Manager (`novanet-dataplane/src/maps.rs`)

Attach to root cgroup on startup, detach on shutdown:

```rust
let cgroup = std::fs::File::open("/sys/fs/cgroup")?;
for name in ["sock_connect4", "sock_sendmsg4", "sock_recvmsg4", "sock_getpeername4"] {
    let prog: &mut CgroupSockAddr = ebpf.program_mut(name)?.try_into()?;
    prog.attach(&cgroup, CgroupAttachMode::Single)?;
}
```

---

## TC Code Removal

Remove the ClusterIP DNAT code path from `tc_egress` (lines ~812-825 in main.rs) that calls `service_lookup()` + `perform_dnat()` for ClusterIP scope. The `service_lookup()`, `perform_dnat()`, and `perform_snat()` helpers stay — they're still used by `tc_host_ingress` for NodePort/ExternalIP.

Remove the reverse SNAT path for ClusterIP in `tc_ingress` (lines ~653-671). The conntrack-based reverse translation for ClusterIP is no longer needed since socket-LB doesn't create conntrack entries.

The CONNTRACK map stays — still used by `tc_host_ingress` for NodePort/ExternalIP reverse SNAT.

---

## Files Changed

| File | Change |
|------|--------|
| `dataplane/novanet-ebpf/src/main.rs` | Add 4 cgroup_sock_addr programs, remove ClusterIP DNAT from tc_egress/tc_ingress |
| `dataplane/novanet-common/src/lib.rs` | Add `SockLbOrigin` struct, `SOCK_LB_ORIGINS` map constant |
| `dataplane/novanet-dataplane/src/loader.rs` | Load CgroupSockAddr programs |
| `dataplane/novanet-dataplane/src/maps.rs` | Attach/detach cgroup programs to root cgroup |

## Files Unchanged

| File | Why |
|------|-----|
| Go agent (`internal/service/`) | Same gRPC calls, same map population |
| Proto definitions | No new RPCs needed |
| Helm chart | Cgroup attachment is automatic, no config needed |
| `novanetctl` | `services` command unchanged |
| `tc_host_ingress` | NodePort/ExternalIP DNAT unchanged |

---

## Kernel Requirements

| Requirement | Minimum | Cluster |
|------------|---------|---------|
| cgroup v2 (unified) | kernel 4.5 | 6.12 |
| `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | kernel 4.17 | 6.12 |
| `bpf_get_socket_cookie()` in cgroup | kernel 4.18 | 6.12 |
| `connect4` attach type | kernel 4.17 | 6.12 |
| `sendmsg4` / `recvmsg4` | kernel 5.2 | 6.12 |
| `getpeername4` | kernel 5.8 | 6.12 |

All requirements met on kernel 6.12.

---

## Testing Strategy

1. **DNS resolution** — `nslookup kubernetes.default` from a pod (UDP ClusterIP)
2. **TCP ClusterIP** — `curl` a ClusterIP service from a pod
3. **Cross-node** — Service with backends on different nodes
4. **NodePort** — External access still works via tc_host_ingress
5. **Backend failover** — Kill a backend pod, verify new connections go to surviving backends
6. **novanetctl services** — Verify service list unchanged
