# NovaNet Architecture

This document describes the internal architecture of NovaNet, including data paths, eBPF programs, the identity model, and tunnel design.

---

## Component Overview

NovaNet runs as a DaemonSet with two containers per node (three in native routing mode):

| Container | Binary | Language | Role |
|-----------|--------|----------|------|
| agent | `novanet-agent` | Go | Management plane: IPAM, identity allocation, policy compilation, Kubernetes watchers, integrated routing manager, CNI handler, metrics |
| dataplane | `novanet-dataplane` | Rust | eBPF program loader and map manager, gRPC server for agent commands, flow event export |
| frr | FRR daemons | C | BGP/OSPF/BFD routing suite (native routing mode only, runs as a sidecar) |

A third binary, `novanet-cni`, is installed as a CNI plugin on the host at `/opt/cni/bin/novanet-cni`. It is invoked by the kubelet during pod creation and deletion.

The CLI tool `novanetctl` connects to the agent and dataplane via Unix sockets to query status.

### Inter-Component Communication

All communication uses gRPC over Unix domain sockets:

```
kubelet ──CNI──► novanet-cni ──gRPC──► novanet-agent
                                           │
                                           │ gRPC
                                           ▼
                                     novanet-dataplane ──► eBPF maps/programs
                                           │
novanetctl ──gRPC──► novanet-agent ◄───────┘
```

| Socket Path | Server | Clients |
|-------------|--------|---------|
| `/run/novanet/cni.sock` | agent | CNI binary |
| `/run/novanet/novanet.sock` | agent | novanetctl |
| `/run/novanet/ipam.sock` | agent | IPAM clients |
| `/run/novanet/ebpf-services.sock` | agent | eBPF service clients |
| `/run/novanet/dataplane.sock` | dataplane | agent |
| `/run/frr/` | FRR sidecar | agent routing manager (native mode) |

### Unix Socket Authentication

All gRPC servers authenticate connecting processes using `SO_PEERCRED` peer
credential checking (Linux only). The `internal/grpcauth` package provides:

- **`NewAuthenticatedServer()`** -- creates a `*grpc.Server` with transport
  credentials and interceptors that verify the peer UID via `SO_PEERCRED`.
- **Unary and stream interceptors** -- reject any connection whose UID is not
  in the allowed set (currently only UID 0 / root).
- **Graceful degradation** -- on non-Linux platforms the interceptors log a
  warning and allow all connections, so development and testing on macOS
  continue to work.

Socket file permissions are set to `0600`, and the `SO_PEERCRED` check
provides defence-in-depth: even if file permissions are weakened, only
processes running as root can call the gRPC API.

---

## eBPF Programs

NovaNet attaches TC (Traffic Control) classifier programs to network interfaces. There are four programs compiled into a single eBPF object file:

### tc_ingress (Pod veth, ingress direction)

Processes packets arriving at a pod.

1. Parse Ethernet + IPv4 + L4 headers
2. Look up source identity from the ENDPOINTS map (by source IP)
3. Look up destination identity from the ENDPOINTS map (by destination IP)
4. Evaluate POLICIES map: `(src_identity, dst_identity, protocol, dst_port)` -> allow/deny
5. If denied, increment DROP_COUNTERS and emit a flow event with the drop reason
6. If allowed, pass to kernel stack

### tc_egress (Pod veth, egress direction)

Processes packets leaving a pod.

1. Parse headers and determine destination
2. Check egress policy in EGRESS_POLICIES map
3. **Local delivery**: If destination IP is in ENDPOINTS map (local pod), return TC_ACT_OK to let the kernel route the packet to that pod's veth
4. **Overlay remote delivery**: Look up TUNNELS map by destination node IP. Redirect to tunnel interface with identity injected into Geneve TLV
5. **Native routing**: Let the kernel routing table handle forwarding (routes installed by the integrated routing manager via FRR)
6. **External traffic**: Passes through iptables MASQUERADE for SNAT

### tc_tunnel_ingress (Tunnel interface, ingress)

Overlay mode only. Processes decapsulated tunnel traffic arriving from remote nodes.

1. Extract source identity from Geneve TLV option (or from ENDPOINTS map for VXLAN)
2. Look up destination pod in ENDPOINTS map
3. Evaluate policy
4. Redirect to destination pod's veth

### tc_tunnel_egress (Tunnel interface, egress)

Overlay mode only. Pass-through (TC_ACT_OK), reserved for future identity TLV injection.

Currently a no-op that returns TC_ACT_OK, allowing the kernel to handle tunnel encapsulation directly. A future version may inject source identity into Geneve TLV options at this hook point.

### Program Attachment

Programs are attached dynamically by the agent via gRPC `AttachProgram` RPCs to the dataplane. Attachment happens:

- When a new pod is created (attach to the host-side veth)
- When a tunnel interface is created (overlay mode)

Programs are pinned to `/sys/fs/bpf/novanet/` so they survive pod restarts.

---

## eBPF Maps

All maps are pinned to `/sys/fs/bpf/novanet/` and shared between the four TC programs.

| Map | Type | Key | Value | Max Entries | Purpose |
|-----|------|-----|-------|-------------|---------|
| ENDPOINTS | HashMap | `u32` (pod IP) | `{ifindex, mac[6], _pad[2], identity, node_ip}` | 65,536 | Pod lookup for local delivery and identity resolution |
| POLICIES | HashMap | `{src_id, dst_id, proto, port}` | `{action}` | 65,536 | Ingress/egress policy enforcement |
| TUNNELS | HashMap | `u32` (node IP) | `{ifindex, remote_ip, vni}` | 1,024 | Overlay tunnel endpoints |
| EGRESS_POLICIES | HashMap | `{src_id, dst_cidr, prefix_len}` | `{action, snat_ip}` | 16,384 | Egress CIDR-based policies |
| CONFIG | HashMap | `u32` (key) | `u64` (value) | 32 | Runtime configuration (mode, tunnel type, node IP, etc.) |
| FLOW_EVENTS | RingBuf | -- | `FlowEvent` struct | 8 MiB | Flow event export to userspace |
| DROP_COUNTERS | PerCpuArray | `u32` (reason) | `u64` (count) | 16 | Per-CPU drop statistics |

### Policy Lookup Order

The policy check uses a 3x3 grid of lookups (9 total), iterating over identity wildcards and port wildcards:

For each of `(src_identity, dst_identity)`, `(src_identity, 0)`, `(0, dst_identity)` in that order:
1. Exact: `(src_id, dst_id, protocol, dst_port)`
2. Wildcard port: `(src_id, dst_id, protocol, 0)`
3. Wildcard protocol+port: `(src_id, dst_id, 0, 0)`

The first match wins. If none of the 9 lookups match, the CONFIG `default_deny` flag determines the verdict.

---

## Identity Model

NovaNet uses **identity-based policy** rather than IP-pair policy. This reduces the size of the policy map and makes policies portable across pod restarts.

### Identity Assignment

1. When a pod is added via CNI, the agent computes a **deterministic identity ID** from the pod's labels
2. The identity is a hash of the sorted label key-value pairs
3. Pods with identical labels share the same identity ID
4. The identity ID is stored in the ENDPOINTS map alongside the pod's IP and MAC

### Benefits

- A NetworkPolicy selecting 100 pods with the same labels needs only 1 rule per port, not 100
- Pod IP changes (restarts) don't require policy map updates if labels stay the same
- Cross-node policy enforcement works without syncing IP lists

---

## Tunnel MAC Architecture

In overlay mode, NovaNet uses a deterministic per-node MAC address scheme for tunnel interfaces:

```
IPToTunnelMAC(ip) -> aa:bb:IP[0]:IP[1]:IP[2]:IP[3]
```

For example, node `192.168.1.10` gets tunnel MAC `aa:bb:c0:a8:01:0a`.

### Why Per-Node MACs?

The inner Ethernet frame inside a tunnel packet must have a destination MAC that matches the receiving interface's MAC. Otherwise:

| Scenario | Result |
|----------|--------|
| Zero MAC (`00:00:00:00:00:00`) | `PACKET_OTHERHOST` -- dropped in `ip_rcv()` |
| Same MAC on all nodes | `PACKET_LOOPBACK` (src == interface MAC) -- dropped |
| Per-node deterministic MAC | `PACKET_HOST` -- delivered correctly |

All local tunnel interfaces share the MAC derived from the local node's IP. Neighbor (ARP) entries point to MACs derived from remote nodes' IPs.

---

## Data Paths

### Same-Node Pod-to-Pod

```
Pod A eth0 -> tc_egress -> ENDPOINTS lookup (Pod B is local)
  -> TC_ACT_OK (let kernel route to Pod B's veth)
  -> Pod B eth0 tc_ingress -> policy check -> deliver
```

No tunnel involved. The eBPF program returns TC_ACT_OK and lets the kernel route between veth pairs.

### Cross-Node (Overlay/Geneve)

```
Pod A eth0 -> tc_egress -> TUNNELS lookup (remote node)
  -> redirect to geneve tunnel interface
  -> tc_tunnel_egress -> pass-through (TC_ACT_OK)
  -> kernel Geneve encapsulation -> UDP/6081 to remote node
  ...
  -> remote node kernel decapsulation
  -> tc_tunnel_ingress -> extract identity from TLV
  -> ENDPOINTS lookup (Pod B) -> policy check
  -> redirect to Pod B veth -> deliver
```

### Cross-Node (Native Routing)

```
Pod A eth0 -> tc_egress -> egress policy check
  -> kernel routing (BGP/OSPF-learned routes via FRR sidecar)
  -> underlay network -> remote node
  -> Pod B eth0 tc_ingress -> ENDPOINTS lookup (src IP -> identity)
  -> policy check -> deliver
```

No encapsulation. Identity resolved from source IP via ENDPOINTS map on the receiving node.

### External Traffic (Egress)

```
Pod A eth0 -> tc_egress -> EGRESS_POLICIES check
  -> kernel routing -> iptables POSTROUTING MASQUERADE
  -> SNAT to node IP -> external network
```

---

## Graceful Shutdown

When the agent receives SIGTERM:

1. Cancel the root context (stops all background watchers)
2. Wait for all goroutines to finish (`sync.WaitGroup`)
3. In native mode: withdraw PodCIDR via the routing manager and shut down FRR
4. Stop gRPC servers
5. Close dataplane connection
6. Exit

eBPF programs remain pinned and continue forwarding traffic until the new pod starts and re-attaches them. IPAM state on disk ensures IP allocations are preserved.

---

## Next Steps

- [Configuration Reference](configuration.md) -- All Helm values and config options
- [API Reference](api-reference.md) -- gRPC services and eBPF map schemas
- [Development Guide](development.md) -- Building and contributing
