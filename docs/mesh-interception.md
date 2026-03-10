# Mesh Traffic Interception

NovaNet provides kernel-level mesh traffic interception using the `BPF_PROG_TYPE_SK_LOOKUP` eBPF program type. This allows service mesh sidecars (such as NovaEdge's Rust dataplane) to transparently capture service-destined connections without relying on iptables or nftables NAT rules.

---

## Overview

In a service mesh, traffic destined for a Kubernetes Service ClusterIP must be intercepted and redirected to a local sidecar proxy. Traditionally this is done with iptables DNAT or nftables NAT REDIRECT rules in the `PREROUTING` chain. These approaches have drawbacks:

- **Conntrack overhead**: every redirected connection creates a conntrack entry, consuming memory and adding latency
- **Rule ordering conflicts**: kube-proxy and the mesh sidecar both install iptables rules, leading to priority ordering issues
- **Performance**: iptables rule evaluation is O(n) in the number of rules

NovaNet's `sk_lookup_mesh` program solves all three problems by operating at the socket lookup layer, before conntrack is involved.

---

## How sk_lookup Works

`BPF_PROG_TYPE_SK_LOOKUP` is a Linux eBPF program type (available since kernel 5.9) that runs during the kernel's socket lookup phase. When an incoming TCP connection or UDP datagram arrives and the kernel searches for a matching listening socket, an sk_lookup program can override the result by assigning a different socket.

### Program Flow

```
Incoming TCP SYN to ClusterIP:port
    │
    ▼
Kernel socket lookup
    │
    ▼
sk_lookup_mesh program triggered
    │
    ├── Look up (dst_ip, dst_port) in MESH_SERVICES map
    │
    ├── Not found → SK_PASS (normal lookup proceeds)
    │
    └── Found → redirect_port
            │
            ├── bpf_sk_lookup_tcp(127.0.0.1, redirect_port)
            │
            ├── Socket not found → SK_PASS (fallback)
            │
            └── Socket found
                    │
                    ├── bpf_sk_assign(sk, BPF_SK_LOOKUP_F_REPLACE)
                    │
                    └── Connection delivered to sidecar listener
```

Key details:

- The program only handles **IPv4 TCP** connections (UDP and IPv6 support planned)
- `bpf_sk_assign` with `BPF_SK_LOOKUP_F_REPLACE` allows overriding any socket assignment from a previous sk_lookup program in the chain
- On any error, the program returns `SK_PASS` so normal socket lookup proceeds -- it never drops traffic
- The redirected connection preserves the original destination address in the socket, so the sidecar can read it via `SO_ORIGINAL_DST`

---

## MESH_SERVICES Map

The `MESH_SERVICES` eBPF map tracks which service IPs and ports should be intercepted.

| Property | Value |
|----------|-------|
| Type | `BPF_MAP_TYPE_HASH` |
| Key | `MeshServiceKey { ip: u32, port: u32 }` |
| Value | `MeshRedirectValue { redirect_port: u32 }` |
| Max entries | 4,096 |
| Pin path | `/sys/fs/bpf/novanet/MESH_SERVICES` |

### Map Population

The map is populated via the **EBPFServices gRPC API** exposed by the NovaNet agent on `/run/novanet/ebpf-services.sock`. NovaEdge (or any authorized mesh sidecar) calls:

- `AddMeshRedirect(ip, port, redirect_port)` -- insert an entry
- `RemoveMeshRedirect(ip, port)` -- remove an entry
- `ListMeshRedirects()` -- list all active entries

The typical flow:

1. NovaEdge watches Kubernetes Services and determines which ClusterIPs need mesh interception
2. For each service, NovaEdge calls `AddMeshRedirect` with the ClusterIP, service port, and the local transparent listener port
3. The NovaNet agent validates the request and calls the dataplane to insert the entry into the MESH_SERVICES eBPF map
4. The `sk_lookup_mesh` program immediately starts intercepting matching connections

---

## Attachment

The `sk_lookup_mesh` program is loaded and attached during dataplane startup (not via the gRPC `AttachProgram` RPC used for TC programs). The attachment sequence:

1. Load the eBPF object file containing `sk_lookup_mesh`
2. Open `/proc/self/ns/net` to get a file descriptor for the host network namespace
3. Attach the program to the network namespace via `aya::programs::SkLookup::attach(netns_fd)`
4. The program is now invoked for every TCP socket lookup in the host network namespace

If the program fails to load or attach (e.g., on older kernels), a warning is logged and mesh interception falls back to nftables rules. No other functionality is affected.

---

## Comparison with iptables/nftables

| Aspect | iptables/nftables REDIRECT | sk_lookup_mesh |
|--------|---------------------------|----------------|
| Conntrack entries | Yes (one per connection) | No |
| Rule ordering issues | Yes (kube-proxy conflicts) | No |
| Kernel version | Any | 5.9+ |
| Performance | O(n) rule traversal | O(1) hash map lookup |
| Failure mode | Silent misrouting possible | Graceful fallback to normal lookup |
| Original destination | Requires conntrack `SO_ORIGINAL_DST` | Socket retains original dst natively |

---

## Requirements

- **Linux kernel 5.9+** for `BPF_PROG_TYPE_SK_LOOKUP` support
- **CAP_BPF + CAP_NET_ADMIN** capabilities for loading and attaching the program
- A listening socket on `127.0.0.1:<redirect_port>` (the mesh sidecar's transparent listener)

On older kernels, NovaEdge automatically falls back to nftables NAT REDIRECT rules.

---

## See Also

- [Architecture](architecture.md) -- full eBPF program and map reference
- [API Reference](api-reference.md) -- EBPFServices gRPC API (AddMeshRedirect, RemoveMeshRedirect, ListMeshRedirects)
