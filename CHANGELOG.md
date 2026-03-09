# Changelog

## v1.13.0 — 2026-03-09

Complete NovaRoute merger into NovaNet. All routing functionality is now built-in.

### Routing Query RPCs

- **5 new gRPC RPCs** on the AgentControl service: `GetRoutingPeers`, `GetRoutingPrefixes`, `GetRoutingBFDSessions`, `GetRoutingOSPFNeighbors`, `StreamRoutingEvents`
- Agent-side RPC handlers that query FRR live state and cross-reference the intent store for owner info
- Event publishing system with subscribe/unsubscribe for real-time routing event streaming

### Routing Manager API

- `RemovePeer` — remove a BGP peer by neighbor address
- `EnableBFD` / `DisableBFD` — manage BFD sessions per peer
- `EnableOSPF` / `DisableOSPF` — manage OSPF interface configuration

### CLI

- Fully implemented `novanetctl routing` subcommands replacing previous stubs:
  - `routing status` — routing mode, FRR connectivity
  - `routing peers` — BGP peer sessions with state, prefix counts, BFD status, uptime, owner
  - `routing prefixes` — advertised route prefixes with protocol and owner
  - `routing bfd` — BFD session state with timers and uptime
  - `routing ospf` — OSPF neighbor adjacencies with state and interface
  - `routing events` — real-time routing event stream with `--owner` filter

### Other

- NovaRoute repository archived on GitHub

---

## v1.12.0 — 2026-03-08

### Control Plane VIP

- **Control plane VIP support** — health-checked virtual IP for Kubernetes API server HA
- VIP advertised via BGP with configurable health check endpoints
- Automatic failover when API server backends become unhealthy
- Configured via `routing.controlPlaneVIP` Helm value

### L4 Load Balancing

- **Re-enabled L4 socket-based load balancing** after hostname parsing fix
- eBPF cgroup programs for Kubernetes Service LB (ClusterIP, NodePort, ExternalIP, LoadBalancer)
- kube-proxy replacement with direct server return

### Bug Fixes

- Fixed L4 LB service watcher parsing hostnames as backend IPs (caused DNS resolution failures)
- Added `net.ParseIP()` validation in `collectBackends` to skip hostname addresses

---

## v1.11.0 — 2026-03-07

### Socket-Based L4 Load Balancing

- **L4 LB implementation** using eBPF cgroup/connect4/connect6 programs
- Kubernetes Service watcher for automatic backend discovery
- Support for ClusterIP, NodePort, ExternalIP, and LoadBalancer service types
- Connection affinity and health-aware backend selection

---

## v1.10.0 — 2026-03-06

### Native Routing Integration

- **Integrated routing manager** — NovaRoute functionality merged into the NovaNet agent in-process
- FRR runs as a sidecar container in the NovaNet DaemonSet (no separate deployment)
- Intent-based routing state management with reconciliation loop
- Automatic BGP peer discovery via Kubernetes Node watcher
- eBGP peering with per-node ASN (65000 + last octet of node IP)
- ToR switch peering with configurable peers
- PodCIDR prefix advertisement and withdrawal
- BFD session management for fast failure detection
- OSPF support as alternative to BGP

### Helm Chart

- Added `routing.*` values for native routing configuration
- FRR sidecar container added when `routingMode: "native"`
- Peer configuration via `routing.peers[]` array
- BFD configuration via `routing.bfd.*` values

---

## v1.0.0 — 2026-02-27

Initial stable release of NovaNet, an eBPF-based Kubernetes CNI providing identity-based network policy enforcement, overlay and native routing, and real-time flow visibility.

### Core Features

- **eBPF Dataplane** — Rust/Aya-based TC programs for packet forwarding, policy enforcement, and flow telemetry
- **Identity-Based Policy** — L3/L4 NetworkPolicy enforcement using label-derived security identities (not IP pairs)
- **Overlay Networking** — Geneve (default) and VXLAN tunnel modes with per-node deterministic MAC addresses
- **IPAM** — Bitmap-based IP allocator with file-backed persistence across restarts
- **NAT Masquerade** — iptables SNAT for pod-to-external traffic
- **Egress Policy** — Per-identity egress rules with ALLOW/DENY/SNAT actions
- **Flow Observability** — Real-time streaming of flow events with verdict, drop reason, and TCP flags
- **CLI (novanetctl)** — Full management CLI: status, flows, drops, tunnels, policy, identity, egress, metrics
- **Kubernetes Operator** — `novanet-operator` with NovaNetCluster CRD for declarative lifecycle management

### Kubernetes Integration

- **CNI Plugin** — Standards-compliant CNI binary with veth pair setup, /32 addressing, and namespace-aware netlink
- **Helm Chart** — Production-ready DaemonSet deployment with configurable values
- **DaemonSet Rolling Update Strategy** — Configurable maxUnavailable for rolling updates
- **Pod Label Identity** — Automatic identity allocation from pod labels at CNI ADD time
- **NetworkPolicy Support** — Full K8s NetworkPolicy with MatchExpressions, named ports, and wildcard identities

### Architecture

- **Go Management Plane** — Agent binary handling K8s API watches, IPAM, identity allocation, policy compilation
- **Rust eBPF Dataplane** — Userspace daemon loading TC programs and managing eBPF maps via gRPC
- **gRPC over Unix Socket** — All inter-component communication (agent-dataplane, agent-CNI, agent-CLI)
- **Graceful Shutdown** — WaitGroup-tracked goroutines, context cancellation, atomic state flags

### CI/CD

- **Multi-arch Docker Images** — linux/amd64 + linux/arm64 via QEMU + Buildx
- **Automated Release** — Tag-triggered pipeline builds binaries, images, runs Trivy scans, creates GitHub Release
- **CI Pipeline** — Go/Rust lint, unit tests with race detection, Helm lint, security scanning (govulncheck)
- **GitHub Pages** — Auto-deployed documentation site with MkDocs Material

### Docker Images

```
ghcr.io/azrtydxb/novanet/novanet-agent:1.0.0
ghcr.io/azrtydxb/novanet/novanet-dataplane:1.0.0
```
