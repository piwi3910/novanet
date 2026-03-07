# Changelog

## v1.0.0 — 2026-02-27

Initial stable release of NovaNet, an eBPF-based Kubernetes CNI providing identity-based network policy enforcement, overlay and native routing, and real-time flow visibility.

### Core Features

- **eBPF Dataplane** — Rust/Aya-based TC programs for packet forwarding, policy enforcement, and flow telemetry
- **Identity-Based Policy** — L3/L4 NetworkPolicy enforcement using label-derived security identities (not IP pairs)
- **Overlay Networking** — Geneve (default) and VXLAN tunnel modes with per-node deterministic MAC addresses
- **Native Routing** — BGP/OSPF route advertisement via NovaRoute integration (eBGP full mesh + TOR peering)
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
- **NovaRoute Integration** — gRPC client for native routing prefix advertisement/withdrawal
- **Graceful Shutdown** — WaitGroup-tracked goroutines, context cancellation, atomic state flags

### CI/CD

- **Multi-arch Docker Images** — linux/amd64 + linux/arm64 via QEMU + Buildx
- **Automated Release** — Tag-triggered pipeline builds binaries, images, runs Trivy scans, creates GitHub Release
- **CI Pipeline** — Go/Rust lint, unit tests with race detection, Helm lint, security scanning (govulncheck)
- **GitHub Pages** — Auto-deployed documentation site with Jekyll

### Documentation

- Architecture guide with eBPF program details, map schemas, and data path diagrams
- CLI reference with all commands, flags, and example output
- gRPC API reference for DataplaneControl and AgentControl services
- Installation guide, configuration reference, and troubleshooting guide
- Development guide with build instructions, testing, and contributor notes

### Docker Images

```
ghcr.io/azrtydxb/novanet/novanet-agent:1.0.0
ghcr.io/azrtydxb/novanet/novanet-dataplane:1.0.0
```
