<p align="center">
  <img src="novanet-logo-light.svg" alt="NovaNet" width="480">
</p>

<p align="center">
  <a href="https://github.com/azrtydxb/novanet/actions/workflows/ci.yml"><img src="https://github.com/azrtydxb/novanet/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/azrtydxb/novanet/actions/workflows/release.yml"><img src="https://github.com/azrtydxb/novanet/actions/workflows/release.yml/badge.svg" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
  <a href="go.mod"><img src="https://img.shields.io/github/go-mod/go-version/azrtydxb/novanet" alt="Go Version"></a>
</p>

---

**NovaNet** is a high-performance, eBPF-based Kubernetes CNI (Container Network Interface) that provides secure pod-to-pod connectivity, identity-based L3/L4 network policy enforcement, native BGP/OSPF/BFD routing via an integrated FRR sidecar, L4 socket-based load balancing, and real-time flow visibility.

NovaNet is part of the **Nova networking stack**:

| Component | Role |
|-----------|------|
| **[NovaEdge](https://github.com/azrtydxb/novaedge)** | Ingress load balancing, reverse proxy, SD-WAN gateway |
| **NovaNet** (this repo) | Pod networking, L3/L4 policy, native routing (BGP/OSPF/BFD), L4 LB, observability |

> **Note:** NovaRoute was merged into NovaNet in v1.13.0. All routing functionality (BGP, OSPF, BFD, prefix advertisement) is now built-in. The [NovaRoute repository](https://github.com/azrtydxb/NovaRoute) has been archived.

---

## Features

- **eBPF dataplane** -- TC-hook programs (Rust/Aya) for packet processing at near-kernel speed
- **Identity-based policy** -- Pods with the same labels share a security identity; policies reference identities, not IP pairs
- **Dual routing modes** -- Overlay (Geneve/VXLAN) or native routing (BGP/OSPF/BFD via integrated FRR sidecar)
- **L4 socket-based load balancing** -- eBPF cgroup programs for Kubernetes Service load balancing (ClusterIP, NodePort, ExternalIP, LoadBalancer) without kube-proxy
- **Control Plane VIP** -- Health-checked virtual IP for Kubernetes API server HA, advertised via BGP
- **Multi-arch** -- Builds and runs on both `amd64` and `arm64`
- **Kubernetes NetworkPolicy** -- Full support for standard ingress/egress policies with an optional cluster-wide default-deny mode
- **Egress control** -- Per-identity egress policies with SNAT support
- **Real-time flow visibility** -- Stream flow events (with TCP flags) via gRPC for observability and debugging
- **Prometheus metrics** -- Endpoint counts, policy verdicts, drop counters, flow statistics, routing state
- **Graceful lifecycle** -- eBPF programs pinned to `/sys/fs/bpf/` survive pod restarts; IPAM state persists on disk

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  Kubernetes Node                                                  │
│                                                                    │
│  ┌──────────────┐   gRPC    ┌──────────────────────────┐         │
│  │ novanet-agent│◄─────────►│  novanet-dataplane       │         │
│  │   (Go)       │           │      (Rust + Aya)        │         │
│  │              │           │                          │         │
│  │  - IPAM      │           │  - eBPF loader           │         │
│  │  - Identity  │           │  - Map management        │         │
│  │  - Policy    │           │  - Flow ring buffer      │         │
│  │  - Routing   │           │  - gRPC server           │         │
│  │  - L4 LB     │           └────────────┬─────────────┘         │
│  │  - K8s watch │                        │                        │
│  └──────┬───────┘            eBPF TC + cgroup hooks               │
│         │     ▲                          ▼                        │
│         │     │              ┌─────────────────────────┐          │
│  ┌──────┴──┐  │              │  tc_ingress / tc_egress  │          │
│  │novanet- │  │              │  tc_tunnel_ingress/egress│          │
│  │  cni    │  │              │  cgroup/connect4/6       │          │
│  └─────────┘  │              └─────────────────────────┘          │
│               │                                                    │
│  ┌────────────┴──┐                                                │
│  │  FRR sidecar  │  (native routing mode only)                    │
│  │  bgpd / ospfd │                                                │
│  │  bfdd / zebra │                                                │
│  └───────────────┘                                                │
└──────────────────────────────────────────────────────────────────┘
```

| Component | Language | Description |
|-----------|----------|-------------|
| `novanet-agent` | Go | Management plane: IPAM, identity, policy compilation, K8s watchers, integrated routing manager, L4 LB service watcher |
| `novanet-dataplane` | Rust | eBPF program loader, map management, gRPC server, flow event export |
| `novanet-cni` | Go | Standard CNI binary called by kubelet for pod ADD/DEL/CHECK |
| `novanetctl` | Go | CLI tool for status, flows, policies, tunnels, identities, routing, BFD, OSPF |
| `novanet-ebpf` | Rust (no_std) | TC classifier and cgroup programs for packet forwarding, policy enforcement, and socket LB |
| `novanet-operator` | Go | Kubernetes operator managing NovaNetCluster CRD for lifecycle automation |
| FRR sidecar | C | BGP/OSPF/BFD routing daemons (bgpd, ospfd, bfdd, zebra) -- native routing mode only |

---

## Quick Start

### Prerequisites

- Kubernetes 1.28+ with no existing CNI (or existing CNI removed)
- Linux kernel 5.15+ with BTF support (`/sys/kernel/btf/vmlinux` must exist)
- Helm 3.x

### Install (Overlay Mode)

```bash
git clone https://github.com/azrtydxb/novanet.git
cd novanet

helm install novanet ./deploy/helm/novanet \
  -n novanet-system --create-namespace \
  --set config.clusterCIDR="10.42.0.0/16"
```

### Install (Native Routing with BGP)

```bash
helm install novanet ./deploy/helm/novanet \
  -n novanet-system --create-namespace \
  --set config.routingMode=native \
  --set routing.enabled=true \
  --set routing.protocol=bgp
```

### Verify

```bash
# All pods should be 3/3 Running (native) or 2/2 (overlay)
kubectl get pods -n novanet-system -o wide

# Check agent status
kubectl exec -n novanet-system ds/novanet -c agent -- novanetctl status

# Check routing status (native mode)
kubectl exec -n novanet-system ds/novanet -c agent -- novanetctl routing status

# Test connectivity
kubectl run test-a --image=busybox --restart=Never -- sleep 3600
kubectl run test-b --image=busybox --restart=Never -- sleep 3600
kubectl exec test-a -- ping -c 3 $(kubectl get pod test-b -o jsonpath='{.status.podIP}')
```

---

## CLI Reference

```
novanetctl status              # Agent and dataplane overview
novanetctl flows               # Stream real-time flow events
novanetctl drops               # Watch denied packets only
novanetctl tunnels             # List overlay tunnels
novanetctl policy              # Show compiled policy rules
novanetctl identity            # Show pod-to-identity mappings
novanetctl egress              # Show egress rules
novanetctl routing status      # Routing mode and FRR connection
novanetctl routing peers       # BGP peer sessions with BFD status
novanetctl routing prefixes    # Advertised route prefixes
novanetctl routing bfd         # BFD session state and timers
novanetctl routing ospf        # OSPF neighbor adjacencies
novanetctl routing events      # Stream real-time routing events
novanetctl metrics             # Summary statistics
novanetctl version             # Print version
```

See the full [CLI Reference](docs/cli-reference.md) for flags and output examples.

---

## Routing Modes

### Overlay (Default)

Works on any network. Creates Geneve (default) or VXLAN tunnels between nodes.

```yaml
config:
  routingMode: "overlay"
  tunnelProtocol: "geneve"   # or "vxlan"
```

### Native Routing

Eliminates encapsulation by advertising PodCIDRs via BGP/OSPF through an integrated FRR sidecar. Requires a routing-capable network fabric.

```yaml
config:
  routingMode: "native"

routing:
  enabled: true
  protocol: "bgp"             # or "ospf"
  bfd:
    enabled: true
    minRxMs: 300
    minTxMs: 300
    detectMultiplier: 3
  controlPlaneVIP: "192.168.100.10"
  peers:
    - neighbor_address: "192.168.100.2"
      remote_as: 65000
      description: "TOR-1"
      bfd_enabled: true
```

---

## L4 Load Balancing

NovaNet provides kube-proxy-free Kubernetes Service load balancing via eBPF cgroup programs attached at the socket level. Supports ClusterIP, NodePort, ExternalIP, and LoadBalancer service types with direct server return and connection affinity.

```yaml
l4lb:
  enabled: true
```

---

## Container Images

Multi-arch images (`linux/amd64` + `linux/arm64`) are published to GHCR on every tagged release:

```
ghcr.io/azrtydxb/novanet/novanet-agent:<version>
ghcr.io/azrtydxb/novanet/novanet-dataplane:<version>
```

---

## Development

### Build from Source

```bash
# Go binaries (agent, CNI, CLI)
make build

# Rust dataplane via Docker (required on macOS)
make build-docker-rust

# Rust dataplane natively (Linux only)
make build-rust-native

# Run tests
make test
```

### Project Layout

```
cmd/                  Go entry points (agent, cni, ctl, operator)
internal/             Go packages (ipam, policy, tunnel, identity, routing, service, ...)
dataplane/            Rust workspace (dataplane, ebpf, common)
deploy/helm/novanet/  Kubernetes Helm chart
api/v1/               Protobuf API definitions
tests/                Integration tests and benchmarks
docs/                 Documentation
```

See the [Development Guide](docs/development.md) for the full setup instructions.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Installation Guide](docs/installation.md) | Prerequisites, Helm install, platform-specific notes |
| [Configuration Reference](docs/configuration.md) | All Helm values, config file schema, environment variables |
| [Architecture](docs/architecture.md) | Data paths, eBPF programs, identity model, tunnel MAC design |
| [CLI Reference](docs/cli-reference.md) | All `novanetctl` commands with flags and output examples |
| [API Reference](docs/api-reference.md) | gRPC services, protobuf messages, eBPF map schemas |
| [Native Routing](docs/novaroute-integration.md) | Native routing setup with BGP/OSPF/BFD |
| [Development Guide](docs/development.md) | Building from source, testing, contributing |
| [Troubleshooting](docs/troubleshooting.md) | Common issues, debugging commands, log analysis |

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
