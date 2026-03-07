<p align="center">
  <img src="assets/novanet-logo-light.svg" alt="NovaNet" width="480">
</p>

**NovaNet** is a high-performance, eBPF-based Kubernetes CNI providing secure pod-to-pod connectivity, identity-based L3/L4 network policy enforcement, and real-time flow visibility.

---

## Getting Started

- [Installation Guide](installation.md) -- Prerequisites, Helm install, platform-specific notes (K3s, Kind)
- [Configuration Reference](configuration.md) -- All Helm values, config file schema, environment variables

## Architecture and Design

- [Architecture](architecture.md) -- Data paths, eBPF programs, identity model, tunnel MAC design
- [API Reference](api-reference.md) -- gRPC services, protobuf messages, eBPF map schemas

## Operations

- [CLI Reference](cli-reference.md) -- All `novanetctl` commands with flags and output examples
- [NovaRoute Integration](novaroute-integration.md) -- Native routing setup with BGP/OSPF
- [Troubleshooting](troubleshooting.md) -- Common issues, debugging commands, log analysis

## Development

- [Development Guide](development.md) -- Building from source, testing, contributing

---

## The Nova Stack

| Component | Role |
|-----------|------|
| [NovaEdge](https://github.com/azrtydxb/novaedge) | Load balancing, reverse proxy, VIP controller, SD-WAN gateway |
| [NovaRoute](https://github.com/azrtydxb/NovaRoute) | Node-local routing control plane (BGP/OSPF/BFD via FRR) |
| **NovaNet** | Pod networking, L3/L4 policy, observability |

---

[GitHub Repository](https://github.com/azrtydxb/novanet) | [Apache 2.0 License](https://github.com/azrtydxb/novanet/blob/main/LICENSE)
