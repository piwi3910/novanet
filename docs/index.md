<p align="center">
  <img src="assets/novanet-logo-light.svg" alt="NovaNet" width="480">
</p>

**NovaNet** is a high-performance, eBPF-based Kubernetes CNI providing secure pod-to-pod connectivity, identity-based L3/L4 network policy enforcement, native BGP/OSPF/BFD routing, L4 socket-based load balancing, and real-time flow visibility.

---

## Getting Started

- [Installation Guide](installation.md) -- Prerequisites, Helm install, platform-specific notes (K3s, Kind)
- [Configuration Reference](configuration.md) -- All Helm values, config file schema, environment variables

## Architecture and Design

- [Architecture](architecture.md) -- Data paths, eBPF programs, identity model, tunnel MAC design
- [API Reference](api-reference.md) -- gRPC services, protobuf messages, eBPF map schemas

## Operations

- [CLI Reference](cli-reference.md) -- All `novanetctl` commands with flags and output examples
- [Native Routing](novaroute-integration.md) -- Native routing setup with BGP/OSPF/BFD
- [Troubleshooting](troubleshooting.md) -- Common issues, debugging commands, log analysis

## Development

- [Development Guide](development.md) -- Building from source, testing, contributing

---

## The Nova Stack

| Component | Role |
|-----------|------|
| [NovaEdge](https://github.com/azrtydxb/novaedge) | Ingress load balancing, reverse proxy, SD-WAN gateway |
| **NovaNet** | Pod networking, L3/L4 policy, native routing (BGP/OSPF/BFD), L4 LB, observability |

> NovaRoute was merged into NovaNet in v1.13.0. All routing functionality is now integrated. The [NovaRoute repository](https://github.com/azrtydxb/NovaRoute) has been archived.

---

[GitHub Repository](https://github.com/azrtydxb/novanet) | [Apache 2.0 License](https://github.com/azrtydxb/novanet/blob/main/LICENSE)
