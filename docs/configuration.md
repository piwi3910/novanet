# NovaNet Configuration Reference

This document covers all configuration options for NovaNet, including Helm values, the novanet.json config file, and environment variables.

---

## Helm Values Reference

The following table lists all configurable values in the NovaNet Helm chart (`deploy/helm/novanet/values.yaml`).

### Image Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `image.agent.repository` | `ghcr.io/piwi3910/novanet/novanet-agent` | Container image for the Go management plane agent |
| `image.agent.tag` | `latest` | Image tag for the agent |
| `image.agent.pullPolicy` | `IfNotPresent` | Image pull policy for the agent. Use `Always` during development. |
| `image.dataplane.repository` | `ghcr.io/piwi3910/novanet/novanet-dataplane` | Container image for the Rust eBPF dataplane |
| `image.dataplane.tag` | `latest` | Image tag for the dataplane |
| `image.dataplane.pullPolicy` | `IfNotPresent` | Image pull policy for the dataplane |

### Core Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `config.clusterCIDR` | `"10.42.0.0/16"` | The cluster-wide CIDR from which PodCIDRs are allocated. Must match the cluster's `--cluster-cidr` setting. |
| `config.nodeCIDRMaskSize` | `24` | Subnet mask size for per-node PodCIDR allocation. A `/24` provides 254 pod IPs per node. |
| `config.tunnelProtocol` | `"geneve"` | Tunnel encapsulation protocol for overlay mode. `"geneve"` supports identity metadata in TLV options. `"vxlan"` provides broader hardware offload compatibility. |
| `config.routingMode` | `"overlay"` | Networking mode. `"overlay"` creates tunnels between nodes. `"native"` uses underlay routing via NovaRoute (requires NovaRoute). |
| `config.logLevel` | `"info"` | Log verbosity level. One of `"debug"`, `"info"`, `"warn"`, `"error"`. |

### NovaRoute Integration

| Key | Default | Description |
|-----|---------|-------------|
| `novaroute.enabled` | `false` | Enable NovaRoute integration for native routing. Must be `true` when `config.routingMode` is `"native"`. |
| `novaroute.socket` | `"/run/novaroute/novaroute.sock"` | Path to the NovaRoute gRPC Unix socket. |
| `novaroute.token` | `""` | Authentication token for registering with NovaRoute as the `"novanet"` owner. Must be set to a real token before enabling NovaRoute. |
| `novaroute.protocol` | `"bgp"` | Routing protocol to use. `"bgp"` for eBGP peering or `"ospf"` for OSPF area injection. |


### CNI Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `cni.binPath` | `"/opt/cni/bin"` | Directory where the CNI binary is installed on the host. |
| `cni.confPath` | `"/etc/cni/net.d"` | Directory where the CNI configuration file is written on the host. |

### Egress Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `egress.masqueradeEnabled` | `true` | Enable SNAT/masquerade for pod-to-external traffic. When enabled, pod source IPs are rewritten to the node IP for traffic leaving the cluster. |

### Policy Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `policy.defaultDeny` | `false` | Enable cluster-wide default-deny policy. When `false` (default), pods without any selecting NetworkPolicy allow all traffic (standard Kubernetes behavior). When `true`, all traffic is denied unless explicitly allowed by a NetworkPolicy. |

### Metrics Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `metrics.enabled` | `true` | Enable the Prometheus metrics endpoint on the agent. |
| `metrics.port` | `9103` | Port for the Prometheus metrics HTTP endpoint. |

### Resource Management

| Key | Default | Description |
|-----|---------|-------------|
| `resources.agent.requests.cpu` | `"100m"` | CPU request for the agent container. |
| `resources.agent.requests.memory` | `"128Mi"` | Memory request for the agent container. |
| `resources.agent.limits.cpu` | `"500m"` | CPU limit for the agent container. |
| `resources.agent.limits.memory` | `"256Mi"` | Memory limit for the agent container. |
| `resources.dataplane.requests.cpu` | `"100m"` | CPU request for the dataplane container. |
| `resources.dataplane.requests.memory` | `"64Mi"` | Memory request for the dataplane container. |
| `resources.dataplane.limits.cpu` | `"500m"` | CPU limit for the dataplane container. |
| `resources.dataplane.limits.memory` | `"128Mi"` | Memory limit for the dataplane container. |

### Scheduling

| Key | Default | Description |
|-----|---------|-------------|
| `tolerations` | `[{"operator": "Exists", "effect": "NoSchedule"}, {"operator": "Exists", "effect": "NoExecute"}]` | Tolerations applied to the DaemonSet pods. Defaults tolerate all taints with NoSchedule and NoExecute effects so NovaNet runs on every node. |
| `nodeSelector` | `{kubernetes.io/os: linux}` | Node selector for the DaemonSet. Defaults to Linux nodes only. |
| `priorityClassName` | `"system-node-critical"` | Priority class for NovaNet pods. CNI pods must be high priority to ensure networking is available for other workloads. |
| `updateStrategy.type` | `"RollingUpdate"` | DaemonSet update strategy. |
| `updateStrategy.rollingUpdate.maxUnavailable` | `1` | Maximum number of nodes updated simultaneously during a rolling update. |

---

## novanet.json Config File

The Helm chart generates a ConfigMap that is mounted as `/etc/novanet/novanet.json` inside the agent container. This file is generated from the Helm values and should not be edited directly in production. However, it is useful to understand the format for debugging.

### Full Schema

```json
{
  "listen_socket": "/run/novanet/novanet.sock",
  "cni_socket": "/run/novanet/cni.sock",
  "dataplane_socket": "/run/novanet/dataplane.sock",
  "cluster_cidr": "10.42.0.0/16",
  "node_cidr_mask_size": 24,
  "tunnel_protocol": "geneve",
  "routing_mode": "overlay",
  "novaroute": {
    "socket": "/run/novaroute/novaroute.sock",
    "token": "novanet-secret-token",
    "protocol": "bgp"
  },
  "egress": {
    "masquerade_enabled": true
  },
  "policy": {
    "default_deny": false
  },
  "log_level": "info",
  "metrics_address": ":9103"
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `listen_socket` | string | Unix socket path where the agent listens for CLI connections. |
| `cni_socket` | string | Unix socket path where the agent listens for CNI binary requests. |
| `dataplane_socket` | string | Unix socket path for agent-to-dataplane gRPC communication. |
| `cluster_cidr` | string | Cluster-wide pod CIDR in notation like `"10.42.0.0/16"`. |
| `node_cidr_mask_size` | int | Subnet mask size for per-node PodCIDR allocation (e.g., `24`). |
| `tunnel_protocol` | string | `"geneve"` or `"vxlan"`. Only used in overlay mode. |
| `routing_mode` | string | `"overlay"` or `"native"`. |
| `novaroute.socket` | string | Path to NovaRoute's gRPC Unix socket. Only used in native mode. |
| `novaroute.token` | string | Token for authenticating with NovaRoute. Only used in native mode. |
| `novaroute.protocol` | string | Routing protocol: `"bgp"` or `"ospf"`. Only used in native mode. |
| `egress.masquerade_enabled` | bool | Enable SNAT/masquerade for pod-to-external traffic. |
| `policy.default_deny` | bool | Enable cluster-wide default-deny policy. |
| `log_level` | string | One of `"debug"`, `"info"`, `"warn"`, `"error"`. |
| `metrics_address` | string | Address for the Prometheus metrics HTTP endpoint. |

### Validation Rules

The agent validates the config on startup and exits with a clear error if any rule is violated:

- `cluster_cidr` must be a valid CIDR notation
- `tunnel_protocol` must be `"geneve"` or `"vxlan"`
- `routing_mode` must be `"overlay"` or `"native"`
- If `routing_mode` is `"native"`, `novaroute.socket` must be set and `novaroute.token` must be non-empty

---

## Environment Variables

The following environment variables are set automatically by the Helm chart via the DaemonSet pod spec (using the downward API and ConfigMap). They can also be used to override config file values.

| Variable | Source | Description |
|----------|--------|-------------|
| `NOVANET_NODE_NAME` | Downward API (`spec.nodeName`) | Name of the Kubernetes node this agent is running on. Used to identify the node in Kubernetes API queries. |
| `NOVANET_NODE_IP` | Downward API (`status.hostIP`) | IP address of the node. Used as the tunnel source IP in overlay mode and as the router ID in native mode. |
| `NOVANET_POD_CIDR` | Kubernetes Node spec | The PodCIDR allocated to this node by the cluster. Discovered via the Kubernetes API using `NOVANET_NODE_NAME`. |
| `NOVANET_CLUSTER_CIDR` | ConfigMap | The cluster-wide pod CIDR (e.g., `10.42.0.0/16`). Overrides `cluster_cidr` in the config file. |
| `NOVANET_ROUTING_MODE` | ConfigMap | Routing mode (`overlay` or `native`). Overrides `routing_mode` in the config file. |
| `NOVANET_TUNNEL_PROTOCOL` | ConfigMap | Tunnel protocol (`geneve` or `vxlan`). Overrides `tunnel_protocol` in the config file. |

The config file supports environment variable expansion. Any value in `novanet.json` containing `${VAR_NAME}` will be replaced with the environment variable's value at load time.

---

## Example Configurations

### Overlay Mode with Geneve (Default)

This is the simplest configuration. Works on any network without special requirements.

```yaml
# values-overlay-geneve.yaml
config:
  clusterCIDR: "10.42.0.0/16"
  nodeCIDRMaskSize: 24
  tunnelProtocol: "geneve"
  routingMode: "overlay"
  logLevel: "info"

novaroute:
  enabled: false

egress:
  masqueradeEnabled: true

policy:
  defaultDeny: false

metrics:
  enabled: true
  port: 9103
```

Install:

```bash
helm install novanet ./deploy/helm/novanet \
  -n nova-system \
  --create-namespace \
  -f values-overlay-geneve.yaml
```

### Native Routing with NovaRoute and BGP

High-performance configuration using BGP to distribute pod routes. Requires NovaRoute and a BGP-capable network.

```yaml
# values-native-bgp.yaml
config:
  clusterCIDR: "10.42.0.0/16"
  nodeCIDRMaskSize: 24
  routingMode: "native"
  logLevel: "info"

novaroute:
  enabled: true
  socket: "/run/novaroute/novaroute.sock"
  token: "novanet-auth-token"
  protocol: "bgp"

egress:
  masqueradeEnabled: true

policy:
  defaultDeny: false

metrics:
  enabled: true
  port: 9103
```

Install:

```bash
helm install novanet ./deploy/helm/novanet \
  -n nova-system \
  --create-namespace \
  -f values-native-bgp.yaml
```

### Security-Hardened with Default Deny

For production environments requiring strict network isolation.

```yaml
# values-secure.yaml
config:
  clusterCIDR: "10.42.0.0/16"
  nodeCIDRMaskSize: 24
  tunnelProtocol: "geneve"
  routingMode: "overlay"
  logLevel: "warn"

novaroute:
  enabled: false

egress:
  masqueradeEnabled: true

policy:
  defaultDeny: true

metrics:
  enabled: true
  port: 9103

resources:
  agent:
    requests:
      cpu: "200m"
      memory: "256Mi"
    limits:
      cpu: "1000m"
      memory: "1Gi"
  dataplane:
    requests:
      cpu: "200m"
      memory: "128Mi"
    limits:
      cpu: "1000m"
      memory: "512Mi"
```

**Important:** When `policy.defaultDeny` is `true`, all pod-to-pod traffic is denied by default. You must create NetworkPolicy objects to allow required communication paths. At minimum, you will need policies for:

- DNS resolution (allow pods to reach CoreDNS on port 53 UDP/TCP)
- Kubernetes API server access (for pods that need it)
- Application-specific ingress and egress rules

### Custom Egress Policies

Example restricting egress for a specific namespace while allowing others:

```yaml
# values-egress-restricted.yaml
config:
  clusterCIDR: "10.42.0.0/16"
  routingMode: "overlay"

egress:
  masqueradeEnabled: true
```

Egress restrictions are applied via standard Kubernetes NetworkPolicy objects:

```yaml
# Deny all egress from the "restricted" namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-egress
  namespace: restricted
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress: []
---
# Allow only DNS and specific external CIDRs
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-and-api
  namespace: restricted
spec:
  podSelector: {}
  policyTypes:
    - Egress
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: kube-system
      ports:
        - protocol: UDP
          port: 53
        - protocol: TCP
          port: 53
    - to:
        - ipBlock:
            cidr: 203.0.113.0/24
      ports:
        - protocol: TCP
          port: 443
```

---

## Socket Paths

NovaNet uses Unix domain sockets for all inter-component communication:

| Socket | Default Path | Purpose |
|--------|-------------|---------|
| Agent listen | `/run/novanet/novanet.sock` | CLI (`novanetctl`) connects here |
| CNI | `/run/novanet/cni.sock` | CNI binary connects here during pod setup |
| Dataplane | `/run/novanet/dataplane.sock` | Agent-to-dataplane gRPC communication |
| NovaRoute | `/run/novaroute/novaroute.sock` | Agent connects here for native routing |

All sockets under `/run/novanet/` are created by the NovaNet agent. The NovaRoute socket is created by the NovaRoute daemon and must exist before the agent starts in native routing mode.

---

## Next Steps

- [Installation Guide](installation.md) -- Getting started
- [NovaRoute Integration Guide](novaroute-integration.md) -- Native routing setup
- [Troubleshooting Guide](troubleshooting.md) -- Debugging issues
