# NovaNet CLI Reference

`novanetctl` is the command-line tool for inspecting and managing a running NovaNet agent. It communicates with the agent and dataplane via gRPC over Unix sockets.

---

## Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--agent-socket` | `/run/novanet/novanet.sock` | Path to the agent gRPC socket |
| `--dataplane-socket` | `/run/novanet/dataplane.sock` | Path to the dataplane gRPC socket |

When running inside a NovaNet pod, the defaults work automatically. From the host, you may need to specify the socket paths.

---

## Commands

### status

Show the overall status of the agent and dataplane.

```bash
novanetctl status [flags]
```

| Flag | Description |
|------|-------------|
| `--output / -o` | Output format: `table` (default) or `json` |

Example output:

```
NovaNet Agent Status
  Node IP:           192.168.100.21
  Pod CIDR:          10.42.1.0/24
  Cluster CIDR:      10.42.0.0/16
  Mode:              overlay
  Tunnel Protocol:   geneve
  Endpoints:         12
  Policies:          48
  Identities:        6
  Tunnels:           4
  Attached Programs: 26
  Dataplane:         connected
  Routing:           disabled (overlay mode)
```

---

### flows

Stream real-time flow events from the eBPF dataplane.

```bash
novanetctl flows [flags]
```

| Flag | Description |
|------|-------------|
| `--identity <id>` | Filter events by source or destination identity |

> **Note:** To view only dropped packets, use the dedicated `drops` subcommand instead of a flag on `flows`.

Example output:

```
TIMESTAMP            SRC_IP          DST_IP          PROTO  SRC_PORT  DST_PORT  SRC_ID  DST_ID  VERDICT
2026-02-27 10:15:03  10.42.1.5       10.42.2.8       TCP    45032     80        1001    1002    ALLOW
2026-02-27 10:15:03  10.42.1.5       10.42.3.12      TCP    45033     443       1001    1003    ALLOW
2026-02-27 10:15:04  10.42.2.8       10.42.1.5       TCP    80        45032     1002    1001    ALLOW
```

---

### drops

Watch denied packets only. Shortcut for `flows --drops-only`.

```bash
novanetctl drops
```

Example output:

```
TIMESTAMP            SRC_IP          DST_IP          PROTO  SRC_PORT  DST_PORT  SRC_ID  DST_ID  DROP_REASON
2026-02-27 10:15:05  10.42.1.5       10.42.4.2       TCP    50001     3306      1001    1004    POLICY_DENIED
2026-02-27 10:15:06  10.42.3.12      10.42.1.5       UDP    12345     53        1003    1001    NO_IDENTITY
```

Drop reasons:

| Code | Meaning |
|------|---------|
| `POLICY_DENIED` | No matching allow rule in the policy map |
| `NO_IDENTITY` | Source pod has no identity in the ENDPOINTS map |
| `NO_ROUTE` | No route to destination (native mode) |
| `NO_TUNNEL` | No tunnel entry for remote node (overlay mode) |
| `TTL_EXCEEDED` | IP TTL reached zero |

---

### tunnels

List active overlay tunnels (overlay mode only).

```bash
novanetctl tunnels
```

Example output:

```
NODE          NODE_IP         POD_CIDR        INTERFACE    IFINDEX  PROTOCOL
worker-21     192.168.100.21  10.42.1.0/24    nv_worker-21  8       geneve
worker-22     192.168.100.22  10.42.2.0/24    nv_worker-22  9       geneve
worker-23     192.168.100.23  10.42.3.0/24    nv_worker-23  10      geneve
```

---

### policy

Show compiled policy rules currently loaded in the eBPF map.

```bash
novanetctl policy
```

Example output:

```
SRC_IDENTITY  DST_IDENTITY  PROTOCOL  DST_PORT  ACTION
1001          1002          TCP       80        ALLOW
1001          1002          TCP       443       ALLOW
0             1005          TCP       53        ALLOW
0             1005          UDP       53        ALLOW
```

Identity `0` is the wildcard (matches any source).

---

### identity

Show pod-to-identity mappings.

```bash
novanetctl identity
```

Example output:

```
IDENTITY  LABELS                                    PODS
1001      app=frontend                              default/frontend-abc12, default/frontend-def34
1002      app=backend                               default/backend-ghi56
1003      app=redis                                 default/redis-jkl78
1005      k8s-app=kube-dns                          kube-system/coredns-abc12
```

---

### egress

Show egress policy rules.

```bash
novanetctl egress
```

Example output:

```
SRC_IDENTITY  DST_CIDR          PROTOCOL  DST_PORT  ACTION  SNAT_IP
1001          0.0.0.0/0         TCP       443       SNAT    192.168.100.21
1002          10.0.0.0/8        ANY       0         ALLOW   -
1003          0.0.0.0/0         ANY       0         DENY    -
```

---

### routing

Inspect and manage native routing state (native routing mode only).

#### routing status

Show the current routing mode, protocol, and FRR connection state.

```bash
novanetctl routing status
```

Example output:

```
Routing Status
  Mode:        native
  Protocol:    bgp
  FRR:         connected
  Local ASN:   65010
  Router ID:   10.0.0.10
  Peers:       4 (4 established)
  Prefixes:    1 advertised, 3 received
```

#### routing peers

Show BGP or OSPF peers and their session state. Queries FRR via vtysh.

```bash
novanetctl routing peers
```

Example output:

```
NEIGHBOR        AS      STATE         UP/DOWN     PREFIXES
10.0.0.1        65000   established   01:30:00    3
10.0.0.2        65000   established   01:30:00    3
10.0.0.11       65011   established   01:15:00    1
10.0.0.12       65012   established   01:10:00    1
```

#### routing prefixes

Show advertised and received route prefixes.

```bash
novanetctl routing prefixes
```

Example output:

```
TYPE          PREFIX           NEXT_HOP      AS_PATH
advertised    10.42.1.0/24     0.0.0.0       i
received      10.42.2.0/24     10.0.0.11     65011 i
received      10.42.3.0/24     10.0.0.12     65012 i
```

---

### metrics

Show summary statistics.

```bash
novanetctl metrics
```

---

### version

Print the novanetctl version.

```bash
novanetctl version
```

```
novanetctl version 0.1.0
```

---

## Running from the Host

To use novanetctl from outside the pod, find the socket path and connect:

```bash
# Find the novanet pod on this node
POD=$(kubectl get pods -n nova-system -l app.kubernetes.io/name=novanet \
  --field-selector spec.nodeName=$(hostname) -o name | head -1)

# Execute inside the pod
kubectl exec -n nova-system $POD -c agent -- novanetctl status
kubectl exec -n nova-system $POD -c agent -- novanetctl flows
```

---

## Next Steps

- [Configuration Reference](configuration.md) -- All config options
- [Troubleshooting](troubleshooting.md) -- Debugging with novanetctl
- [API Reference](api-reference.md) -- gRPC protocol details
