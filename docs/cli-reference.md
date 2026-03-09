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

Inspect routing state (native routing mode only). All subcommands query the agent's integrated routing manager, which communicates with the FRR sidecar.

#### routing status

Show the current routing mode, FRR connection state, and tunnel protocol.

```bash
novanetctl routing status
```

Example output:

```
Routing Status
==============

Routing Mode:       native
Routing Connected:  true
Tunnel Protocol:    geneve
```

#### routing peers

Show BGP peer sessions with state, prefix counts, BFD status, uptime, and owner.

```bash
novanetctl routing peers
```

Example output:

```
NEIGHBOR        REMOTE AS  STATE        PFX RECV  PFX SENT  BFD  UPTIME    OWNER
192.168.100.2   65000      Established  14        16        up   01:30:00  novanet
192.168.100.3   65000      Established  14        16        up   01:30:00  novanet
192.168.100.11  65011      Established  15        16        up   01:15:00  novanet
192.168.100.12  65012      Established  15        16        up   01:10:00  novanet
```

#### routing prefixes

Show advertised route prefixes from the intent store.

```bash
novanetctl routing prefixes
```

Example output:

```
PREFIX             PROTOCOL  STATE       OWNER
10.42.1.0/24       bgp       advertised  novanet
192.168.100.10/32  bgp       advertised  novanet
```

#### routing bfd

Show BFD session state with timers, detect multiplier, and uptime.

```bash
novanetctl routing bfd
```

Example output:

```
PEER ADDRESS    STATUS  MIN RX  MIN TX  DETECT MULT  UPTIME   OWNER
192.168.100.2   up      300ms   300ms   3            0h6m9s   novanet
192.168.100.3   up      300ms   300ms   3            0h6m11s  novanet
192.168.100.11  up      300ms   300ms   3            0h5m31s  novanet
192.168.100.12  up      300ms   300ms   3            0h2m39s  novanet
```

#### routing ospf

Show OSPF neighbor adjacencies with state, interface, and owner.

```bash
novanetctl routing ospf
```

Example output (when OSPF is configured):

```
NEIGHBOR ID  ADDRESS       INTERFACE  STATE  OWNER
10.0.0.1     192.168.1.1   eth0       Full   novanet
10.0.0.2     192.168.1.2   eth0       Full   novanet
```

#### routing events

Stream real-time routing events (BGP state changes, BFD transitions, prefix updates).

```bash
novanetctl routing events [flags]
```

| Flag | Description |
|------|-------------|
| `--owner` | Filter events by owner name |

Example output:

```
Streaming routing events (Ctrl+C to stop)...

[10:15:03.123] bgp_peer_established   owner=novanet    peer 192.168.100.2 AS 65000 established
[10:15:04.456] bfd_session_up         owner=novanet    BFD session to 192.168.100.2 is up
[10:15:05.789] prefix_advertised      owner=novanet    advertised 10.42.1.0/24 via bgp
```

---

### ebpf

Inspect eBPF Services state. These commands connect to the EBPFServices gRPC API via a dedicated Unix socket (default: `/run/novanet/ebpf-services.sock`).

| Flag | Default | Description |
|------|---------|-------------|
| `--ebpf-socket` | `/run/novanet/ebpf-services.sock` | Path to the eBPF Services gRPC socket |

#### ebpf sockmap status

Show SOCKMAP acceleration statistics.

```bash
novanetctl ebpf sockmap status
```

Example output:

```
SOCKMAP Stats
=============

Redirected:      1284032
Fallback:        512
Active Sockets:  48
```

#### ebpf mesh list

List active mesh redirect entries (SK_LOOKUP).

```bash
novanetctl ebpf mesh list
```

Example output:

```
MESH REDIRECTS
==============

IP              PORT  REDIRECT PORT
10.42.1.5       80    15001
10.42.1.5       443   15001
10.42.2.8       8080  15001
```

#### ebpf ratelimit stats

Show rate limit statistics for a specific CIDR.

```bash
novanetctl ebpf ratelimit stats --cidr 10.0.0.0/8
```

| Flag | Description |
|------|-------------|
| `--cidr` | CIDR to query rate limit stats for (required) |

Example output:

```
RATE LIMIT STATS
================

CIDR:     10.0.0.0/8
Allowed:  50432
Denied:   1203
```

#### ebpf health list

Show backend health status from passive TCP monitoring.

```bash
novanetctl ebpf health list [flags]
```

| Flag | Description |
|------|-------------|
| `--ip` | Filter by backend IP (optional) |
| `--port` | Filter by backend port (optional) |

Example output:

```
BACKEND HEALTH
==============

IP           PORT  TOTAL  SUCCESS  FAILED  TIMEOUT  AVG RTT   FAILURE RATE
10.42.1.5    80    5024   4998     20      6        1.23ms    0.52%
10.42.2.8    8080  3201   3180     15      6        2.45ms    0.66%
10.42.3.12   443   8102   8090     8       4        0.89ms    0.15%
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
POD=$(kubectl get pods -n novanet-system -l app.kubernetes.io/name=novanet \
  --field-selector spec.nodeName=$(hostname) -o name | head -1)

# Execute inside the pod
kubectl exec -n novanet-system $POD -c agent -- novanetctl status
kubectl exec -n novanet-system $POD -c agent -- novanetctl flows
kubectl exec -n novanet-system $POD -c agent -- novanetctl routing peers
```

---

## Next Steps

- [Configuration Reference](configuration.md) -- All config options
- [Troubleshooting](troubleshooting.md) -- Debugging with novanetctl
- [API Reference](api-reference.md) -- gRPC protocol details
