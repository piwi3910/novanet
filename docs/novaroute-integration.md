# Native Routing (BGP/OSPF)

This guide covers NovaNet's native routing mode, which eliminates tunnel encapsulation for near line-rate pod networking performance using BGP or OSPF route advertisement via FRR.

---

## Overview

In native routing mode, NovaNet does not create overlay tunnels (Geneve/VXLAN). Instead, the NovaNet agent manages route advertisement directly through an integrated routing manager that configures FRR (Free Range Routing) running as a sidecar container in the NovaNet DaemonSet.

The data path becomes:

```
Pod A --> TC egress --> policy check --> kernel routing table --> underlay fabric --> kernel routing table --> TC ingress --> policy check --> Pod B
```

No encapsulation overhead. Near line-rate performance. The underlay fabric learns pod routes via BGP or OSPF and forwards traffic natively.

### Architecture

Routing is fully integrated into the NovaNet DaemonSet. Each NovaNet pod contains:

| Container | Role |
|-----------|------|
| `novanet-agent` | Management plane: IPAM, identity, policy, routing manager, CNI handler |
| `novanet-dataplane` | eBPF program loader and map manager |
| `frr` | FRR sidecar running BGP, OSPF, and BFD daemons |

The agent communicates with FRR via the FRR management socket (in-process function calls to the routing manager, which writes FRR configuration). There is no gRPC socket, no authentication token, and no separate service to deploy.

### Responsibilities

| Responsibility | NovaNet Agent | FRR Sidecar |
|---------------|---------------|-------------|
| Pod networking (veth, IPAM) | Yes | No |
| L3/L4 policy enforcement | Yes | No |
| Route advertisement (BGP/OSPF) | Configures | Executes |
| BGP session management | Configures | Executes |
| BFD failure detection | Configures | Executes |
| Tunnel management (overlay) | Yes | No |
| eBPF dataplane | Yes | No |

---

## Prerequisites

1. **BGP or OSPF-capable network fabric** (ToR switches, spine switches, or route reflectors)
2. **FRR sidecar enabled** in the NovaNet Helm values (enabled automatically when `routingMode` is `"native"`)

Verify the FRR sidecar is running:

```bash
kubectl get pods -n novanet-system -l app.kubernetes.io/name=novanet -o wide
kubectl logs -n novanet-system <novanet-pod> -c frr
```

---

## Configuration

### Helm Values

Enable native routing in your NovaNet Helm values:

```yaml
config:
  routingMode: "native"

routing:
  enabled: true
  protocol: "bgp"
  frr_socket_dir: "/run/frr"
```

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `routing.enabled` | Yes | Must be `true` for native routing mode. |
| `routing.protocol` | Yes | Routing protocol: `"bgp"` or `"ospf"`. |
| `routing.frr_socket_dir` | No | Path to the FRR management socket directory. Default: `"/run/frr"` |

---

## eBGP Setup

### Per-Node AS Assignment

NovaNet configures BGP with a unique per-node Autonomous System Number (ASN):

```
ASN = 65000 + (last octet of node IP)
```

For example:
- Node `10.0.0.10` gets ASN `65010`
- Node `10.0.0.11` gets ASN `65011`
- Node `10.0.0.12` gets ASN `65012`

This enables eBGP peering between nodes and with ToR switches. The ASN range 64512-65534 is reserved for private use (RFC 6996).

### ToR/Spine Switch Peering

Each node's FRR sidecar establishes BGP sessions with the configured ToR peers:

```
Node (ASN 65010) <--eBGP--> ToR Switch 1 (ASN 65000)
Node (ASN 65010) <--eBGP--> ToR Switch 2 (ASN 65000)
```

Configure your ToR switches to:

1. Accept BGP connections from the node IP range
2. Accept routes for the cluster PodCIDR (e.g., `10.42.0.0/16`)
3. Redistribute learned routes to the spine layer or other ToR switches

Example ToR configuration (vendor-neutral pseudocode):

```
router bgp 65000
  neighbor 10.0.0.10 remote-as 65010
  neighbor 10.0.0.11 remote-as 65011
  neighbor 10.0.0.12 remote-as 65012
  address-family ipv4 unicast
    neighbor 10.0.0.10 prefix-list PODCIDR in
    neighbor 10.0.0.11 prefix-list PODCIDR in
    neighbor 10.0.0.12 prefix-list PODCIDR in

ip prefix-list PODCIDR permit 10.42.0.0/16 le 24
```

### Route Advertisement

Each node advertises its PodCIDR via the integrated routing manager:

```
Node 1 (10.0.0.10): advertises 10.42.1.0/24
Node 2 (10.0.0.11): advertises 10.42.2.0/24
Node 3 (10.0.0.12): advertises 10.42.3.0/24
```

The ToR/spine fabric learns these routes and can forward pod traffic directly between nodes without any encapsulation.

### Node-to-Node Peering

In addition to ToR peering, NovaNet automatically discovers other cluster nodes via the Kubernetes Node watcher and configures eBGP peering between them through the routing manager. This enables direct node-to-node route exchange without relying solely on the ToR fabric.

When a new node joins the cluster:
1. NovaNet's node watcher detects the new Node object
2. The routing manager configures a new BGP peer in FRR pointing to the new node's IP
3. The eBGP session establishes and routes are exchanged

When a node leaves the cluster:
1. NovaNet's node watcher detects the Node deletion
2. The routing manager removes the BGP peer configuration from FRR
3. Routes from that node are withdrawn

---

## How It Works: Lifecycle

### Agent Startup

When the NovaNet agent starts in native routing mode, it performs the following sequence:

```
1. Load config, verify routing_mode = "native"
2. Initialize the integrated routing manager
3. Connect to FRR via the management socket
4. Configure BGP:
   a. Set local AS number (65000 + last octet of node IP)
   b. Set router ID (node IP)
5. Establish ToR peers from config (address + remote ASN)
6. Advertise this node's PodCIDR
7. Start Kubernetes node watcher
8. Discover and peer with other cluster nodes automatically
9. Begin normal operation (CNI handling, policy enforcement)
```

### Steady State

During normal operation:

- New pods are assigned IPs from the node's PodCIDR (already advertised)
- Pod-to-pod traffic across nodes is routed by the underlay fabric
- Identity for policy enforcement is resolved via endpoint map lookup (no in-band metadata)
- FRR handles all BGP keepalives, route refresh, and BFD

### Agent Shutdown

On SIGTERM (graceful shutdown):

```
1. Stop accepting new CNI requests
2. Withdraw PodCIDR prefix via the routing manager
3. Wait for FRR to propagate withdrawal (brief delay)
4. Shut down FRR sidecar
5. Exit
```

The prefix withdrawal ensures that the fabric stops sending traffic to this node before the agent exits, minimizing packet loss during drain.

---

## Identity in Native Routing Mode

In overlay mode, Geneve TLV headers carry identity metadata in-band. In native routing mode, there is no tunnel header, so identity must be resolved differently.

**How it works:**

1. A packet arrives at the destination node via underlay routing
2. TC ingress on the pod veth extracts the source IP
3. The source IP is looked up in the eBPF endpoint map
4. The endpoint map returns the source identity ID
5. Policy is evaluated using (source identity, destination identity, protocol, port)

This is a single eBPF hash map read -- O(1) lookup taking nanoseconds. The endpoint map is kept fresh by the management plane reconciler with a sub-second staleness window.

---

## Troubleshooting

### Check Routing Status

```bash
# Check routing status via novanetctl
novanetctl routing status

# View agent logs for routing-related messages
kubectl logs -n novanet-system <novanet-pod> -c novanet-agent | grep -i routing
```

Look for:
- `"routing manager initialized"` confirming the routing subsystem started
- `"prefix advertised"` messages confirming PodCIDR advertisement
- Any error messages about FRR connection failures

### Verify BGP Sessions

Check FRR's BGP state via the FRR sidecar:

```bash
# Enter the FRR sidecar in the NovaNet pod
kubectl exec -n novanet-system <novanet-pod> -c frr -- vtysh -c "show bgp summary"
```

Expected output shows established sessions with ToR peers and other nodes:

```
Neighbor        V  AS   MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down    State/PfxRcd
10.0.0.1        4  65000     120      115       5    0     0  01:30:00   3
10.0.0.2        4  65000     118      114       5    0     0  01:30:00   3
10.0.0.11       4  65011      95       92       5    0     0  01:15:00   1
10.0.0.12       4  65012      90       88       5    0     0  01:10:00   1
```

If a session shows `Active` or `Connect` instead of a prefix count, the peering is not established. Common causes:

- Firewall blocking TCP port 179 (BGP)
- Incorrect ASN configuration on the ToR switch
- IP reachability issue between node and ToR

### Check Advertised Routes

```bash
kubectl exec -n novanet-system <novanet-pod> -c frr -- vtysh -c "show bgp ipv4 unicast"
```

You should see your node's PodCIDR and routes from other nodes:

```
   Network          Next Hop         Metric  LocPrf  Weight  Path
*> 10.42.1.0/24     0.0.0.0               0         32768   i
*> 10.42.2.0/24     10.0.0.11             0             0   65011 i
*> 10.42.3.0/24     10.0.0.12             0             0   65012 i
```

### Show BGP/OSPF Peers via CLI

```bash
# Show peers
novanetctl routing peers

# Show advertised prefixes
novanetctl routing prefixes
```

### Verify Kernel Routes

Check that BGP-learned routes are installed in the kernel routing table:

```bash
ip route show | grep 10.42
```

Expected output:

```
10.42.1.0/24 dev eth0 proto kernel scope link src 10.0.0.10
10.42.2.0/24 via 10.0.0.11 dev eth0 proto bgp metric 20
10.42.3.0/24 via 10.0.0.12 dev eth0 proto bgp metric 20
```

If routes are missing, check:
- FRR logs for route installation errors: `kubectl logs -n novanet-system <novanet-pod> -c frr`
- Kernel routing table capacity (`sysctl net.ipv4.route.max_size`)

### Common Issues

**Routing manager fails to initialize:**
- Verify the FRR sidecar is running: `kubectl get pods -n novanet-system -o wide`
- Check FRR logs: `kubectl logs -n novanet-system <novanet-pod> -c frr`
- Check agent logs for routing initialization errors

**Routes not propagating to other nodes:**
- Verify BGP sessions are established (see above)
- Check that ToR switches are redistributing routes
- Verify no prefix filters are blocking PodCIDR routes

**Packets dropped after route is installed:**
- Verify `rp_filter` (reverse path filtering) is not dropping asymmetric traffic:

```bash
sysctl net.ipv4.conf.all.rp_filter
# Should be 0 (disabled) or 2 (loose mode)
```

- Check that the return path is also routed correctly

---

## OSPF Mode

NovaNet also supports OSPF as an alternative to BGP, configured via `routing.protocol: "ospf"`. In OSPF mode:

- The routing manager injects PodCIDR routes into the configured OSPF area via FRR
- No per-node ASN configuration is needed
- Suitable for environments where the underlay runs OSPF instead of BGP

The integration flow is identical -- only the FRR protocol handling changes. The routing manager abstracts the protocol differences.

---

## Next Steps

- [Installation Guide](installation.md) -- Getting started
- [Configuration Reference](configuration.md) -- All configuration options
- [Troubleshooting Guide](troubleshooting.md) -- Debugging connectivity issues
