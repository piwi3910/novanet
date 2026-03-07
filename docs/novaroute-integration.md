# NovaRoute Integration Guide

This guide covers how NovaNet integrates with NovaRoute to provide native routing mode, eliminating tunnel encapsulation for near line-rate pod networking performance.

---

## Overview

In native routing mode, NovaNet does not create overlay tunnels (Geneve/VXLAN). Instead, it delegates route advertisement to **NovaRoute**, a per-node routing control plane that manages BGP, OSPF, and BFD sessions via FRR (Free Range Routing).

The data path becomes:

```
Pod A --> TC egress --> policy check --> kernel routing table --> underlay fabric --> kernel routing table --> TC ingress --> policy check --> Pod B
```

No encapsulation overhead. Near line-rate performance. The underlay fabric learns pod routes via BGP or OSPF and forwards traffic natively.

### Role Separation

NovaNet and NovaRoute have distinct responsibilities:

| Responsibility | NovaNet | NovaRoute |
|---------------|---------|-----------|
| Pod networking (veth, IPAM) | Yes | No |
| L3/L4 policy enforcement | Yes | No |
| Route advertisement (BGP/OSPF) | No | Yes |
| BGP session management | No | Yes |
| BFD failure detection | No | Yes |
| Tunnel management (overlay) | Yes | No |
| eBPF dataplane | Yes | No |

NovaNet is a **client** of NovaRoute. It never runs routing protocols directly.

---

## NovaRoute Architecture

NovaRoute runs as a DaemonSet with one pod per node. Each pod contains:

- **novaroute** -- Go control plane that manages FRR configuration and exposes a gRPC API
- **FRR** -- The routing suite that runs BGP, OSPF, and BFD daemons

NovaRoute exposes a gRPC API over a Unix socket at `/run/novaroute/novaroute.sock`. Clients like NovaNet register as "owners" and request route advertisements.

For detailed NovaRoute documentation, see [github.com/azrtydxb/NovaRoute](https://github.com/azrtydxb/NovaRoute).

---

## Prerequisites

1. **NovaRoute deployed as a DaemonSet** on every node where NovaNet runs
2. **BGP or OSPF-capable network fabric** (ToR switches, spine switches, or route reflectors)
3. **NovaRoute authentication token** configured for the `"novanet"` owner

Verify NovaRoute is running:

```bash
kubectl get pods -n novaroute -o wide
```

Verify the NovaRoute socket exists on each node:

```bash
ls -la /run/novaroute/novaroute.sock
```

---

## Configuration

### Helm Values

Enable native routing in your NovaNet Helm values:

```yaml
config:
  routingMode: "native"

novaroute:
  enabled: true
  socket: "/run/novaroute/novaroute.sock"
  token: "novanet-auth-token"
  protocol: "bgp"
```

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `novaroute.enabled` | Yes | Must be `true` for native routing mode. |
| `novaroute.socket` | Yes | Path to the NovaRoute gRPC Unix socket. Default: `/run/novaroute/novaroute.sock` |
| `novaroute.token` | Yes | Authentication token. NovaRoute validates this when NovaNet registers as owner `"novanet"`. |
| `novaroute.protocol` | Yes | Routing protocol: `"bgp"` or `"ospf"`. |

### Authentication

NovaRoute uses token-based authentication. When NovaNet registers, it sends:

- **Owner:** `"novanet"` -- identifies this client as the pod networking component
- **Token:** the configured authentication token

NovaRoute's owner policy for `"novanet"` restricts it to:

- **Subnet prefixes only** (e.g., `/24` PodCIDRs) -- host routes (`/32`) are NovaEdge's domain
- **Configurable CIDR allowlist** (e.g., only prefixes within `10.42.0.0/16`)

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

Each node's NovaRoute instance establishes BGP sessions with the configured ToR peers:

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

Each node advertises its PodCIDR via NovaRoute:

```
Node 1 (10.0.0.10): advertises 10.42.1.0/24
Node 2 (10.0.0.11): advertises 10.42.2.0/24
Node 3 (10.0.0.12): advertises 10.42.3.0/24
```

The ToR/spine fabric learns these routes and can forward pod traffic directly between nodes without any encapsulation.

### Node-to-Node Peering

In addition to ToR peering, NovaNet automatically discovers other cluster nodes via the Kubernetes Node watcher and configures eBGP peering between them through NovaRoute. This enables direct node-to-node route exchange without relying solely on the ToR fabric.

When a new node joins the cluster:
1. NovaNet's node watcher detects the new Node object
2. The agent configures a new BGP peer via NovaRoute pointing to the new node's IP
3. The eBGP session establishes and routes are exchanged

When a node leaves the cluster:
1. NovaNet's node watcher detects the Node deletion
2. The agent removes the BGP peer configuration via NovaRoute
3. Routes from that node are withdrawn

---

## How It Works: Lifecycle

### Agent Startup

When the NovaNet agent starts in native routing mode, it performs the following sequence:

```
1. Load config, verify routing_mode = "native"
2. Connect to NovaRoute via /run/novaroute/novaroute.sock
3. Register as owner "novanet" with token authentication
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
- NovaRoute handles all BGP keepalives, route refresh, and BFD

### Agent Shutdown

On SIGTERM (graceful shutdown):

```
1. Stop accepting new CNI requests
2. Withdraw PodCIDR prefix from NovaRoute
3. Wait for NovaRoute to propagate withdrawal (brief delay)
4. Deregister from NovaRoute
5. Close gRPC connection
6. Exit
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

## Troubleshooting BGP

### Check NovaRoute Status

```bash
kubectl logs -n novaroute <novaroute-pod> -c novaroute
```

Look for:
- `"registered owner"` messages confirming NovaNet connected
- `"prefix advertised"` messages confirming PodCIDR advertisement
- Any error messages about socket or authentication failures

### Verify BGP Sessions

SSH to a node and check FRR's BGP state:

```bash
# Enter the NovaRoute pod
kubectl exec -n novaroute <novaroute-pod> -c frr -- vtysh -c "show bgp summary"
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
kubectl exec -n novaroute <novaroute-pod> -c frr -- vtysh -c "show bgp ipv4 unicast"
```

You should see your node's PodCIDR and routes from other nodes:

```
   Network          Next Hop         Metric  LocPrf  Weight  Path
*> 10.42.1.0/24     0.0.0.0               0         32768   i
*> 10.42.2.0/24     10.0.0.11             0             0   65011 i
*> 10.42.3.0/24     10.0.0.12             0             0   65012 i
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
- NovaRoute FRR logs for route installation errors
- Kernel routing table capacity (`sysctl net.ipv4.route.max_size`)

### Verify NovaRoute Socket

```bash
ls -la /run/novaroute/novaroute.sock
```

If the socket does not exist:
- NovaRoute is not running on this node
- NovaRoute crashed and the socket was cleaned up
- The hostPath volume mount is misconfigured

### Common Issues

**NovaNet agent fails to connect to NovaRoute:**
- Verify NovaRoute pod is running: `kubectl get pods -n novaroute`
- Verify socket exists: `ls -la /run/novaroute/novaroute.sock`
- Check agent logs for connection errors: `kubectl logs -n nova-system <pod> -c novanet-agent`

**Authentication failure:**
- Verify the token in NovaNet config matches the NovaRoute owner configuration
- Check NovaRoute logs for authentication rejection messages

**Routes not propagating to other nodes:**
- Verify BGP sessions are established (see above)
- Check that ToR switches are redistributing routes
- Verify no prefix filters are blocking PodCIDR routes
- Check that the PodCIDR falls within NovaRoute's allowed CIDR range for the `"novanet"` owner

**Packets dropped after route is installed:**
- Verify `rp_filter` (reverse path filtering) is not dropping asymmetric traffic:

```bash
sysctl net.ipv4.conf.all.rp_filter
# Should be 0 (disabled) or 2 (loose mode)
```

- Check that the return path is also routed correctly

---

## OSPF Mode

NovaNet also supports OSPF as an alternative to BGP, configured via `novaroute.protocol: "ospf"`. In OSPF mode:

- NovaRoute injects PodCIDR routes into the configured OSPF area
- No per-node ASN configuration is needed
- Suitable for environments where the underlay runs OSPF instead of BGP

The integration flow is identical -- only the NovaRoute-internal protocol handling changes. NovaNet is unaware of whether routes are distributed via BGP or OSPF.

---

## Next Steps

- [Installation Guide](installation.md) -- Getting started
- [Configuration Reference](configuration.md) -- All configuration options
- [Troubleshooting Guide](troubleshooting.md) -- Debugging connectivity issues
