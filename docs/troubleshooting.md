# NovaNet Troubleshooting Guide

This guide covers common issues, diagnostic commands, and debugging techniques for NovaNet.

---

## Diagnostic Commands

### Agent and Dataplane Status

```bash
# Check overall NovaNet status on the current node
novanetctl status

# Check NovaNet pod status across all nodes
kubectl get pods -n nova-system -o wide

# View agent logs
kubectl logs -n nova-system <pod-name> -c novanet-agent

# View dataplane logs
kubectl logs -n nova-system <pod-name> -c novanet-dataplane

# Follow logs in real time
kubectl logs -n nova-system <pod-name> -c novanet-agent -f
```

### Flow Inspection

```bash
# Watch all flow events in real time
novanetctl flows

# Watch only dropped packets with reasons
novanetctl drops

# Filter flows by identity
novanetctl flows --identity 42

# View compiled policy rules
novanetctl policy

# View pod-to-identity mappings
novanetctl identity

# View egress rules and counters
novanetctl egress

# View summary statistics
novanetctl metrics
```

### Tunnel Inspection (Overlay Mode)

```bash
# Show active tunnels
novanetctl tunnels

# Check Geneve tunnel interfaces on the node
ip link show type geneve

# Check VXLAN tunnel interfaces on the node
ip link show type vxlan

# Check tunnel routes
ip route show
```

---

## Common Issues

### Pods Cannot Communicate (Same Node)

**Symptoms:** Two pods on the same node cannot ping each other. `novanetctl flows` shows no flow events or shows drops.

**Diagnosis:**

1. Verify both pods have IPs assigned:

```bash
kubectl get pods -o wide
```

2. Verify endpoints are registered in the dataplane:

```bash
novanetctl status
# Check that endpoint count matches the number of pods on this node
```

3. Check that eBPF programs are attached to the pod veth interfaces:

```bash
novanetctl status
# Look at the "Programs" section for attached TC programs
```

4. Check agent logs for CNI setup errors:

```bash
kubectl logs -n nova-system <pod-name> -c novanet-agent | grep -i "error\|fail"
```

5. Watch for flow events:

```bash
novanetctl flows
# Then run: kubectl exec <pod-a> -- ping <pod-b-ip>
```

**Common Causes:**

- eBPF programs failed to attach (check kernel version and BTF support)
- Endpoint map was not populated (agent-to-dataplane gRPC issue)
- Pod veth pair was not created correctly (CNI error)
- Policy is blocking traffic (check `novanetctl policy`)

**Resolution:**

- Restart the NovaNet pod on the affected node: `kubectl delete pod -n nova-system <pod-name>`
- eBPF programs are pinned and survive restarts; existing pods retain connectivity

---

### Pods Cannot Communicate (Cross Node)

**Symptoms:** Pods on different nodes cannot reach each other, but same-node communication works.

**Diagnosis:**

1. **Overlay mode** -- check tunnel status:

```bash
novanetctl tunnels
# Verify tunnels exist to all remote nodes
```

```bash
# Check tunnel interfaces on the node
ip link show type geneve
# or
ip link show type vxlan
```

```bash
# Verify tunnel routes exist
ip route show | grep -E "geneve|vxlan"
```

2. **Native mode** -- check routing:

```bash
# Verify BGP routes are installed
ip route show | grep 10.42
# You should see routes to remote PodCIDRs
```

```bash
# Check BGP session status via the FRR sidecar
kubectl exec -n nova-system <novanet-pod> -c frr -- vtysh -c "show bgp summary"

# Or use the novanetctl routing commands
novanetctl routing status
novanetctl routing peers
```

3. Check for firewall rules blocking tunnel traffic:

```bash
# Geneve uses UDP port 6081
iptables -L -n | grep 6081

# VXLAN uses UDP port 4789
iptables -L -n | grep 4789
```

**Common Causes (Overlay):**

- Tunnel interface not created (check agent logs for netlink errors)
- Firewall blocking UDP port 6081 (Geneve) or 4789 (VXLAN)
- MTU issues causing packet drops (tunnel overhead: 50-54 bytes for Geneve, 50 bytes for VXLAN)
- Node IP discovery failure (incorrect `NOVANET_NODE_IP`)

**Common Causes (Native):**

- BGP session not established (see [Native Routing Guide](novaroute-integration.md))
- Routes not propagated through the fabric
- Reverse path filtering dropping packets (`rp_filter`)
- ToR switch not accepting or redistributing PodCIDR routes

**Resolution (Overlay):**

- Verify node-to-node connectivity on the underlay: `ping <remote-node-ip>`
- Check MTU: ensure underlay MTU accommodates tunnel overhead (e.g., 1500 inner + 54 overhead = 1554 underlay MTU needed)
- Open firewall for tunnel ports

**Resolution (Native):**

- See [Troubleshooting](novaroute-integration.md#troubleshooting) in the Native Routing Guide
- Disable strict reverse path filtering: `sysctl -w net.ipv4.conf.all.rp_filter=0`

---

### No External Connectivity

**Symptoms:** Pods cannot reach external services (e.g., `ping 8.8.8.8` fails), but pod-to-pod works.

**Diagnosis:**

1. Check masquerade is enabled:

```bash
novanetctl egress
# Verify masquerade is active
```

2. Check egress policy:

```bash
novanetctl drops
# Look for drops on traffic to external IPs
```

3. Verify SNAT is working by checking the source IP of outgoing packets from the node perspective.

4. Check the node itself has external connectivity:

```bash
# From the node (not a pod)
ping 8.8.8.8
```

**Common Causes:**

- Masquerade/SNAT disabled in config (`egress.masqueradeEnabled: false`)
- Egress NetworkPolicy blocking external traffic
- Default-deny mode enabled without an egress allow rule
- Node itself has no external route

**Resolution:**

- Enable masquerade: `--set egress.masqueradeEnabled=true`
- If using default-deny, create a NetworkPolicy allowing egress to external CIDRs
- Verify the node's default route is functional

---

### DNS Resolution Failures

**Symptoms:** Pods cannot resolve DNS names. `nslookup` or `dig` commands fail inside pods.

**Diagnosis:**

1. Check CoreDNS pods are running:

```bash
kubectl get pods -n kube-system -l k8s-app=kube-dns
```

2. Check if pods can reach the CoreDNS service IP:

```bash
kubectl exec <pod> -- ping -c 1 $(kubectl get svc -n kube-system kube-dns -o jsonpath='{.spec.clusterIP}')
```

3. Check for policy drops on DNS traffic:

```bash
novanetctl drops
# Look for drops on port 53 (UDP or TCP)
```

**Common Causes:**

- Default-deny policy enabled without a DNS allow rule
- CoreDNS pods not running or not ready
- Endpoint for CoreDNS not populated in the dataplane

**Resolution:**

If using `policy.defaultDeny: true`, create a cluster-wide policy allowing DNS:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns
  namespace: default
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
```

Apply this in every namespace that needs DNS resolution.

---

### High Latency

**Symptoms:** Pod-to-pod communication works but latency is significantly higher than expected.

**Diagnosis:**

1. Compare overlay vs native performance:

```bash
# Check current mode
novanetctl status
```

2. Measure latency with a simple test:

```bash
kubectl exec <pod-a> -- ping -c 100 <pod-b-ip>
```

3. Check for CPU throttling on NovaNet pods:

```bash
kubectl top pods -n nova-system
```

4. Check eBPF program execution statistics:

```bash
# Enable BPF stats (requires root on the node)
sysctl -w kernel.bpf_stats_enabled=1

# Check program run time and count via fdinfo
# (see eBPF Verification section below)
```

**Common Causes:**

- Overlay mode adds encap/decap latency (expected: small, typically under 100us)
- CPU resource limits too low on the dataplane container
- Large policy maps causing slower lookups (rare, eBPF hash maps are O(1))
- MTU mismatch causing fragmentation

**Resolution:**

- Switch to native routing mode for lowest latency
- Increase CPU limits on the dataplane container
- Verify MTU is consistent across the path

---

## eBPF Verification

### Check Attached BPF Programs

NovaNet attaches TC (Traffic Control) programs to pod veth interfaces. On kernel 6.12+ using tcx (TC Express), these programs are NOT visible via `tc filter show`. Use the following methods instead.

**Via novanetctl:**

```bash
novanetctl status
# The Programs section lists all attached programs with interface and type
```

**Via /proc fdinfo:**

Find the NovaNet dataplane process and check its BPF file descriptors:

```bash
# Find the dataplane PID
NOVANET_PID=$(pgrep novanet-dataplane)

# List BPF program file descriptors
ls -la /proc/$NOVANET_PID/fdinfo/ | head -20

# Check a specific fd for BPF program info
cat /proc/$NOVANET_PID/fdinfo/<fd-number>
```

Look for entries with `prog_type: 3` (BPF_PROG_TYPE_SCHED_CLS for TC programs).

### Enable BPF Statistics

BPF statistics show how many times each program has run and total execution time:

```bash
# Enable BPF stats collection (requires root)
sysctl -w kernel.bpf_stats_enabled=1
```

After enabling, the fdinfo for each BPF program will show:

```
prog_type:      3
prog_jited:     1
prog_tag:       abc123def456
memlock:        4096
run_time_ns:    1234567
run_cnt:        50000
```

- `run_cnt` -- number of times the program has executed (packets processed)
- `run_time_ns` -- total execution time in nanoseconds
- Average per-packet time: `run_time_ns / run_cnt`

A healthy program should show:
- `run_cnt` increasing (packets flowing)
- Average execution time under 1000ns per packet

### Verify eBPF Maps

Check that eBPF maps are pinned and contain expected data:

```bash
# List pinned BPF objects
ls -la /sys/fs/bpf/novanet/

# Expected contents:
# endpoints    -- pod IP to identity/ifindex map
# policies     -- policy enforcement map
# config       -- mode and settings map
# tunnels      -- tunnel map (overlay mode only)
# flows        -- flow event tracking
# egress       -- egress policy map
```

---

## Tunnel Debugging (Overlay Mode)

### Check Tunnel Interfaces

NovaNet creates tunnel interfaces with the following naming conventions:
- **Geneve**: per-node interfaces named `nv_<nodename>` (e.g., `nv_worker-24`)
- **VXLAN**: a single shared interface named `nvx0`

```bash
# List all Geneve interfaces
ip link show type geneve

# List all VXLAN interfaces
ip link show type vxlan

# Show detailed info for a specific tunnel
ip -d link show geneve0
```

### Verify Tunnel State

```bash
# Check tunnel routes
ip route show

# Look for routes pointing to tunnel interfaces, e.g.:
# 10.42.2.0/24 dev geneve1 proto novanet scope link
```

### Tunnel Traffic Capture

For deep debugging, capture tunnel traffic on the underlay:

```bash
# Capture Geneve traffic (UDP port 6081)
tcpdump -i eth0 -nn udp port 6081

# Capture VXLAN traffic (UDP port 4789)
tcpdump -i eth0 -nn udp port 4789

# Capture and decode Geneve headers
tcpdump -i eth0 -nn -v udp port 6081
```

### Tunnel Map Entries

The dataplane maintains a tunnel map mapping remote node IPs to local tunnel interface indices. Verify entries via the dataplane status:

```bash
novanetctl tunnels
```

Expected output:

```
REMOTE NODE IP    TUNNEL IFACE    VNI     STATUS
10.0.0.11         geneve1         1       active
10.0.0.12         geneve2         2       active
```

If a tunnel is missing, check agent logs for tunnel creation errors.

### Conntrack and KUBE-FORWARD Drops

In overlay mode, the eBPF `tc_egress` program uses `bpf_redirect()` to send packets
directly to the tunnel interface, bypassing the kernel's conntrack hooks. When the
reply arrives via the tunnel on the remote node, conntrack has no record of the
original connection and classifies the reply as `ctstate INVALID`. Kubernetes
distributions (e.g., k3s with kube-router) add a `KUBE-FORWARD` iptables rule that
drops INVALID packets.

NovaNet handles this by setting the `0x4000` skb mark on all packets arriving via
tunnel interfaces in the `tc_tunnel_ingress` eBPF program. The `KUBE-FORWARD` chain
has a rule that accepts packets with `mark match 0x4000/0x4000`, which takes
precedence over the INVALID drop rule.

To diagnose this issue:

```bash
# Check KUBE-FORWARD chain for INVALID drops (high counter = problem)
iptables-legacy -L KUBE-FORWARD -v -n

# Check if the 0x4000 mark ACCEPT rule is present
iptables-legacy -L KUBE-FORWARD -v -n | grep 0x4000

# Monitor drops in real time
watch -n1 'iptables-legacy -L KUBE-FORWARD -v -n'
```

---

## Policy Debugging

### Check NetworkPolicy Objects

```bash
# List all NetworkPolicies across the cluster
kubectl get networkpolicy -A

# Describe a specific policy
kubectl describe networkpolicy <name> -n <namespace>
```

### View Compiled Policy Rules

```bash
# Show the compiled identity-based policy rules in the eBPF map
novanetctl policy
```

Example output:

```
SRC IDENTITY    DST IDENTITY    PROTO    PORT    ACTION
17              42              TCP      80      ALLOW
17              42              TCP      443     ALLOW
0               42              *        *       DENY
```

### Watch Policy Verdicts

```bash
# Watch all flow events with verdict information
novanetctl flows

# Watch only denied flows
novanetctl drops
```

Flow events include the verdict (ALLOW/DENY) and drop reason for denied packets.

### Policy Compilation Failures

If a NetworkPolicy references named ports or namespace selectors, the agent
resolves them at compile time via the Kubernetes API. Failures are logged at
the `warn` level:

```
failed to list pods for named port resolution  port=http namespace=default error=...
failed to list namespaces for policy resolution  selector=app=web error=...
```

Check the agent logs (`kubectl logs -n nova-system <agent-pod>`) for these
warnings when policies using named ports or `namespaceSelector` are not
taking effect as expected.

### Drop Counters and Reasons

Drop reason codes help identify why packets are being denied:

| Code | Reason | Description |
|------|--------|-------------|
| `POLICY_DENIED` | Policy enforcement | Packet matched a deny rule or no allow rule matched (default deny) |
| `NO_IDENTITY` | Identity lookup failure | Source IP not found in endpoint map; stale or unknown endpoint |
| `NO_ROUTE` | Routing failure | No tunnel map entry for the destination node (overlay mode) |
| `NO_TUNNEL` | Tunnel missing | Tunnel interface for the remote node does not exist |
| `TTL_EXCEEDED` | TTL expired | Packet TTL reached zero |

### Default Deny vs Default Allow

Understanding the default policy stance:

- **Default allow** (`policy.defaultDeny: false`): Pods without any selecting NetworkPolicy allow all ingress and egress traffic. This is standard Kubernetes behavior.
- **Default deny** (`policy.defaultDeny: true`): All traffic is denied unless explicitly allowed by a NetworkPolicy.

When a NetworkPolicy selects a pod (via `podSelector`), the behavior changes for that pod:

- **Ingress**: If any NetworkPolicy selects the pod with an ingress rule, all ingress not matching any policy is denied
- **Egress**: If any NetworkPolicy selects the pod with an egress rule, all egress not matching any policy is denied

This follows the Kubernetes NetworkPolicy specification.

---

## Agent Restart Behavior

NovaNet is designed to handle agent and dataplane restarts gracefully without disrupting existing pod connectivity.

### eBPF Program Persistence

eBPF programs are pinned to `/sys/fs/bpf/novanet/` on the host filesystem. This means:

- Programs survive agent and dataplane container restarts
- Existing pod-to-pod traffic continues flowing during restart
- The dataplane re-attaches to pinned programs on startup

### IPAM State Persistence

IPAM allocations are persisted to `/var/lib/cni/networks/novanet/` on the host:

- Pod IP assignments survive restarts
- No IP conflicts after restart
- The agent reconciles IPAM state with Kubernetes on startup

### BGP Session Recovery (Native Mode)

In native routing mode:

- BGP sessions are managed by the FRR sidecar within the NovaNet DaemonSet pod
- When the NovaNet agent restarts, it reconnects to FRR and re-initializes the routing manager
- FRR's BGP sessions are unaffected by agent container restarts (the FRR sidecar runs independently)
- PodCIDR routes remain in the fabric during the brief restart window
- If the FRR sidecar restarts, FRR re-establishes BGP sessions automatically

### State Reconciliation

On startup, the agent performs full reconciliation:

1. Reads current state from Kubernetes (pods, nodes, policies)
2. Reads current state from the dataplane (endpoint map, policy map)
3. Computes the desired state
4. Applies any differences (add missing endpoints, remove stale ones, sync policies)

This ensures that even if the agent was down for an extended period, it converges to the correct state.

### What Happens During a Restart

| Component | During Restart | After Restart |
|-----------|---------------|---------------|
| Same-node traffic | Continues (pinned eBPF programs) | Continues |
| Cross-node traffic | Continues (pinned eBPF programs + tunnels/routes) | Continues |
| Policy enforcement | Continues (pinned policy map) | Reconciled with latest policies |
| New pod creation | Fails (CNI cannot reach agent) | Resumes |
| Pod deletion | Deferred (cleanup on reconcile) | Cleaned up |
| Metrics export | Paused | Resumes |
| Flow events | Paused (ring buffer may fill) | Resumes |

### Diagnosing Restart Problems

If pods lose connectivity after an agent restart, follow these steps:

1. **Verify eBPF programs survived the restart**:

```bash
# SSH to the affected node and check pinned programs
ls -la /sys/fs/bpf/novanet/
bpftool prog show
```

If `/sys/fs/bpf/novanet/` is empty, programs were not pinned. Check the DaemonSet spec
for the `/sys/fs/bpf/` hostPath volume mount.

2. **Verify TC attachments on pod interfaces**:

```bash
# Check TC programs on a pod veth (kernel < 6.12)
tc filter show dev <veth-name> ingress
tc filter show dev <veth-name> egress

# For tcx (kernel 6.12+), use bpftool or novanetctl
novanetctl status
```

3. **Verify IPAM state persisted**:

```bash
ls -la /var/lib/cni/networks/novanet/
# Each file is an allocated IP; contents are container IDs
```

If the directory is empty after restart, the hostPath volume may be misconfigured.

4. **Check routing reconnection (native routing mode)**:

```bash
# Verify routing manager status
novanetctl routing status
# Look for "connected" FRR state

# Verify route advertisement
novanetctl routing prefixes
# The node PodCIDR should be listed as advertised

# Or check FRR directly
kubectl exec -n nova-system <novanet-pod> -c frr -- vtysh -c "show bgp summary"
```

5. **Review agent logs for startup errors**:

```bash
kubectl logs -n nova-system <pod-name> -c novanet-agent --tail=100
# Look for: fatal, panic, cannot attach, failed to load
# Positive indicators: started, ready, attached, reconciling
```

### Common Restart Pitfalls

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| 100% packet loss during restart | eBPF programs not pinned to `/sys/fs/bpf/` | Verify hostPath mount for `/sys/fs/bpf/` in DaemonSet |
| Pods get new IPs after restart | IPAM state directory not on hostPath | Check `/var/lib/cni/` hostPath mount |
| Agent crash-loops after restart | Stale BPF map schema from version upgrade | Delete pins in `/sys/fs/bpf/novanet/` and restart |
| Routes missing after restart | FRR sidecar not running | Verify FRR sidecar is running; check `/run/frr/` socket directory |
| Slow route reconvergence (>30s) | BGP timers too conservative | Enable BFD in the routing configuration for sub-second failover detection |
| New pods fail to start | CNI binary cannot reach agent during restart | Wait for agent pod to become ready; pods retry automatically |

### Running the Graceful Restart Integration Test

The test suite includes a dedicated graceful restart test:

```bash
tests/integration/09-graceful-restart.sh
```

This test creates two pods on different nodes, triggers a rolling restart of the DaemonSet,
and verifies that connectivity is maintained with minimal packet loss. It checks eBPF program
persistence, IPAM state, agent logs, and DaemonSet health. See the test script for details.

---

## Collecting a Debug Bundle

When filing a bug report or asking for help, collect the following information:

```bash
# 1. NovaNet pod status
kubectl get pods -n nova-system -o wide

# 2. Agent logs (last 500 lines)
kubectl logs -n nova-system <pod-name> -c novanet-agent --tail=500

# 3. Dataplane logs (last 500 lines)
kubectl logs -n nova-system <pod-name> -c novanet-dataplane --tail=500

# 4. NovaNet status
novanetctl status

# 5. Node info
kubectl get nodes -o wide

# 6. Kernel version and BTF info
uname -r
ls -la /sys/kernel/btf/vmlinux

# 7. BPF filesystem contents
ls -la /sys/fs/bpf/novanet/

# 8. Network interfaces (on affected node)
ip link show
ip route show

# 9. Tunnel interfaces (overlay mode)
ip link show type geneve
ip link show type vxlan

# 10. NetworkPolicies
kubectl get networkpolicy -A -o yaml

# 11. Kubernetes events
kubectl get events -n nova-system --sort-by='.lastTimestamp'
```

---

## Getting Help

- GitHub Issues: [github.com/azrtydxb/novanet/issues](https://github.com/azrtydxb/novanet/issues)
- Include the debug bundle output when reporting issues
- Specify your Kubernetes distribution, kernel version, and NovaNet version

---

## Next Steps

- [Installation Guide](installation.md) -- Getting started
- [Configuration Reference](configuration.md) -- All configuration options
- [Native Routing Guide](novaroute-integration.md) -- Native routing details
