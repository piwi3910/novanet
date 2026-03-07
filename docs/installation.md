# NovaNet Installation Guide

This guide covers installing, upgrading, and uninstalling NovaNet on a Kubernetes cluster.

---

## Prerequisites

### Kubernetes Cluster

- **Kubernetes 1.28+** (tested on K3s and Kind)
- Cluster must not have another CNI installed, or the existing CNI must be removed first
- Node PodCIDR allocation must be enabled (`--cluster-cidr` on controller manager or equivalent)

### Linux Kernel

- **Linux kernel 5.15+** with BTF (BPF Type Format) support enabled
- BPF CO-RE (Compile Once, Run Everywhere) requires BTF data at `/sys/kernel/btf/vmlinux`
- Verify BTF is available:

```bash
ls -la /sys/kernel/btf/vmlinux
```

- Verify BPF filesystem is mounted:

```bash
mount | grep bpf
# Expected: bpf on /sys/fs/bpf type bpf (rw,nosuid,nodev,noexec,relatime,mode=700)
```

If the BPF filesystem is not mounted:

```bash
mount -t bpf bpf /sys/fs/bpf
```

### Architecture

- **AMD64** (x86_64) or **ARM64** (aarch64)
- Multi-arch container images are provided for both architectures

### Tooling

- **Helm 3.x** for chart-based installation
- **kubectl** configured with cluster access

### For Native Routing Mode (Optional)

- **NovaRoute** deployed as a DaemonSet on each node
- BGP or OSPF-capable network fabric (ToR switches or route reflectors)
- See the [NovaRoute Integration Guide](novaroute-integration.md) for details

---

## Installation

### Step 1: Add the Helm Chart

**From a local clone:**

```bash
git clone https://github.com/azrtydxb/novanet.git
cd novanet
```

**From the Helm repository (when published):**

```bash
helm repo add novanet https://azrtydxb.github.io/novanet/charts
helm repo update
```

### Step 2: Configure values.yaml

Create a custom values file or edit the defaults. At minimum, review these settings:

```yaml
# custom-values.yaml
config:
  clusterCIDR: "10.42.0.0/16"       # Must match your cluster's --cluster-cidr
  nodeCIDRMaskSize: 24                # Per-node subnet size
  tunnelProtocol: "geneve"            # "geneve" or "vxlan"
  routingMode: "overlay"              # "overlay" or "native"
  logLevel: "info"                    # "debug", "info", "warn", "error"
```

See the [Configuration Reference](configuration.md) for all available options.

### Step 3: Install with Helm

```bash
helm install novanet ./deploy/helm/novanet \
  -n nova-system \
  --create-namespace \
  -f custom-values.yaml
```

### Step 4: Verify the Installation

Check that all NovaNet pods are running (one per node):

```bash
kubectl get pods -n nova-system -o wide
```

Expected output:

```
NAME             READY   STATUS    RESTARTS   AGE   IP            NODE
novanet-xxxxx    2/2     Running   0          30s   10.0.0.10     node-1
novanet-yyyyy    2/2     Running   0          30s   10.0.0.11     node-2
novanet-zzzzz    2/2     Running   0          30s   10.0.0.12     node-3
```

Each pod should show `2/2` containers ready (novanet-agent and novanet-dataplane).

Check node status with the CLI:

```bash
novanetctl status
```

Expected output:

```
NovaNet Status
  Mode:             overlay
  Tunnel Protocol:  geneve
  Endpoints:        12
  Policies:         4
  Tunnels:          2
  Programs:         6 attached
```

Verify pods can communicate:

```bash
kubectl run test-a --image=busybox --restart=Never -- sleep 3600
kubectl run test-b --image=busybox --restart=Never -- sleep 3600
kubectl exec test-a -- ping -c 3 $(kubectl get pod test-b -o jsonpath='{.status.podIP}')
```

---

## Quick Start: Overlay Mode

Overlay mode is the simplest deployment. It works on any network fabric without special configuration.

```bash
helm install novanet ./deploy/helm/novanet \
  -n nova-system \
  --create-namespace \
  --set config.routingMode=overlay \
  --set config.tunnelProtocol=geneve
```

This creates Geneve tunnels between all nodes automatically. No underlay changes are needed.

To use VXLAN instead of Geneve (for broader hardware compatibility):

```bash
helm install novanet ./deploy/helm/novanet \
  -n nova-system \
  --create-namespace \
  --set config.routingMode=overlay \
  --set config.tunnelProtocol=vxlan
```

---

## Quick Start: Native Routing Mode

Native routing mode eliminates encapsulation overhead by using BGP or OSPF to distribute pod routes through the underlay network. This requires NovaRoute to be deployed on each node.

### Prerequisites

1. NovaRoute must be installed and running as a DaemonSet
2. The network fabric must support BGP or OSPF
3. NovaRoute must be configured with peer information for ToR switches or route reflectors

### Install NovaNet with Native Routing

```bash
helm install novanet ./deploy/helm/novanet \
  -n nova-system \
  --create-namespace \
  --set config.routingMode=native \
  --set novaroute.enabled=true \
  --set novaroute.socket=/run/novaroute/novaroute.sock \
  --set novaroute.token=<your-novaroute-token> \
  --set novaroute.protocol=bgp
```

Verify NovaRoute integration:

```bash
novanetctl status
```

The output should show `Mode: native` and no tunnels.

See the [NovaRoute Integration Guide](novaroute-integration.md) for detailed configuration.

---

## Upgrading

### Standard Upgrade

Update the Helm values if needed, then run:

```bash
helm upgrade novanet ./deploy/helm/novanet \
  -n nova-system \
  -f custom-values.yaml
```

### Rolling Update Behavior

NovaNet uses a DaemonSet with `RollingUpdate` strategy by default:

- eBPF programs are pinned to `/sys/fs/bpf/novanet/` and survive pod restarts
- Existing pod connectivity is maintained during the upgrade
- IPAM state persists in `/var/lib/cni/networks/novanet/`
- BGP sessions (native mode) re-establish automatically after restart

### Checking Upgrade Status

```bash
kubectl rollout status daemonset/novanet -n nova-system
```

### Upgrading from a Specific Version

If upgrading across major versions, check the release notes for any required migration steps:

```bash
helm upgrade novanet ./deploy/helm/novanet \
  -n nova-system \
  -f custom-values.yaml \
  --version <target-version>
```

---

## Uninstalling

### Remove NovaNet

```bash
helm uninstall novanet -n nova-system
```

### Clean Up Resources

After uninstalling, you may want to remove leftover resources:

```bash
# Remove the namespace
kubectl delete namespace nova-system

# On each node, clean up pinned BPF programs (optional)
rm -rf /sys/fs/bpf/novanet/

# On each node, clean up IPAM state (optional)
rm -rf /var/lib/cni/networks/novanet/

# On each node, remove the CNI binary and config (optional)
rm -f /opt/cni/bin/novanet-cni
rm -f /etc/cni/net.d/10-novanet.conflist
```

**Warning:** Removing the CNI binary and config while pods are still running will break their networking. Ensure all workloads are drained or migrated before full cleanup.

---

## Installation on Specific Platforms

### K3s

K3s ships with Flannel as the default CNI. To use NovaNet instead, disable the built-in CNI when installing K3s:

```bash
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--flannel-backend=none --disable-network-policy" sh -
```

Then install NovaNet:

```bash
helm install novanet ./deploy/helm/novanet \
  -n nova-system \
  --create-namespace \
  --set config.clusterCIDR="10.42.0.0/16"
```

### Kind (Development/Testing)

For local development with Kind, create a cluster without the default CNI:

```yaml
# kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: "10.244.0.0/16"
nodes:
  - role: control-plane
  - role: worker
  - role: worker
```

```bash
kind create cluster --config kind-config.yaml
helm install novanet ./deploy/helm/novanet \
  -n nova-system \
  --create-namespace \
  --set config.clusterCIDR="10.244.0.0/16"
```

---

## Next Steps

- [Configuration Reference](configuration.md) -- All Helm values and config options
- [NovaRoute Integration Guide](novaroute-integration.md) -- Native routing setup
- [Troubleshooting Guide](troubleshooting.md) -- Debugging connectivity issues
