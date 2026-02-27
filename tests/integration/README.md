# NovaNet Integration Tests

Integration test suite for NovaNet CNI. These tests run against a real multi-node Kubernetes cluster with NovaNet deployed.

## Prerequisites

- A multi-node K3s cluster (ARM64, rockchip64 nodes)
  - Masters: `192.168.100.11-13`
  - Workers: `192.168.100.21-25`
- K3s with `KUBECONFIG=/etc/rancher/k3s/k3s.yaml`
- NovaNet deployed as a DaemonSet in namespace `nova-system`
- `kubectl` configured and able to reach the cluster
- `sshpass` installed on the machine running the tests
- SSH root access to cluster nodes (for route/interface inspection)
- Internet access from the cluster (for egress/external tests)

## Test Scripts

| Script | Description |
|--------|-------------|
| `01-same-node.sh` | Same-node pod-to-pod connectivity (ping, iperf3 TCP) |
| `02-cross-node-native.sh` | Cross-node connectivity in native routing mode with BGP route verification |
| `03-cross-node-geneve.sh` | Cross-node connectivity via Geneve overlay with encapsulation verification |
| `04-cross-node-vxlan.sh` | Cross-node connectivity via VXLAN overlay |
| `05-network-policy.sh` | NetworkPolicy enforcement (deny-all, allow-by-label, egress deny, cleanup restore) |
| `06-egress.sh` | Egress/masquerade (pod to external IP, SNAT verification) |
| `07-dns.sh` | DNS resolution (cluster services, external domains, resolv.conf) |
| `08-external.sh` | External HTTP/HTTPS connectivity, TLS, and MTU validation |

## Running

Make scripts executable (one-time):

```bash
chmod +x tests/integration/*.sh
```

Run all tests:

```bash
./tests/integration/run-all.sh
```

Run specific tests by number:

```bash
./tests/integration/run-all.sh 01 05 07
```

Skip specific tests:

```bash
./tests/integration/run-all.sh --skip 03 04
```

## Configuration

Override defaults via environment variables:

```bash
export KUBECONFIG=/path/to/kubeconfig
export NOVANET_NS=nova-system        # Namespace where NovaNet is deployed
export TEST_NS=novanet-test          # Namespace for test pods (created/deleted by tests)
export TEST_IMAGE=nicolaka/netshoot  # Image for test pods
export POD_READY_TIMEOUT=120         # Seconds to wait for pods to become ready
export SSH_PASS=62156215             # SSH password for cluster nodes
```

## Notes

- Tests 03 (Geneve) and 04 (VXLAN) require the cluster to be in overlay mode with the corresponding tunnel protocol. They will skip gracefully if the cluster is configured for native routing.
- Test 02 (native routing) will skip if the cluster is in overlay mode.
- Each test script cleans up after itself using a trap on EXIT.
- All test pods are created in the `novanet-test` namespace.
- The test suite uses `nicolaka/netshoot` as the default test image since it includes networking tools (ping, iperf3, curl, nslookup, nc, tcpdump).
