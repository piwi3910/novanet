# NovaNet Performance Benchmarks

Benchmark suite for measuring NovaNet CNI dataplane performance.
Covers HTTP/TCP request throughput (fortio), raw network bandwidth (iperf3),
latency profiling with percentiles, and NetworkPolicy overhead.

## Prerequisites

- A running K3s cluster with at least 2 worker nodes
- `kubectl` configured and able to reach the cluster
- `jq` installed on the machine running the benchmarks
- The `fortio/fortio:latest` image pullable from all nodes
- The `nicolaka/netshoot:latest` image pullable from all nodes (for iperf3 bandwidth tests)
- NovaNet (or another CNI) installed on the cluster

### Expected cluster topology

| Role    | Hostname    | IP              |
|---------|-------------|-----------------|
| Master  | master-11   | 192.168.100.11  |
| Worker  | worker-21   | 192.168.100.21  |
| Worker  | worker-22   | 192.168.100.22  |
| ...     | ...         | ...             |

By default the benchmarks use `worker-21` and `worker-22`. Override with
`WORKER_NODE_1` and `WORKER_NODE_2` environment variables.

## Quick Start

```bash
# Run all benchmarks
./tests/benchmark/run-all.sh

# Run specific benchmark
./tests/benchmark/run-all.sh throughput
./tests/benchmark/run-all.sh latency
./tests/benchmark/run-all.sh bandwidth
./tests/benchmark/run-all.sh policy

# Run individual scripts directly
./tests/benchmark/bench-throughput.sh
./tests/benchmark/bench-latency.sh
./tests/benchmark/bench-bandwidth.sh
./tests/benchmark/bench-policy.sh
```

## Environment Variables

| Variable                 | Default                        | Description                                |
|--------------------------|--------------------------------|--------------------------------------------|
| `KUBECONFIG`             | `/etc/rancher/k3s/k3s.yaml`   | Path to kubeconfig                         |
| `WORKER_NODE_1`          | `worker-21`                    | First worker node (server pods)            |
| `WORKER_NODE_2`          | `worker-22`                    | Second worker node (client pods)           |
| `DURATION`               | `10s`                          | Duration per test iteration                |
| `CONCURRENCIES`          | `1 4 16 64`                    | Concurrency levels for throughput tests    |
| `QPS_RATES`              | `100 500 1000 5000`            | Fixed QPS rates for latency tests          |
| `POLICY_BENCH_QPS`       | `1000`                         | Fixed QPS for policy comparison            |
| `POLICY_BENCH_CONCURRENCY`| `16`                          | Concurrency for policy comparison          |
| `IPERF_DURATION`         | `10`                           | iperf3 test duration in seconds            |
| `PARALLEL_STREAMS`       | `1 4`                          | Parallel stream counts for bandwidth tests |
| `UDP_BITRATES`           | `100M 500M 1G 0`              | UDP target bitrates (0 = unlimited)        |
| `FORTIO_IMAGE`           | `fortio/fortio:latest`         | Fortio container image                     |
| `NETSHOOT_IMAGE`         | `nicolaka/netshoot:latest`     | Netshoot image (for iperf3 bandwidth)      |
| `BENCHMARK_NS`           | `novanet-bench`                | Kubernetes namespace for test pods         |
| `RESULTS_DIR`            | `tests/benchmark/results`      | Directory for JSON result files            |

## Benchmarks

### Throughput (`bench-throughput.sh`)

Uses fortio to measure maximum QPS at increasing concurrency levels.
Deploys fortio server pods (HTTP :8080, TCP echo :8078) and runs
fortio load tests via kubectl exec.

**Topologies tested:**
- Same-node HTTP + TCP (both pods on worker-21)
- Cross-node HTTP + TCP (server on worker-21, client on worker-22)
- Host-network HTTP baseline (bypasses CNI)

**Concurrency sweep:** 1, 4, 16, 64 concurrent connections (configurable).

Output: `results/throughput-<timestamp>.json`

### Latency (`bench-latency.sh`)

Uses fortio at fixed QPS rates to measure latency percentiles (p50/p90/p99/p99.9).
By controlling the request rate, this isolates latency from throughput saturation.

**Topologies tested:**
- Same-node HTTP + TCP echo
- Cross-node HTTP + TCP echo
- Host-network HTTP baseline

**QPS rates:** 100, 500, 1000, 5000 (configurable).

Includes CNI overhead calculation comparing cross-node vs host-network
latency at each QPS level.

Output: `results/latency-<timestamp>.json`

### Bandwidth (`bench-bandwidth.sh`)

Uses iperf3 to measure raw network bandwidth (Gbps) — the actual data throughput
capacity of the CNI dataplane, as opposed to request rates.

**Tests performed:**
- Same-node TCP (upload + download, 1 & 4 parallel streams)
- Cross-node TCP (upload + download, 1 & 4 parallel streams)
- Cross-node UDP at increasing target bitrates (100M, 500M, 1G, unlimited)
- Host-network TCP baseline (bypasses CNI)

Reports bandwidth in Gbps/Mbps, TCP retransmits, UDP jitter/loss,
and CPU utilization. Includes CNI bandwidth overhead calculation.

Output: `results/bandwidth-<timestamp>.json`

### Policy Overhead (`bench-policy.sh`)

Measures how increasing numbers of NetworkPolicy objects affect dataplane
performance. Runs both max-QPS throughput and fixed-QPS latency tests at
three policy levels:

| Policy Count | Purpose                                          |
|--------------|--------------------------------------------------|
| 0            | Baseline with no policies installed              |
| 100          | Moderate policy load                             |
| 1000         | Heavy policy load                                |

The injected policies target pods with labels that do **not** match the
benchmark pods. This isolates the cost of the eBPF map lookup/walk from
direct enforcement overhead.

Output: `results/policy-<timestamp>.json`

## Output Format

### JSON results

Each benchmark writes a JSON file with fortio-style latency histograms:

```json
{
  "benchmark": "latency",
  "metadata": {
    "timestamp": "20260226T143000Z",
    "kubernetes_version": "v1.31.4+k3s1",
    "novanet_image": "ghcr.io/azrtydxb/novanet/novanet-agent:latest",
    "node_count": 8,
    "duration": "10s"
  },
  "results": [
    {
      "test": "same-node-http-qps1000",
      "actual_qps": 998.5,
      "latency_ms": {
        "min": 0.12,
        "avg": 0.45,
        "p50": 0.38,
        "p90": 0.67,
        "p99": 1.23,
        "p999": 2.45,
        "max": 5.67
      },
      "requests": 9985,
      "errors": 0,
      "protocol": "http",
      "target_qps": 1000
    }
  ]
}
```

### Human-readable output

Each script prints formatted tables to stdout:

```
=== Latency Results Summary ===

  Test                  Proto  Target QPS  Actual QPS  p50 (ms)  p90 (ms)  p99 (ms)  p99.9 (ms)  Errors
  --------------------  -----  ----------  ----------  --------  --------  --------  ----------  ------
  same-node-http-qps100   HTTP   100         99.8      0.35      0.52      0.89      1.23        0
  cross-node-http-qps100  HTTP   100         99.7      0.48      0.71      1.45      2.67        0
  host-net-http-qps100    HTTP   100         99.9      0.31      0.44      0.72      1.01        0

=== CNI Overhead Estimate ===

  QPS 100:  p50 overhead: +0.170ms   p99 overhead: +0.730ms
```

## Interpreting Results

### What to look for

1. **CNI overhead**: Compare pod-network latency against host-network baselines.
   A well-tuned eBPF CNI should add < 0.1ms p50 overhead for same-node,
   < 0.3ms for cross-node.

2. **Tail latency**: p99 and p99.9 reveal worst-case performance. Large gaps
   between p50 and p99 may indicate buffer contention or GC pauses.

3. **QPS scaling**: Throughput should scale roughly linearly with concurrency
   until CPU or network saturation.

4. **Policy scaling**: The delta between 0-policy and 1000-policy runs shows
   how well eBPF policy maps scale. O(1) lookups should show negligible overhead.

5. **Error rates**: Non-zero errors indicate connection failures or timeouts,
   which may point to resource exhaustion or misconfiguration.

6. **Bandwidth capacity**: Compare iperf3 cross-node bandwidth against host-network
   baseline. Multi-stream tests reveal how well the CNI handles parallel flows.
   TCP retransmits indicate congestion or buffer issues. UDP loss percentage
   shows how the dataplane handles sustained high-bitrate traffic.

## Cleanup

Each benchmark script registers an EXIT trap that deletes the `novanet-bench`
namespace. To clean up manually:

```bash
kubectl delete namespace novanet-bench
```
