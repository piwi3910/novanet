#!/usr/bin/env bash
# lib.sh — Shared functions for NovaNet benchmarks (fortio-based).
# Sourced by individual benchmark scripts; not executed directly.

set -euo pipefail

###############################################################################
# Defaults & globals
###############################################################################

export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
BENCHMARK_NS="${BENCHMARK_NS:-novanet-bench}"
FORTIO_IMAGE="${FORTIO_IMAGE:-fortio/fortio:latest}"
RESULTS_DIR="${RESULTS_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/results}"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"

# Cluster topology — adjust if your lab differs.
WORKER_NODE_1="${WORKER_NODE_1:-worker-21}"
WORKER_NODE_2="${WORKER_NODE_2:-worker-22}"

# Default test durations
DURATION="${DURATION:-10s}"

# Colours (disabled when stdout is not a terminal).
if [[ -t 1 ]]; then
    BOLD="\033[1m"
    GREEN="\033[32m"
    YELLOW="\033[33m"
    RED="\033[31m"
    CYAN="\033[36m"
    RESET="\033[0m"
else
    BOLD="" GREEN="" YELLOW="" RED="" CYAN="" RESET=""
fi

###############################################################################
# Logging
###############################################################################

log_info()  { echo -e "${GREEN}[INFO]${RESET}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
log_header(){ echo -e "\n${BOLD}=== $* ===${RESET}\n"; }
log_step()  { echo -e "${CYAN}[STEP]${RESET}  $*"; }

###############################################################################
# Prerequisites check
###############################################################################

check_prerequisites() {
    local missing=0
    for cmd in kubectl jq; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "Required command not found: $cmd"
            missing=1
        fi
    done
    if [[ $missing -ne 0 ]]; then
        log_error "Install missing prerequisites and retry."
        exit 1
    fi

    if ! kubectl cluster-info &>/dev/null; then
        log_error "Cannot reach the Kubernetes cluster. Check KUBECONFIG."
        exit 1
    fi
    log_info "Prerequisites OK (kubectl, jq, cluster reachable)."
}

###############################################################################
# Namespace management
###############################################################################

ensure_namespace() {
    if ! kubectl get namespace "$BENCHMARK_NS" &>/dev/null; then
        log_info "Creating namespace $BENCHMARK_NS"
        kubectl create namespace "$BENCHMARK_NS"
    fi
}

delete_namespace() {
    if kubectl get namespace "$BENCHMARK_NS" &>/dev/null; then
        log_info "Deleting namespace $BENCHMARK_NS"
        kubectl delete namespace "$BENCHMARK_NS" --wait=true --timeout=120s 2>/dev/null || true
    fi
}

###############################################################################
# Pod lifecycle helpers
###############################################################################

# create_fortio_server NAME NODE [--host-network]
# Deploys a fortio server pod (HTTP :8080, gRPC :8079, TCP echo :8078).
create_fortio_server() {
    local name="$1"
    local node="$2"
    local host_network="${3:-}"

    local host_network_spec="false"
    if [[ "$host_network" == "--host-network" ]]; then
        host_network_spec="true"
    fi

    cat <<EOF | kubectl apply -n "$BENCHMARK_NS" -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  labels:
    app: novanet-bench
    role: fortio-server
spec:
  nodeName: ${node}
  hostNetwork: ${host_network_spec}
  terminationGracePeriodSeconds: 0
  containers:
  - name: fortio
    image: ${FORTIO_IMAGE}
    args:
      - server
      - -http-port=8080
      - -grpc-port=8079
      - -tcp-port=8078
    ports:
    - containerPort: 8080
      name: http
    - containerPort: 8079
      name: grpc
    - containerPort: 8078
      name: tcp-echo
    resources:
      requests:
        cpu: "100m"
        memory: "64Mi"
      limits:
        cpu: "2"
        memory: "256Mi"
    readinessProbe:
      httpGet:
        path: /fortio/
        port: 8080
      initialDelaySeconds: 2
      periodSeconds: 3
EOF
    log_info "Created fortio server $name on node $node (hostNetwork=$host_network_spec)"
}

# create_fortio_client NAME NODE [--host-network]
# Deploys a long-running fortio pod that we exec into for client tests.
create_fortio_client() {
    local name="$1"
    local node="$2"
    local host_network="${3:-}"

    local host_network_spec="false"
    if [[ "$host_network" == "--host-network" ]]; then
        host_network_spec="true"
    fi

    cat <<EOF | kubectl apply -n "$BENCHMARK_NS" -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  labels:
    app: novanet-bench
    role: fortio-client
spec:
  nodeName: ${node}
  hostNetwork: ${host_network_spec}
  terminationGracePeriodSeconds: 0
  containers:
  - name: fortio
    image: ${FORTIO_IMAGE}
    args: ["server", "-http-port=18080", "-grpc-port=18079", "-tcp-port=18078"]
    resources:
      requests:
        cpu: "100m"
        memory: "64Mi"
      limits:
        cpu: "2"
        memory: "256Mi"
    readinessProbe:
      httpGet:
        path: /fortio/
        port: 18080
      initialDelaySeconds: 1
      periodSeconds: 3
EOF
    log_info "Created fortio client $name on node $node (hostNetwork=$host_network_spec)"
}

# wait_pod_ready NAME [TIMEOUT_SECONDS]
wait_pod_ready() {
    local name="$1"
    local timeout="${2:-120}"
    log_info "Waiting for pod $name to be ready (timeout ${timeout}s)..."
    if ! kubectl wait -n "$BENCHMARK_NS" "pod/$name" \
            --for=condition=Ready --timeout="${timeout}s" 2>/dev/null; then
        log_error "Pod $name did not become ready within ${timeout}s"
        kubectl describe pod -n "$BENCHMARK_NS" "$name" >&2 || true
        return 1
    fi
    log_info "Pod $name is ready."
}

# get_pod_ip NAME
get_pod_ip() {
    kubectl get pod -n "$BENCHMARK_NS" "$1" -o jsonpath='{.status.podIP}'
}

# exec_pod NAME COMMAND...
exec_pod() {
    local name="$1"; shift
    kubectl exec -n "$BENCHMARK_NS" "$name" -- "$@"
}

# delete_pod NAME
delete_pod() {
    kubectl delete pod -n "$BENCHMARK_NS" "$1" --grace-period=0 --force 2>/dev/null || true
}

###############################################################################
# Fortio helpers
###############################################################################

# _extract_fortio_json RAW_OUTPUT
# Fortio with -json - outputs JSON to stdout but mixes in human-readable lines.
# This extracts just the JSON object.
_extract_fortio_json() {
    local raw="$1"
    # Find the first '{' and extract the JSON object
    echo "$raw" | python3 -c "
import sys, json
data = sys.stdin.read()
start = data.find('{')
if start < 0:
    sys.exit(1)
depth, end = 0, start
for i, ch in enumerate(data[start:], start):
    if ch == '{': depth += 1
    elif ch == '}': depth -= 1
    if depth == 0:
        end = i + 1
        break
try:
    obj = json.loads(data[start:end])
    json.dump(obj, sys.stdout)
except:
    sys.exit(1)
" 2>/dev/null
}

# run_fortio_http CLIENT_POD SERVER_IP QPS CONCURRENCY DURATION [PAYLOAD_SIZE]
# Runs fortio HTTP load test and prints clean JSON to stdout.
run_fortio_http() {
    local client="$1"
    local server_ip="$2"
    local qps="$3"
    local concurrency="$4"
    local duration="$5"
    local size="${6:-1024}"

    local raw
    raw=$(exec_pod "$client" fortio load \
        -json - \
        -qps "$qps" \
        -c "$concurrency" \
        -t "$duration" \
        -payload-size "$size" \
        -allow-initial-errors \
        "http://${server_ip}:8080/echo?size=${size}" 2>/dev/null) || true

    _extract_fortio_json "$raw"
}

# run_fortio_tcp CLIENT_POD SERVER_IP QPS CONCURRENCY DURATION [PAYLOAD_SIZE]
# Runs fortio TCP echo test and prints clean JSON to stdout.
run_fortio_tcp() {
    local client="$1"
    local server_ip="$2"
    local qps="$3"
    local concurrency="$4"
    local duration="$5"
    local size="${6:-256}"

    local raw
    raw=$(exec_pod "$client" fortio load \
        -json - \
        -qps "$qps" \
        -c "$concurrency" \
        -t "$duration" \
        -payload-size "$size" \
        -allow-initial-errors \
        "tcp://${server_ip}:8078" 2>/dev/null) || true

    _extract_fortio_json "$raw"
}

# run_fortio_grpc CLIENT_POD SERVER_IP QPS CONCURRENCY DURATION
# Runs fortio gRPC ping test and prints clean JSON to stdout.
run_fortio_grpc() {
    local client="$1"
    local server_ip="$2"
    local qps="$3"
    local concurrency="$4"
    local duration="$5"

    local raw
    raw=$(exec_pod "$client" fortio load \
        -json - \
        -qps "$qps" \
        -c "$concurrency" \
        -t "$duration" \
        -grpc \
        -ping \
        -allow-initial-errors \
        "${server_ip}:8079" 2>/dev/null) || true

    _extract_fortio_json "$raw"
}

###############################################################################
# Fortio JSON extraction helpers
###############################################################################

# extract_percentile JSON PERCENTILE
# Extracts a latency percentile (in milliseconds) from fortio JSON output.
extract_percentile() {
    local json="$1"
    local pct="$2"
    echo "$json" | jq -r \
        "[.DurationHistogram.Percentiles[] | select(.Percentile == ${pct})][0].Value * 1000 // 0" 2>/dev/null || echo "0"
}

# extract_qps JSON
extract_qps() {
    echo "$1" | jq -r '.ActualQPS // 0' 2>/dev/null || echo "0"
}

# extract_duration JSON
extract_duration() {
    echo "$1" | jq -r '.ActualDuration // 0' 2>/dev/null || echo "0"
}

# extract_errors JSON
# Returns total non-success responses (excludes HTTP "200" and TCP "OK").
extract_errors() {
    echo "$1" | jq -r '(.RetCodes | to_entries | map(select(.key != "200" and .key != "OK")) | map(.value) | add) // 0' 2>/dev/null || echo "0"
}

# extract_total_requests JSON
extract_total_requests() {
    echo "$1" | jq -r '(.RetCodes | to_entries | map(.value) | add) // 0' 2>/dev/null || echo "0"
}

# extract_avg_latency JSON (milliseconds)
extract_avg_latency() {
    echo "$1" | jq -r '(.DurationHistogram.Avg // 0) * 1000' 2>/dev/null || echo "0"
}

# extract_min_latency JSON (milliseconds)
extract_min_latency() {
    echo "$1" | jq -r '(.DurationHistogram.Min // 0) * 1000' 2>/dev/null || echo "0"
}

# extract_max_latency JSON (milliseconds)
extract_max_latency() {
    echo "$1" | jq -r '(.DurationHistogram.Max // 0) * 1000' 2>/dev/null || echo "0"
}

# summarize_fortio_result JSON TEST_NAME
# Produces a compact JSON summary from raw fortio output.
summarize_fortio_result() {
    local json="$1"
    local test_name="$2"

    local qps p50 p90 p99 p999 avg_ms min_ms max_ms errors total
    qps=$(extract_qps "$json")
    p50=$(extract_percentile "$json" 50)
    p90=$(extract_percentile "$json" 90)
    p99=$(extract_percentile "$json" 99)
    p999=$(extract_percentile "$json" 99.9)
    avg_ms=$(extract_avg_latency "$json")
    min_ms=$(extract_min_latency "$json")
    max_ms=$(extract_max_latency "$json")
    errors=$(extract_errors "$json")
    total=$(extract_total_requests "$json")

    jq -n \
        --arg name "$test_name" \
        --argjson qps "$qps" \
        --argjson p50 "$p50" \
        --argjson p90 "$p90" \
        --argjson p99 "$p99" \
        --argjson p999 "$p999" \
        --argjson avg "$avg_ms" \
        --argjson min "$min_ms" \
        --argjson max "$max_ms" \
        --argjson errors "$errors" \
        --argjson total "$total" \
        '{
            test: $name,
            actual_qps: ($qps * 100 | round / 100),
            latency_ms: {
                min: ($min * 1000 | round / 1000),
                avg: ($avg * 1000 | round / 1000),
                p50: ($p50 * 1000 | round / 1000),
                p90: ($p90 * 1000 | round / 1000),
                p99: ($p99 * 1000 | round / 1000),
                p999: ($p999 * 1000 | round / 1000),
                max: ($max * 1000 | round / 1000)
            },
            requests: $total,
            errors: $errors
        }'
}

###############################################################################
# Result helpers
###############################################################################

ensure_results_dir() {
    mkdir -p "$RESULTS_DIR"
}

# save_json FILE_PATH JSON_STRING
save_json() {
    local path="$1"
    local json="$2"
    echo "$json" | jq '.' > "$path"
    log_info "Results written to $path"
}

# print_table HEADER_ROW DATA_ROWS...
# Each row is a pipe-delimited string: "col1|col2|col3"
print_table() {
    local header="$1"; shift
    local rows=("$@")

    # Compute column widths.
    local IFS='|'
    local -a hcols
    read -ra hcols <<< "$header"
    local ncols=${#hcols[@]}
    local -a widths=()
    for (( i=0; i<ncols; i++ )); do
        widths[$i]=${#hcols[$i]}
    done
    for row in "${rows[@]}"; do
        local -a rcols
        read -ra rcols <<< "$row"
        for (( i=0; i<ncols; i++ )); do
            local val="${rcols[$i]:-}"
            local len=${#val}
            if (( len > widths[i] )); then
                widths[$i]=$len
            fi
        done
    done

    # Print header.
    local fmt=""
    for (( i=0; i<ncols; i++ )); do
        fmt+="  %-${widths[$i]}s"
    done
    fmt+="\n"
    # shellcheck disable=SC2059
    printf "$fmt" "${hcols[@]}"
    # Print separator.
    local sep=""
    for (( i=0; i<ncols; i++ )); do
        sep+="  $(printf '%0.s-' $(seq 1 "${widths[$i]}"))"
    done
    echo "$sep"
    # Print data rows.
    for row in "${rows[@]}"; do
        local -a rcols
        read -ra rcols <<< "$row"
        # shellcheck disable=SC2059
        printf "$fmt" "${rcols[@]}"
    done
}

###############################################################################
# Cleanup trap helper
###############################################################################

_CLEANUP_REGISTERED=0
register_cleanup() {
    if [[ $_CLEANUP_REGISTERED -eq 0 ]]; then
        trap '_do_cleanup' EXIT INT TERM
        _CLEANUP_REGISTERED=1
    fi
}

_do_cleanup() {
    log_info "Cleaning up benchmark resources..."
    delete_namespace
}

###############################################################################
# NetworkPolicy helpers (used by bench-policy.sh)
###############################################################################

# create_network_policies COUNT
create_network_policies() {
    local count="$1"
    log_info "Creating $count NetworkPolicies..."
    for (( i=1; i<=count; i++ )); do
        cat <<EOF | kubectl apply -n "$BENCHMARK_NS" -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: bench-policy-${i}
spec:
  podSelector:
    matchLabels:
      policy-id: "bench-${i}"
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          policy-id: "bench-${i}"
  egress:
  - to:
    - podSelector:
        matchLabels:
          policy-id: "bench-${i}"
EOF
    done
    log_info "Created $count NetworkPolicies."
}

delete_network_policies() {
    log_info "Deleting benchmark NetworkPolicies..."
    kubectl delete networkpolicy -n "$BENCHMARK_NS" -l app!=novanet-bench --all 2>/dev/null || true
    kubectl get networkpolicy -n "$BENCHMARK_NS" -o name 2>/dev/null \
        | grep 'bench-policy-' \
        | xargs -r kubectl delete -n "$BENCHMARK_NS" 2>/dev/null || true
}

###############################################################################
# iperf3 helpers (bandwidth testing)
###############################################################################

NETSHOOT_IMAGE="${NETSHOOT_IMAGE:-nicolaka/netshoot:latest}"

# create_iperf3_server NAME NODE [--host-network]
create_iperf3_server() {
    local name="$1"
    local node="$2"
    local host_network="${3:-}"

    local host_network_spec="false"
    if [[ "$host_network" == "--host-network" ]]; then
        host_network_spec="true"
    fi

    cat <<EOF | kubectl apply -n "$BENCHMARK_NS" -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  labels:
    app: novanet-bench
    role: iperf3-server
spec:
  nodeName: ${node}
  hostNetwork: ${host_network_spec}
  terminationGracePeriodSeconds: 0
  containers:
  - name: iperf3
    image: ${NETSHOOT_IMAGE}
    command: ["iperf3", "-s", "-p", "5201"]
    ports:
    - containerPort: 5201
      name: iperf3
    resources:
      requests:
        cpu: "100m"
        memory: "64Mi"
      limits:
        cpu: "4"
        memory: "512Mi"
    readinessProbe:
      tcpSocket:
        port: 5201
      initialDelaySeconds: 2
      periodSeconds: 3
EOF
    log_info "Created iperf3 server $name on node $node (hostNetwork=$host_network_spec)"
}

# create_iperf3_client NAME NODE [--host-network]
create_iperf3_client() {
    local name="$1"
    local node="$2"
    local host_network="${3:-}"

    local host_network_spec="false"
    if [[ "$host_network" == "--host-network" ]]; then
        host_network_spec="true"
    fi

    cat <<EOF | kubectl apply -n "$BENCHMARK_NS" -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  labels:
    app: novanet-bench
    role: iperf3-client
spec:
  nodeName: ${node}
  hostNetwork: ${host_network_spec}
  terminationGracePeriodSeconds: 0
  containers:
  - name: iperf3
    image: ${NETSHOOT_IMAGE}
    command: ["sleep", "3600"]
    resources:
      requests:
        cpu: "100m"
        memory: "64Mi"
      limits:
        cpu: "4"
        memory: "512Mi"
EOF
    log_info "Created iperf3 client $name on node $node (hostNetwork=$host_network_spec)"
}

# run_iperf3_tcp CLIENT_POD SERVER_IP DURATION [PARALLEL_STREAMS]
# Runs iperf3 TCP bandwidth test and prints JSON to stdout.
run_iperf3_tcp() {
    local client="$1"
    local server_ip="$2"
    local duration="$3"
    local parallel="${4:-1}"

    exec_pod "$client" iperf3 \
        -c "$server_ip" \
        -p 5201 \
        -t "$duration" \
        -P "$parallel" \
        --json 2>/dev/null || true
}

# run_iperf3_tcp_reverse CLIENT_POD SERVER_IP DURATION [PARALLEL_STREAMS]
# Runs iperf3 TCP reverse (download) bandwidth test.
run_iperf3_tcp_reverse() {
    local client="$1"
    local server_ip="$2"
    local duration="$3"
    local parallel="${4:-1}"

    exec_pod "$client" iperf3 \
        -c "$server_ip" \
        -p 5201 \
        -t "$duration" \
        -P "$parallel" \
        -R \
        --json 2>/dev/null || true
}

# run_iperf3_udp CLIENT_POD SERVER_IP DURATION BITRATE [PARALLEL_STREAMS]
# Runs iperf3 UDP bandwidth test at the specified target bitrate.
run_iperf3_udp() {
    local client="$1"
    local server_ip="$2"
    local duration="$3"
    local bitrate="$4"
    local parallel="${5:-1}"

    exec_pod "$client" iperf3 \
        -c "$server_ip" \
        -p 5201 \
        -t "$duration" \
        -P "$parallel" \
        -u \
        -b "$bitrate" \
        --json 2>/dev/null || true
}

# summarize_iperf3_result JSON TEST_NAME
# Extracts bandwidth summary from iperf3 JSON output.
summarize_iperf3_result() {
    local json="$1"
    local test_name="$2"

    echo "$json" | jq --arg name "$test_name" '
    # Detect UDP: sum_received has jitter_ms and lost_packets fields
    if (.end.sum_received.jitter_ms // null) != null then
        # UDP result — jitter/loss from receiver side (.sum_received)
        {
            test: $name,
            sent: {
                bytes: .end.sum_sent.bytes,
                bandwidth_bps: .end.sum_sent.bits_per_second,
                bandwidth_gbps: ((.end.sum_sent.bits_per_second / 1000000000 * 1000 | round) / 1000),
                bandwidth_mbps: ((.end.sum_sent.bits_per_second / 1000000 * 100 | round) / 100),
                jitter_ms: ((.end.sum_received.jitter_ms * 1000 | round) / 1000),
                lost_packets: (.end.sum_received.lost_packets // 0),
                total_packets: (.end.sum_received.packets // 0),
                lost_percent: ((.end.sum_received.lost_percent * 100 | round) / 100)
            },
            duration_secs: .end.sum_sent.seconds,
            cpu_utilization: {
                host_total: (.end.cpu_utilization_percent.host_total // 0),
                remote_total: (.end.cpu_utilization_percent.remote_total // 0)
            }
        }
    elif .end.sum_sent then
        # TCP result
        {
            test: $name,
            sent: {
                bytes: .end.sum_sent.bytes,
                bandwidth_bps: .end.sum_sent.bits_per_second,
                bandwidth_gbps: ((.end.sum_sent.bits_per_second / 1000000000 * 1000 | round) / 1000),
                bandwidth_mbps: ((.end.sum_sent.bits_per_second / 1000000 * 100 | round) / 100),
                retransmits: (.end.sum_sent.retransmits // 0)
            },
            received: {
                bytes: .end.sum_received.bytes,
                bandwidth_bps: .end.sum_received.bits_per_second,
                bandwidth_gbps: ((.end.sum_received.bits_per_second / 1000000000 * 1000 | round) / 1000),
                bandwidth_mbps: ((.end.sum_received.bits_per_second / 1000000 * 100 | round) / 100)
            },
            duration_secs: .end.sum_sent.seconds,
            cpu_utilization: {
                host_total: (.end.cpu_utilization_percent.host_total // 0),
                remote_total: (.end.cpu_utilization_percent.remote_total // 0)
            }
        }
    else
        empty
    end
    ' 2>/dev/null
}

###############################################################################
# Metadata
###############################################################################

collect_metadata() {
    local k8s_version
    k8s_version=$(kubectl version -o json 2>/dev/null | jq -r '.serverVersion.gitVersion // "unknown"')

    local node_count
    node_count=$(kubectl get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')

    local novanet_image
    novanet_image=$(kubectl get daemonset -n nova-system -o jsonpath='{.items[0].spec.template.spec.containers[0].image}' 2>/dev/null || echo "unknown")

    jq -n \
        --arg ts "$TIMESTAMP" \
        --arg k8s "$k8s_version" \
        --arg cni "$novanet_image" \
        --arg nodes "$node_count" \
        --arg node1 "$WORKER_NODE_1" \
        --arg node2 "$WORKER_NODE_2" \
        --arg fortio "$FORTIO_IMAGE" \
        --arg duration "$DURATION" \
        '{
            timestamp: $ts,
            kubernetes_version: $k8s,
            novanet_image: $cni,
            node_count: ($nodes|tonumber),
            worker_node_1: $node1,
            worker_node_2: $node2,
            fortio_image: $fortio,
            duration: $duration
        }'
}
