#!/usr/bin/env bash
# lib.sh — Shared utility functions for NovaNet integration tests.
# Source this file at the top of each test script.
set -euo pipefail

###############################################################################
# Configuration
###############################################################################
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
export NOVANET_NS="${NOVANET_NS:-nova-system}"
export TEST_NS="${TEST_NS:-novanet-test}"
export TEST_IMAGE="${TEST_IMAGE:-nicolaka/netshoot:latest}"
export ALPINE_IMAGE="${ALPINE_IMAGE:-alpine:3.19}"
export SSH_PASS="${SSH_PASS:-62156215}"

# Cluster node IPs
MASTER_IPS=("192.168.100.11" "192.168.100.12" "192.168.100.13")
WORKER_IPS=("192.168.100.21" "192.168.100.22" "192.168.100.23" "192.168.100.24" "192.168.100.25")
ALL_IPS=("${MASTER_IPS[@]}" "${WORKER_IPS[@]}")

# Timeouts (seconds)
POD_READY_TIMEOUT="${POD_READY_TIMEOUT:-120}"
CONNECTIVITY_TIMEOUT="${CONNECTIVITY_TIMEOUT:-30}"

###############################################################################
# Colors
###############################################################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'  # No Color

###############################################################################
# Logging
###############################################################################
log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_pass()  { echo -e "${GREEN}[PASS]${NC}  $*"; }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_step()  { echo -e "${CYAN}[STEP]${NC}  $*"; }
log_header() {
    echo ""
    echo -e "${BOLD}========================================${NC}"
    echo -e "${BOLD}  $*${NC}"
    echo -e "${BOLD}========================================${NC}"
    echo ""
}

###############################################################################
# Test tracking
###############################################################################
_TESTS_PASSED=0
_TESTS_FAILED=0
_TESTS_SKIPPED=0
_TEST_NAME=""

begin_test() {
    _TEST_NAME="$1"
    log_step "Running: $_TEST_NAME"
}

pass_test() {
    _TESTS_PASSED=$((_TESTS_PASSED + 1))
    log_pass "$_TEST_NAME"
}

fail_test() {
    _TESTS_FAILED=$((_TESTS_FAILED + 1))
    local msg="${1:-}"
    if [[ -n "$msg" ]]; then
        log_fail "$_TEST_NAME — $msg"
    else
        log_fail "$_TEST_NAME"
    fi
}

skip_test() {
    _TESTS_SKIPPED=$((_TESTS_SKIPPED + 1))
    local reason="${1:-}"
    if [[ -n "$reason" ]]; then
        log_warn "SKIP: $_TEST_NAME — $reason"
    else
        log_warn "SKIP: $_TEST_NAME"
    fi
}

print_summary() {
    echo ""
    echo -e "${BOLD}--- Test Summary ---${NC}"
    echo -e "  ${GREEN}Passed:${NC}  $_TESTS_PASSED"
    echo -e "  ${RED}Failed:${NC}  $_TESTS_FAILED"
    echo -e "  ${YELLOW}Skipped:${NC} $_TESTS_SKIPPED"
    echo ""
    if [[ $_TESTS_FAILED -gt 0 ]]; then
        echo -e "${RED}${BOLD}RESULT: FAILED${NC}"
        return 1
    else
        echo -e "${GREEN}${BOLD}RESULT: PASSED${NC}"
        return 0
    fi
}

###############################################################################
# Namespace management
###############################################################################
ensure_test_ns() {
    if ! kubectl get namespace "$TEST_NS" &>/dev/null; then
        log_info "Creating test namespace: $TEST_NS"
        kubectl create namespace "$TEST_NS"
    fi
}

delete_test_ns() {
    if kubectl get namespace "$TEST_NS" &>/dev/null; then
        log_info "Deleting test namespace: $TEST_NS"
        kubectl delete namespace "$TEST_NS" --timeout=60s --wait=true 2>/dev/null || true
    fi
}

###############################################################################
# Pod creation helpers
###############################################################################

# Create a long-running pod (sleeps forever) on a specific node.
# Usage: create_pod <name> [node_name] [extra_labels]
create_pod() {
    local name="$1"
    local node="${2:-}"
    local labels="${3:-app=novanet-test}"

    local node_override=""
    if [[ -n "$node" ]]; then
        node_override="--overrides={\"spec\":{\"nodeName\":\"$node\"}}"
    fi

    # shellcheck disable=SC2086
    kubectl run "$name" \
        --namespace="$TEST_NS" \
        --image="$TEST_IMAGE" \
        --labels="$labels" \
        --restart=Never \
        $node_override \
        --command -- sleep 3600

    log_info "Created pod $name${node:+ on node $node}"
}

# Create a pod with specific labels for policy testing.
# Usage: create_labeled_pod <name> <label_key=label_value,...> [node_name]
create_labeled_pod() {
    local name="$1"
    local labels="$2"
    local node="${3:-}"

    local node_override=""
    if [[ -n "$node" ]]; then
        node_override="--overrides={\"spec\":{\"nodeName\":\"$node\"}}"
    fi

    # shellcheck disable=SC2086
    kubectl run "$name" \
        --namespace="$TEST_NS" \
        --image="$TEST_IMAGE" \
        --labels="$labels" \
        --restart=Never \
        $node_override \
        --command -- sleep 3600

    log_info "Created pod $name with labels=$labels"
}

# Create an iperf3 server pod.
# Usage: create_iperf3_server <name> [node_name]
create_iperf3_server() {
    local name="$1"
    local node="${2:-}"

    local node_override=""
    if [[ -n "$node" ]]; then
        node_override="--overrides={\"spec\":{\"nodeName\":\"$node\"}}"
    fi

    # shellcheck disable=SC2086
    kubectl run "$name" \
        --namespace="$TEST_NS" \
        --image="$TEST_IMAGE" \
        --labels="app=iperf3-server" \
        --restart=Never \
        $node_override \
        --command -- iperf3 -s

    log_info "Created iperf3 server $name${node:+ on node $node}"
}

###############################################################################
# Wait helpers
###############################################################################

# Wait for a pod to be Running and Ready.
# Usage: wait_pod_ready <pod_name> [timeout_seconds]
wait_pod_ready() {
    local pod="$1"
    local timeout="${2:-$POD_READY_TIMEOUT}"

    log_info "Waiting for pod $pod to be ready (timeout=${timeout}s)..."
    if ! kubectl wait pod "$pod" \
        --namespace="$TEST_NS" \
        --for=condition=Ready \
        --timeout="${timeout}s" 2>/dev/null; then
        log_fail "Pod $pod did not become ready within ${timeout}s"
        kubectl describe pod "$pod" --namespace="$TEST_NS" 2>/dev/null | tail -20
        return 1
    fi
    log_info "Pod $pod is ready"
}

# Wait for all pods matching a label selector to be ready.
# Usage: wait_pods_ready <label_selector> [timeout_seconds]
wait_pods_ready() {
    local selector="$1"
    local timeout="${2:-$POD_READY_TIMEOUT}"

    log_info "Waiting for pods with selector '$selector' to be ready..."
    if ! kubectl wait pods \
        --namespace="$TEST_NS" \
        --selector="$selector" \
        --for=condition=Ready \
        --timeout="${timeout}s" 2>/dev/null; then
        log_fail "Pods with selector '$selector' did not become ready"
        return 1
    fi
}

# Wait for a condition with retries.
# Usage: wait_for <description> <timeout_seconds> <command...>
wait_for() {
    local desc="$1"
    local timeout="$2"
    shift 2

    log_info "Waiting for: $desc (timeout=${timeout}s)"
    local deadline=$((SECONDS + timeout))
    while [[ $SECONDS -lt $deadline ]]; do
        if "$@" &>/dev/null; then
            log_info "$desc — OK"
            return 0
        fi
        sleep 2
    done
    log_fail "$desc — timed out after ${timeout}s"
    return 1
}

###############################################################################
# Pod execution helpers
###############################################################################

# Execute a command inside a running pod.
# Usage: pod_exec <pod_name> <command...>
pod_exec() {
    local pod="$1"
    shift
    kubectl exec "$pod" --namespace="$TEST_NS" -- "$@"
}

# Ping from one pod to an IP address.
# Usage: pod_ping <pod_name> <target_ip> [count]
pod_ping() {
    local pod="$1"
    local target="$2"
    local count="${3:-3}"

    pod_exec "$pod" ping -c "$count" -W 5 "$target"
}

# Get the IP of a pod.
# Usage: get_pod_ip <pod_name>
get_pod_ip() {
    local pod="$1"
    kubectl get pod "$pod" \
        --namespace="$TEST_NS" \
        --output=jsonpath='{.status.podIP}'
}

# Get the node a pod is scheduled on.
# Usage: get_pod_node <pod_name>
get_pod_node() {
    local pod="$1"
    kubectl get pod "$pod" \
        --namespace="$TEST_NS" \
        --output=jsonpath='{.spec.nodeName}'
}

###############################################################################
# Node helpers
###############################################################################

# Get a list of Kubernetes node names.
get_node_names() {
    kubectl get nodes -o jsonpath='{.items[*].metadata.name}'
}

# Get worker node names (nodes without master/control-plane role).
# Uses jsonpath filtering to avoid '!' in selectors which can break through SSH.
get_worker_nodes() {
    local workers
    workers=$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.metadata.labels.node-role\.kubernetes\.io/master}{.metadata.labels.node-role\.kubernetes\.io/control-plane}{"\n"}{end}' 2>/dev/null \
        | awk '$2 == "" { printf "%s ", $1 }')
    workers="${workers% }"  # trim trailing space

    if [[ -n "$workers" ]]; then
        echo "$workers"
    else
        # Fallback: all nodes are schedulable
        kubectl get nodes -o jsonpath='{.items[*].metadata.name}'
    fi
}

# Pick two distinct nodes from the cluster. Outputs two names separated by space.
pick_two_nodes() {
    local nodes
    nodes=($(get_worker_nodes))
    if [[ ${#nodes[@]} -lt 2 ]]; then
        # Fall back to all nodes
        nodes=($(get_node_names))
    fi
    if [[ ${#nodes[@]} -lt 2 ]]; then
        log_fail "Need at least 2 nodes for cross-node tests, found ${#nodes[@]}"
        return 1
    fi
    echo "${nodes[0]} ${nodes[1]}"
}

# SSH to a cluster node and run a command.
# Usage: ssh_node <ip> <command...>
ssh_node() {
    local ip="$1"
    shift
    sshpass -p "$SSH_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "root@${ip}" "$@"
}

###############################################################################
# NovaNet-specific helpers
###############################################################################

# Check that the NovaNet DaemonSet is healthy.
check_novanet_daemonset() {
    local desired ready
    desired=$(kubectl get daemonset -n "$NOVANET_NS" -o jsonpath='{.items[0].status.desiredNumberScheduled}' 2>/dev/null || echo "0")
    ready=$(kubectl get daemonset -n "$NOVANET_NS" -o jsonpath='{.items[0].status.numberReady}' 2>/dev/null || echo "0")

    if [[ "$desired" -eq 0 ]]; then
        log_fail "NovaNet DaemonSet not found in namespace $NOVANET_NS"
        return 1
    fi
    if [[ "$desired" -ne "$ready" ]]; then
        log_warn "NovaNet DaemonSet: desired=$desired ready=$ready (not fully healthy)"
        return 1
    fi
    log_info "NovaNet DaemonSet healthy: $ready/$desired pods ready"
    return 0
}

# Run novanetctl on a specific node via SSH.
# Usage: novanetctl_on_node <node_ip> <args...>
novanetctl_on_node() {
    local ip="$1"
    shift
    ssh_node "$ip" "novanetctl $*"
}

# Get the current routing mode from the NovaNet ConfigMap or helm values.
get_routing_mode() {
    kubectl get configmap -n "$NOVANET_NS" novanet-config -o jsonpath='{.data.routingMode}' 2>/dev/null || echo "unknown"
}

# Get the current tunnel protocol from the NovaNet ConfigMap.
get_tunnel_protocol() {
    kubectl get configmap -n "$NOVANET_NS" novanet-config -o jsonpath='{.data.tunnelProtocol}' 2>/dev/null || echo "unknown"
}

###############################################################################
# Cleanup
###############################################################################

# Delete a specific pod.
# Usage: delete_pod <pod_name>
delete_pod() {
    local pod="$1"
    kubectl delete pod "$pod" --namespace="$TEST_NS" --grace-period=0 --force 2>/dev/null || true
}

# Delete all test pods in the test namespace.
cleanup_test_pods() {
    log_info "Cleaning up test pods in namespace $TEST_NS..."
    kubectl delete pods --all --namespace="$TEST_NS" --grace-period=0 --force 2>/dev/null || true
}

# Delete all network policies in the test namespace.
cleanup_network_policies() {
    log_info "Cleaning up network policies in namespace $TEST_NS..."
    kubectl delete networkpolicies --all --namespace="$TEST_NS" 2>/dev/null || true
}

# Full cleanup: pods, policies, and namespace.
full_cleanup() {
    cleanup_network_policies
    cleanup_test_pods
    delete_test_ns
}

# Register a cleanup trap. Call this in each test script after sourcing lib.sh.
# Usage: register_cleanup
register_cleanup() {
    trap 'log_info "Cleaning up..."; full_cleanup' EXIT
}

###############################################################################
# Assertions
###############################################################################

# Assert that a command succeeds.
# Usage: assert_success <description> <command...>
assert_success() {
    local desc="$1"
    shift
    begin_test "$desc"
    if "$@"; then
        pass_test
        return 0
    else
        fail_test "command returned non-zero"
        return 1
    fi
}

# Assert that a command fails.
# Usage: assert_failure <description> <command...>
assert_failure() {
    local desc="$1"
    shift
    begin_test "$desc"
    if "$@" 2>/dev/null; then
        fail_test "expected failure but command succeeded"
        return 1
    else
        pass_test
        return 0
    fi
}

# Assert that pod-to-pod ping succeeds.
# Usage: assert_ping <description> <source_pod> <target_ip>
assert_ping() {
    local desc="$1"
    local src="$2"
    local target="$3"
    begin_test "$desc"
    if pod_ping "$src" "$target" 3 &>/dev/null; then
        pass_test
        return 0
    else
        fail_test "ping from $src to $target failed"
        return 1
    fi
}

# Assert that pod-to-pod ping fails (for policy tests).
# Usage: assert_no_ping <description> <source_pod> <target_ip>
assert_no_ping() {
    local desc="$1"
    local src="$2"
    local target="$3"
    begin_test "$desc"
    if pod_ping "$src" "$target" 2 2>/dev/null; then
        fail_test "ping from $src to $target succeeded (expected failure)"
        return 1
    else
        pass_test
        return 0
    fi
}

# Assert that TCP connectivity works (using netcat or curl).
# Usage: assert_tcp <description> <source_pod> <target_ip> <port>
assert_tcp() {
    local desc="$1"
    local src="$2"
    local target="$3"
    local port="$4"
    begin_test "$desc"
    if pod_exec "$src" bash -c "echo | nc -w 5 $target $port" &>/dev/null; then
        pass_test
        return 0
    else
        fail_test "TCP connect from $src to $target:$port failed"
        return 1
    fi
}

# Assert that TCP connectivity fails.
# Usage: assert_no_tcp <description> <source_pod> <target_ip> <port>
assert_no_tcp() {
    local desc="$1"
    local src="$2"
    local target="$3"
    local port="$4"
    begin_test "$desc"
    if pod_exec "$src" bash -c "echo | nc -w 3 $target $port" 2>/dev/null; then
        fail_test "TCP connect from $src to $target:$port succeeded (expected failure)"
        return 1
    else
        pass_test
        return 0
    fi
}

###############################################################################
# Prerequisite checks
###############################################################################

# Verify that required tools are available.
preflight_check() {
    log_header "Preflight Check"

    local missing=0

    for cmd in kubectl sshpass; do
        if ! command -v "$cmd" &>/dev/null; then
            log_fail "Required command not found: $cmd"
            missing=$((missing + 1))
        fi
    done

    if [[ $missing -gt 0 ]]; then
        log_fail "Install missing dependencies and retry."
        exit 1
    fi

    # Check kubectl connectivity
    if ! kubectl cluster-info &>/dev/null; then
        log_fail "Cannot connect to Kubernetes cluster. Check KUBECONFIG=$KUBECONFIG"
        exit 1
    fi
    log_info "Cluster reachable"

    # Check NovaNet DaemonSet
    if ! check_novanet_daemonset; then
        log_warn "NovaNet DaemonSet is not fully healthy — tests may fail"
    fi

    log_info "Preflight checks passed"
}
