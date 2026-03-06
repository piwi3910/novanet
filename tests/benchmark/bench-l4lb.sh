#!/usr/bin/env bash
# bench-l4lb.sh — L4 LB (kube-proxy replacement) benchmarks for NovaNet using fortio.
#
# Measures the DNAT overhead of eBPF-based L4 load balancing by comparing:
#   1. Direct pod-to-pod (baseline — no Service DNAT)
#   2. ClusterIP same-node (client and backends on same node)
#   3. ClusterIP cross-node (client on node A, backends on node B)
#   4. NodePort (host-network client via NodePort)
#
# Results are saved as JSON to results/l4lb-<timestamp>.json

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

###############################################################################
# Configuration
###############################################################################

CONCURRENCIES="${CONCURRENCIES:-1 4 16 64}"
BACKEND_REPLICAS="${BACKEND_REPLICAS:-3}"

###############################################################################
# Helpers — Service + Deployment creation
###############################################################################

# create_fortio_deployment NAME NODE REPLICAS
# Creates a Deployment of fortio servers pinned to a node.
create_fortio_deployment() {
    local name="$1"
    local node="$2"
    local replicas="$3"

    cat <<EOF | kubectl apply -n "$BENCHMARK_NS" -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${name}
  labels:
    app: novanet-bench
spec:
  replicas: ${replicas}
  selector:
    matchLabels:
      app: ${name}
  template:
    metadata:
      labels:
        app: ${name}
    spec:
      nodeName: ${node}
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
    log_info "Created fortio deployment $name ($replicas replicas) on node $node"
}

# create_clusterip_service NAME TARGET_APP
# Creates a ClusterIP Service targeting the given app label.
create_clusterip_service() {
    local name="$1"
    local target_app="$2"

    cat <<EOF | kubectl apply -n "$BENCHMARK_NS" -f -
apiVersion: v1
kind: Service
metadata:
  name: ${name}
  labels:
    app: novanet-bench
spec:
  type: ClusterIP
  selector:
    app: ${target_app}
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: tcp-echo
    port: 8078
    targetPort: 8078
EOF
    log_info "Created ClusterIP service $name -> $target_app"
}

# create_nodeport_service NAME TARGET_APP
# Creates a NodePort Service targeting the given app label.
create_nodeport_service() {
    local name="$1"
    local target_app="$2"

    cat <<EOF | kubectl apply -n "$BENCHMARK_NS" -f -
apiVersion: v1
kind: Service
metadata:
  name: ${name}
  labels:
    app: novanet-bench
spec:
  type: NodePort
  selector:
    app: ${target_app}
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: tcp-echo
    port: 8078
    targetPort: 8078
EOF
    log_info "Created NodePort service $name -> $target_app"
}

# wait_deployment_ready NAME [TIMEOUT]
wait_deployment_ready() {
    local name="$1"
    local timeout="${2:-120}"
    log_info "Waiting for deployment $name to be ready (timeout ${timeout}s)..."
    kubectl rollout status deployment/"$name" -n "$BENCHMARK_NS" --timeout="${timeout}s"
}

# get_service_clusterip NAME
get_service_clusterip() {
    kubectl get svc "$1" -n "$BENCHMARK_NS" -o jsonpath='{.spec.clusterIP}'
}

# get_service_nodeport NAME PORT_NAME
get_service_nodeport() {
    kubectl get svc "$1" -n "$BENCHMARK_NS" -o jsonpath="{.spec.ports[?(@.name==\"$2\")].nodePort}"
}

###############################################################################
# Main
###############################################################################

main() {
    log_header "NovaNet L4 LB Benchmark (fortio)"
    check_prerequisites
    ensure_results_dir
    register_cleanup

    delete_namespace
    ensure_namespace

    local all_results=()

    # -------------------------------------------------------------------
    # 1 — Direct pod-to-pod baseline (no Service, no DNAT)
    # -------------------------------------------------------------------
    log_header "Baseline: Direct Pod-to-Pod (${WORKER_NODE_1})"

    create_fortio_server "baseline-server" "$WORKER_NODE_1"
    create_fortio_client "baseline-client" "$WORKER_NODE_1"
    wait_pod_ready "baseline-server"
    wait_pod_ready "baseline-client"

    local server_ip
    server_ip=$(get_pod_ip "baseline-server")

    for c in $CONCURRENCIES; do
        log_step "direct-http c=${c} (max QPS, t=${DURATION})"
        local raw_json summary
        raw_json=$(run_fortio_http "baseline-client" "$server_ip" 0 "$c" "$DURATION") || true
        if [[ -n "$raw_json" ]] && echo "$raw_json" | jq empty 2>/dev/null; then
            summary=$(summarize_fortio_result "$raw_json" "direct-http-c${c}")
            summary=$(echo "$summary" | jq --arg proto "http" --argjson c "$c" '. + {protocol: $proto, concurrency: $c, mode: "direct"}')
            all_results+=("$summary")
            log_info "  -> QPS: $(echo "$summary" | jq -r '.actual_qps')  p50: $(echo "$summary" | jq -r '.latency_ms.p50')ms  p99: $(echo "$summary" | jq -r '.latency_ms.p99')ms"
        else
            log_warn "  -> No valid output for direct-http c=${c}"
        fi
    done

    delete_pod "baseline-server"
    delete_pod "baseline-client"

    # -------------------------------------------------------------------
    # 2 — ClusterIP same-node (client + backends on same node)
    # -------------------------------------------------------------------
    log_header "ClusterIP Same-Node (${WORKER_NODE_1})"

    create_fortio_deployment "samenode-backends" "$WORKER_NODE_1" "$BACKEND_REPLICAS"
    create_clusterip_service "samenode-svc" "samenode-backends"
    create_fortio_client "samenode-client" "$WORKER_NODE_1"
    wait_deployment_ready "samenode-backends"
    wait_pod_ready "samenode-client"

    local clusterip
    clusterip=$(get_service_clusterip "samenode-svc")
    log_info "ClusterIP: $clusterip"

    for c in $CONCURRENCIES; do
        log_step "clusterip-samenode-http c=${c} (max QPS, t=${DURATION})"
        local raw_json summary
        raw_json=$(run_fortio_http "samenode-client" "$clusterip" 0 "$c" "$DURATION") || true
        if [[ -n "$raw_json" ]] && echo "$raw_json" | jq empty 2>/dev/null; then
            summary=$(summarize_fortio_result "$raw_json" "clusterip-samenode-http-c${c}")
            summary=$(echo "$summary" | jq --arg proto "http" --argjson c "$c" '. + {protocol: $proto, concurrency: $c, mode: "clusterip-samenode"}')
            all_results+=("$summary")
            log_info "  -> QPS: $(echo "$summary" | jq -r '.actual_qps')  p50: $(echo "$summary" | jq -r '.latency_ms.p50')ms  p99: $(echo "$summary" | jq -r '.latency_ms.p99')ms"
        else
            log_warn "  -> No valid output for clusterip-samenode-http c=${c}"
        fi
    done

    kubectl delete deployment samenode-backends -n "$BENCHMARK_NS" --ignore-not-found
    kubectl delete svc samenode-svc -n "$BENCHMARK_NS" --ignore-not-found
    delete_pod "samenode-client"

    # -------------------------------------------------------------------
    # 3 — ClusterIP cross-node (client on node A, backends on node B)
    # -------------------------------------------------------------------
    log_header "ClusterIP Cross-Node (${WORKER_NODE_2} -> ${WORKER_NODE_1})"

    create_fortio_deployment "crossnode-backends" "$WORKER_NODE_1" "$BACKEND_REPLICAS"
    create_clusterip_service "crossnode-svc" "crossnode-backends"
    create_fortio_client "crossnode-client" "$WORKER_NODE_2"
    wait_deployment_ready "crossnode-backends"
    wait_pod_ready "crossnode-client"

    clusterip=$(get_service_clusterip "crossnode-svc")
    log_info "ClusterIP: $clusterip"

    for c in $CONCURRENCIES; do
        log_step "clusterip-crossnode-http c=${c} (max QPS, t=${DURATION})"
        local raw_json summary
        raw_json=$(run_fortio_http "crossnode-client" "$clusterip" 0 "$c" "$DURATION") || true
        if [[ -n "$raw_json" ]] && echo "$raw_json" | jq empty 2>/dev/null; then
            summary=$(summarize_fortio_result "$raw_json" "clusterip-crossnode-http-c${c}")
            summary=$(echo "$summary" | jq --arg proto "http" --argjson c "$c" '. + {protocol: $proto, concurrency: $c, mode: "clusterip-crossnode"}')
            all_results+=("$summary")
            log_info "  -> QPS: $(echo "$summary" | jq -r '.actual_qps')  p50: $(echo "$summary" | jq -r '.latency_ms.p50')ms  p99: $(echo "$summary" | jq -r '.latency_ms.p99')ms"
        else
            log_warn "  -> No valid output for clusterip-crossnode-http c=${c}"
        fi
    done

    kubectl delete deployment crossnode-backends -n "$BENCHMARK_NS" --ignore-not-found
    kubectl delete svc crossnode-svc -n "$BENCHMARK_NS" --ignore-not-found
    delete_pod "crossnode-client"

    # -------------------------------------------------------------------
    # 4 — NodePort (host-network client via NodePort)
    # -------------------------------------------------------------------
    log_header "NodePort (host-network client on ${WORKER_NODE_2})"

    create_fortio_deployment "nodeport-backends" "$WORKER_NODE_1" "$BACKEND_REPLICAS"
    create_nodeport_service "nodeport-svc" "nodeport-backends"
    create_fortio_client "nodeport-client" "$WORKER_NODE_2" --host-network
    wait_deployment_ready "nodeport-backends"
    wait_pod_ready "nodeport-client"

    local node_ip nodeport
    node_ip=$(kubectl get node "$WORKER_NODE_1" -o jsonpath='{.status.addresses[?(@.type=="InternalIP")].address}')
    nodeport=$(get_service_nodeport "nodeport-svc" "http")
    log_info "NodePort: ${node_ip}:${nodeport}"

    for c in $CONCURRENCIES; do
        log_step "nodeport-http c=${c} (max QPS, t=${DURATION})"
        local raw_json summary
        raw_json=$(run_fortio_http "nodeport-client" "$node_ip" "$nodeport" "$c" "$DURATION") || true
        if [[ -n "$raw_json" ]] && echo "$raw_json" | jq empty 2>/dev/null; then
            summary=$(summarize_fortio_result "$raw_json" "nodeport-http-c${c}")
            summary=$(echo "$summary" | jq --arg proto "http" --argjson c "$c" '. + {protocol: $proto, concurrency: $c, mode: "nodeport"}')
            all_results+=("$summary")
            log_info "  -> QPS: $(echo "$summary" | jq -r '.actual_qps')  p50: $(echo "$summary" | jq -r '.latency_ms.p50')ms  p99: $(echo "$summary" | jq -r '.latency_ms.p99')ms"
        else
            log_warn "  -> No valid output for nodeport-http c=${c}"
        fi
    done

    kubectl delete deployment nodeport-backends -n "$BENCHMARK_NS" --ignore-not-found
    kubectl delete svc nodeport-svc -n "$BENCHMARK_NS" --ignore-not-found
    delete_pod "nodeport-client"

    # -------------------------------------------------------------------
    # Assemble final JSON & summary
    # -------------------------------------------------------------------
    if [[ ${#all_results[@]} -eq 0 ]]; then
        log_error "No benchmark results collected!"
        return 1
    fi

    local metadata
    metadata=$(collect_metadata)

    local json_results
    json_results=$(printf '%s\n' "${all_results[@]}" | jq -s '.')

    local final_json
    final_json=$(jq -n \
        --argjson meta "$metadata" \
        --argjson tests "$json_results" \
        '{
            benchmark: "l4lb",
            metadata: $meta,
            results: $tests
        }')

    local out_file="$RESULTS_DIR/l4lb-${TIMESTAMP}.json"
    save_json "$out_file" "$final_json"

    log_header "L4 LB Results Summary"

    local header="Test|Proto|Conc|QPS|p50 (ms)|p90 (ms)|p99 (ms)|Errors"
    local rows=()
    for r in "${all_results[@]}"; do
        local name proto c qps p50 p90 p99 errs
        name=$(echo "$r" | jq -r '.test')
        proto=$(echo "$r" | jq -r '.protocol | ascii_upcase')
        c=$(echo "$r" | jq -r '.concurrency')
        qps=$(echo "$r" | jq -r '.actual_qps')
        p50=$(echo "$r" | jq -r '.latency_ms.p50')
        p90=$(echo "$r" | jq -r '.latency_ms.p90')
        p99=$(echo "$r" | jq -r '.latency_ms.p99')
        errs=$(echo "$r" | jq -r '.errors')
        rows+=("${name}|${proto}|${c}|${qps}|${p50}|${p90}|${p99}|${errs}")
    done

    print_table "$header" "${rows[@]}"
    echo ""
    log_info "Full results: $out_file"
}

main "$@"
