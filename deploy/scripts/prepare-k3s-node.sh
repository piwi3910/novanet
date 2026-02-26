#!/bin/bash
# prepare-k3s-node.sh — Prepare a K3s node for NovaNet by disabling built-in Flannel.
# Run this on each K3s SERVER node before deploying NovaNet.
# NOTE: flannel-backend and disable-network-policy are server-only flags.
#       Do NOT run this on agent/worker nodes — only run the cleanup section.
set -euo pipefail

echo "=== Preparing K3s node for NovaNet ==="

# 1. Update K3s config to disable Flannel and built-in network policy.
#    Only apply server flags if this is a server node (k3s service, not k3s-agent).
CONFIG_FILE="/etc/rancher/k3s/config.yaml"
IS_SERVER=false
if systemctl is-active --quiet k3s 2>/dev/null || systemctl is-enabled --quiet k3s 2>/dev/null; then
    IS_SERVER=true
fi

if [ "$IS_SERVER" = true ]; then
    echo "Detected K3s server node"
    if [ -f "$CONFIG_FILE" ]; then
        if grep -q "flannel-backend" "$CONFIG_FILE"; then
            echo "flannel-backend already in config, skipping"
        else
            echo "Adding flannel-backend: none to K3s config"
            echo 'flannel-backend: "none"' >> "$CONFIG_FILE"
        fi
        if grep -q "disable-network-policy" "$CONFIG_FILE"; then
            echo "disable-network-policy already in config, skipping"
        else
            echo "Adding disable-network-policy: true to K3s config"
            echo 'disable-network-policy: true' >> "$CONFIG_FILE"
        fi
    else
        echo "Creating K3s config"
        mkdir -p "$(dirname "$CONFIG_FILE")"
        cat > "$CONFIG_FILE" <<'CONF'
flannel-backend: "none"
disable-network-policy: true
CONF
    fi
    echo "K3s config:"
    cat "$CONFIG_FILE"
else
    echo "Detected K3s agent node — skipping server-only config flags"
fi

# 2. Remove Flannel CNI config (NovaNet will install its own).
FLANNEL_CONF="/var/lib/rancher/k3s/agent/etc/cni/net.d/10-flannel.conflist"
if [ -f "$FLANNEL_CONF" ]; then
    echo "Removing Flannel CNI config: $FLANNEL_CONF"
    rm -f "$FLANNEL_CONF"
fi

# 3. Clean up Flannel interfaces.
if ip link show flannel.1 &>/dev/null; then
    echo "Removing flannel.1 interface"
    ip link delete flannel.1 || true
fi
if ip link show cni0 &>/dev/null; then
    echo "Removing cni0 bridge"
    ip link delete cni0 || true
fi

echo "=== Node prepared for NovaNet ==="
