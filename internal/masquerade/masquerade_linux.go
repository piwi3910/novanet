//go:build linux

// Package masquerade manages iptables MASQUERADE rules for pod traffic
// egressing the cluster, ensuring source NAT is applied correctly.
package masquerade

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// iptablesCmd is the iptables binary path.
const iptablesCmd = "iptables"

// EnsureMasquerade adds an iptables MASQUERADE rule for pod traffic leaving
// the cluster. It is idempotent: if the rule already exists, it does nothing.
func EnsureMasquerade(podCIDR, clusterCIDR string) error {
	ctx := context.Background()

	// Check if the rule already exists.
	checkArgs := []string{
		"-t", "nat", "-C", "POSTROUTING",
		"-s", podCIDR,
		"!", "-d", clusterCIDR,
		"-j", "MASQUERADE",
		"-m", "comment", "--comment", "novanet masquerade",
	}
	if err := exec.CommandContext(ctx, iptablesCmd, checkArgs...).Run(); err == nil { //#nosec G204 -- iptablesCmd is a constant
		return nil // Rule already exists.
	}

	// Add the rule.
	addArgs := []string{
		"-t", "nat", "-A", "POSTROUTING",
		"-s", podCIDR,
		"!", "-d", clusterCIDR,
		"-j", "MASQUERADE",
		"-m", "comment", "--comment", "novanet masquerade",
	}
	out, err := exec.CommandContext(ctx, iptablesCmd, addArgs...).CombinedOutput() //#nosec G204 -- iptablesCmd is a constant
	if err != nil {
		return fmt.Errorf("adding masquerade rule: %w: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}
