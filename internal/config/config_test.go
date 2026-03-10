package config

import (
	"os"
	"path/filepath"
	"testing"
)

const testNativeMode = "native"

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ListenSocket != "/run/novanet/novanet.sock" {
		t.Errorf("unexpected listen_socket: %s", cfg.ListenSocket)
	}
	if cfg.TunnelProtocol != "geneve" {
		t.Errorf("unexpected tunnel_protocol: %s", cfg.TunnelProtocol)
	}
	if cfg.RoutingMode != "overlay" {
		t.Errorf("unexpected routing_mode: %s", cfg.RoutingMode)
	}
	if cfg.NodeCIDRMaskSize != 24 {
		t.Errorf("unexpected node_cidr_mask_size: %d", cfg.NodeCIDRMaskSize)
	}
	if cfg.MetricsAddress != "127.0.0.1:9103" {
		t.Errorf("unexpected metrics_address: %s", cfg.MetricsAddress)
	}
	if !cfg.Egress.MasqueradeEnabled {
		t.Error("expected masquerade_enabled to be true by default")
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	data := []byte(`{
		"listen_socket": "/tmp/test.sock",
		"cluster_cidr": "10.100.0.0/16",
		"tunnel_protocol": "vxlan",
		"routing_mode": "overlay",
		"log_level": "debug"
	}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ListenSocket != "/tmp/test.sock" {
		t.Errorf("expected /tmp/test.sock, got %s", cfg.ListenSocket)
	}
	if cfg.ClusterCIDR != "10.100.0.0/16" {
		t.Errorf("expected 10.100.0.0/16, got %s", cfg.ClusterCIDR)
	}
	if cfg.TunnelProtocol != "vxlan" {
		t.Errorf("expected vxlan, got %s", cfg.TunnelProtocol)
	}
	// Default values should be preserved for unset fields.
	if cfg.CNISocket != "/run/novanet/cni.sock" {
		t.Errorf("expected default cni_socket, got %s", cfg.CNISocket)
	}
	if cfg.DataplaneSocket != "/run/novanet/dataplane.sock" {
		t.Errorf("expected default dataplane_socket, got %s", cfg.DataplaneSocket)
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/config.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadFromFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte("{invalid}"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := LoadFromFile(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestValidate_HappyPath(t *testing.T) {
	cfg := DefaultConfig()
	if err := Validate(cfg); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_NativeMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RoutingMode = testNativeMode
	cfg.Routing.Protocol = "bgp"

	if err := Validate(cfg); err != nil {
		t.Errorf("unexpected error for valid native config: %v", err)
	}
}

func TestValidate_NativeMode_MissingProtocol(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RoutingMode = testNativeMode
	cfg.Routing.Protocol = ""

	err := Validate(cfg)
	if err == nil {
		t.Error("expected error for missing protocol in native mode")
	}
}

func TestValidate_InvalidClusterCIDR(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ClusterCIDR = "not-a-cidr"

	err := Validate(cfg)
	if err == nil {
		t.Error("expected error for invalid cluster_cidr")
	}
}

func TestValidate_EmptyClusterCIDR(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ClusterCIDR = ""

	err := Validate(cfg)
	if err == nil {
		t.Error("expected error for empty cluster_cidr")
	}
}

func TestValidate_InvalidTunnelProtocol(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TunnelProtocol = "ipsec"

	err := Validate(cfg)
	if err == nil {
		t.Error("expected error for invalid tunnel_protocol")
	}
}

func TestValidate_InvalidRoutingMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.RoutingMode = "hybrid"

	err := Validate(cfg)
	if err == nil {
		t.Error("expected error for invalid routing_mode")
	}
}

func TestValidate_InvalidLogLevel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.LogLevel = "verbose"

	err := Validate(cfg)
	if err == nil {
		t.Error("expected error for invalid log_level")
	}
}

func TestValidate_EmptySockets(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"empty listen_socket", func(c *Config) { c.ListenSocket = "" }},
		{"empty cni_socket", func(c *Config) { c.CNISocket = "" }},
		{"empty dataplane_socket", func(c *Config) { c.DataplaneSocket = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.mutate(cfg)
			if err := Validate(cfg); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestValidate_InvalidNodeCIDRMaskSize(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"too small", 15},
		{"too large", 29},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.NodeCIDRMaskSize = tt.size
			if err := Validate(cfg); err == nil {
				t.Errorf("expected error for mask size %d", tt.size)
			}
		})
	}
}

func TestExpandEnvVars(t *testing.T) {
	cfg := DefaultConfig()

	t.Setenv("NOVANET_CLUSTER_CIDR", "10.200.0.0/16")
	t.Setenv("NOVANET_ROUTING_MODE", "native")
	t.Setenv("NOVANET_TUNNEL_PROTOCOL", "vxlan")

	ExpandEnvVars(cfg)

	if cfg.ClusterCIDR != "10.200.0.0/16" {
		t.Errorf("expected overridden cluster_cidr, got %s", cfg.ClusterCIDR)
	}
	if cfg.RoutingMode != "native" {
		t.Errorf("expected overridden routing_mode, got %s", cfg.RoutingMode)
	}
	if cfg.TunnelProtocol != "vxlan" {
		t.Errorf("expected overridden tunnel_protocol, got %s", cfg.TunnelProtocol)
	}
}

func TestValidate_IPv6_Enabled_Valid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IPv6.Enabled = true
	cfg.IPv6.ClusterCIDRv6 = "fd00::/48"
	cfg.IPv6.NodeCIDRv6MaskSize = 112

	if err := Validate(cfg); err != nil {
		t.Errorf("unexpected error for valid IPv6 config: %v", err)
	}
}

func TestValidate_IPv6_EmptyClusterCIDR(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IPv6.Enabled = true
	cfg.IPv6.ClusterCIDRv6 = ""

	err := Validate(cfg)
	if err == nil {
		t.Error("expected error for empty cluster_cidr_v6 when IPv6 is enabled")
	}
}

func TestValidate_IPv6_InvalidCIDR(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IPv6.Enabled = true
	cfg.IPv6.ClusterCIDRv6 = "not-a-cidr"

	err := Validate(cfg)
	if err == nil {
		t.Error("expected error for invalid IPv6 CIDR")
	}
}

func TestValidate_IPv6_IPv4CIDRRejected(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IPv6.Enabled = true
	cfg.IPv6.ClusterCIDRv6 = "10.244.0.0/16"
	cfg.IPv6.NodeCIDRv6MaskSize = 112

	err := Validate(cfg)
	if err == nil {
		t.Error("expected error when IPv4 CIDR is provided as cluster_cidr_v6")
	}
}

func TestValidate_IPv6_MaskSizeOutOfRange(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"too small", 47},
		{"too large", 121},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.IPv6.Enabled = true
			cfg.IPv6.ClusterCIDRv6 = "fd00::/48"
			cfg.IPv6.NodeCIDRv6MaskSize = tt.size
			if err := Validate(cfg); err == nil {
				t.Errorf("expected error for IPv6 mask size %d", tt.size)
			}
		})
	}
}

func TestValidate_IPv6_Disabled_NoValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.IPv6.Enabled = false
	cfg.IPv6.ClusterCIDRv6 = "" // would fail if validated

	if err := Validate(cfg); err != nil {
		t.Errorf("IPv6 validation should be skipped when disabled: %v", err)
	}
}

func TestExpandEnvVars_UnsetVars(t *testing.T) {
	cfg := DefaultConfig()

	ExpandEnvVars(cfg)

	// Defaults should be preserved when env vars are not set.
	if cfg.ClusterCIDR != "10.244.0.0/16" {
		t.Errorf("expected default cluster_cidr, got %s", cfg.ClusterCIDR)
	}
}
