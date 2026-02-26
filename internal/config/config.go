// Package config handles loading and validating the NovaNet agent
// configuration. Configuration is stored as JSON and supports environment
// variable expansion in token strings.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

// Config holds the complete NovaNet agent configuration.
type Config struct {
	// ListenSocket is the Unix socket path for the NovaNet agent gRPC API.
	ListenSocket string `json:"listen_socket"`

	// CNISocket is the Unix socket path for the CNI binary to connect to.
	CNISocket string `json:"cni_socket"`

	// DataplaneSocket is the Unix socket path for the Rust dataplane gRPC server.
	DataplaneSocket string `json:"dataplane_socket"`

	// ClusterCIDR is the overall cluster Pod CIDR (e.g., "10.244.0.0/16").
	ClusterCIDR string `json:"cluster_cidr"`

	// NodeCIDRMaskSize is the prefix length for per-node PodCIDR allocation.
	NodeCIDRMaskSize int `json:"node_cidr_mask_size"`

	// TunnelProtocol selects the overlay encapsulation: "geneve" or "vxlan".
	TunnelProtocol string `json:"tunnel_protocol"`

	// RoutingMode selects the networking mode: "overlay" or "native".
	RoutingMode string `json:"routing_mode"`

	// NovaRoute holds NovaRoute integration settings (native routing mode).
	NovaRoute NovaRouteConfig `json:"novaroute"`

	// Egress holds egress control settings.
	Egress EgressConfig `json:"egress"`

	// Policy holds policy enforcement settings.
	Policy PolicyConfig `json:"policy"`

	// LogLevel sets the logging verbosity (debug, info, warn, error).
	LogLevel string `json:"log_level"`

	// MetricsAddress is the listen address for the Prometheus metrics endpoint.
	MetricsAddress string `json:"metrics_address"`
}

// NovaRouteConfig holds NovaRoute integration settings.
type NovaRouteConfig struct {
	// Socket is the path to the NovaRoute Unix domain socket.
	Socket string `json:"socket"`

	// Token is the pre-shared authentication token for owner "novanet".
	Token string `json:"token"`

	// Protocol selects the routing protocol: "bgp" or "ospf".
	Protocol string `json:"protocol"`

	// TORPeers is a list of TOR/spine switch BGP peers that every node
	// should establish eBGP sessions with (in addition to node-to-node mesh).
	TORPeers []TORPeer `json:"tor_peers,omitempty"`
}

// TORPeer defines an external BGP peer (e.g., TOR switch or spine router).
type TORPeer struct {
	// Address is the peer's IP address.
	Address string `json:"address"`

	// AS is the peer's autonomous system number.
	AS uint32 `json:"as"`
}

// EgressConfig holds egress control settings.
type EgressConfig struct {
	// MasqueradeEnabled controls whether SNAT is applied to pod→external traffic.
	MasqueradeEnabled bool `json:"masquerade_enabled"`

	// MasqueradeInterface is the interface whose IP is used for SNAT.
	// Empty means use the node's default interface.
	MasqueradeInterface string `json:"masquerade_interface"`
}

// PolicyConfig holds policy enforcement settings.
type PolicyConfig struct {
	// DefaultDeny enables cluster-wide default-deny policy.
	// When false (default), Kubernetes standard behavior applies:
	// pods are default-allow unless a NetworkPolicy selects them.
	DefaultDeny bool `json:"default_deny"`
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		ListenSocket:     "/run/novanet/novanet.sock",
		CNISocket:        "/run/novanet/cni.sock",
		DataplaneSocket:  "/run/novanet/dataplane.sock",
		ClusterCIDR:      "10.244.0.0/16",
		NodeCIDRMaskSize: 24,
		TunnelProtocol:   "geneve",
		RoutingMode:      "overlay",
		NovaRoute: NovaRouteConfig{
			Socket:   "/run/novaroute/novaroute.sock",
			Protocol: "bgp",
		},
		Egress: EgressConfig{
			MasqueradeEnabled: true,
		},
		Policy: PolicyConfig{
			DefaultDeny: false,
		},
		LogLevel:       "info",
		MetricsAddress: ":9103",
	}
}

// LoadFromFile reads a JSON configuration file at the given path and returns
// a Config merged with defaults. Fields present in the file override the
// corresponding defaults; fields absent from the file retain their default
// values.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	return cfg, nil
}

// Validate checks that a Config contains all required fields and that the
// values are well-formed. It returns an error describing the first problem
// found, or nil if the configuration is valid.
func Validate(cfg *Config) error {
	if cfg.ListenSocket == "" {
		return fmt.Errorf("listen_socket must not be empty")
	}

	if cfg.CNISocket == "" {
		return fmt.Errorf("cni_socket must not be empty")
	}

	if cfg.DataplaneSocket == "" {
		return fmt.Errorf("dataplane_socket must not be empty")
	}

	if cfg.ClusterCIDR == "" {
		return fmt.Errorf("cluster_cidr must not be empty")
	}
	if _, _, err := net.ParseCIDR(cfg.ClusterCIDR); err != nil {
		return fmt.Errorf("cluster_cidr %q is not a valid CIDR: %w", cfg.ClusterCIDR, err)
	}

	if cfg.NodeCIDRMaskSize < 16 || cfg.NodeCIDRMaskSize > 28 {
		return fmt.Errorf("node_cidr_mask_size must be between 16 and 28, got %d", cfg.NodeCIDRMaskSize)
	}

	switch strings.ToLower(cfg.TunnelProtocol) {
	case "geneve", "vxlan":
		// valid
	default:
		return fmt.Errorf("tunnel_protocol %q is not valid (must be geneve or vxlan)", cfg.TunnelProtocol)
	}

	switch strings.ToLower(cfg.RoutingMode) {
	case "overlay", "native":
		// valid
	default:
		return fmt.Errorf("routing_mode %q is not valid (must be overlay or native)", cfg.RoutingMode)
	}

	if strings.ToLower(cfg.RoutingMode) == "native" {
		if cfg.NovaRoute.Socket == "" {
			return fmt.Errorf("novaroute.socket must not be empty when routing_mode is native")
		}
		if cfg.NovaRoute.Token == "" {
			return fmt.Errorf("novaroute.token must not be empty when routing_mode is native")
		}
		switch strings.ToLower(cfg.NovaRoute.Protocol) {
		case "bgp", "ospf":
			// valid
		case "":
			return fmt.Errorf("novaroute.protocol must not be empty when routing_mode is native")
		default:
			return fmt.Errorf("novaroute.protocol %q is not valid (must be bgp or ospf)", cfg.NovaRoute.Protocol)
		}
	}

	switch strings.ToLower(cfg.LogLevel) {
	case "debug", "info", "warn", "error":
		// valid
	default:
		return fmt.Errorf("log_level %q is not valid (must be debug, info, warn, or error)", cfg.LogLevel)
	}

	return nil
}

// ExpandEnvVars replaces ${VAR} placeholders in configuration strings with
// the corresponding environment variable values.
//
// Supported fields:
//   - NovaRoute token (e.g., "token": "${NOVANET_TOKEN}")
//
// Additionally, the following environment variables override config values:
//   - NOVANET_CLUSTER_CIDR → cluster_cidr
//   - NOVANET_ROUTING_MODE → routing_mode
//   - NOVANET_TUNNEL_PROTOCOL → tunnel_protocol
func ExpandEnvVars(cfg *Config) {
	cfg.NovaRoute.Token = os.ExpandEnv(cfg.NovaRoute.Token)

	if v := os.Getenv("NOVANET_CLUSTER_CIDR"); v != "" {
		cfg.ClusterCIDR = v
	}
	if v := os.Getenv("NOVANET_ROUTING_MODE"); v != "" {
		cfg.RoutingMode = v
	}
	if v := os.Getenv("NOVANET_TUNNEL_PROTOCOL"); v != "" {
		cfg.TunnelProtocol = v
	}
}
