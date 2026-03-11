// Package config handles loading and validating the NovaNet agent
// configuration. Configuration is stored as JSON and supports environment
// variable expansion in token strings.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// Sentinel validation errors.
var (
	ErrEmptyListenSocket    = errors.New("listen_socket must not be empty")
	ErrEmptyCNISocket       = errors.New("cni_socket must not be empty")
	ErrEmptyDataplaneSocket = errors.New("dataplane_socket must not be empty")
	ErrEmptyClusterCIDR     = errors.New("cluster_cidr must not be empty")
	ErrInvalidNodeCIDRMask  = errors.New("node_cidr_mask_size must be between 16 and 28")
	ErrInvalidTunnelProto   = errors.New("tunnel_protocol must be geneve or vxlan")
	ErrInvalidRoutingMode   = errors.New("routing_mode must be overlay or native")
	ErrEmptyRoutingProto    = errors.New("routing.protocol must not be empty when routing_mode is native")
	ErrInvalidRoutingProto  = errors.New("routing.protocol must be bgp or ospf")
	ErrInvalidLogLevel      = errors.New("log_level must be debug, info, warn, or error")
	ErrEmptyClusterCIDRv6   = errors.New("ipv6.cluster_cidr_v6 must not be empty when ipv6 is enabled")
	ErrInvalidClusterCIDRv6 = errors.New("ipv6.cluster_cidr_v6 is not a valid IPv6 CIDR")
	ErrInvalidNodeCIDRv6    = errors.New("ipv6.node_cidr_v6_mask_size must be between 48 and 120")
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

	// Routing holds integrated routing settings (native routing mode via FRR).
	Routing RoutingConfig `json:"routing"`

	// Egress holds egress control settings.
	Egress EgressConfig `json:"egress"`

	// Policy holds policy enforcement settings.
	Policy PolicyConfig `json:"policy"`

	// L4LB holds L4 load balancer settings.
	L4LB L4LBConfig `json:"l4lb"`

	// Encryption holds transparent encryption settings.
	Encryption EncryptionConfig `json:"encryption"`

	// HostFirewall holds host firewall settings.
	HostFirewall HostFirewallConfig `json:"host_firewall"`

	// Bandwidth holds bandwidth management settings.
	Bandwidth BandwidthConfig `json:"bandwidth"`

	// LBIPAM holds LoadBalancer IPAM settings.
	LBIPAM LBIPAMConfig `json:"lb_ipam"`

	// EBPFServices holds eBPF services gRPC server settings.
	EBPFServices EBPFServicesConfig `json:"ebpf_services"`

	// IPv6 holds IPv6 and dual-stack settings.
	IPv6 IPv6Config `json:"ipv6"`

	// DSR enables Direct Server Return for L4 LB.
	DSR bool `json:"dsr"`

	// XDPAcceleration selects the XDP mode: "disabled", "native", or "best-effort".
	XDPAcceleration string `json:"xdp_acceleration"`

	// LogLevel sets the logging verbosity (debug, info, warn, error).
	LogLevel string `json:"log_level"`

	// MetricsAddress is the listen address for the Prometheus metrics endpoint.
	MetricsAddress string `json:"metrics_address"`
}

// RoutingConfig holds integrated routing settings (FRR sidecar).
type RoutingConfig struct {
	// Protocol selects the routing protocol: "bgp" or "ospf".
	Protocol string `json:"protocol"`

	// FRRSocketDir is the directory containing FRR VTY sockets.
	// Default: "/run/frr".
	FRRSocketDir string `json:"frr_socket_dir"`

	// ControlPlaneVIP is the virtual IP for the Kubernetes API server.
	ControlPlaneVIP string `json:"control_plane_vip"`

	// ControlPlaneVIPHealthInterval is the interval between API server
	// health checks in seconds. Default: 5.
	ControlPlaneVIPHealthInterval int `json:"control_plane_vip_health_interval"`

	// BFDEnabled enables BFD on mesh BGP peers for sub-second failover.
	BFDEnabled bool `json:"bfd_enabled"`

	// BFDMinRxMs is the minimum BFD receive interval in milliseconds.
	BFDMinRxMs uint32 `json:"bfd_min_rx_ms"`

	// BFDMinTxMs is the minimum BFD transmit interval in milliseconds.
	BFDMinTxMs uint32 `json:"bfd_min_tx_ms"`

	// BFDDetectMult is the BFD detect multiplier. 0 means FRR default (3).
	BFDDetectMult uint32 `json:"bfd_detect_mult"`

	// Peers defines external BGP peers (e.g., TOR routers) to configure on
	// each agent node. These are applied in addition to the auto-discovered
	// inter-node mesh peers.
	Peers []RoutingPeerConfig `json:"peers"`
}

// RoutingPeerConfig defines an external BGP peer (e.g., TOR switch).
type RoutingPeerConfig struct {
	// NeighborAddress is the IP address of the BGP neighbor.
	NeighborAddress string `json:"neighbor_address"`

	// RemoteAS is the remote autonomous system number.
	RemoteAS uint32 `json:"remote_as"`

	// Description is an optional human-readable label.
	Description string `json:"description"`

	// BFDEnabled enables BFD for this peer.
	BFDEnabled bool `json:"bfd_enabled"`

	// BFDMinRxMs overrides the BFD minimum receive interval (ms). 0 = use global default.
	BFDMinRxMs uint32 `json:"bfd_min_rx_ms"`

	// BFDMinTxMs overrides the BFD minimum transmit interval (ms). 0 = use global default.
	BFDMinTxMs uint32 `json:"bfd_min_tx_ms"`

	// BFDDetectMultiplier overrides the BFD detect multiplier. 0 = use global default.
	BFDDetectMultiplier uint32 `json:"bfd_detect_multiplier"`
}

// EgressConfig holds egress control settings.
type EgressConfig struct {
	// MasqueradeEnabled controls whether SNAT is applied to pod→external traffic.
	MasqueradeEnabled bool `json:"masquerade_enabled"`
}

// PolicyConfig holds policy enforcement settings.
type PolicyConfig struct {
	// DefaultDeny enables cluster-wide default-deny policy.
	// When false (default), Kubernetes standard behavior applies:
	// pods are default-allow unless a NetworkPolicy selects them.
	DefaultDeny bool `json:"default_deny"`
}

// L4LBConfig holds L4 load balancer settings.
type L4LBConfig struct {
	// Enabled controls whether eBPF-based L4 load balancing is active.
	// When enabled, NovaNet replaces kube-proxy for Service DNAT.
	Enabled bool `json:"enabled"`

	// DefaultAlgorithm is the default backend selection algorithm.
	// Valid values: "random", "round-robin", "maglev". Default: "random".
	DefaultAlgorithm string `json:"default_algorithm"`
}

// EncryptionConfig holds transparent encryption settings.
type EncryptionConfig struct {
	// Type selects the encryption method: "disabled" or "wireguard".
	Type string `json:"type"`

	// WireGuardPort is the UDP listen port for WireGuard.
	WireGuardPort int `json:"wireguard_port"`

	// NodeAnnotationKey is the annotation key for the WireGuard public key.
	NodeAnnotationKey string `json:"node_annotation_key"`
}

// HostFirewallConfig holds host firewall settings.
type HostFirewallConfig struct {
	// Enabled activates host-level firewall enforcement.
	Enabled bool `json:"enabled"`
}

// BandwidthConfig holds bandwidth management settings.
type BandwidthConfig struct {
	// Enabled activates per-pod bandwidth enforcement via TC qdisc.
	Enabled bool `json:"enabled"`
}

// LBIPAMConfig holds LoadBalancer IP address management settings.
type LBIPAMConfig struct {
	// Enabled activates LB-IPAM.
	Enabled bool `json:"enabled"`

	// L2AnnouncementEnabled enables Gratuitous ARP/NDP.
	L2AnnouncementEnabled bool `json:"l2_announcement_enabled"`
}

// EBPFServicesConfig holds eBPF services gRPC server settings.
type EBPFServicesConfig struct {
	// Enabled controls whether the EBPFServices gRPC server is started.
	Enabled bool `json:"enabled"`

	// SocketPath is the Unix socket path for the EBPFServices gRPC server.
	SocketPath string `json:"socket_path"`
}

// IPv6Config holds IPv6 and dual-stack settings.
type IPv6Config struct {
	// Enabled activates IPv6 and dual-stack support.
	Enabled bool `json:"enabled"`

	// ClusterCIDRv6 is the IPv6 pod CIDR for dual-stack.
	ClusterCIDRv6 string `json:"cluster_cidr_v6"`

	// NodeCIDRv6MaskSize is the prefix length for per-node IPv6 PodCIDR.
	NodeCIDRv6MaskSize int `json:"node_cidr_v6_mask_size"`
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
		Routing: RoutingConfig{
			Protocol:     "bgp",
			FRRSocketDir: "/run/frr",
		},
		Egress: EgressConfig{
			MasqueradeEnabled: true,
		},
		Policy: PolicyConfig{
			DefaultDeny: false,
		},
		L4LB: L4LBConfig{
			Enabled:          false,
			DefaultAlgorithm: "random",
		},
		Encryption: EncryptionConfig{
			Type:              "disabled",
			WireGuardPort:     51871,
			NodeAnnotationKey: "novanet.io/wireguard-pubkey",
		},
		HostFirewall: HostFirewallConfig{
			Enabled: false,
		},
		Bandwidth: BandwidthConfig{
			Enabled: false,
		},
		EBPFServices: EBPFServicesConfig{
			Enabled:    true,
			SocketPath: "/run/novanet/ebpf-services.sock",
		},
		LBIPAM: LBIPAMConfig{
			Enabled:               false,
			L2AnnouncementEnabled: true,
		},
		IPv6: IPv6Config{
			Enabled:            false,
			NodeCIDRv6MaskSize: 112,
		},
		DSR:             false,
		XDPAcceleration: "disabled",
		LogLevel:        "info",
		MetricsAddress:  "127.0.0.1:9103",
	}
}

// LoadFromFile reads a JSON configuration file at the given path and returns
// a Config merged with defaults. Fields present in the file override the
// corresponding defaults; fields absent from the file retain their default
// values.
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(filepath.Clean(path))
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
		return ErrEmptyListenSocket
	}

	if cfg.CNISocket == "" {
		return ErrEmptyCNISocket
	}

	if cfg.DataplaneSocket == "" {
		return ErrEmptyDataplaneSocket
	}

	if cfg.ClusterCIDR == "" {
		return ErrEmptyClusterCIDR
	}
	if _, _, err := net.ParseCIDR(cfg.ClusterCIDR); err != nil {
		return fmt.Errorf("cluster_cidr %q is not a valid CIDR: %w", cfg.ClusterCIDR, err)
	}

	if cfg.NodeCIDRMaskSize < 16 || cfg.NodeCIDRMaskSize > 28 {
		return fmt.Errorf("%w: got %d", ErrInvalidNodeCIDRMask, cfg.NodeCIDRMaskSize)
	}

	switch strings.ToLower(cfg.TunnelProtocol) {
	case "geneve", "vxlan":
		// valid
	default:
		return fmt.Errorf("%w: got %q", ErrInvalidTunnelProto, cfg.TunnelProtocol)
	}

	switch strings.ToLower(cfg.RoutingMode) {
	case "overlay", "native":
		// valid
	default:
		return fmt.Errorf("%w: got %q", ErrInvalidRoutingMode, cfg.RoutingMode)
	}

	if strings.ToLower(cfg.RoutingMode) == "native" {
		switch strings.ToLower(cfg.Routing.Protocol) {
		case "bgp", "ospf":
			// valid
		case "":
			return ErrEmptyRoutingProto
		default:
			return fmt.Errorf("%w: got %q", ErrInvalidRoutingProto, cfg.Routing.Protocol)
		}
	}

	switch strings.ToLower(cfg.LogLevel) {
	case "debug", "info", "warn", "error":
		// valid
	default:
		return fmt.Errorf("%w: got %q", ErrInvalidLogLevel, cfg.LogLevel)
	}

	// IPv6 validation: when enabled, ClusterCIDRv6 must be set and valid,
	// and NodeCIDRv6MaskSize must be in a reasonable range.
	if cfg.IPv6.Enabled {
		if cfg.IPv6.ClusterCIDRv6 == "" {
			return ErrEmptyClusterCIDRv6
		}
		ip, _, err := net.ParseCIDR(cfg.IPv6.ClusterCIDRv6)
		if err != nil {
			return fmt.Errorf("%w: %q: %v", ErrInvalidClusterCIDRv6, cfg.IPv6.ClusterCIDRv6, err)
		}
		if ip.To4() != nil {
			return fmt.Errorf("%w: %q is an IPv4 CIDR", ErrInvalidClusterCIDRv6, cfg.IPv6.ClusterCIDRv6)
		}
		if cfg.IPv6.NodeCIDRv6MaskSize < 48 || cfg.IPv6.NodeCIDRv6MaskSize > 120 {
			return fmt.Errorf("%w: got %d", ErrInvalidNodeCIDRv6, cfg.IPv6.NodeCIDRv6MaskSize)
		}
	}

	return nil
}

// parseBoolEnv parses an environment variable as a boolean.
// "true" and "1" enable the feature; "false" and "0" disable it.
// An empty or unset variable returns the current value unchanged.
func parseBoolEnv(envVar string, current bool) bool {
	v := os.Getenv(envVar)
	switch strings.ToLower(v) {
	case "true", "1":
		return true
	case "false", "0":
		return false
	default:
		return current
	}
}

// ExpandEnvVars replaces ${VAR} placeholders in configuration strings with
// the corresponding environment variable values.
//
// Boolean environment variables support "true"/"1" to enable and
// "false"/"0" to disable features.
//
// The following environment variables override config values:
//   - NOVANET_CLUSTER_CIDR → cluster_cidr
//   - NOVANET_ROUTING_MODE → routing_mode
//   - NOVANET_TUNNEL_PROTOCOL → tunnel_protocol
//
// Legacy NOVAROUTE_* variables are also accepted for backward compatibility
// with older deployments that used the NOVAROUTE_ prefix:
//   - NOVAROUTE_CLUSTER_CIDR → cluster_cidr
//   - NOVAROUTE_ROUTING_MODE → routing_mode
//   - NOVAROUTE_TUNNEL_PROTOCOL → tunnel_protocol
//
// When both NOVANET_* and NOVAROUTE_* are set for the same field, the
// NOVANET_* value takes precedence.
func ExpandEnvVars(cfg *Config) {
	// No token expansion needed — routing is in-process now.

	if v := os.Getenv("NOVANET_CLUSTER_CIDR"); v != "" {
		cfg.ClusterCIDR = v
	}
	if v := os.Getenv("NOVANET_ROUTING_MODE"); v != "" {
		cfg.RoutingMode = v
	}
	if v := os.Getenv("NOVANET_TUNNEL_PROTOCOL"); v != "" {
		cfg.TunnelProtocol = v
	}
	cfg.L4LB.Enabled = parseBoolEnv("NOVANET_L4LB_ENABLED", cfg.L4LB.Enabled)
	if v := os.Getenv("NOVANET_ENCRYPTION_TYPE"); v != "" {
		cfg.Encryption.Type = v
	}
	cfg.HostFirewall.Enabled = parseBoolEnv("NOVANET_HOST_FIREWALL_ENABLED", cfg.HostFirewall.Enabled)
	cfg.Bandwidth.Enabled = parseBoolEnv("NOVANET_BANDWIDTH_ENABLED", cfg.Bandwidth.Enabled)
	cfg.LBIPAM.Enabled = parseBoolEnv("NOVANET_LBIPAM_ENABLED", cfg.LBIPAM.Enabled)
	cfg.IPv6.Enabled = parseBoolEnv("NOVANET_IPV6_ENABLED", cfg.IPv6.Enabled)
	if v := os.Getenv("NOVANET_CLUSTER_CIDR_V6"); v != "" {
		cfg.IPv6.ClusterCIDRv6 = v
	}
	cfg.DSR = parseBoolEnv("NOVANET_DSR_ENABLED", cfg.DSR)
	if v := os.Getenv("NOVANET_XDP_ACCELERATION"); v != "" {
		cfg.XDPAcceleration = v
	}

	// Backward-compatible NOVAROUTE_ env var aliases.
	// These are accepted for users migrating from older deployments that
	// used the NOVAROUTE_ prefix. NOVANET_ takes precedence: the legacy
	// fallback is only applied when the corresponding NOVANET_ variable
	// was not explicitly set in the environment.
	if _, ok := os.LookupEnv("NOVANET_ROUTING_MODE"); !ok {
		if v := os.Getenv("NOVAROUTE_ROUTING_MODE"); v != "" {
			cfg.RoutingMode = v
		}
	}
	if _, ok := os.LookupEnv("NOVANET_CLUSTER_CIDR"); !ok {
		if v := os.Getenv("NOVAROUTE_CLUSTER_CIDR"); v != "" {
			cfg.ClusterCIDR = v
		}
	}
	if _, ok := os.LookupEnv("NOVANET_TUNNEL_PROTOCOL"); !ok {
		if v := os.Getenv("NOVAROUTE_TUNNEL_PROTOCOL"); v != "" {
			cfg.TunnelProtocol = v
		}
	}
}
