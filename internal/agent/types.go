// Package agent implements the NovaNet agent daemon's core logic.
package agent

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	pb "github.com/azrtydxb/novanet/api/v1"
	"github.com/azrtydxb/novanet/internal/constants"
	"github.com/azrtydxb/novanet/internal/encryption"
	"github.com/azrtydxb/novanet/internal/routing"
	"github.com/azrtydxb/novanet/internal/tunnel"
	"github.com/azrtydxb/novanet/internal/xdp"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

const (
	// Version is the build version of novanet-agent. Overridden at build time.
	Version = "0.1.0"

	// ShutdownTimeout is the maximum time to wait for graceful shutdown.
	ShutdownTimeout = 10 * time.Second

	// DataplaneRetryInterval is the interval between dataplane connection attempts.
	DataplaneRetryInterval = 5 * time.Second

	// ConfigKeyMode identifies the routing mode (overlay vs native).
	ConfigKeyMode = uint32(pb.ConfigKey_CONFIG_KEY_MODE)
	// ConfigKeyTunnelType selects tunnel protocol.
	ConfigKeyTunnelType = uint32(pb.ConfigKey_CONFIG_KEY_TUNNEL_TYPE)
	// ConfigKeyNodeIP stores the node's IP address.
	ConfigKeyNodeIP = uint32(pb.ConfigKey_CONFIG_KEY_NODE_IP)
	// ConfigKeyClusterCIDRIP stores the cluster CIDR IP.
	ConfigKeyClusterCIDRIP = uint32(pb.ConfigKey_CONFIG_KEY_CLUSTER_CIDR_IP)
	// ConfigKeyClusterCIDRPL stores the cluster CIDR prefix length.
	ConfigKeyClusterCIDRPL = uint32(pb.ConfigKey_CONFIG_KEY_CLUSTER_CIDR_PL)
	// ConfigKeyDefaultDeny enables default-deny policy.
	ConfigKeyDefaultDeny = uint32(pb.ConfigKey_CONFIG_KEY_DEFAULT_DENY)
	// ConfigKeyMasqueradeEnable enables masquerade.
	ConfigKeyMasqueradeEnable = uint32(pb.ConfigKey_CONFIG_KEY_MASQUERADE_ENABLE)
	// ConfigKeySNATIP is reserved for eBPF-level SNAT (currently using iptables fallback).
	ConfigKeySNATIP = uint32(pb.ConfigKey_CONFIG_KEY_SNAT_IP) //nolint:unused // Reserved for eBPF-level SNAT (currently using iptables fallback).
	// ConfigKeyPodCIDRIP stores the pod CIDR IP.
	ConfigKeyPodCIDRIP = uint32(pb.ConfigKey_CONFIG_KEY_POD_CIDR_IP)
	// ConfigKeyPodCIDRPL stores the pod CIDR prefix length.
	ConfigKeyPodCIDRPL = uint32(pb.ConfigKey_CONFIG_KEY_POD_CIDR_PL)
	// ConfigKeyL4LBEnabled enables L4 load balancing.
	ConfigKeyL4LBEnabled = uint32(pb.ConfigKey_CONFIG_KEY_L4LB_ENABLED)

	// ModeOverlay selects overlay routing mode.
	ModeOverlay = uint64(pb.ConfigMode_CONFIG_MODE_OVERLAY)
	// ModeNative selects native routing mode.
	ModeNative = uint64(pb.ConfigMode_CONFIG_MODE_NATIVE)
	// TunnelGEV selects Geneve tunnel encapsulation.
	TunnelGEV = uint64(pb.ConfigTunnelType_CONFIG_TUNNEL_GENEVE)
	// TunnelVXL selects VXLAN tunnel encapsulation.
	TunnelVXL = uint64(pb.ConfigTunnelType_CONFIG_TUNNEL_VXLAN)
)

// Endpoint tracks a pod's network state.
type Endpoint struct {
	PodName      string
	PodNamespace string
	ContainerID  string
	IP           net.IP
	MAC          net.HardwareAddr
	IfIndex      uint32
	IdentityID   uint64
	Netns        string
	IfName       string
	HostVeth     string
}

// EgressMapKey identifies an entry in the eBPF EGRESS_POLICIES map.
type EgressMapKey struct {
	SrcIdentity  uint64
	DstCidr      string // CIDR string, e.g. "10.0.0.0/24" or "fd00::/64"
	DstPrefixLen uint32
}

// Params holds the resolved startup parameters after flag parsing and
// auto-detection from the Kubernetes API.
type Params struct {
	ConfigPath string
	PodCIDR    string
	NodeIPStr  string
	NodeName   string
}

// ShutdownState holds references needed for graceful shutdown.
type ShutdownState struct {
	Logger           *zap.Logger
	Cancel           context.CancelFunc
	BgWg             *sync.WaitGroup
	CniGRPC          *grpc.Server
	AgentGRPC        *grpc.Server
	IpamGRPC         *grpc.Server
	EbpfServicesGRPC *grpc.Server
	MetricsServer    *http.Server
	DpConn           *grpc.ClientConn
	RoutingMgr       *routing.Manager
	PodCIDR          string
	XdpMgr           *xdp.Manager
	WgManager        *encryption.WireGuardManager
}

// NodeWatcherState holds the context needed for overlay node watching operations.
type NodeWatcherState struct {
	Ctx        context.Context
	Logger     *zap.Logger
	TunnelMgr  *tunnel.Manager
	DpClient   pb.DataplaneControlClient
	SelfNodeIP net.IP

	// TunnelProgramsAttached tracks whether TC programs have been attached
	// to the shared collect-metadata tunnel interface. With FlowBased tunnels,
	// all remote nodes share a single interface, so programs are attached once.
	TunnelProgramsAttached bool
}

// DpServiceAdapter wraps pb.DataplaneControlClient to satisfy
// the service.DataplaneServiceClient interface (strips grpc.CallOption variadic).
type DpServiceAdapter struct {
	Client pb.DataplaneControlClient
}

// UpsertService proxies to the underlying DataplaneControlClient.
func (a *DpServiceAdapter) UpsertService(ctx context.Context, in *pb.UpsertServiceRequest) (*pb.UpsertServiceResponse, error) {
	return a.Client.UpsertService(ctx, in)
}

// DeleteService proxies to the underlying DataplaneControlClient.
func (a *DpServiceAdapter) DeleteService(ctx context.Context, in *pb.DeleteServiceRequest) (*pb.DeleteServiceResponse, error) {
	return a.Client.DeleteService(ctx, in)
}

// UpsertBackends proxies to the underlying DataplaneControlClient.
func (a *DpServiceAdapter) UpsertBackends(ctx context.Context, in *pb.UpsertBackendsRequest) (*pb.UpsertBackendsResponse, error) {
	return a.Client.UpsertBackends(ctx, in)
}

// UpsertMaglevTable proxies to the underlying DataplaneControlClient.
func (a *DpServiceAdapter) UpsertMaglevTable(ctx context.Context, in *pb.UpsertMaglevTableRequest) (*pb.UpsertMaglevTableResponse, error) {
	return a.Client.UpsertMaglevTable(ctx, in)
}

// FlowTuple identifies a TCP connection direction.
type FlowTuple struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint32
}

// Flow consumer constants.
const (
	FlowRetryInterval = 5 * time.Second
	ProtoTCP          = uint32(constants.ProtocolTCP)
	MaxTrackedTuples  = 10000 // cap tracked tuples to prevent memory growth

	// TCP flag bits.
	TCPFIN uint32 = 0x01
	TCPSYN uint32 = 0x02
	TCPRST uint32 = 0x04
	TCPACK uint32 = 0x10
)
