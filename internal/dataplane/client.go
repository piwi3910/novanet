// Package dataplane provides a Go gRPC client for communicating with the
// Rust eBPF dataplane via the novanet.v1.DataplaneControl service.
package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/azrtydxb/novanet/api/v1"
)

// Sentinel errors for the dataplane client.
var (
	ErrNotConnected    = errors.New("not connected to dataplane")
	ErrEmptySocketPath = errors.New("socket path must not be empty")
)

// AttachType specifies the direction of a TC program attachment.
type AttachType int

const (
	// AttachTCIngress attaches the TC program on ingress.
	AttachTCIngress AttachType = iota
	// AttachTCEgress attaches the TC program on egress.
	AttachTCEgress
)

// Endpoint represents a pod endpoint in the dataplane.
type Endpoint struct {
	IP         string
	Ifindex    uint32
	MAC        net.HardwareAddr
	IdentityID uint32
	PodName    string
	Namespace  string
	NodeIP     string
}

// PolicyRule represents a compiled policy rule.
type PolicyRule struct {
	SrcIdentity uint32
	DstIdentity uint32
	Protocol    uint32
	DstPort     uint32
	Action      pb.PolicyAction
}

// FlowEvent represents a network flow event from the dataplane.
type FlowEvent struct {
	SrcIP       string
	DstIP       string
	SrcIdentity uint32
	DstIdentity uint32
	Protocol    uint32
	SrcPort     uint32
	DstPort     uint32
	Verdict     pb.PolicyAction
	Bytes       uint64
	Packets     uint64
	TimestampNs int64
	DropReason  pb.DropReason
}

// Status contains the current status of the dataplane.
type Status struct {
	EndpointCount  uint32
	PolicyCount    uint32
	TunnelCount    uint32
	Programs       []*pb.AttachedProgram
	Mode           string
	TunnelProtocol string
}

// SyncResult contains the result of a policy sync operation.
type SyncResult struct {
	Added   uint32
	Removed uint32
	Updated uint32
}

// SockmapStats contains SOCKMAP redirect statistics.
type SockmapStats struct {
	Redirected      uint64
	Fallback        uint64
	ActiveEndpoints uint32
}

// MeshServiceEntry represents a mesh service redirect entry.
type MeshServiceEntry struct {
	IP           string
	Port         uint32
	RedirectPort uint32
}

// RateLimitStats contains rate limiting statistics.
type RateLimitStats struct {
	Allowed uint64
	Denied  uint64
}

// BackendHealthInfo contains health statistics for a backend.
type BackendHealthInfo struct {
	IP           string
	Port         uint32
	TotalConns   uint64
	FailedConns  uint64
	TimeoutConns uint64
	SuccessConns uint64
	AvgRTTNs     uint64
	FailureRate  float64
}

// Backend represents an L4 LB backend entry.
type Backend struct {
	Index  uint32
	IP     string
	Port   uint32
	NodeIP string
}

// ServiceConfig represents an L4 LB service entry.
type ServiceConfig struct {
	IP              string
	Port            uint32
	Protocol        uint32
	Scope           uint32
	BackendCount    uint32
	BackendOffset   uint32
	Algorithm       uint32
	Flags           uint32
	AffinityTimeout uint32
	MaglevOffset    uint32
}

// ClientInterface defines the interface for the dataplane client.
// Used for testing with mock implementations.
type ClientInterface interface {
	Connect(ctx context.Context) error
	UpsertEndpoint(ctx context.Context, ep *Endpoint) error
	DeleteEndpoint(ctx context.Context, ip string) error
	UpsertPolicy(ctx context.Context, rule *PolicyRule) error
	DeletePolicy(ctx context.Context, rule *PolicyRule) error
	SyncPolicies(ctx context.Context, rules []*PolicyRule) (*SyncResult, error)
	UpsertTunnel(ctx context.Context, nodeIP string, ifindex, vni uint32) error
	DeleteTunnel(ctx context.Context, nodeIP string) error
	UpdateConfig(ctx context.Context, entries map[uint32]uint64) error
	AttachProgram(ctx context.Context, iface string, attachType AttachType) error
	DetachProgram(ctx context.Context, iface string, attachType AttachType) error
	StreamFlows(ctx context.Context, identityFilter uint32) (<-chan *FlowEvent, error)
	GetStatus(ctx context.Context) (*Status, error)

	// SOCKMAP endpoints
	UpsertSockmapEndpoint(ctx context.Context, ip string, port uint32) error
	DeleteSockmapEndpoint(ctx context.Context, ip string, port uint32) error
	GetSockmapStats(ctx context.Context) (*SockmapStats, error)

	// Mesh redirect
	UpsertMeshService(ctx context.Context, ip string, port, redirectPort uint32) error
	DeleteMeshService(ctx context.Context, ip string, port uint32) error
	ListMeshServices(ctx context.Context) ([]*MeshServiceEntry, error)

	// Rate limiting
	UpdateRateLimitConfig(ctx context.Context, rate, burst uint32, windowNs uint64) error
	GetRateLimitStats(ctx context.Context) (*RateLimitStats, error)

	// Health monitoring
	GetBackendHealthStats(ctx context.Context, ip string, port uint32) ([]*BackendHealthInfo, error)

	// L4 LB service management
	UpsertBackends(ctx context.Context, backends []*Backend) error
	UpsertServiceEntry(ctx context.Context, svc *ServiceConfig) error

	Close() error
}

// Client is a gRPC client for the Rust eBPF dataplane.
type Client struct {
	mu sync.RWMutex

	socketPath string
	logger     *zap.Logger

	conn   *grpc.ClientConn
	client pb.DataplaneControlClient
}

// Ensure Client implements ClientInterface.
var _ ClientInterface = (*Client)(nil)

// NewClient creates a new dataplane client.
func NewClient(socketPath string, logger *zap.Logger) (*Client, error) {
	if socketPath == "" {
		return nil, ErrEmptySocketPath
	}
	return &Client{
		socketPath: socketPath,
		logger:     logger,
	}, nil
}

// Connect establishes a connection to the dataplane gRPC server.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := grpc.NewClient(
		"unix://"+c.socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("connecting to dataplane at %s: %w", c.socketPath, err)
	}

	c.conn = conn
	c.client = pb.NewDataplaneControlClient(conn)

	c.logger.Info("connected to dataplane",
		zap.String("socket", c.socketPath),
	)
	return nil
}

// UpsertEndpoint registers or updates an endpoint in the dataplane.
func (c *Client) UpsertEndpoint(ctx context.Context, ep *Endpoint) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	start := time.Now()
	_, err := client.UpsertEndpoint(ctx, &pb.UpsertEndpointRequest{
		Ip:         ep.IP,
		Ifindex:    ep.Ifindex,
		Mac:        ep.MAC,
		IdentityId: ep.IdentityID,
		PodName:    ep.PodName,
		Namespace:  ep.Namespace,
		NodeIp:     ep.NodeIP,
	})

	c.logger.Debug("UpsertEndpoint",
		zap.String("ip", ep.IP),
		zap.Uint32("identity", ep.IdentityID),
		zap.Duration("duration", time.Since(start)),
		zap.Error(err),
	)

	if err != nil {
		return fmt.Errorf("upserting endpoint: %w", err)
	}
	return nil
}

// DeleteEndpoint removes an endpoint from the dataplane.
func (c *Client) DeleteEndpoint(ctx context.Context, ip string) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	_, err := client.DeleteEndpoint(ctx, &pb.DeleteEndpointRequest{
		Ip: ip,
	})
	if err != nil {
		return fmt.Errorf("deleting endpoint: %w", err)
	}
	return nil
}

// UpsertPolicy adds or updates a policy rule in the dataplane.
func (c *Client) UpsertPolicy(ctx context.Context, rule *PolicyRule) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	_, err := client.UpsertPolicy(ctx, &pb.UpsertPolicyRequest{
		SrcIdentity: rule.SrcIdentity,
		DstIdentity: rule.DstIdentity,
		Protocol:    rule.Protocol,
		DstPort:     rule.DstPort,
		Action:      rule.Action,
	})
	if err != nil {
		return fmt.Errorf("upserting policy: %w", err)
	}
	return nil
}

// DeletePolicy removes a policy rule from the dataplane.
func (c *Client) DeletePolicy(ctx context.Context, rule *PolicyRule) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	_, err := client.DeletePolicy(ctx, &pb.DeletePolicyRequest{
		SrcIdentity: rule.SrcIdentity,
		DstIdentity: rule.DstIdentity,
		Protocol:    rule.Protocol,
		DstPort:     rule.DstPort,
	})
	if err != nil {
		return fmt.Errorf("deleting policy: %w", err)
	}
	return nil
}

// SyncPolicies performs a full sync of all policy rules with the dataplane.
func (c *Client) SyncPolicies(ctx context.Context, rules []*PolicyRule) (*SyncResult, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, ErrNotConnected
	}

	entries := make([]*pb.PolicyEntry, len(rules))
	for i, r := range rules {
		entries[i] = &pb.PolicyEntry{
			SrcIdentity: r.SrcIdentity,
			DstIdentity: r.DstIdentity,
			Protocol:    r.Protocol,
			DstPort:     r.DstPort,
			Action:      r.Action,
		}
	}

	start := time.Now()
	resp, err := client.SyncPolicies(ctx, &pb.SyncPoliciesRequest{
		Policies: entries,
	})

	c.logger.Debug("SyncPolicies",
		zap.Int("rule_count", len(rules)),
		zap.Duration("duration", time.Since(start)),
		zap.Error(err),
	)

	if err != nil {
		return nil, fmt.Errorf("syncing policies: %w", err)
	}

	return &SyncResult{
		Added:   resp.Added,
		Removed: resp.Removed,
		Updated: resp.Updated,
	}, nil
}

// UpsertTunnel registers a tunnel with the dataplane.
func (c *Client) UpsertTunnel(ctx context.Context, nodeIP string, ifindex, vni uint32) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	_, err := client.UpsertTunnel(ctx, &pb.UpsertTunnelRequest{
		NodeIp:        nodeIP,
		TunnelIfindex: ifindex,
		Vni:           vni,
	})
	if err != nil {
		return fmt.Errorf("upserting tunnel: %w", err)
	}
	return nil
}

// DeleteTunnel removes a tunnel from the dataplane.
func (c *Client) DeleteTunnel(ctx context.Context, nodeIP string) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	_, err := client.DeleteTunnel(ctx, &pb.DeleteTunnelRequest{
		NodeIp: nodeIP,
	})
	if err != nil {
		return fmt.Errorf("deleting tunnel: %w", err)
	}
	return nil
}

// UpdateConfig sends configuration entries to the dataplane.
func (c *Client) UpdateConfig(ctx context.Context, entries map[uint32]uint64) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	_, err := client.UpdateConfig(ctx, &pb.UpdateConfigRequest{
		Entries: entries,
	})
	if err != nil {
		return fmt.Errorf("updating config: %w", err)
	}
	return nil
}

// AttachProgram attaches a TC program to an interface.
func (c *Client) AttachProgram(ctx context.Context, iface string, attachType AttachType) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	pbType := pb.AttachType_ATTACH_TC_INGRESS
	if attachType == AttachTCEgress {
		pbType = pb.AttachType_ATTACH_TC_EGRESS
	}

	_, err := client.AttachProgram(ctx, &pb.AttachProgramRequest{
		InterfaceName: iface,
		AttachType:    pbType,
	})
	if err != nil {
		return fmt.Errorf("attaching program to %s: %w", iface, err)
	}
	return nil
}

// DetachProgram detaches a TC program from an interface.
func (c *Client) DetachProgram(ctx context.Context, iface string, attachType AttachType) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	pbType := pb.AttachType_ATTACH_TC_INGRESS
	if attachType == AttachTCEgress {
		pbType = pb.AttachType_ATTACH_TC_EGRESS
	}

	_, err := client.DetachProgram(ctx, &pb.DetachProgramRequest{
		InterfaceName: iface,
		AttachType:    pbType,
	})
	if err != nil {
		return fmt.Errorf("detaching program from %s: %w", iface, err)
	}
	return nil
}

// StreamFlows starts streaming flow events from the dataplane.
// Returns a channel that receives flow events. The channel is closed when
// the stream ends or the context is canceled.
func (c *Client) StreamFlows(ctx context.Context, identityFilter uint32) (<-chan *FlowEvent, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, ErrNotConnected
	}

	stream, err := client.StreamFlows(ctx, &pb.StreamFlowsRequest{
		IdentityFilter: identityFilter,
	})
	if err != nil {
		return nil, fmt.Errorf("starting flow stream: %w", err)
	}

	ch := make(chan *FlowEvent, 100)
	go func() {
		defer close(ch)
		for {
			event, err := stream.Recv()
			if err != nil {
				c.logger.Debug("flow stream ended",
					zap.Error(err),
				)
				return
			}
			flowEvent := &FlowEvent{
				SrcIP:       event.SrcIp,
				DstIP:       event.DstIp,
				SrcIdentity: event.SrcIdentity,
				DstIdentity: event.DstIdentity,
				Protocol:    event.Protocol,
				SrcPort:     event.SrcPort,
				DstPort:     event.DstPort,
				Verdict:     event.Verdict,
				Bytes:       event.Bytes,
				Packets:     event.Packets,
				TimestampNs: event.TimestampNs,
				DropReason:  event.DropReason,
			}
			select {
			case ch <- flowEvent:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, nil
}

// GetStatus returns the current dataplane status.
func (c *Client) GetStatus(ctx context.Context) (*Status, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, ErrNotConnected
	}

	resp, err := client.GetDataplaneStatus(ctx, &pb.GetDataplaneStatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("getting dataplane status: %w", err)
	}

	return &Status{
		EndpointCount:  resp.EndpointCount,
		PolicyCount:    resp.PolicyCount,
		TunnelCount:    resp.TunnelCount,
		Programs:       resp.Programs,
		Mode:           resp.Mode,
		TunnelProtocol: resp.TunnelProtocol,
	}, nil
}

// UpsertSockmapEndpoint registers a SOCKMAP endpoint in the dataplane.
func (c *Client) UpsertSockmapEndpoint(ctx context.Context, ip string, port uint32) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	_, err := client.UpsertSockmapEndpoint(ctx, &pb.UpsertSockmapEndpointRequest{
		Ip:   ip,
		Port: port,
	})
	if err != nil {
		return fmt.Errorf("upserting sockmap endpoint: %w", err)
	}
	return nil
}

// DeleteSockmapEndpoint removes a SOCKMAP endpoint from the dataplane.
func (c *Client) DeleteSockmapEndpoint(ctx context.Context, ip string, port uint32) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	_, err := client.DeleteSockmapEndpoint(ctx, &pb.DeleteSockmapEndpointRequest{
		Ip:   ip,
		Port: port,
	})
	if err != nil {
		return fmt.Errorf("deleting sockmap endpoint: %w", err)
	}
	return nil
}

// GetSockmapStats returns SOCKMAP redirect statistics from the dataplane.
func (c *Client) GetSockmapStats(ctx context.Context) (*SockmapStats, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, ErrNotConnected
	}

	resp, err := client.GetSockmapStats(ctx, &pb.GetInternalSockmapStatsRequest{})
	if err != nil {
		return nil, fmt.Errorf("getting sockmap stats: %w", err)
	}

	return &SockmapStats{
		Redirected:      resp.Redirected,
		Fallback:        resp.Fallback,
		ActiveEndpoints: resp.ActiveEndpoints,
	}, nil
}

// UpsertMeshService registers a mesh service redirect in the dataplane.
func (c *Client) UpsertMeshService(ctx context.Context, ip string, port, redirectPort uint32) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	_, err := client.UpsertMeshService(ctx, &pb.UpsertMeshServiceRequest{
		Ip:           ip,
		Port:         port,
		RedirectPort: redirectPort,
	})
	if err != nil {
		return fmt.Errorf("upserting mesh service: %w", err)
	}
	return nil
}

// DeleteMeshService removes a mesh service redirect from the dataplane.
func (c *Client) DeleteMeshService(ctx context.Context, ip string, port uint32) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	_, err := client.DeleteMeshService(ctx, &pb.DeleteMeshServiceRequest{
		Ip:   ip,
		Port: port,
	})
	if err != nil {
		return fmt.Errorf("deleting mesh service: %w", err)
	}
	return nil
}

// ListMeshServices returns all mesh service redirect entries from the dataplane.
func (c *Client) ListMeshServices(ctx context.Context) ([]*MeshServiceEntry, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, ErrNotConnected
	}

	resp, err := client.ListMeshServices(ctx, &pb.ListInternalMeshServicesRequest{})
	if err != nil {
		return nil, fmt.Errorf("listing mesh services: %w", err)
	}

	entries := make([]*MeshServiceEntry, len(resp.Entries))
	for i, e := range resp.Entries {
		entries[i] = &MeshServiceEntry{
			IP:           e.Ip,
			Port:         e.Port,
			RedirectPort: e.RedirectPort,
		}
	}
	return entries, nil
}

// UpdateRateLimitConfig updates the global rate limit configuration in the dataplane.
func (c *Client) UpdateRateLimitConfig(ctx context.Context, rate, burst uint32, windowNs uint64) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	_, err := client.UpdateRateLimitConfig(ctx, &pb.UpdateRateLimitConfigRequest{
		Rate:     rate,
		Burst:    burst,
		WindowNs: windowNs,
	})
	if err != nil {
		return fmt.Errorf("updating rate limit config: %w", err)
	}
	return nil
}

// GetRateLimitStats returns rate limiting statistics from the dataplane.
func (c *Client) GetRateLimitStats(ctx context.Context) (*RateLimitStats, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, ErrNotConnected
	}

	resp, err := client.GetInternalRateLimitStats(ctx, &pb.GetInternalRateLimitStatsRequest{})
	if err != nil {
		return nil, fmt.Errorf("getting rate limit stats: %w", err)
	}

	return &RateLimitStats{
		Allowed: resp.Allowed,
		Denied:  resp.Denied,
	}, nil
}

// GetBackendHealthStats returns backend health statistics from the dataplane.
// If ip is empty, returns stats for all backends.
func (c *Client) GetBackendHealthStats(ctx context.Context, ip string, port uint32) ([]*BackendHealthInfo, error) {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return nil, ErrNotConnected
	}

	resp, err := client.GetBackendHealthStats(ctx, &pb.GetBackendHealthStatsRequest{
		Ip:   ip,
		Port: port,
	})
	if err != nil {
		return nil, fmt.Errorf("getting backend health stats: %w", err)
	}

	backends := make([]*BackendHealthInfo, len(resp.Backends))
	for i, b := range resp.Backends {
		backends[i] = &BackendHealthInfo{
			IP:           b.Ip,
			Port:         b.Port,
			TotalConns:   b.TotalConns,
			FailedConns:  b.FailedConns,
			TimeoutConns: b.TimeoutConns,
			SuccessConns: b.SuccessConns,
			AvgRTTNs:     b.AvgRttNs,
			FailureRate:  b.FailureRate,
		}
	}
	return backends, nil
}

// UpsertBackends registers or updates L4 LB backends in the dataplane.
func (c *Client) UpsertBackends(ctx context.Context, backends []*Backend) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	entries := make([]*pb.BackendEntry, len(backends))
	for i, b := range backends {
		entries[i] = &pb.BackendEntry{
			Index:  b.Index,
			Ip:     b.IP,
			Port:   b.Port,
			NodeIp: b.NodeIP,
		}
	}

	_, err := client.UpsertBackends(ctx, &pb.UpsertBackendsRequest{
		Backends: entries,
	})
	if err != nil {
		return fmt.Errorf("upserting backends: %w", err)
	}
	return nil
}

// UpsertServiceEntry registers or updates an L4 LB service in the dataplane.
func (c *Client) UpsertServiceEntry(ctx context.Context, svc *ServiceConfig) error {
	c.mu.RLock()
	client := c.client
	c.mu.RUnlock()

	if client == nil {
		return ErrNotConnected
	}

	_, err := client.UpsertService(ctx, &pb.UpsertServiceRequest{
		Ip:              svc.IP,
		Port:            svc.Port,
		Protocol:        svc.Protocol,
		Scope:           svc.Scope,
		BackendCount:    svc.BackendCount,
		BackendOffset:   svc.BackendOffset,
		Algorithm:       svc.Algorithm,
		Flags:           svc.Flags,
		AffinityTimeout: svc.AffinityTimeout,
		MaglevOffset:    svc.MaglevOffset,
	})
	if err != nil {
		return fmt.Errorf("upserting service: %w", err)
	}
	return nil
}

// Close closes the gRPC connection to the dataplane.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return nil
	}

	err := c.conn.Close()
	c.conn = nil
	c.client = nil

	if err != nil {
		return fmt.Errorf("closing dataplane connection: %w", err)
	}

	c.logger.Info("closed dataplane connection")
	return nil
}
