package agent

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/azrtydxb/novanet/api/v1"
	"github.com/azrtydxb/novanet/internal/bandwidth"
	cnisetup "github.com/azrtydxb/novanet/internal/cni"
	"github.com/azrtydxb/novanet/internal/config"
	"github.com/azrtydxb/novanet/internal/egress"
	"github.com/azrtydxb/novanet/internal/encryption"
	"github.com/azrtydxb/novanet/internal/identity"
	"github.com/azrtydxb/novanet/internal/ipam"
	"github.com/azrtydxb/novanet/internal/l2announce"
	"github.com/azrtydxb/novanet/internal/lbipam"
	"github.com/azrtydxb/novanet/internal/policy"
	"github.com/azrtydxb/novanet/internal/routing"
	"github.com/azrtydxb/novanet/internal/service"
	"github.com/azrtydxb/novanet/internal/tunnel"
	"github.com/azrtydxb/novanet/internal/xdp"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Server implements the AgentControl gRPC service.
type Server struct {
	pb.UnimplementedAgentControlServer

	Logger           *zap.Logger
	Cfg              *config.Config
	IPAlloc          *ipam.Allocator
	IDAlloc          *identity.Allocator
	DpClient         pb.DataplaneControlClient
	K8sClient        kubernetes.Interface
	NodeIP           net.IP
	PodCIDR          string
	DpConnected      atomic.Bool
	RoutingConnected bool

	// Policy enforcement.
	PolicyCompiler *policy.Compiler
	PolicyWatcher  *policy.Watcher
	TunnelMgr      *tunnel.Manager
	EgressMgr      *egress.Manager

	// L4 LB service watcher.
	SvcWatcher *service.Watcher

	// WireGuard encryption manager (nil if disabled).
	WgManager *encryption.WireGuardManager

	// Host firewall manager (nil if disabled).
	HostFW interface{}

	// Bandwidth manager (nil if disabled).
	BwManager *bandwidth.Manager

	// LB-IPAM allocator (nil if disabled).
	LbIPAM *lbipam.Allocator

	// L2 announcer for GARP (nil if disabled).
	L2Announcer *l2announce.Announcer

	// XDP manager (nil if disabled).
	XdpMgr *xdp.Manager

	// Routing manager for native mode (nil in overlay mode).
	RoutingMgr *routing.Manager

	// Compiled policy rules (updated by the policy watcher callback).
	PolicyMu    sync.RWMutex
	PolicyRules []*policy.CompiledRule

	// Previously synced egress eBPF keys, for cleanup on recompilation.
	PrevEgressKeys map[EgressMapKey]bool

	Mu        sync.RWMutex
	Endpoints map[string]*Endpoint // key: namespace/name
}

// ServerOptions holds the configuration for creating a new Server.
type ServerOptions struct {
	// Required fields.
	Logger         *zap.Logger
	Cfg            *config.Config
	IPAlloc        *ipam.Allocator
	IDAlloc        *identity.Allocator
	NodeIP         net.IP
	PodCIDR        string
	PolicyCompiler *policy.Compiler

	// Optional fields — may be nil when not applicable.
	DpClient    pb.DataplaneControlClient
	K8sClient   kubernetes.Interface
	EgressMgr   *egress.Manager
	WgManager   *encryption.WireGuardManager
	HostFW      interface{}
	BwManager   *bandwidth.Manager
	LbIPAM      *lbipam.Allocator
	L2Announcer *l2announce.Announcer
	XdpMgr      *xdp.Manager

	// DpConnected indicates whether the dataplane gRPC connection is established.
	DpConnected bool
}

// NewServer creates a Server with validated required fields and sensible defaults.
// It panics if any required option (Logger, Cfg, IPAlloc, IDAlloc, NodeIP,
// PodCIDR, PolicyCompiler) is zero-valued.
func NewServer(opts ServerOptions) *Server {
	if opts.Logger == nil {
		panic("agent.NewServer: Logger is required")
	}
	if opts.Cfg == nil {
		panic("agent.NewServer: Cfg is required")
	}
	if opts.IPAlloc == nil {
		panic("agent.NewServer: IPAlloc is required")
	}
	if opts.IDAlloc == nil {
		panic("agent.NewServer: IDAlloc is required")
	}
	if opts.NodeIP == nil {
		panic("agent.NewServer: NodeIP is required")
	}
	if opts.PodCIDR == "" {
		panic("agent.NewServer: PodCIDR is required")
	}
	if opts.PolicyCompiler == nil {
		panic("agent.NewServer: PolicyCompiler is required")
	}

	s := &Server{
		Logger:         opts.Logger,
		Cfg:            opts.Cfg,
		IPAlloc:        opts.IPAlloc,
		IDAlloc:        opts.IDAlloc,
		DpClient:       opts.DpClient,
		K8sClient:      opts.K8sClient,
		NodeIP:         opts.NodeIP,
		PodCIDR:        opts.PodCIDR,
		PolicyCompiler: opts.PolicyCompiler,
		EgressMgr:      opts.EgressMgr,
		WgManager:      opts.WgManager,
		HostFW:         opts.HostFW,
		BwManager:      opts.BwManager,
		LbIPAM:         opts.LbIPAM,
		L2Announcer:    opts.L2Announcer,
		XdpMgr:         opts.XdpMgr,
		PrevEgressKeys: make(map[EgressMapKey]bool),
		Endpoints:      make(map[string]*Endpoint),
	}
	s.DpConnected.Store(opts.DpConnected)
	return s
}

// validateAddPodRequest checks that all required fields are present in a CNI ADD request.
func validateAddPodRequest(req *pb.AddPodRequest) error {
	if req.PodName == "" {
		return grpcstatus.Error(codes.InvalidArgument, "PodName is required")
	}
	if req.PodNamespace == "" {
		return grpcstatus.Error(codes.InvalidArgument, "PodNamespace is required")
	}
	if req.ContainerId == "" {
		return grpcstatus.Error(codes.InvalidArgument, "ContainerId is required")
	}
	if req.Netns == "" {
		return grpcstatus.Error(codes.InvalidArgument, "Netns is required")
	}
	if req.IfName == "" {
		return grpcstatus.Error(codes.InvalidArgument, "IfName is required")
	}
	if len(req.ContainerId) < 11 {
		return grpcstatus.Errorf(codes.InvalidArgument, "ContainerId too short: must be at least 11 characters, got %d", len(req.ContainerId))
	}
	return nil
}

// AddPod handles CNI ADD requests.
func (s *Server) AddPod(ctx context.Context, req *pb.AddPodRequest) (*pb.AddPodResponse, error) {
	start := time.Now()
	defer func() {
		MetricCNIAddLatency.Observe(time.Since(start).Seconds())
	}()

	if err := validateAddPodRequest(req); err != nil {
		return nil, err
	}

	key := req.PodNamespace + "/" + req.PodName
	s.Logger.Info("AddPod request",
		zap.String("pod", key),
		zap.String("container_id", req.ContainerId),
		zap.String("netns", req.Netns),
		zap.String("if_name", req.IfName),
	)

	podIP, err := s.IPAlloc.Allocate()
	if err != nil {
		s.Logger.Error("failed to allocate IP", zap.String("pod", key), zap.Error(err))
		return nil, grpcstatus.Errorf(codes.ResourceExhausted, "IP allocation failed: %v", err)
	}

	labels := make(map[string]string)
	if s.K8sClient != nil {
		pod, err := s.K8sClient.CoreV1().Pods(req.PodNamespace).Get(ctx, req.PodName, metav1.GetOptions{})
		if err != nil {
			s.Logger.Warn("failed to fetch pod labels from K8s, using empty labels",
				zap.String("pod", key), zap.Error(err))
		} else if pod.Labels != nil {
			for k, v := range pod.Labels {
				labels[k] = v
			}
		}
	} else if req.Labels != nil {
		for k, v := range req.Labels {
			labels[k] = v
		}
	}
	labels["novanet.io/namespace"] = req.PodNamespace
	identityID := s.IDAlloc.AllocateIdentity(labels)

	mac := GenerateMAC(podIP)
	gateway := s.IPAlloc.Gateway()
	prefixLen := s.IPAlloc.PrefixLength()

	hostVethName := "nv" + req.ContainerId[:11]

	ifindex, err := cnisetup.SetupPodNetwork(req.Netns, req.IfName, hostVethName, podIP, gateway, mac, prefixLen)
	if err != nil {
		_ = s.IPAlloc.Release(podIP)
		s.IDAlloc.RemoveIdentity(identityID)
		s.Logger.Error("failed to setup pod network", zap.String("pod", key), zap.Error(err))
		return nil, grpcstatus.Errorf(codes.Internal, "pod network setup failed: %v", err)
	}

	ep := &Endpoint{
		PodName:      req.PodName,
		PodNamespace: req.PodNamespace,
		ContainerID:  req.ContainerId,
		IP:           podIP,
		MAC:          mac,
		IfIndex:      uint32(ifindex), //nolint:gosec // ifindex from kernel, always small positive
		IdentityID:   identityID,
		Netns:        req.Netns,
		IfName:       req.IfName,
		HostVeth:     hostVethName,
	}

	s.Mu.Lock()
	s.Endpoints[key] = ep
	count := len(s.Endpoints)
	s.Mu.Unlock()

	MetricEndpoints.Set(float64(count))
	MetricIdentities.Set(float64(s.IDAlloc.Count()))

	if s.DpClient != nil && s.DpConnected.Load() {
		dpReq := &pb.UpsertEndpointRequest{
			Ip:         podIP.String(),
			Ifindex:    uint32(ifindex), //nolint:gosec // ifindex from kernel, always small positive
			Mac:        mac,
			IdentityId: uint32(identityID), //nolint:gosec // truncated to uint32 for proto wire format
			PodName:    req.PodName,
			Namespace:  req.PodNamespace,
			NodeIp:     s.NodeIP.String(),
		}
		if _, err := s.DpClient.UpsertEndpoint(ctx, dpReq); err != nil {
			s.Logger.Warn("failed to push endpoint to dataplane",
				zap.String("pod", key), zap.Error(err))
		}

		if _, err := s.DpClient.AttachProgram(ctx, &pb.AttachProgramRequest{
			InterfaceName: hostVethName,
			AttachType:    pb.AttachType_ATTACH_TC_INGRESS,
		}); err != nil {
			s.Logger.Warn("failed to attach TC ingress program",
				zap.String("pod", key), zap.String("iface", hostVethName), zap.Error(err))
		}
		if _, err := s.DpClient.AttachProgram(ctx, &pb.AttachProgramRequest{
			InterfaceName: hostVethName,
			AttachType:    pb.AttachType_ATTACH_TC_EGRESS,
		}); err != nil {
			s.Logger.Warn("failed to attach TC egress program",
				zap.String("pod", key), zap.String("iface", hostVethName), zap.Error(err))
		}
	}

	s.Logger.Info("AddPod completed",
		zap.String("pod", key),
		zap.String("ip", podIP.String()),
		zap.String("gateway", gateway.String()),
		zap.String("host_veth", hostVethName),
		zap.Int("ifindex", ifindex),
		zap.Uint64("identity_id", identityID),
	)

	if s.PolicyWatcher != nil {
		s.PolicyWatcher.Recompile()
	}

	return &pb.AddPodResponse{
		Ip:           podIP.String(),
		Gateway:      gateway.String(),
		Mac:          mac.String(),
		PrefixLength: int32(prefixLen), //nolint:gosec // CIDR prefix length 0-128 fits int32
	}, nil
}

// DelPod handles CNI DEL requests.
func (s *Server) DelPod(ctx context.Context, req *pb.DelPodRequest) (*pb.DelPodResponse, error) {
	start := time.Now()
	defer func() {
		MetricCNIDelLatency.Observe(time.Since(start).Seconds())
	}()

	key := req.PodNamespace + "/" + req.PodName
	s.Logger.Info("DelPod request",
		zap.String("pod", key),
		zap.String("container_id", req.ContainerId),
	)

	s.Mu.Lock()
	ep, exists := s.Endpoints[key]
	if exists && ep.ContainerID != req.ContainerId {
		s.Mu.Unlock()
		s.Logger.Warn("DelPod: stale container_id, ignoring",
			zap.String("pod", key),
			zap.String("req_container_id", req.ContainerId),
			zap.String("current_container_id", ep.ContainerID),
		)
		return &pb.DelPodResponse{}, nil
	}
	if exists {
		delete(s.Endpoints, key)
	}
	count := len(s.Endpoints)
	s.Mu.Unlock()

	if !exists {
		s.Logger.Warn("DelPod: endpoint not found, treating as success", zap.String("pod", key))
		return &pb.DelPodResponse{}, nil
	}

	cnisetup.CleanupPodNetwork(ep.HostVeth, ep.IP)

	if err := s.IPAlloc.Release(ep.IP); err != nil {
		s.Logger.Warn("failed to release IP", zap.String("pod", key), zap.Error(err))
	}

	s.IDAlloc.RemoveIdentity(ep.IdentityID)

	MetricEndpoints.Set(float64(count))
	MetricIdentities.Set(float64(s.IDAlloc.Count()))

	if s.DpClient != nil && s.DpConnected.Load() {
		dpReq := &pb.DeleteEndpointRequest{
			Ip: ep.IP.String(),
		}
		if _, err := s.DpClient.DeleteEndpoint(ctx, dpReq); err != nil {
			s.Logger.Warn("failed to remove endpoint from dataplane",
				zap.String("pod", key), zap.Error(err))
		}
	}

	s.Logger.Info("DelPod completed", zap.String("pod", key))
	return &pb.DelPodResponse{}, nil
}

// GetAgentStatus returns the agent's current state.
func (s *Server) GetAgentStatus(ctx context.Context, _ *pb.GetAgentStatusRequest) (*pb.GetAgentStatusResponse, error) {
	s.Mu.RLock()
	epCount := uint32(len(s.Endpoints)) //nolint:gosec // bounded by system memory
	s.Mu.RUnlock()

	resp := &pb.GetAgentStatusResponse{
		RoutingMode:        s.Cfg.RoutingMode,
		TunnelProtocol:     s.Cfg.TunnelProtocol,
		EndpointCount:      epCount,
		IdentityCount:      uint32(s.IDAlloc.Count()), //nolint:gosec // bounded count
		NodeIp:             s.NodeIP.String(),
		PodCidr:            s.PodCIDR,
		ClusterCidr:        s.Cfg.ClusterCIDR,
		NovarouteConnected: s.RoutingConnected,
		Dataplane: &pb.DataplaneStatusInfo{
			Connected: s.DpConnected.Load(),
		},
		Encryption:       s.Cfg.Encryption.Type,
		HostFirewall:     s.Cfg.HostFirewall.Enabled,
		BandwidthEnabled: s.Cfg.Bandwidth.Enabled,
		Ipv6Enabled:      s.Cfg.IPv6.Enabled,
		DsrEnabled:       s.Cfg.DSR,
		XdpMode:          s.Cfg.XDPAcceleration,
		LbIpamEnabled:    s.Cfg.LBIPAM.Enabled,
	}

	if s.DpClient != nil && s.DpConnected.Load() {
		dpStatus, err := s.DpClient.GetDataplaneStatus(ctx, &pb.GetDataplaneStatusRequest{})
		if err == nil {
			resp.PolicyCount = dpStatus.PolicyCount
			resp.TunnelCount = dpStatus.TunnelCount
			resp.Dataplane.AttachedPrograms = uint32(len(dpStatus.Programs)) //nolint:gosec // bounded count
		}
	}

	return resp, nil
}

// StreamAgentFlows proxies flow events from the dataplane to clients.
func (s *Server) StreamAgentFlows(req *pb.StreamAgentFlowsRequest, stream grpc.ServerStreamingServer[pb.FlowEvent]) error {
	if s.DpClient == nil || !s.DpConnected.Load() {
		return grpcstatus.Error(codes.Unavailable, "dataplane not connected")
	}

	dpReq := &pb.StreamFlowsRequest{
		IdentityFilter: req.IdentityFilter,
	}
	dpStream, err := s.DpClient.StreamFlows(stream.Context(), dpReq)
	if err != nil {
		return grpcstatus.Errorf(codes.Internal, "failed to open dataplane flow stream: %v", err)
	}

	for {
		flow, err := dpStream.Recv()
		if err != nil {
			return err
		}

		if req.DropsOnly && flow.Verdict != pb.PolicyAction_POLICY_ACTION_DENY {
			continue
		}

		if err := stream.Send(flow); err != nil {
			return err
		}
	}
}

// ListPolicies returns the compiled policy rules.
func (s *Server) ListPolicies(_ context.Context, _ *pb.ListPoliciesRequest) (*pb.ListPoliciesResponse, error) {
	s.PolicyMu.RLock()
	rules := s.PolicyRules
	s.PolicyMu.RUnlock()

	resp := &pb.ListPoliciesResponse{
		Rules: make([]*pb.PolicyRuleInfo, 0, len(rules)),
	}
	for _, r := range rules {
		action := pb.PolicyAction_POLICY_ACTION_DENY
		if r.Action == policy.ActionAllow {
			action = pb.PolicyAction_POLICY_ACTION_ALLOW
		}
		resp.Rules = append(resp.Rules, &pb.PolicyRuleInfo{
			SrcIdentity: uint32(r.SrcIdentity), //nolint:gosec // truncated to uint32 for proto wire format
			DstIdentity: uint32(r.DstIdentity), //nolint:gosec // truncated to uint32 for proto wire format
			Protocol:    uint32(r.Protocol),
			DstPort:     uint32(r.DstPort),
			Action:      action,
		})
	}
	return resp, nil
}

// ListIdentities returns all identity mappings.
func (s *Server) ListIdentities(_ context.Context, _ *pb.ListIdentitiesRequest) (*pb.ListIdentitiesResponse, error) {
	entries := s.IDAlloc.ListAll()
	resp := &pb.ListIdentitiesResponse{
		Identities: make([]*pb.IdentityInfo, 0, len(entries)),
	}
	for _, e := range entries {
		resp.Identities = append(resp.Identities, &pb.IdentityInfo{
			IdentityId: uint32(e.ID), //nolint:gosec // truncated to uint32 for proto wire format
			Labels:     e.Labels,
			RefCount:   uint32(e.RefCount), //nolint:gosec // bounded count
		})
	}
	return resp, nil
}

// ListTunnels returns the current tunnel state.
func (s *Server) ListTunnels(_ context.Context, _ *pb.ListTunnelsRequest) (*pb.ListTunnelsResponse, error) {
	resp := &pb.ListTunnelsResponse{}
	if s.TunnelMgr == nil {
		return resp, nil
	}
	tunnels := s.TunnelMgr.ListTunnels()
	resp.Tunnels = make([]*pb.TunnelInfoMsg, 0, len(tunnels))
	for _, t := range tunnels {
		resp.Tunnels = append(resp.Tunnels, &pb.TunnelInfoMsg{
			NodeName:      t.NodeName,
			NodeIp:        t.NodeIP,
			PodCidr:       t.PodCIDR,
			InterfaceName: t.InterfaceName,
			Ifindex:       uint32(t.Ifindex), //nolint:gosec // ifindex from kernel, always small positive
			Protocol:      s.TunnelMgr.Protocol(),
		})
	}
	return resp, nil
}

// ListEgressPolicies returns the egress policy rules.
func (s *Server) ListEgressPolicies(_ context.Context, _ *pb.ListEgressPoliciesRequest) (*pb.ListEgressPoliciesResponse, error) {
	resp := &pb.ListEgressPoliciesResponse{}
	if s.EgressMgr == nil {
		return resp, nil
	}
	rules := s.EgressMgr.GetRules()
	resp.Rules = make([]*pb.EgressPolicyInfo, 0, len(rules))
	for _, r := range rules {
		action := pb.EgressAction_EGRESS_ACTION_DENY
		switch r.Action {
		case egress.ActionAllow:
			action = pb.EgressAction_EGRESS_ACTION_ALLOW
		case egress.ActionSNAT:
			action = pb.EgressAction_EGRESS_ACTION_SNAT
		}
		resp.Rules = append(resp.Rules, &pb.EgressPolicyInfo{
			Namespace:   r.Namespace,
			Name:        r.Name,
			SrcIdentity: uint32(r.SrcIdentity), //nolint:gosec // truncated to uint32 for proto wire format
			DstCidr:     r.DstCIDR.String(),
			Protocol:    uint32(r.Protocol),
			DstPort:     uint32(r.DstPort),
			Action:      action,
		})
	}
	return resp, nil
}

// ListServices returns the L4 LB service state.
func (s *Server) ListServices(_ context.Context, _ *pb.ListServicesRequest) (*pb.ListServicesResponse, error) {
	resp := &pb.ListServicesResponse{}
	if s.SvcWatcher == nil {
		return resp, nil
	}
	resp.Services = s.SvcWatcher.ListTrackedServices()
	return resp, nil
}

// OnPolicyChange is the callback invoked by the policy watcher when
// NetworkPolicy resources change. It syncs compiled rules to the dataplane.
func (s *Server) OnPolicyChange(rules []*policy.CompiledRule) {
	s.PolicyMu.Lock()
	s.PolicyRules = rules
	s.PolicyMu.Unlock()

	MetricPolicies.Set(float64(len(rules)))

	if s.DpClient == nil || !s.DpConnected.Load() {
		s.Logger.Debug("skipping policy sync — dataplane not connected")
		return
	}

	entries := make([]*pb.PolicyEntry, 0, len(rules))
	for _, r := range rules {
		if r.CIDR != "" {
			continue
		}

		action := pb.PolicyAction_POLICY_ACTION_DENY
		if r.Action == policy.ActionAllow {
			action = pb.PolicyAction_POLICY_ACTION_ALLOW
		}
		entries = append(entries, &pb.PolicyEntry{
			SrcIdentity: uint32(r.SrcIdentity), //nolint:gosec // truncated to uint32 for proto wire format
			DstIdentity: uint32(r.DstIdentity), //nolint:gosec // truncated to uint32 for proto wire format
			Protocol:    uint32(r.Protocol),
			DstPort:     uint32(r.DstPort),
			Action:      action,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := s.DpClient.SyncPolicies(ctx, &pb.SyncPoliciesRequest{
		Policies: entries,
	})
	if err != nil {
		s.Logger.Error("failed to sync policies to dataplane", zap.Error(err))
		return
	}

	s.Logger.Info("synced policies to dataplane",
		zap.Uint32("added", resp.Added),
		zap.Uint32("removed", resp.Removed),
		zap.Uint32("updated", resp.Updated),
		zap.Int("total_rules", len(entries)),
	)

	s.SyncEgressRules(rules)
}

// LookupEndpoint returns the IP address of the pod identified by namespace/name.
// It satisfies the ebpfservices.EndpointResolver interface.
func (s *Server) LookupEndpoint(namespace, name string) (ip string, found bool) {
	key := namespace + "/" + name
	s.Mu.RLock()
	ep, ok := s.Endpoints[key]
	s.Mu.RUnlock()
	if !ok || ep.IP == nil {
		return "", false
	}
	return ep.IP.String(), true
}

// SyncEgressRules extracts egress CIDR rules from the compiled policy set
// and pushes them to the egress manager and eBPF dataplane.
func (s *Server) SyncEgressRules(rules []*policy.CompiledRule) {
	if s.EgressMgr == nil || s.DpClient == nil || !s.DpConnected.Load() {
		return
	}

	newKeys := make(map[EgressMapKey]bool)
	var egressCount int
	for i, r := range rules {
		if r.CIDR == "" {
			continue
		}
		egressCount++

		_, cidrNet, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			s.Logger.Warn("failed to parse egress CIDR",
				zap.String("cidr", r.CIDR), zap.Error(err))
			continue
		}

		ones, _ := cidrNet.Mask.Size()
		cidrStr := cidrNet.String()

		action := pb.EgressAction_EGRESS_ACTION_DENY
		if r.Action == policy.ActionAllow {
			action = pb.EgressAction_EGRESS_ACTION_ALLOW
		}

		key := EgressMapKey{
			SrcIdentity:  r.SrcIdentity,
			DstCidr:      cidrStr,
			DstPrefixLen: uint32(ones), //nolint:gosec // CIDR prefix 0-128
		}
		newKeys[key] = true

		name := fmt.Sprintf("np-cidr-%d", i)
		if err := s.EgressMgr.AddEgressRule(r.Namespace, egress.Rule{
			Name:        name,
			SrcIdentity: r.SrcIdentity,
			DstCIDR:     r.CIDR,
			Protocol:    r.Protocol,
			DstPort:     r.DstPort,
			Action:      uint8(action),
		}); err != nil {
			s.Logger.Warn("failed to add egress rule",
				zap.String("namespace", r.Namespace),
				zap.String("cidr", r.CIDR), zap.Error(err))
		}

		var snatIPStr string
		if s.EgressMgr != nil && s.EgressMgr.IsMasqueradeEnabled() {
			snatIPStr = s.NodeIP.String()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = s.DpClient.UpsertEgressPolicy(ctx, &pb.UpsertEgressPolicyRequest{
			SrcIdentity:      uint32(r.SrcIdentity), //nolint:gosec // truncated to uint32 for proto wire format
			DstCidr:          cidrStr,
			DstCidrPrefixLen: uint32(ones), //nolint:gosec // CIDR prefix 0-128
			Protocol:         uint32(r.Protocol),
			DstPort:          uint32(r.DstPort),
			Action:           action,
			SnatIp:           snatIPStr,
		})
		cancel()
		if err != nil {
			s.Logger.Warn("failed to push egress policy to dataplane",
				zap.String("cidr", r.CIDR), zap.Error(err))
		}
	}

	if s.PrevEgressKeys != nil {
		for oldKey := range s.PrevEgressKeys {
			if !newKeys[oldKey] {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, err := s.DpClient.DeleteEgressPolicy(ctx, &pb.DeleteEgressPolicyRequest{
					SrcIdentity:      uint32(oldKey.SrcIdentity), //nolint:gosec // truncated to uint32 for proto wire format
					DstCidr:          oldKey.DstCidr,
					DstCidrPrefixLen: oldKey.DstPrefixLen,
				})
				cancel()
				if err != nil {
					s.Logger.Warn("failed to delete stale egress policy from dataplane",
						zap.Uint64("src_identity", oldKey.SrcIdentity),
						zap.String("dst_cidr", oldKey.DstCidr), zap.Error(err))
				}
			}
		}
	}
	s.PrevEgressKeys = newKeys

	for _, existing := range s.EgressMgr.GetRules() {
		ones, _ := existing.DstCIDR.Mask.Size()
		key := EgressMapKey{
			SrcIdentity:  existing.SrcIdentity,
			DstCidr:      existing.DstCIDR.String(),
			DstPrefixLen: uint32(ones), //nolint:gosec // CIDR prefix 0-128
		}
		if !newKeys[key] {
			s.EgressMgr.RemoveEgressRule(existing.Namespace, existing.Name)
		}
	}

	s.Logger.Info("synced egress CIDR rules",
		zap.Int("count", egressCount),
		zap.Int("previous", len(s.PrevEgressKeys)))
}
