// Package main implements the NovaNet agent daemon. It is the management
// plane component that bridges the CNI binary, the Rust eBPF dataplane,
// and (optionally) the NovaRoute routing control plane.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	pb "github.com/azrtydxb/novanet/api/v1"
	"github.com/azrtydxb/novanet/internal/agent/cpvip"
	"github.com/azrtydxb/novanet/internal/agentmetrics"
	cnisetup "github.com/azrtydxb/novanet/internal/cni"
	"github.com/azrtydxb/novanet/internal/config"
	"github.com/azrtydxb/novanet/internal/egress"
	"github.com/azrtydxb/novanet/internal/identity"
	"github.com/azrtydxb/novanet/internal/ipam"
	"github.com/azrtydxb/novanet/internal/masquerade"
	"github.com/azrtydxb/novanet/internal/novaroute"
	"github.com/azrtydxb/novanet/internal/policy"
	"github.com/azrtydxb/novanet/internal/service"
	"github.com/azrtydxb/novanet/internal/tunnel"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

const (
	// Version is the build version of novanet-agent. Overridden at build time.
	Version = "0.1.0"

	// shutdownTimeout is the maximum time to wait for graceful shutdown.
	shutdownTimeout = 10 * time.Second

	// dataplaneRetryInterval is the interval between dataplane connection attempts.
	dataplaneRetryInterval = 5 * time.Second

	// Config map key constants — MUST match novanet-common/src/lib.rs.
	configKeyMode             uint32 = 0
	configKeyTunnelType       uint32 = 1
	configKeyNodeIP           uint32 = 2
	configKeyClusterCIDRIP    uint32 = 3
	configKeyClusterCIDRPL    uint32 = 4
	configKeyDefaultDeny      uint32 = 5
	configKeyMasqueradeEnable uint32 = 6
	configKeySNATIP           uint32 = 7 // Reserved for eBPF-level SNAT (currently using iptables fallback).
	configKeyPodCIDRIP        uint32 = 8
	configKeyPodCIDRPL        uint32 = 9
	configKeyL4LBEnabled      uint32 = 10

	// Config value constants — MUST match novanet-common/src/lib.rs.
	modeOverlay uint64 = 0
	modeNative  uint64 = 1
	tunnelGEV   uint64 = 0
	tunnelVXL   uint64 = 1
)

// Prometheus agentmetrics.
var (
	metricEndpoints = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "novanet",
		Subsystem: "agent",
		Name:      "endpoints_total",
		Help:      "Number of pod endpoints managed by the agent.",
	})
	metricPolicies = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "novanet",
		Subsystem: "agent",
		Name:      "policies_total",
		Help:      "Number of compiled policy rules.",
	})
	metricTunnels = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "novanet",
		Subsystem: "agent",
		Name:      "tunnels_total",
		Help:      "Number of overlay tunnels.",
	})
	metricIdentities = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "novanet",
		Subsystem: "agent",
		Name:      "identities_total",
		Help:      "Number of distinct identities.",
	})
	metricCNIAddLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "novanet",
		Subsystem: "cni",
		Name:      "add_duration_seconds",
		Help:      "Latency of CNI ADD operations.",
		Buckets:   prometheus.DefBuckets,
	})
	metricCNIDelLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "novanet",
		Subsystem: "cni",
		Name:      "del_duration_seconds",
		Help:      "Latency of CNI DEL operations.",
		Buckets:   prometheus.DefBuckets,
	})
	metricRemoteEndpoints = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "novanet",
		Subsystem: "agent",
		Name:      "remote_endpoints_total",
		Help:      "Number of remote pod endpoints synced for cross-node identity resolution.",
	})
)

// registerMetrics registers all Prometheus metrics for the agent.
func registerMetrics() {
	prometheus.MustRegister(
		metricEndpoints,
		metricPolicies,
		metricTunnels,
		metricIdentities,
		metricCNIAddLatency,
		metricCNIDelLatency,
		metricRemoteEndpoints,
	)
	// Register shared dataplane metrics (flow counters, TCP latency histogram, etc.).
	agentmetrics.Register()
}

// endpoint tracks a pod's network state.
type endpoint struct {
	PodName      string
	PodNamespace string
	ContainerID  string
	IP           net.IP
	MAC          net.HardwareAddr
	IfIndex      uint32
	IdentityID   uint32
	Netns        string
	IfName       string
	HostVeth     string
}

// agentServer implements the AgentControl gRPC service.
type agentServer struct {
	pb.UnimplementedAgentControlServer

	logger             *zap.Logger
	cfg                *config.Config
	ipAlloc            *ipam.Allocator
	idAlloc            *identity.Allocator
	dpClient           pb.DataplaneControlClient
	k8sClient          kubernetes.Interface
	nodeIP             net.IP
	podCIDR            string
	dpConnected        atomic.Bool
	novarouteConnected bool

	// Policy enforcement.
	policyCompiler *policy.Compiler
	policyWatcher  *policy.Watcher
	tunnelMgr      *tunnel.Manager
	egressMgr      *egress.Manager

	// L4 LB service watcher.
	svcWatcher *service.Watcher

	// Compiled policy rules (updated by the policy watcher callback).
	policyMu    sync.RWMutex
	policyRules []*policy.CompiledRule

	// Previously synced egress eBPF keys, for cleanup on recompilation.
	prevEgressKeys map[egressMapKey]bool

	mu        sync.RWMutex
	endpoints map[string]*endpoint // key: namespace/name
}

// egressMapKey identifies an entry in the eBPF EGRESS_POLICIES map.
type egressMapKey struct {
	srcIdentity  uint32
	dstCidrIP    uint32
	dstPrefixLen uint32
}

// AddPod handles CNI ADD requests.
func (s *agentServer) AddPod(ctx context.Context, req *pb.AddPodRequest) (*pb.AddPodResponse, error) {
	start := time.Now()
	defer func() {
		metricCNIAddLatency.Observe(time.Since(start).Seconds())
	}()

	key := req.PodNamespace + "/" + req.PodName
	s.logger.Info("AddPod request",
		zap.String("pod", key),
		zap.String("container_id", req.ContainerId),
		zap.String("netns", req.Netns),
		zap.String("if_name", req.IfName),
	)

	// Allocate an IP from the local PodCIDR.
	podIP, err := s.ipAlloc.Allocate()
	if err != nil {
		s.logger.Error("failed to allocate IP", zap.String("pod", key), zap.Error(err))
		return nil, grpcstatus.Errorf(codes.ResourceExhausted, "IP allocation failed: %v", err)
	}

	// Fetch pod labels from K8s API to ensure identity matches policy compiler.
	// The policy compiler includes namespace scoping (novanet.io/namespace)
	// so we must do the same here for consistent identity allocation.
	labels := make(map[string]string)
	if s.k8sClient != nil {
		pod, err := s.k8sClient.CoreV1().Pods(req.PodNamespace).Get(ctx, req.PodName, metav1.GetOptions{})
		if err != nil {
			s.logger.Warn("failed to fetch pod labels from K8s, using empty labels",
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
	// Add namespace scoping label to match policy compiler identity allocation.
	labels["novanet.io/namespace"] = req.PodNamespace
	identityID := s.idAlloc.AllocateIdentity(labels)

	// Generate a deterministic MAC based on the IP.
	mac := generateMAC(podIP)
	gateway := s.ipAlloc.Gateway()
	prefixLen := s.ipAlloc.PrefixLength()

	// Generate a host veth name from the container ID (truncated to 15 chars).
	hostVethName := "nv" + req.ContainerId[:11]

	// Create veth pair, move pod-end into netns, configure IP/routes.
	ifindex, err := cnisetup.SetupPodNetwork(req.Netns, req.IfName, hostVethName, podIP, gateway, mac, prefixLen)
	if err != nil {
		_ = s.ipAlloc.Release(podIP)
		s.idAlloc.RemoveIdentity(identityID)
		s.logger.Error("failed to setup pod network", zap.String("pod", key), zap.Error(err))
		return nil, grpcstatus.Errorf(codes.Internal, "pod network setup failed: %v", err)
	}

	ep := &endpoint{
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

	s.mu.Lock()
	s.endpoints[key] = ep
	count := len(s.endpoints)
	s.mu.Unlock()

	metricEndpoints.Set(float64(count))
	metricIdentities.Set(float64(s.idAlloc.Count()))

	// Push endpoint to dataplane eBPF maps.
	if s.dpClient != nil && s.dpConnected.Load() {
		dpReq := &pb.UpsertEndpointRequest{
			Ip:         ipToUint32(podIP),
			Ifindex:    uint32(ifindex), //nolint:gosec // ifindex from kernel, always small positive
			Mac:        mac,
			IdentityId: identityID,
			PodName:    req.PodName,
			Namespace:  req.PodNamespace,
			NodeIp:     ipToUint32(s.nodeIP),
		}
		if _, err := s.dpClient.UpsertEndpoint(ctx, dpReq); err != nil {
			s.logger.Warn("failed to push endpoint to dataplane",
				zap.String("pod", key), zap.Error(err))
		}

		// Attach TC ingress and egress programs to the host-side veth.
		if _, err := s.dpClient.AttachProgram(ctx, &pb.AttachProgramRequest{
			InterfaceName: hostVethName,
			AttachType:    pb.AttachType_ATTACH_TC_INGRESS,
		}); err != nil {
			s.logger.Warn("failed to attach TC ingress program",
				zap.String("pod", key), zap.String("iface", hostVethName), zap.Error(err))
		}
		if _, err := s.dpClient.AttachProgram(ctx, &pb.AttachProgramRequest{
			InterfaceName: hostVethName,
			AttachType:    pb.AttachType_ATTACH_TC_EGRESS,
		}); err != nil {
			s.logger.Warn("failed to attach TC egress program",
				zap.String("pod", key), zap.String("iface", hostVethName), zap.Error(err))
		}
	}

	s.logger.Info("AddPod completed",
		zap.String("pod", key),
		zap.String("ip", podIP.String()),
		zap.String("gateway", gateway.String()),
		zap.String("host_veth", hostVethName),
		zap.Int("ifindex", ifindex),
		zap.Uint32("identity_id", identityID),
	)

	// Trigger policy recompilation so that rules reference the actual pod
	// identity rather than a hash of selector labels.
	if s.policyWatcher != nil {
		s.policyWatcher.Recompile()
	}

	return &pb.AddPodResponse{
		Ip:           podIP.String(),
		Gateway:      gateway.String(),
		Mac:          mac.String(),
		PrefixLength: int32(prefixLen), //nolint:gosec // CIDR prefix length 0-128 fits int32
	}, nil
}

// DelPod handles CNI DEL requests.
func (s *agentServer) DelPod(ctx context.Context, req *pb.DelPodRequest) (*pb.DelPodResponse, error) {
	start := time.Now()
	defer func() {
		metricCNIDelLatency.Observe(time.Since(start).Seconds())
	}()

	key := req.PodNamespace + "/" + req.PodName
	s.logger.Info("DelPod request",
		zap.String("pod", key),
		zap.String("container_id", req.ContainerId),
	)

	s.mu.Lock()
	ep, exists := s.endpoints[key]
	if exists && ep.ContainerID != req.ContainerId {
		// Stale DEL for an old container — a new container already took over.
		s.mu.Unlock()
		s.logger.Warn("DelPod: stale container_id, ignoring",
			zap.String("pod", key),
			zap.String("req_container_id", req.ContainerId),
			zap.String("current_container_id", ep.ContainerID),
		)
		return &pb.DelPodResponse{}, nil
	}
	if exists {
		delete(s.endpoints, key)
	}
	count := len(s.endpoints)
	s.mu.Unlock()

	if !exists {
		s.logger.Warn("DelPod: endpoint not found, treating as success", zap.String("pod", key))
		return &pb.DelPodResponse{}, nil
	}

	// Clean up the veth pair and host route.
	cnisetup.CleanupPodNetwork(ep.HostVeth, ep.IP)

	// Release the IP.
	if err := s.ipAlloc.Release(ep.IP); err != nil {
		s.logger.Warn("failed to release IP", zap.String("pod", key), zap.Error(err))
	}

	// Decrement the identity reference.
	s.idAlloc.RemoveIdentity(ep.IdentityID)

	metricEndpoints.Set(float64(count))
	metricIdentities.Set(float64(s.idAlloc.Count()))

	// Remove endpoint from dataplane.
	if s.dpClient != nil && s.dpConnected.Load() {
		dpReq := &pb.DeleteEndpointRequest{
			Ip: ipToUint32(ep.IP),
		}
		if _, err := s.dpClient.DeleteEndpoint(ctx, dpReq); err != nil {
			s.logger.Warn("failed to remove endpoint from dataplane",
				zap.String("pod", key), zap.Error(err))
		}
	}

	s.logger.Info("DelPod completed", zap.String("pod", key))
	return &pb.DelPodResponse{}, nil
}

// GetAgentStatus returns the agent's current state.
func (s *agentServer) GetAgentStatus(ctx context.Context, _ *pb.GetAgentStatusRequest) (*pb.GetAgentStatusResponse, error) {
	s.mu.RLock()
	epCount := uint32(len(s.endpoints)) //nolint:gosec // bounded by system memory
	s.mu.RUnlock()

	resp := &pb.GetAgentStatusResponse{
		RoutingMode:        s.cfg.RoutingMode,
		TunnelProtocol:     s.cfg.TunnelProtocol,
		EndpointCount:      epCount,
		IdentityCount:      uint32(s.idAlloc.Count()), //nolint:gosec // bounded count
		NodeIp:             s.nodeIP.String(),
		PodCidr:            s.podCIDR,
		ClusterCidr:        s.cfg.ClusterCIDR,
		NovarouteConnected: s.novarouteConnected,
		Dataplane: &pb.DataplaneStatusInfo{
			Connected: s.dpConnected.Load(),
		},
	}

	// Fetch live dataplane metrics if connected.
	if s.dpClient != nil && s.dpConnected.Load() {
		dpStatus, err := s.dpClient.GetDataplaneStatus(ctx, &pb.GetDataplaneStatusRequest{})
		if err == nil {
			resp.PolicyCount = dpStatus.PolicyCount
			resp.TunnelCount = dpStatus.TunnelCount
			resp.Dataplane.AttachedPrograms = uint32(len(dpStatus.Programs)) //nolint:gosec // bounded count
		}
	}

	return resp, nil
}

// StreamAgentFlows proxies flow events from the dataplane to clients.
func (s *agentServer) StreamAgentFlows(req *pb.StreamAgentFlowsRequest, stream grpc.ServerStreamingServer[pb.FlowEvent]) error {
	if s.dpClient == nil || !s.dpConnected.Load() {
		return grpcstatus.Error(codes.Unavailable, "dataplane not connected")
	}

	dpReq := &pb.StreamFlowsRequest{
		IdentityFilter: req.IdentityFilter,
	}
	dpStream, err := s.dpClient.StreamFlows(stream.Context(), dpReq)
	if err != nil {
		return grpcstatus.Errorf(codes.Internal, "failed to open dataplane flow stream: %v", err)
	}

	for {
		flow, err := dpStream.Recv()
		if err != nil {
			return err
		}

		// Apply drops-only filter.
		if req.DropsOnly && flow.Verdict != pb.PolicyAction_POLICY_ACTION_DENY {
			continue
		}

		if err := stream.Send(flow); err != nil {
			return err
		}
	}
}

// ListPolicies returns the compiled policy rules.
func (s *agentServer) ListPolicies(_ context.Context, _ *pb.ListPoliciesRequest) (*pb.ListPoliciesResponse, error) {
	s.policyMu.RLock()
	rules := s.policyRules
	s.policyMu.RUnlock()

	resp := &pb.ListPoliciesResponse{
		Rules: make([]*pb.PolicyRuleInfo, 0, len(rules)),
	}
	for _, r := range rules {
		action := pb.PolicyAction_POLICY_ACTION_DENY
		if r.Action == policy.ActionAllow {
			action = pb.PolicyAction_POLICY_ACTION_ALLOW
		}
		resp.Rules = append(resp.Rules, &pb.PolicyRuleInfo{
			SrcIdentity: r.SrcIdentity,
			DstIdentity: r.DstIdentity,
			Protocol:    uint32(r.Protocol),
			DstPort:     uint32(r.DstPort),
			Action:      action,
		})
	}
	return resp, nil
}

// ListIdentities returns all identity mappings.
func (s *agentServer) ListIdentities(_ context.Context, _ *pb.ListIdentitiesRequest) (*pb.ListIdentitiesResponse, error) {
	entries := s.idAlloc.ListAll()
	resp := &pb.ListIdentitiesResponse{
		Identities: make([]*pb.IdentityInfo, 0, len(entries)),
	}
	for _, e := range entries {
		resp.Identities = append(resp.Identities, &pb.IdentityInfo{
			IdentityId: e.ID,
			Labels:     e.Labels,
			RefCount:   uint32(e.RefCount), //nolint:gosec // bounded count
		})
	}
	return resp, nil
}

// ListTunnels returns the current tunnel state.
func (s *agentServer) ListTunnels(_ context.Context, _ *pb.ListTunnelsRequest) (*pb.ListTunnelsResponse, error) {
	resp := &pb.ListTunnelsResponse{}
	if s.tunnelMgr == nil {
		return resp, nil
	}
	tunnels := s.tunnelMgr.ListTunnels()
	resp.Tunnels = make([]*pb.TunnelInfoMsg, 0, len(tunnels))
	for _, t := range tunnels {
		resp.Tunnels = append(resp.Tunnels, &pb.TunnelInfoMsg{
			NodeName:      t.NodeName,
			NodeIp:        t.NodeIP,
			PodCidr:       t.PodCIDR,
			InterfaceName: t.InterfaceName,
			Ifindex:       uint32(t.Ifindex), //nolint:gosec // ifindex from kernel, always small positive
			Protocol:      s.tunnelMgr.Protocol(),
		})
	}
	return resp, nil
}

// ListEgressPolicies returns the egress policy rules.
func (s *agentServer) ListEgressPolicies(_ context.Context, _ *pb.ListEgressPoliciesRequest) (*pb.ListEgressPoliciesResponse, error) {
	resp := &pb.ListEgressPoliciesResponse{}
	if s.egressMgr == nil {
		return resp, nil
	}
	rules := s.egressMgr.GetRules()
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
			SrcIdentity: r.SrcIdentity,
			DstCidr:     r.DstCIDR.String(),
			Protocol:    uint32(r.Protocol),
			DstPort:     uint32(r.DstPort),
			Action:      action,
		})
	}
	return resp, nil
}

// ListServices returns the L4 LB service state.
func (s *agentServer) ListServices(_ context.Context, _ *pb.ListServicesRequest) (*pb.ListServicesResponse, error) {
	resp := &pb.ListServicesResponse{}
	if s.svcWatcher == nil {
		return resp, nil
	}
	resp.Services = s.svcWatcher.ListTrackedServices()
	return resp, nil
}

// onPolicyChange is the callback invoked by the policy watcher when
// NetworkPolicy resources change. It syncs compiled rules to the dataplane.
func (s *agentServer) onPolicyChange(rules []*policy.CompiledRule) {
	// Store for ListPolicies RPC.
	s.policyMu.Lock()
	s.policyRules = rules
	s.policyMu.Unlock()

	metricPolicies.Set(float64(len(rules)))

	// Sync to dataplane.
	if s.dpClient == nil || !s.dpConnected.Load() {
		s.logger.Debug("skipping policy sync — dataplane not connected")
		return
	}

	entries := make([]*pb.PolicyEntry, 0, len(rules))
	for _, r := range rules {
		if r.CIDR != "" {
			// CIDR-based rules are handled by syncEgressRules() via the
			// EGRESS_POLICIES eBPF map, not the identity-based POLICIES map.
			continue
		}

		action := pb.PolicyAction_POLICY_ACTION_DENY
		if r.Action == policy.ActionAllow {
			action = pb.PolicyAction_POLICY_ACTION_ALLOW
		}
		entries = append(entries, &pb.PolicyEntry{
			SrcIdentity: r.SrcIdentity,
			DstIdentity: r.DstIdentity,
			Protocol:    uint32(r.Protocol),
			DstPort:     uint32(r.DstPort),
			Action:      action,
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := s.dpClient.SyncPolicies(ctx, &pb.SyncPoliciesRequest{
		Policies: entries,
	})
	if err != nil {
		s.logger.Error("failed to sync policies to dataplane", zap.Error(err))
		return
	}

	s.logger.Info("synced policies to dataplane",
		zap.Uint32("added", resp.Added),
		zap.Uint32("removed", resp.Removed),
		zap.Uint32("updated", resp.Updated),
		zap.Int("total_rules", len(entries)),
	)

	// Also sync egress (CIDR-based) rules to the egress manager and dataplane.
	s.syncEgressRules(rules)
}

// syncEgressRules extracts egress CIDR rules from the compiled policy set
// and pushes them to the egress manager. This bridges NetworkPolicy egress
// rules to the eBPF EGRESS_POLICIES map. Stale entries from the previous
// sync are deleted.
func (s *agentServer) syncEgressRules(rules []*policy.CompiledRule) {
	if s.egressMgr == nil || s.dpClient == nil || !s.dpConnected.Load() {
		return
	}

	// Build the new set of egress keys.
	newKeys := make(map[egressMapKey]bool)
	var egressCount int
	for i, r := range rules {
		if r.CIDR == "" {
			continue
		}
		egressCount++

		// Parse the CIDR to get IP and prefix length.
		_, cidrNet, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			s.logger.Warn("failed to parse egress CIDR",
				zap.String("cidr", r.CIDR),
				zap.Error(err))
			continue
		}

		cidrIP := cidrNet.IP.To4()
		if cidrIP == nil {
			continue // skip IPv6
		}
		ones, _ := cidrNet.Mask.Size()
		cidrIPu32 := ipToUint32(cidrIP)

		action := pb.EgressAction_EGRESS_ACTION_DENY
		if r.Action == policy.ActionAllow {
			action = pb.EgressAction_EGRESS_ACTION_ALLOW
		}

		key := egressMapKey{
			srcIdentity:  r.SrcIdentity,
			dstCidrIP:    cidrIPu32,
			dstPrefixLen: uint32(ones), //nolint:gosec // CIDR prefix 0-128
		}
		newKeys[key] = true

		name := fmt.Sprintf("np-cidr-%d", i)
		// Store in egress manager for ListEgressPolicies RPC.
		if err := s.egressMgr.AddEgressRule(r.Namespace, egress.Rule{
			Name:        name,
			SrcIdentity: r.SrcIdentity,
			DstCIDR:     r.CIDR,
			Protocol:    r.Protocol,
			DstPort:     r.DstPort,
			Action:      uint8(action),
		}); err != nil {
			s.logger.Warn("failed to add egress rule",
				zap.String("namespace", r.Namespace),
				zap.String("cidr", r.CIDR),
				zap.Error(err))
		}

		// Push to eBPF dataplane.
		// Include the node IP as SNAT target so eBPF can perform masquerade.
		var snatIP uint32
		if s.egressMgr != nil && s.egressMgr.IsMasqueradeEnabled() {
			snatIP = ipToUint32(s.nodeIP.To4())
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err = s.dpClient.UpsertEgressPolicy(ctx, &pb.UpsertEgressPolicyRequest{
			SrcIdentity:      r.SrcIdentity,
			DstCidrIp:        cidrIPu32,
			DstCidrPrefixLen: uint32(ones), //nolint:gosec // CIDR prefix 0-128
			Protocol:         uint32(r.Protocol),
			DstPort:          uint32(r.DstPort),
			Action:           action,
			SnatIp:           snatIP,
		})
		cancel()
		if err != nil {
			s.logger.Warn("failed to push egress policy to dataplane",
				zap.String("cidr", r.CIDR),
				zap.Error(err))
		}
	}

	// Delete stale egress entries that are no longer in the compiled set.
	if s.prevEgressKeys != nil {
		for oldKey := range s.prevEgressKeys {
			if !newKeys[oldKey] {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				_, err := s.dpClient.DeleteEgressPolicy(ctx, &pb.DeleteEgressPolicyRequest{
					SrcIdentity:      oldKey.srcIdentity,
					DstCidrIp:        oldKey.dstCidrIP,
					DstCidrPrefixLen: oldKey.dstPrefixLen,
				})
				cancel()
				if err != nil {
					s.logger.Warn("failed to delete stale egress policy from dataplane",
						zap.Uint32("src_identity", oldKey.srcIdentity),
						zap.Uint32("dst_ip", oldKey.dstCidrIP),
						zap.Error(err))
				}
			}
		}
	}
	s.prevEgressKeys = newKeys

	// Clean egress manager rules that no longer exist.
	for _, existing := range s.egressMgr.GetRules() {
		cidrIP := existing.DstCIDR.IP.To4()
		if cidrIP == nil {
			continue
		}
		ones, _ := existing.DstCIDR.Mask.Size()
		key := egressMapKey{
			srcIdentity:  existing.SrcIdentity,
			dstCidrIP:    ipToUint32(cidrIP),
			dstPrefixLen: uint32(ones), //nolint:gosec // CIDR prefix 0-128
		}
		if !newKeys[key] {
			s.egressMgr.RemoveEgressRule(existing.Namespace, existing.Name)
		}
	}

	s.logger.Info("synced egress CIDR rules",
		zap.Int("count", egressCount),
		zap.Int("previous", len(s.prevEgressKeys)))
}

// startRemoteEndpointSync watches all cluster pods via an informer and pushes
// remote (non-local) pod endpoints to the eBPF dataplane. This enables
// cross-node identity resolution for policy enforcement in all routing modes
// (Geneve, VXLAN, Native/BGP).
//
// For remote pods, ifindex=0 and mac=nil (not needed for policy lookup).
// The identity_id is computed from the pod's labels using the same FNV-1a hash,
// and node_ip is set from the pod's Status.HostIP.
func startRemoteEndpointSync(ctx context.Context, logger *zap.Logger, k8sClient kubernetes.Interface,
	dpClient pb.DataplaneControlClient, selfNode string) {

	factory := informers.NewSharedInformerFactory(k8sClient, 30*time.Second)
	podInformer := factory.Core().V1().Pods().Informer()

	var remoteCount int64
	var mu sync.Mutex

	_, _ = podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok || pod.Spec.NodeName == selfNode || pod.Status.PodIP == "" {
				return
			}
			if upsertRemoteEndpoint(ctx, logger, dpClient, pod) {
				mu.Lock()
				remoteCount++
				metricRemoteEndpoints.Set(float64(remoteCount))
				mu.Unlock()
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok || pod.Spec.NodeName == selfNode {
				return
			}
			if pod.Status.PodIP == "" {
				return
			}
			upsertRemoteEndpoint(ctx, logger, dpClient, pod)
		},
		DeleteFunc: func(obj any) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if ok {
					pod, _ = tombstone.Obj.(*corev1.Pod)
				}
			}
			if pod == nil || pod.Spec.NodeName == selfNode || pod.Status.PodIP == "" {
				return
			}
			if deleteRemoteEndpoint(ctx, logger, dpClient, pod) {
				mu.Lock()
				remoteCount--
				if remoteCount < 0 {
					remoteCount = 0
				}
				metricRemoteEndpoints.Set(float64(remoteCount))
				mu.Unlock()
			}
		},
	})

	factory.Start(ctx.Done())
	factory.WaitForCacheSync(ctx.Done())

	logger.Info("remote endpoint sync started — cross-node identity resolution enabled")
	<-ctx.Done()
}

// upsertRemoteEndpoint pushes a remote pod's endpoint to the eBPF dataplane
// for identity resolution. Returns true if the upsert succeeded.
func upsertRemoteEndpoint(ctx context.Context, logger *zap.Logger,
	dpClient pb.DataplaneControlClient, pod *corev1.Pod) bool {

	podIP := net.ParseIP(pod.Status.PodIP)
	if podIP == nil {
		return false
	}
	podIP = podIP.To4()
	if podIP == nil {
		return false // skip IPv6
	}

	hostIP := net.ParseIP(pod.Status.HostIP)
	if hostIP == nil {
		return false
	}
	hostIP = hostIP.To4()
	if hostIP == nil {
		return false
	}

	// Compute identity from pod labels using the same FNV-1a hash
	// that the local identity allocator uses. Include namespace scoping
	// label to match the policy compiler's selectorToIdentity.
	labels := make(map[string]string)
	for k, v := range pod.Labels {
		labels[k] = v
	}
	labels["novanet.io/namespace"] = pod.Namespace
	identityID := identity.HashLabels(labels)

	req := &pb.UpsertEndpointRequest{
		Ip:         ipToUint32(podIP),
		Ifindex:    0,                        // Remote pod — no local interface.
		Mac:        []byte{0, 0, 0, 0, 0, 0}, // Remote pod — zero MAC (not used for policy).
		IdentityId: identityID,
		PodName:    pod.Name,
		Namespace:  pod.Namespace,
		NodeIp:     ipToUint32(hostIP),
	}

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if _, err := dpClient.UpsertEndpoint(callCtx, req); err != nil {
		logger.Debug("failed to sync remote endpoint",
			zap.String("pod", pod.Namespace+"/"+pod.Name),
			zap.String("pod_ip", pod.Status.PodIP),
			zap.Error(err))
		return false
	}

	logger.Debug("synced remote endpoint",
		zap.String("pod", pod.Namespace+"/"+pod.Name),
		zap.String("pod_ip", pod.Status.PodIP),
		zap.Uint32("identity_id", identityID),
	)
	return true
}

// deleteRemoteEndpoint removes a remote pod's endpoint from the eBPF dataplane.
// Returns true if the deletion succeeded.
func deleteRemoteEndpoint(ctx context.Context, logger *zap.Logger,
	dpClient pb.DataplaneControlClient, pod *corev1.Pod) bool {

	podIP := net.ParseIP(pod.Status.PodIP)
	if podIP == nil {
		return false
	}
	podIP = podIP.To4()
	if podIP == nil {
		return false
	}

	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if _, err := dpClient.DeleteEndpoint(callCtx, &pb.DeleteEndpointRequest{
		Ip: ipToUint32(podIP),
	}); err != nil {
		logger.Debug("failed to remove remote endpoint",
			zap.String("pod", pod.Namespace+"/"+pod.Name),
			zap.String("pod_ip", pod.Status.PodIP),
			zap.Error(err))
		return false
	}

	logger.Debug("removed remote endpoint",
		zap.String("pod", pod.Namespace+"/"+pod.Name),
		zap.String("pod_ip", pod.Status.PodIP),
	)
	return true
}

// agentParams holds the resolved startup parameters after flag parsing and
// auto-detection from the Kubernetes API.
type agentParams struct {
	configPath string
	podCIDR    string
	nodeIPStr  string
	nodeName   string
}

// shutdownState holds references needed for graceful shutdown.
type shutdownState struct {
	logger        *zap.Logger
	cancel        context.CancelFunc
	bgWg          *sync.WaitGroup
	cniGRPC       *grpc.Server
	agentGRPC     *grpc.Server
	metricsServer *http.Server
	dpConn        *grpc.ClientConn
	nrClient      *novaroute.Client
	podCIDR       string
}

func main() {
	registerMetrics()

	// Parse flags and handle --version.
	params := parseFlags()

	// Load and validate configuration.
	cfg := loadConfig(params.configPath)

	// Build logger.
	logger, err := buildLogger(cfg.LogLevel)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("novanet-agent starting",
		zap.String("version", Version),
		zap.String("config", params.configPath),
		zap.String("routing_mode", cfg.RoutingMode),
		zap.String("tunnel_protocol", cfg.TunnelProtocol),
	)

	// Create Kubernetes client.
	k8sClient := createK8sClient(logger, params.nodeName)

	// Resolve node-ip and pod-cidr (auto-detect from K8s if needed).
	resolveNodeParams(logger, k8sClient, &params)
	nodeIP := parseNodeIP(logger, params.nodeIPStr)

	// Create root context.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var bgWg sync.WaitGroup

	// Initialize core subsystems.
	ipAlloc := createIPAM(logger, params.podCIDR)
	setupMasquerade(logger, cfg, params.podCIDR)
	idAlloc := identity.NewAllocator(logger)
	logger.Info("identity allocator created")

	policyCompiler := createPolicyCompiler(ctx, logger, k8sClient, idAlloc)
	egressMgr := createEgressManager(logger, cfg, nodeIP)

	// Connect to dataplane.
	dpConn, dpClient, dpConnected := connectToDataplane(ctx, logger, cfg.DataplaneSocket)
	initDataplane(ctx, logger, cfg, dpClient, dpConnected, nodeIP, params.podCIDR, &bgWg)

	// Create agent gRPC server.
	agentSrv := &agentServer{
		logger:         logger,
		cfg:            cfg,
		ipAlloc:        ipAlloc,
		idAlloc:        idAlloc,
		dpClient:       dpClient,
		k8sClient:      k8sClient,
		nodeIP:         nodeIP,
		podCIDR:        params.podCIDR,
		policyCompiler: policyCompiler,
		egressMgr:      egressMgr,
		prevEgressKeys: make(map[egressMapKey]bool),
		endpoints:      make(map[string]*endpoint),
	}
	agentSrv.dpConnected.Store(dpConnected)

	// Start background watchers.
	startPolicyWatcher(ctx, logger, k8sClient, policyCompiler, agentSrv, &bgWg)
	startRemoteSync(ctx, logger, k8sClient, dpClient, dpConnected, params.nodeName, &bgWg)

	// Start L4 LB service watcher if enabled.
	if dpConnected {
		startServiceWatcher(ctx, logger, cfg, k8sClient, dpClient, agentSrv)
	}

	// Start gRPC and metrics servers.
	cniGRPC := startCNIServer(logger, cfg, agentSrv)
	agentGRPC := startAgentServer(logger, cfg, agentSrv)
	metricsServer := startMetricsServer(logger, cfg, agentSrv)

	// Mode-specific initialization (overlay tunnels or native BGP).
	nrClient := initRoutingMode(ctx, logger, cfg, k8sClient, agentSrv,
		dpClient, nodeIP, params.podCIDR, params.nodeName, &bgWg)

	// Wait for termination signal and shut down gracefully.
	waitForSignal(logger)
	gracefulShutdown(&shutdownState{
		logger:        logger,
		cancel:        cancel,
		bgWg:          &bgWg,
		cniGRPC:       cniGRPC,
		agentGRPC:     agentGRPC,
		metricsServer: metricsServer,
		dpConn:        dpConn,
		nrClient:      nrClient,
		podCIDR:       params.podCIDR,
	})
}

// parseFlags parses command-line flags and handles --version.
func parseFlags() agentParams {
	configPath := flag.String("config", "/etc/novanet/config.json", "Path to configuration file")
	podCIDR := flag.String("pod-cidr", "", "Node's PodCIDR (e.g., 10.244.1.0/24)")
	nodeIPStr := flag.String("node-ip", "", "Node IP address")
	printVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *printVersion {
		_, _ = fmt.Fprintf(os.Stdout, "novanet-agent %s\n", Version)
		os.Exit(0)
	}

	return agentParams{
		configPath: *configPath,
		podCIDR:    *podCIDR,
		nodeIPStr:  *nodeIPStr,
		nodeName:   os.Getenv("NOVANET_NODE_NAME"),
	}
}

// loadConfig loads and validates the agent configuration file.
func loadConfig(configPath string) *config.Config {
	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			cfg = config.DefaultConfig()
		} else {
			_, _ = fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
			os.Exit(1)
		}
	}
	config.ExpandEnvVars(cfg)

	if err := config.Validate(cfg); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

// createK8sClient creates a Kubernetes clientset if running inside a cluster
// (NOVANET_NODE_NAME is set).
func createK8sClient(logger *zap.Logger, nodeName string) *kubernetes.Clientset {
	if nodeName == "" {
		return nil
	}
	k8sCfg, err := rest.InClusterConfig()
	if err != nil {
		logger.Fatal("failed to create in-cluster config", zap.Error(err))
	}
	k8sClient, err := kubernetes.NewForConfig(k8sCfg)
	if err != nil {
		logger.Fatal("failed to create kubernetes client", zap.Error(err))
	}
	return k8sClient
}

// resolveNodeParams auto-detects pod-cidr and node-ip from the Kubernetes API
// when not provided via flags.
func resolveNodeParams(logger *zap.Logger, k8sClient *kubernetes.Clientset, params *agentParams) {
	if (params.podCIDR == "" || params.nodeIPStr == "") && k8sClient != nil {
		logger.Info("auto-detecting node-ip/pod-cidr from Kubernetes API",
			zap.String("node_name", params.nodeName),
		)
		nodeCtx, nodeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		node, err := k8sClient.CoreV1().Nodes().Get(nodeCtx, params.nodeName, metav1.GetOptions{})
		nodeCancel()
		if err != nil {
			logger.Fatal("failed to get node for auto-detection", zap.Error(err), zap.String("node", params.nodeName))
		}
		if params.podCIDR == "" && node.Spec.PodCIDR != "" {
			params.podCIDR = node.Spec.PodCIDR
			logger.Info("auto-detected pod-cidr", zap.String("pod_cidr", params.podCIDR))
		}
		if params.nodeIPStr == "" {
			for _, addr := range node.Status.Addresses {
				if addr.Type == "InternalIP" {
					params.nodeIPStr = addr.Address
					logger.Info("auto-detected node-ip", zap.String("node_ip", params.nodeIPStr))
					break
				}
			}
		}
	}

	if params.podCIDR == "" {
		logger.Fatal("--pod-cidr is required (or set NOVANET_NODE_NAME for auto-detection)")
	}
	if params.nodeIPStr == "" {
		logger.Fatal("--node-ip is required (or set NOVANET_NODE_NAME for auto-detection)")
	}
}

// parseNodeIP parses and validates the node IP string as an IPv4 address.
func parseNodeIP(logger *zap.Logger, nodeIPStr string) net.IP {
	nodeIP := net.ParseIP(nodeIPStr)
	if nodeIP == nil {
		logger.Fatal("invalid --node-ip", zap.String("value", nodeIPStr))
	}
	nodeIP = nodeIP.To4()
	if nodeIP == nil {
		logger.Fatal("--node-ip must be an IPv4 address", zap.String("value", nodeIPStr))
	}
	return nodeIP
}

// createIPAM creates the IPAM allocator for the node's PodCIDR.
func createIPAM(logger *zap.Logger, podCIDR string) *ipam.Allocator {
	ipAlloc, err := ipam.NewAllocatorWithStateDir(podCIDR, "/var/lib/cni/networks/novanet")
	if err != nil {
		logger.Fatal("failed to create IPAM allocator", zap.Error(err))
	}
	logger.Info("IPAM allocator created",
		zap.String("pod_cidr", podCIDR),
		zap.Int("available", ipAlloc.Available()),
	)
	return ipAlloc
}

// setupMasquerade configures NAT masquerade if a cluster CIDR is configured.
func setupMasquerade(logger *zap.Logger, cfg *config.Config, podCIDR string) {
	if cfg.ClusterCIDR == "" {
		return
	}
	if err := masquerade.EnsureMasquerade(podCIDR, cfg.ClusterCIDR); err != nil {
		logger.Error("failed to setup NAT masquerade", zap.Error(err))
	} else {
		logger.Info("NAT masquerade configured",
			zap.String("pod_cidr", podCIDR),
			zap.String("cluster_cidr", cfg.ClusterCIDR),
		)
	}
}

// createPolicyCompiler creates the policy compiler and wires up port and
// namespace resolvers if a Kubernetes client is available.
func createPolicyCompiler(ctx context.Context, logger *zap.Logger, k8sClient *kubernetes.Clientset,
	idAlloc *identity.Allocator) *policy.Compiler {

	policyCompiler := policy.NewCompiler(idAlloc, logger)

	if k8sClient != nil {
		policyCompiler.SetPortResolver(func(portName string, protocol corev1.Protocol, namespace string, selector metav1.LabelSelector) []uint16 {
			return resolveNamedPorts(ctx, k8sClient, portName, protocol, namespace, selector)
		})

		policyCompiler.SetNamespaceResolver(func(selector metav1.LabelSelector) []string {
			return resolveNamespaces(ctx, k8sClient, selector)
		})
	}

	logger.Info("policy compiler created")
	return policyCompiler
}

// resolveNamedPorts resolves named ports by looking up pod container specs.
func resolveNamedPorts(ctx context.Context, k8sClient *kubernetes.Clientset,
	portName string, protocol corev1.Protocol, namespace string, selector metav1.LabelSelector) []uint16 {

	sel, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return nil
	}
	pods, err := k8sClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: sel.String(),
	})
	if err != nil {
		return nil
	}
	seen := make(map[uint16]bool)
	var ports []uint16
	for _, pod := range pods.Items {
		for _, c := range pod.Spec.Containers {
			for _, cp := range c.Ports {
				if cp.Name == portName && cp.Protocol == protocol {
					if !seen[uint16(cp.ContainerPort)] { //nolint:gosec // K8s port range 1-65535 fits uint16
						seen[uint16(cp.ContainerPort)] = true           //nolint:gosec // K8s port range 1-65535 fits uint16
						ports = append(ports, uint16(cp.ContainerPort)) //nolint:gosec // K8s port range 1-65535 fits uint16
					}
				}
			}
		}
	}
	return ports
}

// resolveNamespaces resolves namespace selectors to namespace names.
func resolveNamespaces(ctx context.Context, k8sClient *kubernetes.Clientset, selector metav1.LabelSelector) []string {
	sel, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return nil
	}
	nsList, err := k8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: sel.String(),
	})
	if err != nil {
		return nil
	}
	var names []string
	for _, ns := range nsList.Items {
		names = append(names, ns.Name)
	}
	return names
}

// createEgressManager creates the egress manager if a cluster CIDR is configured.
func createEgressManager(logger *zap.Logger, cfg *config.Config, nodeIP net.IP) *egress.Manager {
	if cfg.ClusterCIDR == "" {
		return nil
	}
	_, clusterNet, err := net.ParseCIDR(cfg.ClusterCIDR)
	if err != nil {
		logger.Warn("failed to parse cluster CIDR, egress manager disabled",
			zap.String("cluster_cidr", cfg.ClusterCIDR),
			zap.Error(err))
		return nil
	}
	mgr := egress.NewManager(nodeIP, clusterNet, logger)
	logger.Info("egress manager created")
	return mgr
}

// initDataplane sends initial configuration and starts flow consumer if connected.
func initDataplane(ctx context.Context, logger *zap.Logger, cfg *config.Config,
	dpClient pb.DataplaneControlClient, dpConnected bool, nodeIP net.IP, podCIDR string, bgWg *sync.WaitGroup) {

	if !dpConnected {
		return
	}
	if err := pushDataplaneConfig(ctx, logger, dpClient, cfg, nodeIP, podCIDR); err != nil {
		logger.Error("failed to push initial config to dataplane", zap.Error(err))
	}

	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		consumeFlows(ctx, logger, dpClient)
	}()
}

// startPolicyWatcher starts the NetworkPolicy watcher if a Kubernetes client is available.
func startPolicyWatcher(ctx context.Context, logger *zap.Logger, k8sClient *kubernetes.Clientset,
	policyCompiler *policy.Compiler, agentSrv *agentServer, bgWg *sync.WaitGroup) {

	if k8sClient == nil {
		logger.Warn("no Kubernetes client — NetworkPolicy watcher disabled")
		return
	}
	policyWatcher := policy.NewWatcher(k8sClient, policyCompiler, logger)
	policyWatcher.OnChange(agentSrv.onPolicyChange)
	agentSrv.policyWatcher = policyWatcher
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		logger.Info("starting NetworkPolicy watcher")
		if err := policyWatcher.Start(ctx); err != nil {
			logger.Error("NetworkPolicy watcher error", zap.Error(err))
		}
	}()
}

// startRemoteSync starts the remote endpoint sync for cross-node identity resolution.
func startRemoteSync(ctx context.Context, logger *zap.Logger, k8sClient *kubernetes.Clientset,
	dpClient pb.DataplaneControlClient, dpConnected bool, nodeName string, bgWg *sync.WaitGroup) {

	if k8sClient == nil || dpClient == nil || !dpConnected {
		return
	}
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		startRemoteEndpointSync(ctx, logger, k8sClient, dpClient, nodeName)
	}()
}

// dpServiceAdapter wraps pb.DataplaneControlClient to satisfy
// the service.DataplaneServiceClient interface (strips grpc.CallOption variadic).
type dpServiceAdapter struct {
	client pb.DataplaneControlClient
}

func (a *dpServiceAdapter) UpsertService(ctx context.Context, in *pb.UpsertServiceRequest) (*pb.UpsertServiceResponse, error) {
	return a.client.UpsertService(ctx, in)
}

func (a *dpServiceAdapter) DeleteService(ctx context.Context, in *pb.DeleteServiceRequest) (*pb.DeleteServiceResponse, error) {
	return a.client.DeleteService(ctx, in)
}

func (a *dpServiceAdapter) UpsertBackends(ctx context.Context, in *pb.UpsertBackendsRequest) (*pb.UpsertBackendsResponse, error) {
	return a.client.UpsertBackends(ctx, in)
}

func (a *dpServiceAdapter) UpsertMaglevTable(ctx context.Context, in *pb.UpsertMaglevTableRequest) (*pb.UpsertMaglevTableResponse, error) {
	return a.client.UpsertMaglevTable(ctx, in)
}

// startServiceWatcher starts the L4 LB service watcher when l4lb is enabled.
func startServiceWatcher(ctx context.Context, logger *zap.Logger, cfg *config.Config,
	k8sClient *kubernetes.Clientset, dpClient pb.DataplaneControlClient, agentSrv *agentServer) {

	if !cfg.L4LB.Enabled {
		return
	}
	if k8sClient == nil {
		logger.Warn("no Kubernetes client — L4 LB service watcher disabled")
		return
	}

	logger.Info("L4 LB enabled — starting service watcher",
		zap.String("default_algorithm", cfg.L4LB.DefaultAlgorithm))

	adapter := &dpServiceAdapter{client: dpClient}
	allocator := service.NewSlotAllocator(65536)
	svcWatcher := service.NewWatcher(k8sClient, adapter, allocator, cfg.L4LB.DefaultAlgorithm, logger)
	agentSrv.svcWatcher = svcWatcher

	if err := svcWatcher.Start(ctx); err != nil {
		logger.Error("failed to start service watcher", zap.Error(err))
		return
	}

	// Attach tc_host_ingress to physical interface for NodePort/ExternalIP.
	hostIface := detectHostInterface(logger)
	if _, err := dpClient.AttachProgram(ctx, &pb.AttachProgramRequest{
		InterfaceName: hostIface,
		AttachType:    pb.AttachType_ATTACH_TC_INGRESS,
	}); err != nil {
		logger.Error("failed to attach host ingress program",
			zap.String("interface", hostIface), zap.Error(err))
	} else {
		logger.Info("attached tc_host_ingress for NodePort/ExternalIP",
			zap.String("interface", hostIface))
	}
}

// detectHostInterface returns the name of the node's primary physical interface.
func detectHostInterface(logger *zap.Logger) string {
	for _, name := range []string{"bond0", "eth0", "ens192", "enp0s3", "ens3", "ens5"} {
		if _, err := net.InterfaceByName(name); err == nil {
			logger.Debug("detected host interface", zap.String("interface", name))
			return name
		}
	}
	logger.Warn("no known physical interface found, falling back to eth0")
	return "eth0"
}

// startCNIServer starts the CNI gRPC server and returns the server handle.
func startCNIServer(logger *zap.Logger, cfg *config.Config, agentSrv *agentServer) *grpc.Server {
	cniListener, cniGRPC, err := startGRPCServer(logger, cfg.CNISocket, "CNI", func(s *grpc.Server) {
		pb.RegisterAgentControlServer(s, agentSrv)
	})
	if err != nil {
		logger.Fatal("failed to start CNI gRPC server", zap.Error(err))
	}
	go func() {
		logger.Info("CNI gRPC server listening", zap.String("socket", cfg.CNISocket))
		if err := cniGRPC.Serve(cniListener); err != nil {
			logger.Error("CNI gRPC server error", zap.Error(err))
		}
	}()
	return cniGRPC
}

// startAgentServer starts the agent gRPC server (for novanetctl) and returns the server handle.
func startAgentServer(logger *zap.Logger, cfg *config.Config, agentSrv *agentServer) *grpc.Server {
	agentListener, agentGRPC, err := startGRPCServer(logger, cfg.ListenSocket, "agent", func(s *grpc.Server) {
		pb.RegisterAgentControlServer(s, agentSrv)
	})
	if err != nil {
		logger.Fatal("failed to start agent gRPC server", zap.Error(err))
	}
	go func() {
		logger.Info("agent gRPC server listening", zap.String("socket", cfg.ListenSocket))
		if err := agentGRPC.Serve(agentListener); err != nil {
			logger.Error("agent gRPC server error", zap.Error(err))
		}
	}()
	return agentGRPC
}

// startMetricsServer starts the Prometheus metrics and health check HTTP server.
func startMetricsServer(logger *zap.Logger, cfg *config.Config, agentSrv *agentServer) *http.Server {
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !agentSrv.dpConnected.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, `{"status":"not ready","reason":"dataplane not connected","version":"%s"}`, Version)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok","version":"%s"}`, Version)
	})
	metricsServer := &http.Server{
		Addr:              cfg.MetricsAddress,
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		logger.Info("metrics server listening", zap.String("address", cfg.MetricsAddress))
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server error", zap.Error(err))
		}
	}()
	return metricsServer
}

// initRoutingMode performs mode-specific initialization (overlay tunnels or native BGP).
// Returns the NovaRoute client if native mode, nil otherwise.
func initRoutingMode(ctx context.Context, logger *zap.Logger, cfg *config.Config,
	k8sClient *kubernetes.Clientset, agentSrv *agentServer, dpClient pb.DataplaneControlClient,
	nodeIP net.IP, podCIDR, nodeName string, bgWg *sync.WaitGroup) *novaroute.Client {

	switch strings.ToLower(cfg.RoutingMode) {
	case "overlay":
		initOverlayMode(ctx, logger, cfg, k8sClient, agentSrv, dpClient, nodeIP, nodeName, bgWg)
	case "native":
		return initNativeMode(ctx, logger, cfg, k8sClient, agentSrv, dpClient, nodeIP, podCIDR, nodeName, bgWg)
	}
	return nil
}

// initOverlayMode sets up overlay tunnel mode (Geneve/VXLAN).
func initOverlayMode(ctx context.Context, logger *zap.Logger, cfg *config.Config,
	k8sClient *kubernetes.Clientset, agentSrv *agentServer, dpClient pb.DataplaneControlClient,
	nodeIP net.IP, nodeName string, bgWg *sync.WaitGroup) {

	logger.Info("running in overlay mode",
		zap.String("tunnel_protocol", cfg.TunnelProtocol))

	if k8sClient == nil {
		logger.Fatal("overlay mode requires NOVANET_NODE_NAME to be set for node discovery")
	}

	// Clean up stale tunnel interfaces and reload the kernel module.
	// This works around a kernel bug where the geneve module's internal
	// state gets corrupted after repeated interface create/delete cycles.
	if err := tunnel.PrepareOverlay(cfg.TunnelProtocol); err != nil {
		logger.Warn("failed to prepare overlay", zap.Error(err))
	}

	tunnelMgr := tunnel.NewManager(cfg.TunnelProtocol, nodeIP, 1, nil, logger)
	agentSrv.tunnelMgr = tunnelMgr
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		watchNodes(ctx, logger, k8sClient, tunnelMgr, dpClient, nodeName, nodeIP)
	}()
}

// initNativeMode sets up native routing mode with eBGP via NovaRoute.
func initNativeMode(ctx context.Context, logger *zap.Logger, cfg *config.Config,
	k8sClient *kubernetes.Clientset, agentSrv *agentServer, dpClient pb.DataplaneControlClient,
	nodeIP net.IP, podCIDR, nodeName string, bgWg *sync.WaitGroup) *novaroute.Client {

	logger.Info("running in native routing mode (eBGP)",
		zap.String("socket", cfg.NovaRoute.Socket))

	if k8sClient == nil {
		logger.Fatal("native mode requires NOVANET_NODE_NAME to be set for node discovery")
	}

	// Clean up stale overlay interfaces from previous mode.
	if err := tunnel.PrepareOverlay("geneve"); err != nil {
		logger.Debug("overlay cleanup (geneve)", zap.Error(err))
	}
	if err := tunnel.PrepareOverlay("vxlan"); err != nil {
		logger.Debug("overlay cleanup (vxlan)", zap.Error(err))
	}

	// Add a blackhole route for the local PodCIDR so the kernel RIB
	// has the prefix. FRR/BGP needs it in the RIB to advertise via
	// the "network" command. Individual /32 pod routes take precedence.
	if err := tunnel.AddBlackholeRoute(podCIDR); err != nil {
		logger.Warn("failed to add blackhole route for PodCIDR", zap.Error(err))
	} else {
		logger.Info("added blackhole route for local PodCIDR", zap.String("pod_cidr", podCIDR))
	}

	nrClient := novaroute.NewClient(cfg.NovaRoute.Socket, "novanet", cfg.NovaRoute.Token, logger)

	if err := nrClient.Connect(ctx); err != nil {
		logger.Fatal("failed to connect to NovaRoute", zap.Error(err))
	}

	resp, err := nrClient.Register(ctx)
	if err != nil {
		logger.Fatal("failed to register with NovaRoute", zap.Error(err))
	}
	logger.Info("registered with NovaRoute",
		zap.Strings("current_prefixes", resp.CurrentPrefixes))

	// Compute per-node eBGP AS: 65000 + last octet of node IP.
	lastOctet := uint32(nodeIP.To4()[3])
	localAS := uint32(65000) + lastOctet
	routerID := nodeIP.String()

	if err := nrClient.ConfigureBGP(ctx, localAS, routerID); err != nil {
		logger.Fatal("failed to configure BGP", zap.Error(err))
	}
	logger.Info("BGP configured",
		zap.Uint32("local_as", localAS),
		zap.String("router_id", routerID))

	// Advertise this node's PodCIDR.
	if err := nrClient.AdvertisePrefix(ctx, podCIDR); err != nil {
		logger.Fatal("failed to advertise PodCIDR", zap.Error(err))
	}
	logger.Info("advertised PodCIDR via BGP", zap.String("pod_cidr", podCIDR))
	agentSrv.novarouteConnected = true

	// Control-plane VIP: register as L4 LB service with health-checked backends.
	if vip := cfg.NovaRoute.ControlPlaneVIP; vip != "" && cfg.L4LB.Enabled {
		healthInterval := 5 * time.Second
		if cfg.NovaRoute.ControlPlaneVIPHealthInterval > 0 {
			healthInterval = time.Duration(cfg.NovaRoute.ControlPlaneVIPHealthInterval) * time.Second
		}

		cpvipMgr := cpvip.NewManager(cpvip.Config{
			VIP:            vip,
			HealthInterval: healthInterval,
			NodeName:       nodeName,
			IsControlPlane: isControlPlaneNode(ctx, k8sClient, nodeName, logger),
		}, dpClient, nrClient, k8sClient, logger)

		bgWg.Add(1)
		go func() {
			defer bgWg.Done()
			cpvipMgr.Run(ctx)
		}()
	}

	// Watch nodes and establish eBGP peering with each remote node.
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		var bfdOpts *novaroute.BFDOptions
		if cfg.NovaRoute.BFDEnabled {
			bfdOpts = &novaroute.BFDOptions{
				Enabled:          true,
				MinRxMs:          cfg.NovaRoute.BFDMinRxMs,
				MinTxMs:          cfg.NovaRoute.BFDMinTxMs,
				DetectMultiplier: cfg.NovaRoute.BFDDetectMultiplier,
			}
		}
		watchNodesNative(ctx, logger, k8sClient, nrClient, nodeName, bfdOpts)
	}()

	return nrClient
}

// isControlPlaneNode checks if the given node has the control-plane role label.
func isControlPlaneNode(ctx context.Context, k8sClient *kubernetes.Clientset, nodeName string, logger *zap.Logger) bool {
	node, err := k8sClient.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		logger.Error("failed to get node for cp-vip check", zap.String("node", nodeName), zap.Error(err))
		return false
	}
	_, ok := node.Labels["node-role.kubernetes.io/control-plane"]
	return ok
}

// waitForSignal blocks until a SIGTERM or SIGINT signal is received.
func waitForSignal(logger *zap.Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	sig := <-sigCh
	logger.Info("received signal, starting graceful shutdown", zap.String("signal", sig.String()))
}

// gracefulShutdown performs an orderly shutdown of all agent components.
func gracefulShutdown(s *shutdownState) {
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// Cancel root context to stop background operations.
	s.cancel()

	// Wait for background goroutines (node watchers) to finish.
	s.bgWg.Wait()
	s.logger.Info("background goroutines stopped")

	// If native mode, withdraw prefix and close NovaRoute connection.
	shutdownNovaRoute(shutdownCtx, s.logger, s.nrClient, s.podCIDR)

	// Stop gRPC servers.
	s.cniGRPC.GracefulStop()
	s.logger.Info("CNI gRPC server stopped")

	s.agentGRPC.GracefulStop()
	s.logger.Info("agent gRPC server stopped")

	// Stop metrics server.
	if err := s.metricsServer.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("metrics server shutdown error", zap.Error(err))
	}
	s.logger.Info("metrics server stopped")

	// Close dataplane connection.
	if s.dpConn != nil {
		_ = s.dpConn.Close()
		s.logger.Info("dataplane connection closed")
	}

	s.logger.Info("novanet-agent shutdown complete")
}

// shutdownNovaRoute withdraws the PodCIDR prefix and closes the NovaRoute connection.
// CP-VIP shutdown is handled by the cpvip.Manager via context cancellation.
func shutdownNovaRoute(ctx context.Context, logger *zap.Logger, nrClient *novaroute.Client, podCIDR string) {
	if nrClient == nil {
		return
	}

	logger.Info("withdrawing PodCIDR from NovaRoute", zap.String("pod_cidr", podCIDR))
	if err := nrClient.WithdrawPrefix(ctx, podCIDR); err != nil {
		logger.Error("failed to withdraw prefix", zap.Error(err))
	}
	if err := nrClient.Close(); err != nil {
		logger.Error("failed to close NovaRoute connection", zap.Error(err))
	}
	// Remove the blackhole route.
	if err := tunnel.RemoveBlackholeRoute(podCIDR); err != nil {
		logger.Debug("failed to remove blackhole route", zap.Error(err))
	}
	logger.Info("NovaRoute connection closed")
}

// buildLogger creates a production zap logger with JSON encoding and ISO8601
// timestamps at the given level.
func buildLogger(level string) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	switch strings.ToLower(level) {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.TimeKey = "ts"
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder

	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(zapLevel),
		Encoding:         "json",
		EncoderConfig:    encoderCfg,
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	return cfg.Build()
}

// connectToDataplane establishes a gRPC connection to the Rust dataplane,
// retrying every dataplaneRetryInterval until the context is cancelled or
// the connection succeeds.
func connectToDataplane(ctx context.Context, logger *zap.Logger, socketPath string) (*grpc.ClientConn, pb.DataplaneControlClient, bool) {
	logger.Info("connecting to dataplane", zap.String("socket", socketPath))

	for {
		select {
		case <-ctx.Done():
			logger.Warn("context cancelled before dataplane connection established")
			return nil, nil, false
		default:
		}

		conn, err := grpc.NewClient(
			"unix://"+socketPath,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			logger.Warn("failed to create dataplane client, retrying",
				zap.Error(err),
				zap.Duration("retry_in", dataplaneRetryInterval))
			select {
			case <-ctx.Done():
				return nil, nil, false
			case <-time.After(dataplaneRetryInterval):
				continue
			}
		}

		client := pb.NewDataplaneControlClient(conn)

		// Test connectivity with a status call.
		testCtx, testCancel := context.WithTimeout(ctx, 3*time.Second)
		_, err = client.GetDataplaneStatus(testCtx, &pb.GetDataplaneStatusRequest{})
		testCancel()

		if err != nil {
			logger.Warn("dataplane not ready, retrying",
				zap.Error(err),
				zap.Duration("retry_in", dataplaneRetryInterval))
			_ = conn.Close()
			select {
			case <-ctx.Done():
				return nil, nil, false
			case <-time.After(dataplaneRetryInterval):
				continue
			}
		}

		logger.Info("connected to dataplane")
		return conn, client, true
	}
}

// pushDataplaneConfig sends initial configuration to the dataplane via
// the UpdateConfig RPC.
func pushDataplaneConfig(ctx context.Context, logger *zap.Logger, client pb.DataplaneControlClient, cfg *config.Config, nodeIP net.IP, podCIDR string) error {
	entries := make(map[uint32]uint64)

	// Routing mode.
	switch strings.ToLower(cfg.RoutingMode) {
	case "overlay":
		entries[configKeyMode] = modeOverlay
	case "native":
		entries[configKeyMode] = modeNative
	}

	// Tunnel type.
	switch strings.ToLower(cfg.TunnelProtocol) {
	case "geneve":
		entries[configKeyTunnelType] = tunnelGEV
	case "vxlan":
		entries[configKeyTunnelType] = tunnelVXL
	}

	// Node IP.
	entries[configKeyNodeIP] = uint64(ipToUint32(nodeIP))

	// Cluster CIDR.
	clusterIP, clusterNet, err := net.ParseCIDR(cfg.ClusterCIDR)
	if err == nil {
		entries[configKeyClusterCIDRIP] = uint64(ipToUint32(clusterIP.To4()))
		ones, _ := clusterNet.Mask.Size()
		entries[configKeyClusterCIDRPL] = uint64(ones) //nolint:gosec // CIDR prefix 0-128
	}

	// Pod CIDR.
	podIP, podNet, err := net.ParseCIDR(podCIDR)
	if err == nil {
		entries[configKeyPodCIDRIP] = uint64(ipToUint32(podIP.To4()))
		ones, _ := podNet.Mask.Size()
		entries[configKeyPodCIDRPL] = uint64(ones) //nolint:gosec // CIDR prefix 0-128
	}

	// Default deny flag.
	if cfg.Policy.DefaultDeny {
		entries[configKeyDefaultDeny] = 1
	} else {
		entries[configKeyDefaultDeny] = 0
	}

	// Masquerade enabled.
	if cfg.Egress.MasqueradeEnabled {
		entries[configKeyMasqueradeEnable] = 1
	} else {
		entries[configKeyMasqueradeEnable] = 0
	}

	// L4 LB enabled.
	if cfg.L4LB.Enabled {
		entries[configKeyL4LBEnabled] = 1
	} else {
		entries[configKeyL4LBEnabled] = 0
	}

	req := &pb.UpdateConfigRequest{Entries: entries}
	_, err = client.UpdateConfig(ctx, req)
	if err != nil {
		return fmt.Errorf("UpdateConfig RPC failed: %w", err)
	}

	logger.Info("dataplane config pushed",
		zap.Int("entry_count", len(entries)),
	)
	return nil
}

// watchNodesNative periodically lists Kubernetes nodes and establishes
// eBGP peering via NovaRoute for each remote node.
func watchNodesNative(ctx context.Context, logger *zap.Logger, k8sClient *kubernetes.Clientset,
	nrClient *novaroute.Client, selfNode string, bfdOpts *novaroute.BFDOptions) {

	const pollInterval = 15 * time.Second

	logger.Info("native node watcher started", zap.String("self_node", selfNode))

	peered := make(map[string]bool) // track nodes we've already peered with

	for {
		nodes, err := k8sClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to list nodes", zap.Error(err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(pollInterval):
				continue
			}
		}

		for _, n := range nodes.Items {
			if n.Name == selfNode {
				continue
			}

			remoteIP := ""
			for _, addr := range n.Status.Addresses {
				if addr.Type == "InternalIP" {
					remoteIP = addr.Address
					break
				}
			}
			if remoteIP == "" {
				continue
			}

			if peered[n.Name] {
				continue
			}

			// Compute remote node's eBGP AS: 65000 + last octet.
			parsedIP := net.ParseIP(remoteIP)
			if parsedIP == nil {
				logger.Warn("invalid remote node IP, skipping",
					zap.String("node", n.Name),
					zap.String("remote_ip", remoteIP))
				continue
			}
			ip := parsedIP.To4()
			if ip == nil {
				continue // IPv6 node, skip eBGP peering.
			}
			remoteAS := uint32(65000) + uint32(ip[3])

			if err := nrClient.ApplyPeer(ctx, remoteIP, remoteAS, bfdOpts); err != nil {
				logger.Error("failed to apply BGP peer",
					zap.Error(err),
					zap.String("node", n.Name),
					zap.String("remote_ip", remoteIP),
					zap.Uint32("remote_as", remoteAS),
				)
				continue
			}

			peered[n.Name] = true
			logger.Info("eBGP peer established",
				zap.String("node", n.Name),
				zap.String("remote_ip", remoteIP),
				zap.Uint32("remote_as", remoteAS),
			)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

// startGRPCServer creates a Unix socket listener and gRPC server. It removes
// any stale socket file before binding.
func startGRPCServer(logger *zap.Logger, socketPath, name string, register func(*grpc.Server)) (net.Listener, *grpc.Server, error) {
	// Ensure parent directory exists.
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, nil, fmt.Errorf("creating directory %s: %w", dir, err)
	}

	// Remove stale socket.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		logger.Warn("failed to remove stale socket",
			zap.String("socket", socketPath), zap.Error(err))
	}

	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("listening on %s: %w", socketPath, err)
	}

	// Set socket permissions so the CNI binary and CLI can connect.
	if err := os.Chmod(socketPath, 0o600); err != nil {
		logger.Warn("failed to chmod socket", zap.String("socket", socketPath), zap.Error(err))
	}

	srv := grpc.NewServer()
	register(srv)

	logger.Info("gRPC server created", zap.String("name", name), zap.String("socket", socketPath))
	return lis, srv, nil
}

// watchNodes periodically lists Kubernetes nodes and creates/removes Geneve
// tunnels and host routes for remote nodes' PodCIDRs.
// nodeWatcherState holds the context needed for node watching operations.
type nodeWatcherState struct {
	ctx        context.Context
	logger     *zap.Logger
	tunnelMgr  *tunnel.Manager
	dpClient   pb.DataplaneControlClient
	selfNodeIP net.IP

	// tunnelProgramsAttached tracks whether TC programs have been attached
	// to the shared collect-metadata tunnel interface. With FlowBased tunnels,
	// all remote nodes share a single interface, so programs are attached once.
	tunnelProgramsAttached bool
}

func watchNodes(ctx context.Context, logger *zap.Logger, k8sClient *kubernetes.Clientset,
	tunnelMgr *tunnel.Manager, dpClient pb.DataplaneControlClient, selfNode string, selfNodeIP net.IP) {

	const pollInterval = 15 * time.Second
	nw := &nodeWatcherState{ctx: ctx, logger: logger, tunnelMgr: tunnelMgr, dpClient: dpClient, selfNodeIP: selfNodeIP}

	logger.Info("node watcher started", zap.String("self_node", selfNode))

	for {
		nodes, err := k8sClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			logger.Error("failed to list nodes", zap.Error(err))
			select {
			case <-ctx.Done():
				return
			case <-time.After(pollInterval):
				continue
			}
		}

		seen := nw.reconcileNodes(nodes, selfNode)
		nw.cleanupStaleTunnels(seen)

		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

// reconcileNodes processes the current node list, creating or updating tunnels
// for remote nodes. Returns the set of seen node names.
func (nw *nodeWatcherState) reconcileNodes(nodes *corev1.NodeList, selfNode string) map[string]bool {
	seen := make(map[string]bool)
	for _, node := range nodes.Items {
		if node.Name == selfNode || node.Spec.PodCIDR == "" {
			continue
		}

		nodeIP := nodeInternalIP(&node)
		if nodeIP == "" {
			continue
		}

		parsedNodeIP := net.ParseIP(nodeIP)
		if parsedNodeIP == nil {
			nw.logger.Warn("invalid node IP, skipping",
				zap.String("node", node.Name), zap.String("node_ip", nodeIP))
			continue
		}

		seen[node.Name] = true
		nw.ensureTunnel(node.Name, nodeIP, node.Spec.PodCIDR, parsedNodeIP)
	}
	return seen
}

// ensureTunnel ensures a tunnel exists to a remote node, creating it if necessary.
func (nw *nodeWatcherState) ensureTunnel(nodeName, nodeIP, podCIDR string, parsedNodeIP net.IP) {
	// If tunnel already exists, just reconcile the route.
	if tunnelInfo, exists := nw.tunnelMgr.GetTunnel(nodeName); exists {
		if err := tunnel.AddRoute(podCIDR, tunnelInfo.InterfaceName, nw.selfNodeIP, parsedNodeIP, nw.tunnelMgr.Protocol()); err != nil {
			nw.logger.Warn("failed to reconcile route", zap.Error(err), zap.String("node", nodeName))
		}
		return
	}

	// Create tunnel.
	if err := nw.tunnelMgr.AddTunnel(nw.ctx, nodeName, nodeIP, podCIDR); err != nil {
		nw.logger.Error("failed to create tunnel", zap.Error(err),
			zap.String("node", nodeName), zap.String("node_ip", nodeIP))
		return
	}

	tunnelInfo, ok := nw.tunnelMgr.GetTunnel(nodeName)
	if !ok {
		return
	}

	// Register with dataplane.
	if nw.dpClient != nil {
		_, err := nw.dpClient.UpsertTunnel(nw.ctx, &pb.UpsertTunnelRequest{
			NodeIp:        ipToUint32(parsedNodeIP),
			TunnelIfindex: uint32(tunnelInfo.Ifindex), //nolint:gosec // ifindex from kernel
			Vni:           1,
		})
		if err != nil {
			nw.logger.Error("failed to register tunnel with dataplane", zap.Error(err), zap.String("node", nodeName))
		}

		// Attach TC programs to the shared tunnel interface (once only).
		if !nw.tunnelProgramsAttached {
			if _, err := nw.dpClient.AttachProgram(nw.ctx, &pb.AttachProgramRequest{
				InterfaceName: tunnelInfo.InterfaceName,
				AttachType:    pb.AttachType_ATTACH_TC_INGRESS,
			}); err != nil {
				nw.logger.Warn("failed to attach TC ingress to tunnel", zap.String("iface", tunnelInfo.InterfaceName), zap.Error(err))
			}
			if _, err := nw.dpClient.AttachProgram(nw.ctx, &pb.AttachProgramRequest{
				InterfaceName: tunnelInfo.InterfaceName,
				AttachType:    pb.AttachType_ATTACH_TC_EGRESS,
			}); err != nil {
				nw.logger.Warn("failed to attach TC egress to tunnel", zap.String("iface", tunnelInfo.InterfaceName), zap.Error(err))
			}
			nw.tunnelProgramsAttached = true
		}
	}

	// Add kernel route.
	if err := tunnel.AddRoute(podCIDR, tunnelInfo.InterfaceName, nw.selfNodeIP, parsedNodeIP, nw.tunnelMgr.Protocol()); err != nil {
		nw.logger.Error("failed to add route for remote PodCIDR", zap.Error(err),
			zap.String("cidr", podCIDR), zap.String("interface", tunnelInfo.InterfaceName))
	} else {
		nw.logger.Info("tunnel and route created",
			zap.String("node", nodeName), zap.String("node_ip", nodeIP),
			zap.String("pod_cidr", podCIDR), zap.String("interface", tunnelInfo.InterfaceName),
			zap.Int("ifindex", tunnelInfo.Ifindex))
	}

	metricTunnels.Set(float64(nw.tunnelMgr.Count()))
}

// cleanupStaleTunnels removes tunnels for nodes that are no longer in the cluster.
func (nw *nodeWatcherState) cleanupStaleTunnels(seen map[string]bool) {
	for _, t := range nw.tunnelMgr.ListTunnels() {
		if seen[t.NodeName] {
			continue
		}

		// Remove route first.
		if t.PodCIDR != "" {
			if err := tunnel.RemoveRoute(t.PodCIDR); err != nil {
				nw.logger.Warn("failed to remove route for departed node",
					zap.Error(err), zap.String("node", t.NodeName), zap.String("cidr", t.PodCIDR))
			}
		}

		// Remove dataplane entry.
		if nw.dpClient != nil && net.ParseIP(t.NodeIP) != nil {
			if _, err := nw.dpClient.DeleteTunnel(nw.ctx, &pb.DeleteTunnelRequest{
				NodeIp: ipToUint32(net.ParseIP(t.NodeIP)),
			}); err != nil {
				nw.logger.Warn("failed to delete tunnel from dataplane",
					zap.Error(err), zap.String("node", t.NodeName))
			}
		}

		if err := nw.tunnelMgr.RemoveTunnel(nw.ctx, t.NodeName); err != nil {
			nw.logger.Error("failed to remove tunnel for departed node",
				zap.Error(err), zap.String("node", t.NodeName))
		} else {
			nw.logger.Info("tunnel removed for departed node", zap.String("node", t.NodeName))
		}

		metricTunnels.Set(float64(nw.tunnelMgr.Count()))
	}
}

// nodeInternalIP returns the InternalIP address of a Kubernetes node, or empty string if not found.
func nodeInternalIP(node *corev1.Node) string {
	for _, addr := range node.Status.Addresses {
		if addr.Type == "InternalIP" {
			return addr.Address
		}
	}
	return ""
}

// consumeFlows subscribes to the dataplane flow event stream and updates
// Prometheus metrics from flow events. For TCP flows, it estimates round-trip
// latency by tracking request/response pairs (matching reversed 4-tuples).
const (
	flowRetryInterval = 5 * time.Second
	protoTCP          = 6
	maxTrackedTuples  = 10000 // cap tracked tuples to prevent memory growth

	// TCP flag bits.
	tcpFIN uint32 = 0x01
	tcpSYN uint32 = 0x02
	tcpRST uint32 = 0x04
	tcpACK uint32 = 0x10
)

// flowTuple identifies a TCP connection direction.
type flowTuple struct {
	srcIP, dstIP     uint32
	srcPort, dstPort uint32
}

func consumeFlows(ctx context.Context, logger *zap.Logger, client pb.DataplaneControlClient) {
	for {
		stream, err := client.StreamFlows(ctx, &pb.StreamFlowsRequest{})
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Debug("flow consumer: failed to open stream, retrying",
				zap.Error(err), zap.Duration("retry_in", flowRetryInterval))
			select {
			case <-ctx.Done():
				return
			case <-time.After(flowRetryInterval):
				continue
			}
		}

		logger.Info("flow consumer: connected, streaming metrics")
		if processFlowStream(ctx, logger, stream) {
			return
		}
	}
}

// processFlowStream processes flow events from a stream. Returns true if the
// context was cancelled (caller should exit), false if the stream errored
// (caller should reconnect).
func processFlowStream(ctx context.Context, logger *zap.Logger, stream grpc.ServerStreamingClient[pb.FlowEvent]) bool {
	pending := make(map[flowTuple]time.Time)

	for {
		flow, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return true
			}
			logger.Debug("flow consumer: stream error, reconnecting", zap.Error(err))
			return false
		}

		updateFlowMetrics(flow)

		if flow.Protocol == protoTCP {
			updateTCPMetrics(flow, pending)
		}
	}
}

// updateFlowMetrics updates general flow Prometheus counters from a flow event.
func updateFlowMetrics(flow *pb.FlowEvent) {
	verdict := "allow"
	if flow.Verdict == pb.PolicyAction_POLICY_ACTION_DENY {
		verdict = "deny"
	}
	agentmetrics.FlowTotal.WithLabelValues(
		fmt.Sprintf("%d", flow.SrcIdentity),
		fmt.Sprintf("%d", flow.DstIdentity),
		verdict,
	).Add(float64(flow.Packets))

	if flow.DropReason != pb.DropReason_DROP_REASON_NONE {
		agentmetrics.DropsTotal.WithLabelValues(flow.DropReason.String()).Add(float64(flow.Packets))
	}

	agentmetrics.PolicyVerdictTotal.WithLabelValues(verdict).Add(float64(flow.Packets))
}

// updateTCPMetrics updates TCP connection state counters and SYN-ACK latency.
func updateTCPMetrics(flow *pb.FlowEvent, pending map[flowTuple]time.Time) {
	flags := flow.TcpFlags
	if flags&tcpSYN != 0 && flags&tcpACK == 0 {
		agentmetrics.TCPConnectionTotal.WithLabelValues("syn").Inc()
	}
	if flags&tcpFIN != 0 {
		agentmetrics.TCPConnectionTotal.WithLabelValues("fin").Inc()
	}
	if flags&tcpRST != 0 {
		agentmetrics.TCPConnectionTotal.WithLabelValues("rst").Inc()
	}

	now := time.Now()
	fwd := flowTuple{flow.SrcIp, flow.DstIp, flow.SrcPort, flow.DstPort}
	rev := flowTuple{flow.DstIp, flow.SrcIp, flow.DstPort, flow.SrcPort}

	if flags&tcpSYN != 0 && flags&tcpACK == 0 {
		if len(pending) < maxTrackedTuples {
			pending[fwd] = now
		}
	} else if flags&tcpSYN != 0 && flags&tcpACK != 0 {
		if synTime, ok := pending[rev]; ok {
			rtt := now.Sub(synTime)
			if rtt > 0 && rtt < 10*time.Second {
				agentmetrics.TCPLatencySeconds.Observe(rtt.Seconds())
			}
			delete(pending, rev)
		}
	}

	// Evict stale entries older than 10 seconds.
	if len(pending) > maxTrackedTuples/2 {
		cutoff := now.Add(-10 * time.Second)
		for k, t := range pending {
			if t.Before(cutoff) {
				delete(pending, k)
			}
		}
	}
}

// ipToUint32 delegates to tunnel.IPToUint32 for IPv4→uint32 conversion.
func ipToUint32(ip net.IP) uint32 {
	return tunnel.IPToUint32(ip)
}

// generateMAC creates a deterministic locally-administered MAC address from
// an IPv4 address. The first byte has the locally-administered bit set.
func generateMAC(ip net.IP) net.HardwareAddr {
	ip4 := ip.To4()
	if ip4 == nil {
		return net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}
	}
	return net.HardwareAddr{
		0x02, // locally administered, unicast
		0xfe,
		ip4[0],
		ip4[1],
		ip4[2],
		ip4[3],
	}
}
