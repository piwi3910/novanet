// Package main implements the NovaNet agent daemon. It is the management
// plane component that bridges the CNI binary, the Rust eBPF dataplane,
// and (optionally) the NovaRoute routing control plane.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	pb "github.com/piwi3910/novanet/api/v1"
	cnisetup "github.com/piwi3910/novanet/internal/cni"
	"github.com/piwi3910/novanet/internal/config"
	"github.com/piwi3910/novanet/internal/identity"
	"github.com/piwi3910/novanet/internal/ipam"
	"github.com/piwi3910/novanet/internal/masquerade"
	"github.com/piwi3910/novanet/internal/novaroute"
	"github.com/piwi3910/novanet/internal/tunnel"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	grpcstatus "google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	// Version is the build version of novanet-agent. Overridden at build time.
	Version = "0.1.0"

	// shutdownTimeout is the maximum time to wait for graceful shutdown.
	shutdownTimeout = 10 * time.Second

	// dataplaneRetryInterval is the interval between dataplane connection attempts.
	dataplaneRetryInterval = 5 * time.Second

	// Config map key constants for dataplane UpdateConfig.
	configKeyMode          uint32 = 1
	configKeyTunnelType    uint32 = 2
	configKeyNodeIP        uint32 = 3
	configKeyClusterCIDRIP uint32 = 4
	configKeyClusterCIDRPL uint32 = 5
	configKeyPodCIDRIP     uint32 = 6
	configKeyPodCIDRPL     uint32 = 7

	// Config value constants.
	modeOverlay uint64 = 1
	modeNative  uint64 = 2
	tunnelGEV   uint64 = 1
	tunnelVXL   uint64 = 2
)

// Prometheus metrics.
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
)

func init() {
	prometheus.MustRegister(
		metricEndpoints,
		metricPolicies,
		metricTunnels,
		metricIdentities,
		metricCNIAddLatency,
		metricCNIDelLatency,
	)
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

	logger     *zap.Logger
	cfg        *config.Config
	ipAlloc    *ipam.Allocator
	idAlloc    *identity.Allocator
	dpClient   pb.DataplaneControlClient
	nodeIP     net.IP
	podCIDR    string
	dpConnected bool

	mu        sync.RWMutex
	endpoints map[string]*endpoint // key: namespace/name
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

	// Allocate an identity from the pod labels.
	labels := req.Labels
	if labels == nil {
		labels = map[string]string{}
	}
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
		s.ipAlloc.Release(podIP)
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
		IfIndex:      uint32(ifindex),
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
	if s.dpClient != nil && s.dpConnected {
		dpReq := &pb.UpsertEndpointRequest{
			Ip:         ipToUint32(podIP),
			Ifindex:    uint32(ifindex),
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

	return &pb.AddPodResponse{
		Ip:           podIP.String(),
		Gateway:      gateway.String(),
		Mac:          mac.String(),
		PrefixLength: int32(prefixLen),
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
	if s.dpClient != nil && s.dpConnected {
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
	epCount := uint32(len(s.endpoints))
	s.mu.RUnlock()

	resp := &pb.GetAgentStatusResponse{
		RoutingMode:    s.cfg.RoutingMode,
		TunnelProtocol: s.cfg.TunnelProtocol,
		EndpointCount:  epCount,
		IdentityCount:  uint32(s.idAlloc.Count()),
		NodeIp:         s.nodeIP.String(),
		PodCidr:        s.podCIDR,
		ClusterCidr:    s.cfg.ClusterCIDR,
		Dataplane: &pb.DataplaneStatusInfo{
			Connected: s.dpConnected,
		},
	}

	// Fetch live dataplane metrics if connected.
	if s.dpClient != nil && s.dpConnected {
		dpStatus, err := s.dpClient.GetDataplaneStatus(ctx, &pb.GetDataplaneStatusRequest{})
		if err == nil {
			resp.PolicyCount = dpStatus.PolicyCount
			resp.TunnelCount = dpStatus.TunnelCount
			resp.Dataplane.AttachedPrograms = uint32(len(dpStatus.Programs))
		}
	}

	return resp, nil
}

// StreamAgentFlows proxies flow events from the dataplane to clients.
func (s *agentServer) StreamAgentFlows(req *pb.StreamAgentFlowsRequest, stream grpc.ServerStreamingServer[pb.FlowEvent]) error {
	if s.dpClient == nil || !s.dpConnected {
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

func main() {
	// Parse flags.
	configPath := flag.String("config", "/etc/novanet/config.json", "Path to configuration file")
	podCIDR := flag.String("pod-cidr", "", "Node's PodCIDR (e.g., 10.244.1.0/24)")
	nodeIPStr := flag.String("node-ip", "", "Node IP address")
	printVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *printVersion {
		fmt.Fprintf(os.Stdout, "novanet-agent %s\n", Version)
		os.Exit(0)
	}

	// ---- Load configuration ----
	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		// If config file doesn't exist, use defaults.
		if os.IsNotExist(err) {
			cfg = config.DefaultConfig()
		} else {
			fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
			os.Exit(1)
		}
	}
	config.ExpandEnvVars(cfg)

	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// ---- Build logger ----
	logger, err := buildLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("novanet-agent starting",
		zap.String("version", Version),
		zap.String("config", *configPath),
		zap.String("routing_mode", cfg.RoutingMode),
		zap.String("tunnel_protocol", cfg.TunnelProtocol),
	)

	// ---- Create Kubernetes client ----
	nodeName := os.Getenv("NOVANET_NODE_NAME")
	var k8sClient *kubernetes.Clientset
	if nodeName != "" {
		k8sCfg, err := rest.InClusterConfig()
		if err != nil {
			logger.Fatal("failed to create in-cluster config", zap.Error(err))
		}
		k8sClient, err = kubernetes.NewForConfig(k8sCfg)
		if err != nil {
			logger.Fatal("failed to create kubernetes client", zap.Error(err))
		}
	}

	// ---- Resolve node-ip and pod-cidr ----
	// Auto-detect from Kubernetes node spec when not provided via flags.
	if (*podCIDR == "" || *nodeIPStr == "") && k8sClient != nil {
		logger.Info("auto-detecting node-ip/pod-cidr from Kubernetes API",
			zap.String("node_name", nodeName),
		)
		node, err := k8sClient.CoreV1().Nodes().Get(context.Background(), nodeName, metav1.GetOptions{})
		if err != nil {
			logger.Fatal("failed to get node for auto-detection", zap.Error(err), zap.String("node", nodeName))
		}
		if *podCIDR == "" && node.Spec.PodCIDR != "" {
			*podCIDR = node.Spec.PodCIDR
			logger.Info("auto-detected pod-cidr", zap.String("pod_cidr", *podCIDR))
		}
		if *nodeIPStr == "" {
			for _, addr := range node.Status.Addresses {
				if addr.Type == "InternalIP" {
					*nodeIPStr = addr.Address
					logger.Info("auto-detected node-ip", zap.String("node_ip", *nodeIPStr))
					break
				}
			}
		}
	}

	if *podCIDR == "" {
		logger.Fatal("--pod-cidr is required (or set NOVANET_NODE_NAME for auto-detection)")
	}
	if *nodeIPStr == "" {
		logger.Fatal("--node-ip is required (or set NOVANET_NODE_NAME for auto-detection)")
	}

	nodeIP := net.ParseIP(*nodeIPStr)
	if nodeIP == nil {
		logger.Fatal("invalid --node-ip", zap.String("value", *nodeIPStr))
	}
	nodeIP = nodeIP.To4()
	if nodeIP == nil {
		logger.Fatal("--node-ip must be an IPv4 address", zap.String("value", *nodeIPStr))
	}

	// ---- Create root context ----
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ---- Create IPAM allocator ----
	ipAlloc, err := ipam.NewAllocatorWithStateDir(*podCIDR, "/var/lib/cni/networks/novanet")
	if err != nil {
		logger.Fatal("failed to create IPAM allocator", zap.Error(err))
	}
	logger.Info("IPAM allocator created",
		zap.String("pod_cidr", *podCIDR),
		zap.Int("available", ipAlloc.Available()),
	)

	// ---- Setup NAT masquerade ----
	if cfg.ClusterCIDR != "" {
		if err := masquerade.EnsureMasquerade(*podCIDR, cfg.ClusterCIDR); err != nil {
			logger.Error("failed to setup NAT masquerade", zap.Error(err))
		} else {
			logger.Info("NAT masquerade configured",
				zap.String("pod_cidr", *podCIDR),
				zap.String("cluster_cidr", cfg.ClusterCIDR),
			)
		}
	}

	// ---- Create identity allocator ----
	idAlloc := identity.NewAllocator(logger)
	logger.Info("identity allocator created")

	// ---- Connect to dataplane ----
	dpConn, dpClient, dpConnected := connectToDataplane(ctx, logger, cfg.DataplaneSocket)

	// Send initial configuration to dataplane.
	if dpConnected {
		if err := pushDataplaneConfig(ctx, logger, dpClient, cfg, nodeIP, *podCIDR); err != nil {
			logger.Error("failed to push initial config to dataplane", zap.Error(err))
		}
	}

	// ---- Create agent gRPC server ----
	agentSrv := &agentServer{
		logger:      logger,
		cfg:         cfg,
		ipAlloc:     ipAlloc,
		idAlloc:     idAlloc,
		dpClient:    dpClient,
		nodeIP:      nodeIP,
		podCIDR:     *podCIDR,
		dpConnected: dpConnected,
		endpoints:   make(map[string]*endpoint),
	}

	// ---- Start CNI gRPC server ----
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

	// ---- Start agent gRPC server (for novanetctl) ----
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

	// ---- Start Prometheus metrics server ----
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","version":"%s"}`, Version)
	})
	metricsServer := &http.Server{
		Addr:              cfg.MetricsAddress,
		Handler:           metricsMux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		logger.Info("metrics server listening", zap.String("address", cfg.MetricsAddress))
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server error", zap.Error(err))
		}
	}()

	// ---- Mode-specific initialization ----
	var nrClient *novaroute.Client

	switch strings.ToLower(cfg.RoutingMode) {
	case "overlay":
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
		go watchNodes(ctx, logger, k8sClient, tunnelMgr, dpClient, nodeName, nodeIP)

	case "native":
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
		if err := tunnel.AddBlackholeRoute(*podCIDR); err != nil {
			logger.Warn("failed to add blackhole route for PodCIDR", zap.Error(err))
		} else {
			logger.Info("added blackhole route for local PodCIDR", zap.String("pod_cidr", *podCIDR))
		}

		nrClient = novaroute.NewClient(cfg.NovaRoute.Socket, "novanet", cfg.NovaRoute.Token, logger)

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

		// Establish eBGP sessions with TOR/spine switches.
		for _, tor := range cfg.NovaRoute.TORPeers {
			if err := nrClient.ApplyPeer(ctx, tor.Address, tor.AS); err != nil {
				logger.Error("failed to apply TOR peer",
					zap.Error(err),
					zap.String("address", tor.Address),
					zap.Uint32("as", tor.AS),
				)
			} else {
				logger.Info("TOR eBGP peer configured",
					zap.String("address", tor.Address),
					zap.Uint32("as", tor.AS),
				)
			}
		}

		// Advertise this node's PodCIDR.
		if err := nrClient.AdvertisePrefix(ctx, *podCIDR); err != nil {
			logger.Fatal("failed to advertise PodCIDR", zap.Error(err))
		}
		logger.Info("advertised PodCIDR via BGP", zap.String("pod_cidr", *podCIDR))

		// Watch nodes and establish eBGP peering with each remote node.
		go watchNodesNative(ctx, logger, k8sClient, nrClient, nodeName)
	}

	// ---- Wait for termination signal ----
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	sig := <-sigCh
	logger.Info("received signal, starting graceful shutdown", zap.String("signal", sig.String()))

	// ---- Graceful shutdown ----
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// Cancel root context to stop background operations.
	cancel()

	// If native mode, withdraw prefix and close NovaRoute connection.
	if nrClient != nil {
		logger.Info("withdrawing PodCIDR from NovaRoute", zap.String("pod_cidr", *podCIDR))
		if err := nrClient.WithdrawPrefix(shutdownCtx, *podCIDR); err != nil {
			logger.Error("failed to withdraw prefix", zap.Error(err))
		}
		if err := nrClient.Close(); err != nil {
			logger.Error("failed to close NovaRoute connection", zap.Error(err))
		}
		// Remove the blackhole route.
		if err := tunnel.RemoveBlackholeRoute(*podCIDR); err != nil {
			logger.Debug("failed to remove blackhole route", zap.Error(err))
		}
		logger.Info("NovaRoute connection closed")
	}

	// Stop gRPC servers.
	cniGRPC.GracefulStop()
	logger.Info("CNI gRPC server stopped")

	agentGRPC.GracefulStop()
	logger.Info("agent gRPC server stopped")

	// Stop metrics server.
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("metrics server shutdown error", zap.Error(err))
	}
	logger.Info("metrics server stopped")

	// Close dataplane connection.
	if dpConn != nil {
		dpConn.Close()
		logger.Info("dataplane connection closed")
	}

	logger.Info("novanet-agent shutdown complete")
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
			conn.Close()
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
		entries[configKeyClusterCIDRPL] = uint64(ones)
	}

	// Pod CIDR.
	podIP, podNet, err := net.ParseCIDR(podCIDR)
	if err == nil {
		entries[configKeyPodCIDRIP] = uint64(ipToUint32(podIP.To4()))
		ones, _ := podNet.Mask.Size()
		entries[configKeyPodCIDRPL] = uint64(ones)
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
	nrClient *novaroute.Client, selfNode string) {

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
			ip := net.ParseIP(remoteIP).To4()
			if ip == nil {
				continue
			}
			remoteAS := uint32(65000) + uint32(ip[3])

			if err := nrClient.ApplyPeer(ctx, remoteIP, remoteAS); err != nil {
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
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, nil, fmt.Errorf("creating directory %s: %w", dir, err)
	}

	// Remove stale socket.
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		logger.Warn("failed to remove stale socket",
			zap.String("socket", socketPath), zap.Error(err))
	}

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("listening on %s: %w", socketPath, err)
	}

	// Set socket permissions so the CNI binary and CLI can connect.
	if err := os.Chmod(socketPath, 0o660); err != nil {
		logger.Warn("failed to chmod socket", zap.String("socket", socketPath), zap.Error(err))
	}

	srv := grpc.NewServer()
	register(srv)

	logger.Info("gRPC server created", zap.String("name", name), zap.String("socket", socketPath))
	return lis, srv, nil
}

// watchNodes periodically lists Kubernetes nodes and creates/removes Geneve
// tunnels and host routes for remote nodes' PodCIDRs.
func watchNodes(ctx context.Context, logger *zap.Logger, k8sClient *kubernetes.Clientset,
	tunnelMgr *tunnel.Manager, dpClient pb.DataplaneControlClient, selfNode string, selfNodeIP net.IP) {

	const pollInterval = 15 * time.Second

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

		seen := make(map[string]bool)
		for _, node := range nodes.Items {
			if node.Name == selfNode {
				continue
			}
			if node.Spec.PodCIDR == "" {
				continue
			}

			nodeIP := ""
			for _, addr := range node.Status.Addresses {
				if addr.Type == "InternalIP" {
					nodeIP = addr.Address
					break
				}
			}
			if nodeIP == "" {
				continue
			}

			seen[node.Name] = true

			// If tunnel already exists, reconcile route/neighbor entries
			// (they may have been lost due to ARP resolution overwriting
			// permanent entries on kernels without NOARP support).
			if tunnelInfo, exists := tunnelMgr.GetTunnel(node.Name); exists {
				if err := tunnel.AddRoute(node.Spec.PodCIDR, tunnelInfo.InterfaceName, selfNodeIP, net.ParseIP(tunnelInfo.NodeIP), tunnelMgr.Protocol()); err != nil {
					logger.Debug("failed to reconcile route",
						zap.Error(err),
						zap.String("node", node.Name),
					)
				}
				continue
			}

			// Create tunnel to remote node.
			if err := tunnelMgr.AddTunnel(node.Name, nodeIP, node.Spec.PodCIDR); err != nil {
				logger.Error("failed to create tunnel",
					zap.Error(err),
					zap.String("node", node.Name),
					zap.String("node_ip", nodeIP),
				)
				continue
			}

			tunnelInfo, ok := tunnelMgr.GetTunnel(node.Name)
			if !ok {
				continue
			}

			// Register tunnel with dataplane.
			if dpClient != nil {
				remoteIPUint := ipToUint32(net.ParseIP(nodeIP))
				_, err := dpClient.UpsertTunnel(ctx, &pb.UpsertTunnelRequest{
					NodeIp:        remoteIPUint,
					TunnelIfindex: uint32(tunnelInfo.Ifindex),
					Vni:           1,
				})
				if err != nil {
					logger.Error("failed to register tunnel with dataplane",
						zap.Error(err),
						zap.String("node", node.Name),
					)
				}
			}

			// Add kernel route for the remote node's PodCIDR via the tunnel.
			if err := tunnel.AddRoute(node.Spec.PodCIDR, tunnelInfo.InterfaceName, selfNodeIP, net.ParseIP(nodeIP), tunnelMgr.Protocol()); err != nil {
				logger.Error("failed to add route for remote PodCIDR",
					zap.Error(err),
					zap.String("cidr", node.Spec.PodCIDR),
					zap.String("interface", tunnelInfo.InterfaceName),
				)
			} else {
				logger.Info("tunnel and route created",
					zap.String("node", node.Name),
					zap.String("node_ip", nodeIP),
					zap.String("pod_cidr", node.Spec.PodCIDR),
					zap.String("interface", tunnelInfo.InterfaceName),
					zap.Int("ifindex", tunnelInfo.Ifindex),
				)
			}

			metricTunnels.Set(float64(tunnelMgr.Count()))
		}

		// Remove tunnels for nodes that no longer exist.
		for _, t := range tunnelMgr.ListTunnels() {
			if !seen[t.NodeName] {
				// Remove route first.
				if t.PodCIDR != "" {
					if err := tunnel.RemoveRoute(t.PodCIDR); err != nil {
						logger.Warn("failed to remove route for departed node",
							zap.Error(err),
							zap.String("node", t.NodeName),
							zap.String("cidr", t.PodCIDR),
						)
					}
				}

				// Remove tunnel and dataplane entry.
				if dpClient != nil {
					remoteIPUint := ipToUint32(net.ParseIP(t.NodeIP))
					_, _ = dpClient.DeleteTunnel(ctx, &pb.DeleteTunnelRequest{
						NodeIp: remoteIPUint,
					})
				}

				if err := tunnelMgr.RemoveTunnel(t.NodeName); err != nil {
					logger.Error("failed to remove tunnel for departed node",
						zap.Error(err),
						zap.String("node", t.NodeName),
					)
				} else {
					logger.Info("tunnel removed for departed node",
						zap.String("node", t.NodeName),
					)
				}

				metricTunnels.Set(float64(tunnelMgr.Count()))
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

// ipToUint32 converts a 4-byte IPv4 address to a uint32 in network byte order.
func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
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
