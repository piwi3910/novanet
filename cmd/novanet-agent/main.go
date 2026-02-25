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
	"github.com/piwi3910/novanet/internal/config"
	"github.com/piwi3910/novanet/internal/identity"
	"github.com/piwi3910/novanet/internal/ipam"

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

	ep := &endpoint{
		PodName:      req.PodName,
		PodNamespace: req.PodNamespace,
		ContainerID:  req.ContainerId,
		IP:           podIP,
		MAC:          mac,
		IdentityID:   identityID,
		Netns:        req.Netns,
		IfName:       req.IfName,
	}

	s.mu.Lock()
	s.endpoints[key] = ep
	count := len(s.endpoints)
	s.mu.Unlock()

	metricEndpoints.Set(float64(count))
	metricIdentities.Set(float64(s.idAlloc.Count()))

	// Push endpoint to dataplane.
	if s.dpClient != nil && s.dpConnected {
		dpReq := &pb.UpsertEndpointRequest{
			Ip:         ipToUint32(podIP),
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
	}

	gateway := s.ipAlloc.Gateway()
	prefixLen := s.ipAlloc.PrefixLength()

	s.logger.Info("AddPod completed",
		zap.String("pod", key),
		zap.String("ip", podIP.String()),
		zap.String("gateway", gateway.String()),
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
	if exists {
		delete(s.endpoints, key)
	}
	count := len(s.endpoints)
	s.mu.Unlock()

	if !exists {
		s.logger.Warn("DelPod: endpoint not found, treating as success", zap.String("pod", key))
		return &pb.DelPodResponse{}, nil
	}

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

	// ---- Resolve node-ip and pod-cidr ----
	// Auto-detect from Kubernetes node spec when not provided via flags.
	nodeName := os.Getenv("NOVANET_NODE_NAME")
	if (*podCIDR == "" || *nodeIPStr == "") && nodeName != "" {
		logger.Info("auto-detecting node-ip/pod-cidr from Kubernetes API",
			zap.String("node_name", nodeName),
		)
		k8sCfg, err := rest.InClusterConfig()
		if err != nil {
			logger.Fatal("failed to create in-cluster config for auto-detection", zap.Error(err))
		}
		k8sClient, err := kubernetes.NewForConfig(k8sCfg)
		if err != nil {
			logger.Fatal("failed to create kubernetes client", zap.Error(err))
		}
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
	ipAlloc, err := ipam.NewAllocator(*podCIDR)
	if err != nil {
		logger.Fatal("failed to create IPAM allocator", zap.Error(err))
	}
	logger.Info("IPAM allocator created",
		zap.String("pod_cidr", *podCIDR),
		zap.Int("available", ipAlloc.Available()),
	)

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
	var novarouteConn *grpc.ClientConn

	switch strings.ToLower(cfg.RoutingMode) {
	case "overlay":
		logger.Info("running in overlay mode",
			zap.String("tunnel_protocol", cfg.TunnelProtocol))
		// In production, tunnel manager would watch node registry and
		// create/remove tunnels via the dataplane. For now, log readiness.
		logger.Info("tunnel manager initialized (waiting for node events)")

	case "native":
		logger.Info("running in native routing mode, connecting to NovaRoute",
			zap.String("socket", cfg.NovaRoute.Socket))
		novarouteConn, err = connectToNovaRoute(ctx, logger, cfg)
		if err != nil {
			logger.Error("failed to connect to NovaRoute", zap.Error(err))
		} else {
			agentSrv.mu.Lock()
			agentSrv.mu.Unlock()
			logger.Info("connected to NovaRoute, advertising PodCIDR",
				zap.String("pod_cidr", *podCIDR))
			// In production, we would call AdvertisePrefix here.
		}
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

	// If native mode, withdraw prefix from NovaRoute.
	if strings.ToLower(cfg.RoutingMode) == "native" && novarouteConn != nil {
		logger.Info("withdrawing PodCIDR from NovaRoute", zap.String("pod_cidr", *podCIDR))
		// In production: call WithdrawPrefix RPC.
		novarouteConn.Close()
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

// connectToNovaRoute establishes a gRPC connection to the NovaRoute daemon.
func connectToNovaRoute(ctx context.Context, logger *zap.Logger, cfg *config.Config) (*grpc.ClientConn, error) {
	conn, err := grpc.NewClient(
		"unix://"+cfg.NovaRoute.Socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to NovaRoute at %s: %w", cfg.NovaRoute.Socket, err)
	}

	logger.Info("NovaRoute gRPC connection established",
		zap.String("socket", cfg.NovaRoute.Socket),
	)
	_ = ctx // available for future use with registration RPCs
	return conn, nil
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
