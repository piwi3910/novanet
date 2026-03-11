package agent

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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
	"syscall"
	"time"

	pb "github.com/azrtydxb/novanet/api/v1"
	"github.com/azrtydxb/novanet/internal/agent/cpvip"
	"github.com/azrtydxb/novanet/internal/agentmetrics"
	"github.com/azrtydxb/novanet/internal/config"
	"github.com/azrtydxb/novanet/internal/dataplane"
	"github.com/azrtydxb/novanet/internal/ebpfservices"
	"github.com/azrtydxb/novanet/internal/egress"
	"github.com/azrtydxb/novanet/internal/grpcauth"
	"github.com/azrtydxb/novanet/internal/identity"
	"github.com/azrtydxb/novanet/internal/ipam"
	"github.com/azrtydxb/novanet/internal/masquerade"
	"github.com/azrtydxb/novanet/internal/policy"
	"github.com/azrtydxb/novanet/internal/routing"
	"github.com/azrtydxb/novanet/internal/service"
	"github.com/azrtydxb/novanet/internal/tunnel"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// SetRemoteEndpointSyncFunc allows the caller to inject the actual remote
// endpoint sync implementation to avoid circular imports.
func SetRemoteEndpointSyncFunc(fn func(ctx context.Context, logger *zap.Logger,
	k8sClient kubernetes.Interface, dpClient pb.DataplaneControlClient, nodeName string)) {
	startRemoteEndpointSyncDirect = fn
}

var startRemoteEndpointSyncDirect = func(ctx context.Context, logger *zap.Logger,
	k8sClient kubernetes.Interface, dpClient pb.DataplaneControlClient, nodeName string) {
	logger.Warn("remote endpoint sync not wired — call remotesync.StartRemoteEndpointSync directly")
}

// ParseFlags parses command-line flags and handles --version.
func ParseFlags() Params {
	configPath := flag.String("config", "/etc/novanet/config.json", "Path to configuration file")
	podCIDR := flag.String("pod-cidr", "", "Node's PodCIDR (e.g., 10.244.1.0/24)")
	nodeIPStr := flag.String("node-ip", "", "Node IP address")
	printVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *printVersion {
		_, _ = fmt.Fprintf(os.Stdout, "novanet-agent %s\n", Version)
		os.Exit(0)
	}

	return Params{
		ConfigPath: *configPath,
		PodCIDR:    *podCIDR,
		NodeIPStr:  *nodeIPStr,
		NodeName:   os.Getenv("NOVANET_NODE_NAME"),
	}
}

// LoadConfig loads and validates the agent configuration file.
func LoadConfig(configPath string) *config.Config {
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

// CreateK8sClient creates a Kubernetes clientset if running inside a cluster.
func CreateK8sClient(logger *zap.Logger, nodeName string) *kubernetes.Clientset {
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

// ResolveNodeParams auto-detects pod-cidr and node-ip from the Kubernetes API.
func ResolveNodeParams(logger *zap.Logger, k8sClient *kubernetes.Clientset, params *Params) {
	if (params.PodCIDR == "" || params.NodeIPStr == "") && k8sClient != nil {
		logger.Info("auto-detecting node-ip/pod-cidr from Kubernetes API",
			zap.String("node_name", params.NodeName))
		nodeCtx, nodeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		node, err := k8sClient.CoreV1().Nodes().Get(nodeCtx, params.NodeName, metav1.GetOptions{})
		nodeCancel()
		if err != nil {
			logger.Fatal("failed to get node for auto-detection", zap.Error(err), zap.String("node", params.NodeName))
		}
		if params.PodCIDR == "" && node.Spec.PodCIDR != "" {
			params.PodCIDR = node.Spec.PodCIDR
			logger.Info("auto-detected pod-cidr", zap.String("pod_cidr", params.PodCIDR))
		}
		if params.NodeIPStr == "" {
			for _, addr := range node.Status.Addresses {
				if addr.Type == "InternalIP" {
					params.NodeIPStr = addr.Address
					logger.Info("auto-detected node-ip", zap.String("node_ip", params.NodeIPStr))
					break
				}
			}
		}
	}
	if params.PodCIDR == "" {
		logger.Fatal("--pod-cidr is required (or set NOVANET_NODE_NAME for auto-detection)")
	}
	if params.NodeIPStr == "" {
		logger.Fatal("--node-ip is required (or set NOVANET_NODE_NAME for auto-detection)")
	}
}

// ParseNodeIP parses and validates the node IP string (IPv4 or IPv6).
func ParseNodeIP(logger *zap.Logger, nodeIPStr string) net.IP {
	nodeIP := net.ParseIP(nodeIPStr)
	if nodeIP == nil {
		logger.Fatal("invalid --node-ip", zap.String("value", nodeIPStr))
	}
	return nodeIP
}

// CreateIPAM creates the IPAM allocator for the node's PodCIDR.
func CreateIPAM(logger *zap.Logger, podCIDR string) *ipam.Allocator {
	ipAlloc, err := ipam.NewAllocatorWithStateDir(podCIDR, "/var/lib/cni/networks/novanet")
	if err != nil {
		logger.Fatal("failed to create IPAM allocator", zap.Error(err))
	}
	ipAlloc.SetLogger(logger)
	logger.Info("IPAM allocator created", zap.String("pod_cidr", podCIDR), zap.Int("available", ipAlloc.Available()))
	return ipAlloc
}

// SetupMasquerade configures NAT masquerade if a cluster CIDR is configured.
func SetupMasquerade(logger *zap.Logger, cfg *config.Config, podCIDR string) {
	if cfg.ClusterCIDR == "" {
		return
	}
	if err := masquerade.EnsureMasquerade(podCIDR, cfg.ClusterCIDR); err != nil {
		logger.Error("failed to setup NAT masquerade", zap.Error(err))
	} else {
		logger.Info("NAT masquerade configured", zap.String("pod_cidr", podCIDR), zap.String("cluster_cidr", cfg.ClusterCIDR))
	}
}

// CreatePolicyCompiler creates the policy compiler with port/namespace resolvers.
func CreatePolicyCompiler(ctx context.Context, logger *zap.Logger, k8sClient *kubernetes.Clientset,
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

func resolveNamedPorts(ctx context.Context, k8sClient *kubernetes.Clientset,
	portName string, protocol corev1.Protocol, namespace string, selector metav1.LabelSelector) []uint16 {
	sel, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return nil
	}
	pods, err := k8sClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: sel.String()})
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

func resolveNamespaces(ctx context.Context, k8sClient *kubernetes.Clientset, selector metav1.LabelSelector) []string {
	sel, err := metav1.LabelSelectorAsSelector(&selector)
	if err != nil {
		return nil
	}
	nsList, err := k8sClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: sel.String()})
	if err != nil {
		return nil
	}
	var names []string
	for _, ns := range nsList.Items {
		names = append(names, ns.Name)
	}
	return names
}

// CreateEgressManager creates the egress manager if a cluster CIDR is configured.
func CreateEgressManager(logger *zap.Logger, cfg *config.Config, nodeIP net.IP) *egress.Manager {
	if cfg.ClusterCIDR == "" {
		return nil
	}
	_, clusterNet, err := net.ParseCIDR(cfg.ClusterCIDR)
	if err != nil {
		logger.Warn("failed to parse cluster CIDR, egress manager disabled",
			zap.String("cluster_cidr", cfg.ClusterCIDR), zap.Error(err))
		return nil
	}
	mgr := egress.NewManager(nodeIP, clusterNet, logger)
	logger.Info("egress manager created")
	return mgr
}

// ConnectToDataplane establishes a gRPC connection to the Rust dataplane.
func ConnectToDataplane(ctx context.Context, logger *zap.Logger, socketPath string) (*grpc.ClientConn, pb.DataplaneControlClient, bool) {
	logger.Info("connecting to dataplane", zap.String("socket", socketPath))
	for {
		select {
		case <-ctx.Done():
			logger.Warn("context cancelled before dataplane connection established")
			return nil, nil, false
		default:
		}
		conn, err := grpc.NewClient("unix://"+socketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			logger.Warn("failed to create dataplane client, retrying",
				zap.Error(err), zap.Duration("retry_in", DataplaneRetryInterval))
			select {
			case <-ctx.Done():
				return nil, nil, false
			case <-time.After(DataplaneRetryInterval):
				continue
			}
		}
		client := pb.NewDataplaneControlClient(conn)
		testCtx, testCancel := context.WithTimeout(ctx, 3*time.Second)
		_, err = client.GetDataplaneStatus(testCtx, &pb.GetDataplaneStatusRequest{})
		testCancel()
		if err != nil {
			logger.Warn("dataplane not ready, retrying",
				zap.Error(err), zap.Duration("retry_in", DataplaneRetryInterval))
			_ = conn.Close()
			select {
			case <-ctx.Done():
				return nil, nil, false
			case <-time.After(DataplaneRetryInterval):
				continue
			}
		}
		logger.Info("connected to dataplane")
		return conn, client, true
	}
}

// PushDataplaneConfig sends initial configuration to the dataplane.
func PushDataplaneConfig(ctx context.Context, logger *zap.Logger, client pb.DataplaneControlClient, cfg *config.Config, nodeIP net.IP, podCIDR string) error {
	entries := make(map[uint32]uint64)
	switch strings.ToLower(cfg.RoutingMode) {
	case "overlay":
		entries[ConfigKeyMode] = ModeOverlay
	case "native":
		entries[ConfigKeyMode] = ModeNative
	}
	switch strings.ToLower(cfg.TunnelProtocol) {
	case "geneve":
		entries[ConfigKeyTunnelType] = TunnelGEV
	case "vxlan":
		entries[ConfigKeyTunnelType] = TunnelVXL
	}
	if ip4 := nodeIP.To4(); ip4 != nil {
		entries[ConfigKeyNodeIP] = uint64(binary.BigEndian.Uint32(ip4))
	}
	clusterIP, clusterNet, err := net.ParseCIDR(cfg.ClusterCIDR)
	if err == nil {
		if cip4 := clusterIP.To4(); cip4 != nil {
			entries[ConfigKeyClusterCIDRIP] = uint64(binary.BigEndian.Uint32(cip4))
		}
		ones, _ := clusterNet.Mask.Size()
		entries[ConfigKeyClusterCIDRPL] = uint64(ones) //nolint:gosec // CIDR prefix 0-128
	}
	podIP, podNet, err := net.ParseCIDR(podCIDR)
	if err == nil {
		if pip4 := podIP.To4(); pip4 != nil {
			entries[ConfigKeyPodCIDRIP] = uint64(binary.BigEndian.Uint32(pip4))
		}
		ones, _ := podNet.Mask.Size()
		entries[ConfigKeyPodCIDRPL] = uint64(ones) //nolint:gosec // CIDR prefix 0-128
	}
	if cfg.Policy.DefaultDeny {
		entries[ConfigKeyDefaultDeny] = 1
	} else {
		entries[ConfigKeyDefaultDeny] = 0
	}
	if cfg.Egress.MasqueradeEnabled {
		entries[ConfigKeyMasqueradeEnable] = 1
	} else {
		entries[ConfigKeyMasqueradeEnable] = 0
	}
	if cfg.L4LB.Enabled {
		entries[ConfigKeyL4LBEnabled] = 1
	} else {
		entries[ConfigKeyL4LBEnabled] = 0
	}
	req := &pb.UpdateConfigRequest{Entries: entries}
	_, err = client.UpdateConfig(ctx, req)
	if err != nil {
		return fmt.Errorf("UpdateConfig RPC failed: %w", err)
	}
	logger.Info("dataplane config pushed", zap.Int("entry_count", len(entries)))
	return nil
}

// InitDataplane sends initial configuration and starts flow consumer if connected.
func InitDataplane(ctx context.Context, logger *zap.Logger, cfg *config.Config,
	dpClient pb.DataplaneControlClient, dpConnected bool, nodeIP net.IP, podCIDR string, bgWg *sync.WaitGroup) {
	if !dpConnected {
		return
	}
	if err := PushDataplaneConfig(ctx, logger, dpClient, cfg, nodeIP, podCIDR); err != nil {
		logger.Error("failed to push initial config to dataplane", zap.Error(err))
	}
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		ConsumeFlows(ctx, logger, dpClient)
	}()
}

// StartPolicyWatcher starts the NetworkPolicy watcher if a Kubernetes client is available.
func StartPolicyWatcher(ctx context.Context, logger *zap.Logger, k8sClient *kubernetes.Clientset,
	policyCompiler *policy.Compiler, agentSrv *Server, bgWg *sync.WaitGroup) {
	if k8sClient == nil {
		logger.Warn("no Kubernetes client — NetworkPolicy watcher disabled")
		return
	}
	policyWatcher := policy.NewWatcher(k8sClient, policyCompiler, logger)
	policyWatcher.OnChange(agentSrv.OnPolicyChange)
	agentSrv.PolicyWatcher = policyWatcher
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		logger.Info("starting NetworkPolicy watcher")
		if err := policyWatcher.Start(ctx); err != nil {
			logger.Error("NetworkPolicy watcher error", zap.Error(err))
		}
	}()
}

// StartRemoteSync starts the remote endpoint sync for cross-node identity resolution.
func StartRemoteSync(ctx context.Context, logger *zap.Logger, k8sClient *kubernetes.Clientset,
	dpClient pb.DataplaneControlClient, dpConnected bool, nodeName string, bgWg *sync.WaitGroup) {
	if k8sClient == nil || dpClient == nil || !dpConnected {
		return
	}
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		startRemoteEndpointSyncDirect(ctx, logger, k8sClient, dpClient, nodeName)
	}()
}

// StartServiceWatcher starts the L4 LB service watcher when l4lb is enabled.
func StartServiceWatcher(ctx context.Context, logger *zap.Logger, cfg *config.Config,
	k8sClient *kubernetes.Clientset, dpClient pb.DataplaneControlClient, agentSrv *Server) {
	if !cfg.L4LB.Enabled {
		return
	}
	if k8sClient == nil {
		logger.Warn("no Kubernetes client — L4 LB service watcher disabled")
		return
	}
	logger.Info("L4 LB enabled — starting service watcher", zap.String("default_algorithm", cfg.L4LB.DefaultAlgorithm))
	adapter := &DpServiceAdapter{Client: dpClient}
	allocator := service.NewSlotAllocator(65536)
	svcWatcher := service.NewWatcher(k8sClient, adapter, allocator, cfg.L4LB.DefaultAlgorithm, logger,
		service.WithDSR(cfg.DSR))
	agentSrv.SvcWatcher = svcWatcher
	if err := svcWatcher.Start(ctx); err != nil {
		logger.Error("failed to start service watcher", zap.Error(err))
		return
	}
	hostIface := DetectHostInterface(logger)
	if _, err := dpClient.AttachProgram(ctx, &pb.AttachProgramRequest{
		InterfaceName: hostIface, AttachType: pb.AttachType_ATTACH_TC_INGRESS,
	}); err != nil {
		logger.Error("failed to attach host ingress program", zap.String("interface", hostIface), zap.Error(err))
	} else {
		logger.Info("attached tc_host_ingress for NodePort/ExternalIP", zap.String("interface", hostIface))
	}
}

// DetectHostInterface returns the name of the node's primary physical interface.
func DetectHostInterface(logger *zap.Logger) string {
	for _, name := range []string{"bond0", "eth0", "ens192", "enp0s3", "ens3", "ens5"} {
		if _, err := net.InterfaceByName(name); err == nil {
			logger.Debug("detected host interface", zap.String("interface", name))
			return name
		}
	}
	logger.Warn("no known physical interface found, falling back to eth0")
	return "eth0"
}

// StartCNIServer starts the CNI gRPC server and returns the server handle.
func StartCNIServer(logger *zap.Logger, cfg *config.Config, agentSrv *Server) *grpc.Server {
	cniListener, cniGRPC, err := StartGRPCServer(logger, cfg.CNISocket, "CNI", func(s *grpc.Server) {
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

// StartAgentGRPCServer starts the agent gRPC server for novanetctl.
func StartAgentGRPCServer(logger *zap.Logger, cfg *config.Config, agentSrv *Server) *grpc.Server {
	agentListener, agentGRPC, err := StartGRPCServer(logger, cfg.ListenSocket, "agent", func(s *grpc.Server) {
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

// StartIPAMServer starts the shared IPAM gRPC server.
func StartIPAMServer(logger *zap.Logger, ipamMgr *ipam.Manager) *grpc.Server {
	const ipamSocket = "/run/novanet/ipam.sock"
	ipamSrv := ipam.NewGRPCServer(ipamMgr, logger)
	ipamListener, ipamGRPC, err := StartGRPCServer(logger, ipamSocket, "IPAM", func(s *grpc.Server) {
		pb.RegisterIPAMServiceServer(s, ipamSrv)
	})
	if err != nil {
		logger.Fatal("failed to start IPAM gRPC server", zap.Error(err))
	}
	go func() {
		logger.Info("IPAM gRPC server listening", zap.String("socket", ipamSocket))
		if err := ipamGRPC.Serve(ipamListener); err != nil {
			logger.Error("IPAM gRPC server error", zap.Error(err))
		}
	}()
	return ipamGRPC
}

// StartEBPFServicesServer starts the EBPFServices gRPC server if enabled.
func StartEBPFServicesServer(logger *zap.Logger, cfg *config.Config, dpConnected bool, resolver ebpfservices.EndpointResolver) *grpc.Server {
	if !cfg.EBPFServices.Enabled {
		logger.Info("EBPFServices gRPC server disabled")
		return nil
	}
	var dpClient dataplane.ClientInterface
	if dpConnected {
		client, err := dataplane.NewClient(cfg.DataplaneSocket, logger.Named("ebpf-dp"))
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if connErr := client.Connect(ctx); connErr != nil {
				logger.Warn("EBPFServices: failed to connect dataplane client", zap.Error(connErr))
			} else {
				dpClient = client
			}
		} else {
			logger.Warn("EBPFServices: failed to create dataplane client", zap.Error(err))
		}
	}
	ebpfSrv := ebpfservices.NewServer(logger, dpClient, resolver)
	ebpfListener, ebpfGRPC, err := StartGRPCServer(logger, cfg.EBPFServices.SocketPath, "EBPFServices", func(s *grpc.Server) {
		pb.RegisterEBPFServicesServer(s, ebpfSrv)
	})
	if err != nil {
		logger.Fatal("failed to start EBPFServices gRPC server", zap.Error(err))
	}
	go func() {
		logger.Info("EBPFServices gRPC server listening", zap.String("socket", cfg.EBPFServices.SocketPath))
		if err := ebpfGRPC.Serve(ebpfListener); err != nil {
			logger.Error("EBPFServices gRPC server error", zap.Error(err))
		}
	}()
	return ebpfGRPC
}

// StartMetricsServer starts the Prometheus metrics and health check HTTP server.
func StartMetricsServer(logger *zap.Logger, cfg *config.Config, agentSrv *Server) *http.Server {
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !agentSrv.DpConnected.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = fmt.Fprintf(w, `{"status":"not ready","reason":"dataplane not connected","version":"%s"}`, Version)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok","version":"%s"}`, Version)
	})
	metricsServer := &http.Server{Addr: cfg.MetricsAddress, Handler: metricsMux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		logger.Info("metrics server listening", zap.String("address", cfg.MetricsAddress))
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server error", zap.Error(err))
		}
	}()
	return metricsServer
}

// InitRoutingMode performs mode-specific initialization (overlay tunnels or native BGP).
func InitRoutingMode(ctx context.Context, logger *zap.Logger, cfg *config.Config,
	k8sClient *kubernetes.Clientset, agentSrv *Server, dpClient pb.DataplaneControlClient,
	nodeIP net.IP, podCIDR, nodeName string, bgWg *sync.WaitGroup) *routing.Manager {
	switch strings.ToLower(cfg.RoutingMode) {
	case "overlay":
		InitOverlayMode(ctx, logger, cfg, k8sClient, agentSrv, dpClient, nodeIP, nodeName, bgWg)
	case "native":
		return InitNativeMode(ctx, logger, cfg, k8sClient, agentSrv, nodeIP, podCIDR, nodeName, bgWg)
	}
	return nil
}

// InitOverlayMode sets up overlay tunnel mode (Geneve/VXLAN).
func InitOverlayMode(ctx context.Context, logger *zap.Logger, cfg *config.Config,
	k8sClient *kubernetes.Clientset, agentSrv *Server, dpClient pb.DataplaneControlClient,
	nodeIP net.IP, nodeName string, bgWg *sync.WaitGroup) {
	logger.Info("running in overlay mode", zap.String("tunnel_protocol", cfg.TunnelProtocol))
	if k8sClient == nil {
		logger.Fatal("overlay mode requires NOVANET_NODE_NAME to be set for node discovery")
	}
	if err := tunnel.PrepareOverlay(cfg.TunnelProtocol); err != nil {
		logger.Warn("failed to prepare overlay", zap.Error(err))
	}
	tunnelMgr := tunnel.NewManager(cfg.TunnelProtocol, nodeIP, 1, nil, logger)
	agentSrv.TunnelMgr = tunnelMgr
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		WatchNodes(ctx, logger, k8sClient, tunnelMgr, dpClient, nodeName, nodeIP)
	}()
}

// InitNativeMode sets up native routing mode with eBGP via FRR.
func InitNativeMode(ctx context.Context, logger *zap.Logger, cfg *config.Config,
	k8sClient *kubernetes.Clientset, agentSrv *Server,
	nodeIP net.IP, podCIDR, nodeName string, bgWg *sync.WaitGroup) *routing.Manager {
	logger.Info("running in native routing mode (eBGP)")
	if k8sClient == nil {
		logger.Fatal("native mode requires NOVANET_NODE_NAME to be set for node discovery")
	}
	if err := tunnel.PrepareOverlay("geneve"); err != nil {
		logger.Debug("overlay cleanup (geneve)", zap.Error(err))
	}
	if err := tunnel.PrepareOverlay("vxlan"); err != nil {
		logger.Debug("overlay cleanup (vxlan)", zap.Error(err))
	}
	if err := tunnel.AddBlackholeRoute(podCIDR); err != nil {
		logger.Warn("failed to add blackhole route for PodCIDR", zap.Error(err))
	} else {
		logger.Info("added blackhole route for local PodCIDR", zap.String("pod_cidr", podCIDR))
	}
	routingMgr := routing.NewManager(routing.ManagerConfig{FRRSocketDir: cfg.Routing.FRRSocketDir}, "novanet", logger)
	if err := routingMgr.WaitForFRR(ctx); err != nil {
		logger.Fatal("FRR daemons not ready", zap.Error(err))
	}
	routingMgr.Start(ctx)
	ipBytes := nodeIP.To16()
	localAS := uint32(64512) + uint32(ipBytes[14])*256 + uint32(ipBytes[15])
	routerID := nodeIP.String()
	routingMgr.ConfigureBGP(localAS, routerID)
	if err := routingMgr.AdvertisePrefix(podCIDR); err != nil {
		logger.Fatal("failed to advertise PodCIDR", zap.Error(err))
	}
	logger.Info("advertised PodCIDR via BGP", zap.String("pod_cidr", podCIDR))
	agentSrv.RoutingConnected = true
	agentSrv.RoutingMgr = routingMgr
	if vip := cfg.Routing.ControlPlaneVIP; vip != "" && cfg.L4LB.Enabled {
		healthInterval := 5 * time.Second
		if cfg.Routing.ControlPlaneVIPHealthInterval > 0 {
			healthInterval = time.Duration(cfg.Routing.ControlPlaneVIPHealthInterval) * time.Second
		}

		// Create a dedicated dataplane client for the cp-vip manager
		// using the dataplane.ClientInterface abstraction.
		cpvipDPClient, cpvipDPErr := dataplane.NewClient(cfg.DataplaneSocket, logger.Named("cpvip-dp"))
		if cpvipDPErr != nil {
			logger.Error("failed to create cpvip dataplane client", zap.Error(cpvipDPErr))
		}
		var cpvipDP dataplane.ClientInterface
		if cpvipDPErr == nil {
			connCtx, connCancel := context.WithTimeout(ctx, 5*time.Second)
			if connErr := cpvipDPClient.Connect(connCtx); connErr != nil {
				logger.Error("failed to connect cpvip dataplane client", zap.Error(connErr))
			} else {
				cpvipDP = cpvipDPClient
			}
			connCancel()
		}

		cpvipMgr := cpvip.NewManager(cpvip.Config{
			VIP: vip, HealthInterval: healthInterval, NodeName: nodeName,
			IsControlPlane: IsControlPlaneNode(ctx, k8sClient, nodeName, logger),
		}, cpvipDP, routingMgr, k8sClient, logger)
		bgWg.Add(1)
		go func() {
			defer bgWg.Done()
			cpvipMgr.Run(ctx)
		}()
	}
	for _, peer := range cfg.Routing.Peers {
		peerBFD := &routing.BFDOptions{Enabled: peer.BFDEnabled}
		if peer.BFDEnabled {
			peerBFD.MinRxMs = peer.BFDMinRxMs
			peerBFD.MinTxMs = peer.BFDMinTxMs
			peerBFD.DetectMultiplier = peer.BFDDetectMultiplier
			if peerBFD.MinRxMs == 0 {
				peerBFD.MinRxMs = cfg.Routing.BFDMinRxMs
			}
			if peerBFD.MinTxMs == 0 {
				peerBFD.MinTxMs = cfg.Routing.BFDMinTxMs
			}
			if peerBFD.DetectMultiplier == 0 {
				peerBFD.DetectMultiplier = cfg.Routing.BFDDetectMult
			}
		}
		if err := routingMgr.ApplyPeer(peer.NeighborAddress, peer.RemoteAS, peerBFD); err != nil {
			logger.Error("failed to apply external BGP peer", zap.Error(err),
				zap.String("neighbor", peer.NeighborAddress), zap.Uint32("remote_as", peer.RemoteAS),
				zap.String("description", peer.Description))
		} else {
			logger.Info("applied external BGP peer", zap.String("neighbor", peer.NeighborAddress),
				zap.Uint32("remote_as", peer.RemoteAS), zap.String("description", peer.Description),
				zap.Bool("bfd", peer.BFDEnabled))
		}
	}
	bgWg.Add(1)
	go func() {
		defer bgWg.Done()
		var bfdOpts *routing.BFDOptions
		if cfg.Routing.BFDEnabled {
			bfdOpts = &routing.BFDOptions{Enabled: true, MinRxMs: cfg.Routing.BFDMinRxMs,
				MinTxMs: cfg.Routing.BFDMinTxMs, DetectMultiplier: cfg.Routing.BFDDetectMult}
		}
		WatchNodesNative(ctx, logger, k8sClient, routingMgr, nodeName, bfdOpts)
	}()
	return routingMgr
}

// IsControlPlaneNode checks if the given node has the control-plane role label.
func IsControlPlaneNode(ctx context.Context, k8sClient *kubernetes.Clientset, nodeName string, logger *zap.Logger) bool {
	node, err := k8sClient.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		logger.Error("failed to get node for cp-vip check", zap.String("node", nodeName), zap.Error(err))
		return false
	}
	_, ok := node.Labels["node-role.kubernetes.io/control-plane"]
	return ok
}

// WaitForSignal blocks until a SIGTERM or SIGINT signal is received.
func WaitForSignal(logger *zap.Logger) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("received signal, starting graceful shutdown", zap.String("signal", sig.String()))
}

// GracefulShutdown performs an orderly shutdown of all agent components.
func GracefulShutdown(s *ShutdownState) {
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer shutdownCancel()
	s.Cancel()
	s.BgWg.Wait()
	s.Logger.Info("background goroutines stopped")
	ShutdownRouting(s.Logger, s.NrClient, s.PodCIDR)
	s.CniGRPC.GracefulStop()
	s.Logger.Info("CNI gRPC server stopped")
	s.AgentGRPC.GracefulStop()
	s.Logger.Info("agent gRPC server stopped")
	if s.IpamGRPC != nil {
		s.IpamGRPC.GracefulStop()
		s.Logger.Info("IPAM gRPC server stopped")
	}
	if s.EbpfServicesGRPC != nil {
		s.EbpfServicesGRPC.GracefulStop()
		s.Logger.Info("EBPFServices gRPC server stopped")
	}
	if err := s.MetricsServer.Shutdown(shutdownCtx); err != nil {
		s.Logger.Error("metrics server shutdown error", zap.Error(err))
	}
	s.Logger.Info("metrics server stopped")
	if s.XdpMgr != nil {
		s.XdpMgr.DetachAll()
		s.Logger.Info("XDP programs detached")
	}
	if s.WgManager != nil {
		if err := s.WgManager.Close(); err != nil {
			s.Logger.Error("failed to close WireGuard interface", zap.Error(err))
		} else {
			s.Logger.Info("WireGuard interface removed")
		}
	}
	if s.DpConn != nil {
		_ = s.DpConn.Close()
		s.Logger.Info("dataplane connection closed")
	}
	s.Logger.Info("novanet-agent shutdown complete")
}

// ShutdownRouting withdraws the PodCIDR prefix and shuts down the routing manager.
func ShutdownRouting(logger *zap.Logger, routingMgr *routing.Manager, podCIDR string) {
	if routingMgr == nil {
		return
	}
	logger.Info("withdrawing PodCIDR", zap.String("pod_cidr", podCIDR))
	if err := routingMgr.WithdrawPrefix(podCIDR); err != nil {
		logger.Error("failed to withdraw prefix", zap.Error(err))
	}
	routingMgr.Shutdown()
	if err := tunnel.RemoveBlackholeRoute(podCIDR); err != nil {
		logger.Debug("failed to remove blackhole route", zap.Error(err))
	}
	logger.Info("routing manager stopped")
}

// BuildLogger creates a production zap logger with JSON encoding and ISO8601 timestamps.
func BuildLogger(level string) (*zap.Logger, error) {
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
	cfg := zap.Config{Level: zap.NewAtomicLevelAt(zapLevel), Encoding: "json", EncoderConfig: encoderCfg,
		OutputPaths: []string{"stderr"}, ErrorOutputPaths: []string{"stderr"}}
	return cfg.Build()
}

// StartGRPCServer creates a Unix socket listener and gRPC server.
func StartGRPCServer(logger *zap.Logger, socketPath, name string, register func(*grpc.Server)) (net.Listener, *grpc.Server, error) {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, nil, fmt.Errorf("creating directory %s: %w", dir, err)
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		logger.Warn("failed to remove stale socket", zap.String("socket", socketPath), zap.Error(err))
	}
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("listening on %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		logger.Warn("failed to chmod socket", zap.String("socket", socketPath), zap.Error(err))
	}
	// Only allow root (UID 0) to connect to gRPC Unix sockets.
	srv := grpcauth.NewAuthenticatedServer(logger, []uint32{0})
	register(srv)
	logger.Info("gRPC server created", zap.String("name", name), zap.String("socket", socketPath))
	return lis, srv, nil
}

// WatchNodes periodically lists Kubernetes nodes and manages tunnels.
func WatchNodes(ctx context.Context, logger *zap.Logger, k8sClient *kubernetes.Clientset,
	tunnelMgr *tunnel.Manager, dpClient pb.DataplaneControlClient, selfNode string, selfNodeIP net.IP) {
	const pollInterval = 15 * time.Second
	nw := &NodeWatcherState{Ctx: ctx, Logger: logger, TunnelMgr: tunnelMgr, DpClient: dpClient, SelfNodeIP: selfNodeIP}
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
		seen := nw.ReconcileNodes(nodes, selfNode)
		nw.CleanupStaleTunnels(seen)
		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

// ReconcileNodes processes the current node list for tunnel management.
func (nw *NodeWatcherState) ReconcileNodes(nodes *corev1.NodeList, selfNode string) map[string]bool {
	seen := make(map[string]bool)
	for _, node := range nodes.Items {
		if node.Name == selfNode || node.Spec.PodCIDR == "" {
			continue
		}
		nodeIP := NodeInternalIP(&node)
		if nodeIP == "" {
			continue
		}
		parsedNodeIP := net.ParseIP(nodeIP)
		if parsedNodeIP == nil {
			nw.Logger.Warn("invalid node IP, skipping", zap.String("node", node.Name), zap.String("node_ip", nodeIP))
			continue
		}
		seen[node.Name] = true
		nw.EnsureTunnel(node.Name, nodeIP, node.Spec.PodCIDR, parsedNodeIP)
	}
	return seen
}

// EnsureTunnel ensures a tunnel exists to a remote node.
func (nw *NodeWatcherState) EnsureTunnel(nodeName, nodeIP, podCIDR string, parsedNodeIP net.IP) {
	if tunnelInfo, exists := nw.TunnelMgr.GetTunnel(nodeName); exists {
		if err := tunnel.AddRoute(podCIDR, tunnelInfo.InterfaceName, nw.SelfNodeIP, parsedNodeIP, nw.TunnelMgr.Protocol()); err != nil {
			nw.Logger.Warn("failed to reconcile route", zap.Error(err), zap.String("node", nodeName))
		}
		return
	}
	if err := nw.TunnelMgr.AddTunnel(nw.Ctx, nodeName, nodeIP, podCIDR); err != nil {
		nw.Logger.Error("failed to create tunnel", zap.Error(err), zap.String("node", nodeName), zap.String("node_ip", nodeIP))
		return
	}
	tunnelInfo, ok := nw.TunnelMgr.GetTunnel(nodeName)
	if !ok {
		return
	}
	if nw.DpClient != nil {
		_, err := nw.DpClient.UpsertTunnel(nw.Ctx, &pb.UpsertTunnelRequest{
			NodeIp: parsedNodeIP.String(), TunnelIfindex: uint32(tunnelInfo.Ifindex), Vni: 1, //nolint:gosec // ifindex from kernel
		})
		if err != nil {
			nw.Logger.Error("failed to register tunnel with dataplane", zap.Error(err), zap.String("node", nodeName))
		}
		if !nw.TunnelProgramsAttached {
			if _, err := nw.DpClient.AttachProgram(nw.Ctx, &pb.AttachProgramRequest{
				InterfaceName: tunnelInfo.InterfaceName, AttachType: pb.AttachType_ATTACH_TC_INGRESS,
			}); err != nil {
				nw.Logger.Warn("failed to attach TC ingress to tunnel", zap.String("iface", tunnelInfo.InterfaceName), zap.Error(err))
			}
			if _, err := nw.DpClient.AttachProgram(nw.Ctx, &pb.AttachProgramRequest{
				InterfaceName: tunnelInfo.InterfaceName, AttachType: pb.AttachType_ATTACH_TC_EGRESS,
			}); err != nil {
				nw.Logger.Warn("failed to attach TC egress to tunnel", zap.String("iface", tunnelInfo.InterfaceName), zap.Error(err))
			}
			nw.TunnelProgramsAttached = true
		}
	}
	if err := tunnel.AddRoute(podCIDR, tunnelInfo.InterfaceName, nw.SelfNodeIP, parsedNodeIP, nw.TunnelMgr.Protocol()); err != nil {
		nw.Logger.Error("failed to add route for remote PodCIDR", zap.Error(err),
			zap.String("cidr", podCIDR), zap.String("interface", tunnelInfo.InterfaceName))
	} else {
		nw.Logger.Info("tunnel and route created", zap.String("node", nodeName), zap.String("node_ip", nodeIP),
			zap.String("pod_cidr", podCIDR), zap.String("interface", tunnelInfo.InterfaceName), zap.Int("ifindex", tunnelInfo.Ifindex))
	}
	MetricTunnels.Set(float64(nw.TunnelMgr.Count()))
}

// CleanupStaleTunnels removes tunnels for departed nodes.
func (nw *NodeWatcherState) CleanupStaleTunnels(seen map[string]bool) {
	for _, t := range nw.TunnelMgr.ListTunnels() {
		if seen[t.NodeName] {
			continue
		}
		if t.PodCIDR != "" {
			if err := tunnel.RemoveRoute(t.PodCIDR); err != nil {
				nw.Logger.Warn("failed to remove route for departed node", zap.Error(err), zap.String("node", t.NodeName), zap.String("cidr", t.PodCIDR))
			}
		}
		if nw.DpClient != nil && t.NodeIP != "" {
			if _, err := nw.DpClient.DeleteTunnel(nw.Ctx, &pb.DeleteTunnelRequest{NodeIp: t.NodeIP}); err != nil {
				nw.Logger.Warn("failed to delete tunnel from dataplane", zap.Error(err), zap.String("node", t.NodeName))
			}
		}
		if err := nw.TunnelMgr.RemoveTunnel(nw.Ctx, t.NodeName); err != nil {
			nw.Logger.Error("failed to remove tunnel for departed node", zap.Error(err), zap.String("node", t.NodeName))
		} else {
			nw.Logger.Info("tunnel removed for departed node", zap.String("node", t.NodeName))
		}
		MetricTunnels.Set(float64(nw.TunnelMgr.Count()))
	}
}

// NodeInternalIP returns the InternalIP address of a Kubernetes node.
func NodeInternalIP(node *corev1.Node) string {
	for _, addr := range node.Status.Addresses {
		if addr.Type == "InternalIP" {
			return addr.Address
		}
	}
	return ""
}

// WatchNodesNative periodically lists nodes and establishes eBGP peering.
func WatchNodesNative(ctx context.Context, logger *zap.Logger, k8sClient *kubernetes.Clientset,
	routingMgr *routing.Manager, selfNode string, bfdOpts *routing.BFDOptions) {
	const pollInterval = 15 * time.Second
	logger.Info("native node watcher started", zap.String("self_node", selfNode))
	peered := make(map[string]bool)
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
			if remoteIP == "" || peered[n.Name] {
				continue
			}
			parsedIP := net.ParseIP(remoteIP)
			if parsedIP == nil {
				logger.Warn("invalid remote node IP, skipping", zap.String("node", n.Name), zap.String("remote_ip", remoteIP))
				continue
			}
			ipBytes := parsedIP.To16()
			remoteAS := uint32(64512) + uint32(ipBytes[14])*256 + uint32(ipBytes[15])
			if err := routingMgr.ApplyPeer(remoteIP, remoteAS, bfdOpts); err != nil {
				logger.Error("failed to apply BGP peer", zap.Error(err), zap.String("node", n.Name),
					zap.String("remote_ip", remoteIP), zap.Uint32("remote_as", remoteAS))
				continue
			}
			peered[n.Name] = true
			logger.Info("eBGP peer established", zap.String("node", n.Name),
				zap.String("remote_ip", remoteIP), zap.Uint32("remote_as", remoteAS))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pollInterval):
		}
	}
}

// ConsumeFlows subscribes to the dataplane flow event stream and updates metrics.
func ConsumeFlows(ctx context.Context, logger *zap.Logger, client pb.DataplaneControlClient) {
	for {
		stream, err := client.StreamFlows(ctx, &pb.StreamFlowsRequest{})
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Debug("flow consumer: failed to open stream, retrying", zap.Error(err), zap.Duration("retry_in", FlowRetryInterval))
			select {
			case <-ctx.Done():
				return
			case <-time.After(FlowRetryInterval):
				continue
			}
		}
		logger.Info("flow consumer: connected, streaming metrics")
		if ProcessFlowStream(ctx, logger, stream) {
			return
		}
	}
}

// ProcessFlowStream processes flow events from a stream.
func ProcessFlowStream(ctx context.Context, logger *zap.Logger, stream grpc.ServerStreamingClient[pb.FlowEvent]) bool {
	pending := make(map[FlowTuple]time.Time)
	for {
		flow, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return true
			}
			logger.Debug("flow consumer: stream error, reconnecting", zap.Error(err))
			return false
		}
		UpdateFlowMetrics(flow)
		if flow.Protocol == ProtoTCP {
			UpdateTCPMetrics(flow, pending)
		}
	}
}

// UpdateFlowMetrics updates general flow Prometheus counters.
func UpdateFlowMetrics(flow *pb.FlowEvent) {
	verdict := "allow"
	if flow.Verdict == pb.PolicyAction_POLICY_ACTION_DENY {
		verdict = "deny"
	}
	agentmetrics.FlowTotal.WithLabelValues(fmt.Sprintf("%d", flow.SrcIdentity), fmt.Sprintf("%d", flow.DstIdentity), verdict).Add(float64(flow.Packets))
	if flow.DropReason != pb.DropReason_DROP_REASON_NONE {
		agentmetrics.DropsTotal.WithLabelValues(flow.DropReason.String()).Add(float64(flow.Packets))
	}
	agentmetrics.PolicyVerdictTotal.WithLabelValues(verdict).Add(float64(flow.Packets))
}

// UpdateTCPMetrics updates TCP connection state counters and SYN-ACK latency.
func UpdateTCPMetrics(flow *pb.FlowEvent, pending map[FlowTuple]time.Time) {
	flags := flow.TcpFlags
	if flags&TCPSYN != 0 && flags&TCPACK == 0 {
		agentmetrics.TCPConnectionTotal.WithLabelValues("syn").Inc()
	}
	if flags&TCPFIN != 0 {
		agentmetrics.TCPConnectionTotal.WithLabelValues("fin").Inc()
	}
	if flags&TCPRST != 0 {
		agentmetrics.TCPConnectionTotal.WithLabelValues("rst").Inc()
	}
	now := time.Now()
	fwd := FlowTuple{flow.SrcIp, flow.DstIp, flow.SrcPort, flow.DstPort}
	rev := FlowTuple{flow.DstIp, flow.SrcIp, flow.DstPort, flow.SrcPort}
	if flags&TCPSYN != 0 && flags&TCPACK == 0 {
		if len(pending) < MaxTrackedTuples {
			pending[fwd] = now
		}
	} else if flags&TCPSYN != 0 && flags&TCPACK != 0 {
		if synTime, ok := pending[rev]; ok {
			rtt := now.Sub(synTime)
			if rtt > 0 && rtt < 10*time.Second {
				agentmetrics.TCPLatencySeconds.Observe(rtt.Seconds())
			}
			delete(pending, rev)
		}
	}
	if len(pending) > MaxTrackedTuples/2 {
		cutoff := now.Add(-10 * time.Second)
		for k, t := range pending {
			if t.Before(cutoff) {
				delete(pending, k)
			}
		}
	}
}

// GenerateMAC creates a deterministic locally-administered MAC address from an IP.
func GenerateMAC(ip net.IP) net.HardwareAddr {
	ip4 := ip.To4()
	if ip4 != nil {
		return net.HardwareAddr{0x02, 0xfe, ip4[0], ip4[1], ip4[2], ip4[3]}
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x00}
	}
	h := sha256.Sum256(ip16)
	return net.HardwareAddr{0x02, 0xfe, h[28], h[29], h[30], h[31]}
}
