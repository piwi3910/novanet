package agent

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	pb "github.com/azrtydxb/novanet/api/v1"
	"github.com/azrtydxb/novanet/internal/agent/cpvip"
	"github.com/azrtydxb/novanet/internal/config"
	"github.com/azrtydxb/novanet/internal/dataplane"
	"github.com/azrtydxb/novanet/internal/policy"
	"github.com/azrtydxb/novanet/internal/routing"
	"github.com/azrtydxb/novanet/internal/service"
	"github.com/azrtydxb/novanet/internal/tunnel"

	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// SetRemoteEndpointSyncFunc allows the caller to inject the actual remote
// endpoint sync implementation to avoid circular imports.
func SetRemoteEndpointSyncFunc(fn func(ctx context.Context, logger *zap.Logger,
	k8sClient kubernetes.Interface, dpClient pb.DataplaneControlClient, nodeName string,
	remoteEndpointsGauge prometheus.Gauge)) {
	startRemoteEndpointSyncDirect = fn
}

var startRemoteEndpointSyncDirect = func(ctx context.Context, logger *zap.Logger,
	k8sClient kubernetes.Interface, dpClient pb.DataplaneControlClient, nodeName string,
	_ prometheus.Gauge) {
	logger.Warn("remote endpoint sync not wired — ensure agent.SetRemoteEndpointSyncFunc(remotesync.StartRemoteEndpointSync) is called during initialization")
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
		startRemoteEndpointSyncDirect(ctx, logger, k8sClient, dpClient, nodeName, MetricRemoteEndpoints)
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
