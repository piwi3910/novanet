// Package main implements the NovaNet agent daemon. It is the management
// plane component that bridges the CNI binary, the Rust eBPF dataplane,
// and the integrated routing subsystem (BGP/BFD/OSPF via FRR).
package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	pb "github.com/azrtydxb/novanet/api/v1"
	"github.com/azrtydxb/novanet/internal/agent"
	"github.com/azrtydxb/novanet/internal/agent/remotesync"
	"github.com/azrtydxb/novanet/internal/bandwidth"
	"github.com/azrtydxb/novanet/internal/encryption"
	"github.com/azrtydxb/novanet/internal/hostfirewall"
	"github.com/azrtydxb/novanet/internal/identity"
	"github.com/azrtydxb/novanet/internal/ipam"
	"github.com/azrtydxb/novanet/internal/l2announce"
	"github.com/azrtydxb/novanet/internal/lbipam"
	"github.com/azrtydxb/novanet/internal/xdp"

	"go.uber.org/zap"
)

func main() {
	agent.RegisterMetrics()
	params := agent.ParseFlags()
	cfg := agent.LoadConfig(params.ConfigPath)

	logger, err := agent.BuildLogger(cfg.LogLevel)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("novanet-agent starting",
		zap.String("version", agent.Version),
		zap.String("config", params.ConfigPath),
		zap.String("routing_mode", cfg.RoutingMode),
		zap.String("tunnel_protocol", cfg.TunnelProtocol),
	)

	k8sClient := agent.CreateK8sClient(logger, params.NodeName)
	agent.ResolveNodeParams(logger, k8sClient, &params)
	nodeIP := agent.ParseNodeIP(logger, params.NodeIPStr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var bgWg sync.WaitGroup

	ipAlloc := agent.CreateIPAM(logger, params.PodCIDR)
	ipamMgr := ipam.NewManager(logger)
	agent.SetupMasquerade(logger, cfg, params.PodCIDR)
	idAlloc := identity.NewAllocator(logger)
	logger.Info("identity allocator created")

	policyCompiler := agent.CreatePolicyCompiler(ctx, logger, k8sClient, idAlloc)
	egressMgr := agent.CreateEgressManager(logger, cfg, nodeIP)

	var wgMgr *encryption.WireGuardManager
	if cfg.Encryption.Type == "wireguard" {
		var wgErr error
		wgMgr, wgErr = encryption.NewWireGuardManager(nodeIP, cfg.Encryption.WireGuardPort, logger)
		if wgErr != nil {
			logger.Error("failed to initialize WireGuard", zap.Error(wgErr))
		} else {
			logger.Info("WireGuard encryption enabled",
				zap.Int("port", cfg.Encryption.WireGuardPort),
				zap.String("public_key", wgMgr.PublicKey()))
		}
	}

	var hostFW *hostfirewall.Manager
	if cfg.HostFirewall.Enabled {
		hostFW = hostfirewall.NewManager(logger)
		logger.Info("host firewall enabled")
	}

	var bwMgr *bandwidth.Manager
	if cfg.Bandwidth.Enabled {
		bwMgr = bandwidth.NewManager(logger)
		logger.Info("bandwidth management enabled")
	}

	var lbIPAMAlloc *lbipam.Allocator
	var l2Ann *l2announce.Announcer
	if cfg.LBIPAM.Enabled {
		lbIPAMAlloc = lbipam.NewAllocator(logger)
		logger.Info("LB-IPAM enabled")
		if cfg.LBIPAM.L2AnnouncementEnabled {
			hostIface := agent.DetectHostInterface(logger)
			l2Ann = l2announce.NewAnnouncer(hostIface, logger)
			logger.Info("L2 announcement (GARP) enabled", zap.String("interface", hostIface))
		}
	}

	dpConn, dpClient, dpConnected := agent.ConnectToDataplane(ctx, logger, cfg.DataplaneSocket)
	agent.InitDataplane(ctx, logger, cfg, dpClient, dpConnected, nodeIP, params.PodCIDR, &bgWg)

	xdpMode := xdp.Mode(cfg.XDPAcceleration)
	var xdpMgr *xdp.Manager
	if xdpMode != xdp.ModeDisabled && dpConnected {
		xdpMgr = xdp.NewManager(xdpMode,
			func(iface string, native bool) error {
				mode := pb.XDPMode_XDP_MODE_SKB
				if native {
					mode = pb.XDPMode_XDP_MODE_NATIVE
				}
				_, xdpErr := dpClient.AttachXDP(ctx, &pb.AttachXDPRequest{InterfaceName: iface, Mode: mode})
				return xdpErr
			},
			func(iface string) error {
				_, xdpErr := dpClient.DetachXDP(ctx, &pb.DetachXDPRequest{InterfaceName: iface})
				return xdpErr
			},
			logger,
		)
		if err := xdpMgr.AttachAll(); err != nil {
			logger.Warn("XDP attach", zap.Error(err))
		} else {
			logger.Info("XDP acceleration enabled",
				zap.String("mode", cfg.XDPAcceleration),
				zap.Strings("interfaces", xdpMgr.AttachedInterfaces()))
		}
	}

	agentSrv := &agent.Server{
		Logger: logger, Cfg: cfg, IPAlloc: ipAlloc, IDAlloc: idAlloc,
		DpClient: dpClient, K8sClient: k8sClient, NodeIP: nodeIP, PodCIDR: params.PodCIDR,
		PolicyCompiler: policyCompiler, EgressMgr: egressMgr, WgManager: wgMgr,
		HostFW: hostFW, BwManager: bwMgr, LbIPAM: lbIPAMAlloc, L2Announcer: l2Ann,
		XdpMgr: xdpMgr, PrevEgressKeys: make(map[agent.EgressMapKey]bool),
		Endpoints: make(map[string]*agent.Endpoint),
	}
	agentSrv.DpConnected.Store(dpConnected)

	agent.SetRemoteEndpointSyncFunc(remotesync.StartRemoteEndpointSync)
	agent.StartPolicyWatcher(ctx, logger, k8sClient, policyCompiler, agentSrv, &bgWg)
	agent.StartRemoteSync(ctx, logger, k8sClient, dpClient, dpConnected, params.NodeName, &bgWg)
	if dpConnected {
		agent.StartServiceWatcher(ctx, logger, cfg, k8sClient, dpClient, agentSrv)
	}

	cniGRPC := agent.StartCNIServer(logger, cfg, agentSrv)
	agentGRPC := agent.StartAgentGRPCServer(logger, cfg, agentSrv)
	ipamGRPC := agent.StartIPAMServer(logger, ipamMgr)
	ebpfServicesGRPC := agent.StartEBPFServicesServer(logger, cfg, dpConnected)
	metricsServer := agent.StartMetricsServer(logger, cfg, agentSrv)

	nrClient := agent.InitRoutingMode(ctx, logger, cfg, k8sClient, agentSrv,
		dpClient, nodeIP, params.PodCIDR, params.NodeName, &bgWg)

	agent.WaitForSignal(logger)
	agent.GracefulShutdown(&agent.ShutdownState{
		Logger: logger, Cancel: cancel, BgWg: &bgWg,
		CniGRPC: cniGRPC, AgentGRPC: agentGRPC, IpamGRPC: ipamGRPC,
		EbpfServicesGRPC: ebpfServicesGRPC, MetricsServer: metricsServer,
		DpConn: dpConn, NrClient: nrClient, PodCIDR: params.PodCIDR,
		XdpMgr: xdpMgr, WgManager: wgMgr,
	})
}
