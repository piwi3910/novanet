package agent

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	pb "github.com/azrtydxb/novanet/api/v1"
	"github.com/azrtydxb/novanet/internal/agentmetrics"
	"github.com/azrtydxb/novanet/internal/config"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

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
