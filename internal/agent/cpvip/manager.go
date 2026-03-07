// Package cpvip manages the Kubernetes control-plane VIP through the L4 LB
// dataplane. It health-checks each control-plane node's API server and
// registers only healthy backends in the eBPF service map. On control-plane
// nodes it also manages BGP advertisement of the VIP (advertising when the
// local API server is healthy, withdrawing when it is not) and binds/unbinds
// the VIP on the loopback interface.
package cpvip

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	pb "github.com/azrtydxb/novanet/api/v1"
	"github.com/azrtydxb/novanet/internal/novaroute"
	"github.com/azrtydxb/novanet/internal/tunnel"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	// backendBaseOffset is the starting index in the BACKENDS array reserved
	// for cp-vip backends. The service watcher allocates from 0 upward so
	// these high indices will not conflict.
	backendBaseOffset uint32 = 65520
	// apiServerPort is the standard Kubernetes API server port.
	apiServerPort uint32 = 6443
	// protocolTCP is the IP protocol number for TCP.
	protocolTCP uint32 = 6
	// scopeClusterIP matches the service watcher's scope constant.
	scopeClusterIP uint32 = 0
	// algRoundRobin matches the service watcher's algorithm constant.
	algRoundRobin uint32 = 1
)

// Config holds the configuration for the cp-vip manager.
type Config struct {
	VIP            string
	HealthInterval time.Duration
	HealthTimeout  time.Duration
	NodeName       string
	IsControlPlane bool
}

// Manager watches control-plane nodes, health-checks their API servers, and
// keeps the L4 LB service map and BGP advertisements in sync.
type Manager struct {
	cfg        Config
	dpClient   pb.DataplaneControlClient
	nrClient   *novaroute.Client
	k8sClient  kubernetes.Interface
	logger     *zap.Logger
	httpClient *http.Client

	mu            sync.Mutex
	backends      map[string]bool // nodeIP -> healthy
	bgpAdvertised bool
	loopbackBound bool
}

// NewManager creates a cp-vip manager. nrClient may be nil if BGP is not used.
func NewManager(cfg Config, dpClient pb.DataplaneControlClient, nrClient *novaroute.Client,
	k8sClient kubernetes.Interface, logger *zap.Logger) *Manager {

	if cfg.HealthInterval == 0 {
		cfg.HealthInterval = 5 * time.Second
	}
	if cfg.HealthTimeout == 0 {
		cfg.HealthTimeout = 3 * time.Second
	}

	return &Manager{
		cfg:       cfg,
		dpClient:  dpClient,
		nrClient:  nrClient,
		k8sClient: k8sClient,
		logger:    logger.With(zap.String("component", "cpvip")),
		httpClient: &http.Client{
			Timeout: cfg.HealthTimeout,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // health check only
			},
		},
		backends: make(map[string]bool),
	}
}

// Run starts the cp-vip management loop. It blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) {
	m.logger.Info("cp-vip manager started",
		zap.String("vip", m.cfg.VIP),
		zap.Bool("is_control_plane", m.cfg.IsControlPlane),
		zap.Duration("health_interval", m.cfg.HealthInterval))

	ticker := time.NewTicker(m.cfg.HealthInterval)
	defer ticker.Stop()

	// Run immediately on start, then on tick.
	m.reconcile(ctx)

	for {
		select {
		case <-ctx.Done():
			m.shutdown()
			return
		case <-ticker.C:
			m.reconcile(ctx)
		}
	}
}

// reconcile discovers control-plane nodes, health-checks them, and updates
// the dataplane service map and BGP advertisements.
func (m *Manager) reconcile(ctx context.Context) {
	cpNodes, err := m.discoverCPNodes(ctx)
	if err != nil {
		m.logger.Error("failed to discover control-plane nodes", zap.Error(err))
		return
	}

	if len(cpNodes) == 0 {
		m.logger.Warn("no control-plane nodes found")
		return
	}

	// Health-check each CP node's API server.
	healthy := make(map[string]bool, len(cpNodes))
	for _, nodeIP := range cpNodes {
		healthy[nodeIP] = m.checkHealth(ctx, nodeIP)
	}

	m.mu.Lock()
	changed := !mapsEqual(m.backends, healthy)
	m.backends = healthy
	m.mu.Unlock()

	if !changed {
		return
	}

	// Build the list of healthy backends.
	var healthyIPs []string
	for ip, ok := range healthy {
		if ok {
			healthyIPs = append(healthyIPs, ip)
		}
	}

	m.logger.Info("cp-vip backends changed",
		zap.Int("total_cp_nodes", len(cpNodes)),
		zap.Int("healthy", len(healthyIPs)),
		zap.Strings("healthy_ips", healthyIPs))

	// Update the L4 LB dataplane.
	if err := m.updateDataplane(ctx, healthyIPs); err != nil {
		m.logger.Error("failed to update dataplane service", zap.Error(err))
	}

	// On control-plane nodes, manage BGP and loopback.
	if m.cfg.IsControlPlane {
		localHealthy := healthy[m.localIP(cpNodes)]
		m.manageBGP(ctx, localHealthy)
		m.manageLoopback(localHealthy)
	}
}

// discoverCPNodes lists Kubernetes nodes with the control-plane label and
// returns their InternalIP addresses.
func (m *Manager) discoverCPNodes(ctx context.Context) ([]string, error) {
	nodes, err := m.k8sClient.CoreV1().Nodes().List(ctx, metav1.ListOptions{
		LabelSelector: "node-role.kubernetes.io/control-plane",
	})
	if err != nil {
		return nil, fmt.Errorf("listing control-plane nodes: %w", err)
	}

	var ips []string
	for _, n := range nodes.Items {
		for _, addr := range n.Status.Addresses {
			if addr.Type == "InternalIP" {
				ips = append(ips, addr.Address)
				break
			}
		}
	}
	return ips, nil
}

// checkHealth hits the API server's /livez endpoint on the given node IP.
func (m *Manager) checkHealth(ctx context.Context, nodeIP string) bool {
	url := fmt.Sprintf("https://%s:%d/livez", nodeIP, apiServerPort)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}

	resp, err := m.httpClient.Do(req) //nolint:gosec // URL is built from trusted k8s node IPs
	if err != nil {
		m.logger.Debug("health check failed", zap.String("node_ip", nodeIP), zap.Error(err))
		return false
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort close

	// Any HTTP response means the API server is alive and accepting TCP
	// connections. 401/403 is expected when anonymous auth is disabled.
	// Only connection failures/timeouts indicate an unhealthy API server.
	if resp.StatusCode >= 500 {
		m.logger.Warn("API server unhealthy",
			zap.String("node_ip", nodeIP),
			zap.Int("status", resp.StatusCode))
		return false
	}
	return true
}

// updateDataplane pushes the healthy backends and service entry to the
// eBPF dataplane via gRPC.
func (m *Manager) updateDataplane(ctx context.Context, healthyIPs []string) error {
	backendCount := uint32(len(healthyIPs)) //nolint:gosec // len bounded by cluster size

	// Build backend entries at reserved offsets.
	entries := make([]*pb.BackendEntry, 0, backendCount)
	for i, ip := range healthyIPs {
		entries = append(entries, &pb.BackendEntry{
			Index:  backendBaseOffset + uint32(i),
			Ip:     ipToU32(ip),
			Port:   apiServerPort,
			NodeIp: ipToU32(ip), // backend is on the node itself
		})
	}

	if len(entries) > 0 {
		if _, err := m.dpClient.UpsertBackends(ctx, &pb.UpsertBackendsRequest{
			Backends: entries,
		}); err != nil {
			return fmt.Errorf("upserting backends: %w", err)
		}
	}

	// Upsert the service entry pointing to our reserved backend slots.
	if _, err := m.dpClient.UpsertService(ctx, &pb.UpsertServiceRequest{
		Ip:            ipToU32(m.cfg.VIP),
		Port:          apiServerPort,
		Protocol:      protocolTCP,
		Scope:         scopeClusterIP,
		BackendCount:  backendCount,
		BackendOffset: backendBaseOffset,
		Algorithm:     algRoundRobin,
	}); err != nil {
		return fmt.Errorf("upserting service: %w", err)
	}

	return nil
}

// manageBGP advertises or withdraws the VIP prefix based on local health.
func (m *Manager) manageBGP(ctx context.Context, localHealthy bool) {
	if m.nrClient == nil {
		return
	}

	vipCIDR := m.cfg.VIP + "/32"

	if localHealthy && !m.bgpAdvertised {
		if err := m.nrClient.AdvertisePrefix(ctx, vipCIDR); err != nil {
			m.logger.Error("failed to advertise cp-vip", zap.Error(err))
		} else {
			m.bgpAdvertised = true
			m.logger.Info("advertised cp-vip via BGP (local API server healthy)")
		}
	} else if !localHealthy && m.bgpAdvertised {
		if err := m.nrClient.WithdrawPrefix(ctx, vipCIDR); err != nil {
			m.logger.Error("failed to withdraw cp-vip", zap.Error(err))
		} else {
			m.bgpAdvertised = false
			m.logger.Warn("withdrew cp-vip from BGP (local API server unhealthy)")
		}
	}
}

// manageLoopback binds or unbinds the VIP on the loopback interface based on
// local API server health.
func (m *Manager) manageLoopback(localHealthy bool) {
	vipCIDR := m.cfg.VIP + "/32"

	if localHealthy && !m.loopbackBound {
		if err := tunnel.AddLoopbackAddress(vipCIDR); err != nil {
			m.logger.Warn("failed to bind cp-vip on loopback (may already exist)",
				zap.String("vip", vipCIDR), zap.Error(err))
		}
		m.loopbackBound = true
		m.logger.Info("bound cp-vip on loopback")
	} else if !localHealthy && m.loopbackBound {
		if err := tunnel.RemoveLoopbackAddress(vipCIDR); err != nil {
			m.logger.Warn("failed to remove cp-vip from loopback",
				zap.String("vip", vipCIDR), zap.Error(err))
		}
		m.loopbackBound = false
		m.logger.Warn("removed cp-vip from loopback (local API server unhealthy)")
	}
}

// shutdown cleans up BGP advertisement and loopback binding.
func (m *Manager) shutdown() {
	m.logger.Info("cp-vip manager shutting down")

	if m.cfg.IsControlPlane {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if m.bgpAdvertised && m.nrClient != nil {
			vipCIDR := m.cfg.VIP + "/32"
			if err := m.nrClient.WithdrawPrefix(ctx, vipCIDR); err != nil {
				m.logger.Error("failed to withdraw cp-vip on shutdown", zap.Error(err))
			}
		}
		if m.loopbackBound {
			vipCIDR := m.cfg.VIP + "/32"
			if err := tunnel.RemoveLoopbackAddress(vipCIDR); err != nil {
				m.logger.Warn("failed to remove cp-vip from loopback on shutdown", zap.Error(err))
			}
		}
	}
}

// localIP returns the IP of the local node from the CP node list by matching
// the node name.
func (m *Manager) localIP(cpNodeIPs []string) string {
	// We need to find our own IP in the list. The manager knows the node name,
	// and the IPs were collected from the same API. We resolve it by checking
	// which IP is local.
	for _, ip := range cpNodeIPs {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.String() == ip {
					return ip
				}
			}
		}
	}
	return ""
}

func ipToU32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip4)
}

func mapsEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
