// Package tunnel manages overlay tunnels (Geneve or VXLAN) between
// cluster nodes for pod-to-pod communication.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"go.uber.org/zap"

	"github.com/azrtydxb/novanet/internal/dataplane"
)

// Protocol constants for tunnel types.
const (
	protocolGeneve = "geneve"
	protocolVxlan  = "vxlan"
)

// Sentinel errors for tunnel operations.
var (
	ErrInvalidNodeIP          = errors.New("invalid node IP")
	ErrUnsupportedTunnelProto = errors.New("unsupported tunnel protocol")
)

// Info holds information about a tunnel to a remote node.
type Info struct {
	// NodeName is the Kubernetes node name.
	NodeName string
	// NodeIP is the remote node's IP address.
	NodeIP string
	// PodCIDR is the remote node's pod CIDR.
	PodCIDR string
	// InterfaceName is the local tunnel interface name.
	InterfaceName string
	// Ifindex is the local tunnel interface index.
	Ifindex int
}

// Manager manages overlay tunnel interfaces.
type Manager struct {
	mu sync.RWMutex

	protocol string // "geneve" or "vxlan"
	nodeIP   net.IP
	vni      uint32
	dpClient dataplane.ClientInterface
	logger   *zap.Logger

	// tunnelIfName is the single collect-metadata tunnel interface name.
	tunnelIfName string
	// tunnelIfindex is the ifindex of the single tunnel interface.
	tunnelIfindex int

	// tunnels maps node name to tunnel info.
	tunnels map[string]*Info
}

// NewManager creates a new tunnel manager.
func NewManager(protocol string, nodeIP net.IP, vni uint32, dpClient dataplane.ClientInterface, logger *zap.Logger) *Manager {
	return &Manager{
		protocol: protocol,
		nodeIP:   nodeIP,
		vni:      vni,
		dpClient: dpClient,
		logger:   logger,
		tunnels:  make(map[string]*Info),
	}
}

// AddTunnel registers a remote node for overlay communication.
// Both Geneve and VXLAN use a single collect-metadata (FlowBased) interface.
// The eBPF dataplane sets per-packet tunnel metadata via bpf_skb_set_tunnel_key
// and redirects to the shared tunnel interface.
func (m *Manager) AddTunnel(ctx context.Context, nodeName, nodeIP, podCIDR string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	parsedIP := net.ParseIP(nodeIP)
	if parsedIP == nil {
		return fmt.Errorf("%w: %s", ErrInvalidNodeIP, nodeIP)
	}

	if _, exists := m.tunnels[nodeName]; exists {
		m.logger.Debug("tunnel already exists, updating",
			zap.String("node", nodeName),
			zap.String("node_ip", nodeIP),
		)
		m.removeTunnelLocked(ctx, nodeName)
	}

	// Ensure the single tunnel interface exists.
	if err := m.ensureTunnelInterface(); err != nil {
		return err
	}

	// Register this remote node in the eBPF TUNNELS map.
	// All remotes share the same ifindex; the eBPF program sets per-packet
	// tunnel metadata (remote IP, VNI) via bpf_skb_set_tunnel_key.
	remoteIP := IPToUint32(parsedIP)
	if m.dpClient != nil {
		if err := m.dpClient.UpsertTunnel(ctx, remoteIP, uint32(m.tunnelIfindex), m.vni); err != nil { //nolint:gosec // ifindex is always positive and small
			return fmt.Errorf("registering tunnel with dataplane: %w", err)
		}
	}

	m.tunnels[nodeName] = &Info{
		NodeName:      nodeName,
		NodeIP:        nodeIP,
		PodCIDR:       podCIDR,
		InterfaceName: m.tunnelIfName,
		Ifindex:       m.tunnelIfindex,
	}

	m.logger.Info("registered remote node for tunnel",
		zap.String("node", nodeName),
		zap.String("node_ip", nodeIP),
		zap.String("protocol", m.protocol),
		zap.String("interface", m.tunnelIfName),
		zap.Int("ifindex", m.tunnelIfindex),
	)

	return nil
}

// ensureTunnelInterface creates the single collect-metadata tunnel interface
// if it doesn't already exist.
func (m *Manager) ensureTunnelInterface() error {
	if m.tunnelIfindex != 0 {
		return nil
	}

	var ifindex int
	var err error
	var ifName string

	switch m.protocol {
	case protocolGeneve:
		ifName = "nv_geneve"
		ifindex, err = createGeneveTunnel(ifName, m.vni, m.nodeIP)
	case protocolVxlan:
		ifName = "nvx0"
		ifindex, err = createVxlanTunnel(ifName, m.vni, m.nodeIP)
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedTunnelProto, m.protocol)
	}

	if err != nil {
		return fmt.Errorf("creating %s tunnel interface: %w", m.protocol, err)
	}

	m.tunnelIfName = ifName
	m.tunnelIfindex = ifindex

	m.logger.Info("created collect-metadata tunnel interface",
		zap.String("protocol", m.protocol),
		zap.String("interface", ifName),
		zap.Int("ifindex", ifindex),
	)

	return nil
}

// RemoveTunnel removes a tunnel to a remote node.
func (m *Manager) RemoveTunnel(ctx context.Context, nodeName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeTunnelLocked(ctx, nodeName)
	return nil
}

// removeTunnelLocked removes a remote node's tunnel entry while holding the lock.
// The shared tunnel interface is kept — only the eBPF TUNNELS map entry is removed.
func (m *Manager) removeTunnelLocked(ctx context.Context, nodeName string) {
	info, ok := m.tunnels[nodeName]
	if !ok {
		return
	}

	// Remove from eBPF TUNNELS map.
	parsedIP := net.ParseIP(info.NodeIP)
	if m.dpClient != nil && parsedIP != nil {
		remoteIP := IPToUint32(parsedIP)
		if err := m.dpClient.DeleteTunnel(ctx, remoteIP); err != nil {
			m.logger.Error("failed to delete tunnel from dataplane",
				zap.Error(err),
				zap.String("node", nodeName),
			)
		}
	}

	delete(m.tunnels, nodeName)

	m.logger.Info("removed tunnel entry",
		zap.String("node", nodeName),
	)
}

// GetTunnel returns tunnel info for a specific node.
func (m *Manager) GetTunnel(nodeName string) (*Info, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	info, ok := m.tunnels[nodeName]
	if !ok {
		return nil, false
	}
	result := *info
	return &result, true
}

// ListTunnels returns a snapshot of all tunnels.
func (m *Manager) ListTunnels() []*Info {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*Info, 0, len(m.tunnels))
	for _, info := range m.tunnels {
		t := *info
		result = append(result, &t)
	}
	return result
}

// Count returns the number of active tunnels.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tunnels)
}

// Protocol returns the tunnel protocol in use.
func (m *Manager) Protocol() string {
	return m.protocol
}

// IPToUint32 converts an IPv4 address to a uint32 in network byte order.
func IPToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}
