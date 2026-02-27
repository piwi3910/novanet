// Package tunnel manages overlay tunnels (Geneve or VXLAN) between
// cluster nodes for pod-to-pod communication.
package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync"

	"go.uber.org/zap"

	"github.com/piwi3910/novanet/internal/dataplane"
)

// TunnelInfo holds information about a tunnel to a remote node.
type TunnelInfo struct {
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

	// tunnels maps node name to tunnel info.
	tunnels map[string]*TunnelInfo
}

// NewManager creates a new tunnel manager.
func NewManager(protocol string, nodeIP net.IP, vni uint32, dpClient dataplane.ClientInterface, logger *zap.Logger) *Manager {
	return &Manager{
		protocol: protocol,
		nodeIP:   nodeIP,
		vni:      vni,
		dpClient: dpClient,
		logger:   logger,
		tunnels:  make(map[string]*TunnelInfo),
	}
}

// AddTunnel creates a tunnel interface to a remote node.
func (m *Manager) AddTunnel(ctx context.Context, nodeName, nodeIP, podCIDR string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tunnels[nodeName]; exists {
		m.logger.Debug("tunnel already exists, updating",
			zap.String("node", nodeName),
			zap.String("node_ip", nodeIP),
		)
		// Remove existing tunnel before recreating.
		if err := m.removeTunnelLocked(ctx, nodeName); err != nil {
			return fmt.Errorf("removing existing tunnel for %s: %w", nodeName, err)
		}
	}

	ifName := tunnelInterfaceName(m.protocol, nodeName)

	var ifindex int
	var err error
	switch m.protocol {
	case "geneve":
		ifindex, err = createGeneveTunnel(ifName, nodeIP, m.vni, m.nodeIP)
	case "vxlan":
		// VXLAN uses a single shared interface for all remotes.
		// The interface name is always "nvx0" regardless of nodeName.
		ifName = "nvx0"
		ifindex, err = createVxlanTunnel(ifName, m.vni, m.nodeIP)
		if err == nil {
			// Add FDB entry mapping remote MAC → remote physical IP.
			remoteMAC := IPToTunnelMAC(net.ParseIP(nodeIP))
			if fdbErr := addVxlanFDB(ifName, remoteMAC, net.ParseIP(nodeIP)); fdbErr != nil {
				m.logger.Error("failed to add VXLAN FDB entry",
					zap.Error(fdbErr),
					zap.String("node", nodeName),
					zap.String("node_ip", nodeIP),
				)
			}
		}
	default:
		return fmt.Errorf("unsupported tunnel protocol: %s", m.protocol)
	}

	if err != nil {
		return fmt.Errorf("creating %s tunnel to %s: %w", m.protocol, nodeName, err)
	}

	// Register the tunnel with the dataplane.
	remoteIP := ipToUint32(net.ParseIP(nodeIP))
	if m.dpClient != nil {
		if err := m.dpClient.UpsertTunnel(ctx, remoteIP, uint32(ifindex), m.vni); err != nil {
			destroyTunnel(ifName)
			return fmt.Errorf("registering tunnel with dataplane: %w", err)
		}
	}

	m.tunnels[nodeName] = &TunnelInfo{
		NodeName:      nodeName,
		NodeIP:        nodeIP,
		PodCIDR:       podCIDR,
		InterfaceName: ifName,
		Ifindex:       ifindex,
	}

	m.logger.Info("created tunnel",
		zap.String("node", nodeName),
		zap.String("node_ip", nodeIP),
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
	return m.removeTunnelLocked(ctx, nodeName)
}

// removeTunnelLocked removes a tunnel while already holding the lock.
func (m *Manager) removeTunnelLocked(ctx context.Context, nodeName string) error {
	info, ok := m.tunnels[nodeName]
	if !ok {
		return nil
	}

	// Remove from dataplane.
	if m.dpClient != nil {
		remoteIP := ipToUint32(net.ParseIP(info.NodeIP))
		if err := m.dpClient.DeleteTunnel(ctx, remoteIP); err != nil {
			m.logger.Error("failed to delete tunnel from dataplane",
				zap.Error(err),
				zap.String("node", nodeName),
			)
		}
	}

	// For VXLAN, remove FDB entry but keep the shared interface.
	// For Geneve, destroy the per-node interface.
	if m.protocol == "vxlan" {
		remoteMAC := IPToTunnelMAC(net.ParseIP(info.NodeIP))
		if err := removeVxlanFDB(info.InterfaceName, remoteMAC, net.ParseIP(info.NodeIP)); err != nil {
			m.logger.Warn("failed to remove VXLAN FDB entry",
				zap.Error(err),
				zap.String("node", nodeName),
				zap.String("interface", info.InterfaceName),
			)
		}
	} else {
		destroyTunnel(info.InterfaceName)
	}

	delete(m.tunnels, nodeName)

	m.logger.Info("removed tunnel",
		zap.String("node", nodeName),
		zap.String("interface", info.InterfaceName),
	)

	return nil
}

// GetTunnel returns tunnel info for a specific node.
func (m *Manager) GetTunnel(nodeName string) (*TunnelInfo, bool) {
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
func (m *Manager) ListTunnels() []*TunnelInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*TunnelInfo, 0, len(m.tunnels))
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

// tunnelInterfaceName generates a tunnel interface name. Truncated to 15 chars.
func tunnelInterfaceName(protocol, nodeName string) string {
	prefix := "nv_"
	if protocol == "vxlan" {
		prefix = "nvx_"
	}
	name := prefix + nodeName
	if len(name) > 15 {
		name = name[:15]
	}
	return name
}

// ipToUint32 converts an IPv4 address to a uint32 in network byte order.
func ipToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}
