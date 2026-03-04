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

	"github.com/piwi3910/novanet/internal/dataplane"
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

// AddTunnel creates a tunnel interface to a remote node.
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
		// Remove existing tunnel before recreating.
		m.removeTunnelLocked(ctx, nodeName)
	}

	ifName := tunnelInterfaceName(m.protocol, nodeName)

	var ifindex int
	var err error
	switch m.protocol {
	case protocolGeneve:
		ifindex, err = createGeneveTunnel(ifName, nodeIP, m.vni, m.nodeIP)
	case protocolVxlan:
		// VXLAN uses a single shared interface for all remotes.
		// The interface name is always "nvx0" regardless of nodeName.
		ifName = "nvx0"
		ifindex, err = createVxlanTunnel(ifName, m.vni, m.nodeIP)
		if err == nil {
			// Add FDB entry mapping remote MAC → remote physical IP.
			remoteMAC := IPToTunnelMAC(parsedIP)
			if fdbErr := addVxlanFDB(ifName, remoteMAC, parsedIP); fdbErr != nil {
				m.logger.Error("failed to add VXLAN FDB entry",
					zap.Error(fdbErr),
					zap.String("node", nodeName),
					zap.String("node_ip", nodeIP),
				)
			}
		}
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedTunnelProto, m.protocol)
	}

	if err != nil {
		return fmt.Errorf("creating %s tunnel to %s: %w", m.protocol, nodeName, err)
	}

	// Register the tunnel with the dataplane.
	remoteIP := IPToUint32(parsedIP)
	if m.dpClient != nil {
		if err := m.dpClient.UpsertTunnel(ctx, remoteIP, uint32(ifindex), m.vni); err != nil { //nolint:gosec // ifindex is a kernel interface index, always positive and small
			destroyTunnel(ifName)
			return fmt.Errorf("registering tunnel with dataplane: %w", err)
		}
	}

	m.tunnels[nodeName] = &Info{
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
	m.removeTunnelLocked(ctx, nodeName)
	return nil
}

// removeTunnelLocked removes a tunnel while already holding the lock.
func (m *Manager) removeTunnelLocked(ctx context.Context, nodeName string) {
	info, ok := m.tunnels[nodeName]
	if !ok {
		return
	}

	// Remove from dataplane.
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

	// For VXLAN, remove FDB entry but keep the shared interface.
	// For Geneve, destroy the per-node interface.
	if m.protocol == protocolVxlan && parsedIP != nil {
		remoteMAC := IPToTunnelMAC(parsedIP)
		if err := removeVxlanFDB(info.InterfaceName, remoteMAC, parsedIP); err != nil {
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

// tunnelInterfaceName generates a tunnel interface name. Truncated to 15 chars.
func tunnelInterfaceName(protocol, nodeName string) string {
	prefix := "nv_"
	if protocol == protocolVxlan {
		prefix = "nvx_"
	}
	name := prefix + nodeName
	if len(name) > 15 {
		name = name[:15]
	}
	return name
}

// IPToUint32 converts an IPv4 address to a uint32 in network byte order.
func IPToUint32(ip net.IP) uint32 {
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return uint32(ip4[0])<<24 | uint32(ip4[1])<<16 | uint32(ip4[2])<<8 | uint32(ip4[3])
}
