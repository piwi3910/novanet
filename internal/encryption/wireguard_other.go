//go:build !linux

package encryption

import (
	"net"

	"go.uber.org/zap"
)

// WireGuardManager manages WireGuard encryption for inter-node traffic.
// On non-Linux platforms, all operations return ErrNotSupported.
type WireGuardManager struct{}

// NewWireGuardManager returns ErrNotSupported on non-Linux platforms.
func NewWireGuardManager(_ net.IP, _ int, _ *zap.Logger) (*WireGuardManager, error) {
	return nil, ErrNotSupported
}

// PublicKey returns an empty string on non-Linux platforms.
func (m *WireGuardManager) PublicKey() string {
	return ""
}

// AddPeer returns ErrNotSupported on non-Linux platforms.
func (m *WireGuardManager) AddPeer(_ string, _ net.UDPAddr, _ []net.IPNet) error {
	return ErrNotSupported
}

// RemovePeer returns ErrNotSupported on non-Linux platforms.
func (m *WireGuardManager) RemovePeer(_ string) error {
	return ErrNotSupported
}

// ListPeers returns nil on non-Linux platforms.
func (m *WireGuardManager) ListPeers() []PeerInfo {
	return nil
}

// Close returns nil on non-Linux platforms (no resources to clean up).
func (m *WireGuardManager) Close() error {
	return nil
}
