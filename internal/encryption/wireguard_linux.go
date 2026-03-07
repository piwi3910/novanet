//go:build linux

package encryption

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"

	"go.uber.org/zap"
)

const defaultIfaceName = "novanet-wg0"

// WireGuardManager manages WireGuard encryption for inter-node traffic.
type WireGuardManager struct {
	mu         sync.RWMutex
	nodeIP     net.IP
	listenPort int
	publicKey  string
	privateKey string
	ifaceName  string
	logger     *zap.Logger
	peers      map[string]PeerInfo
}

// NewWireGuardManager creates a new WireGuard interface and generates a key pair.
// The interface is named "novanet-wg0" and listens on the specified port.
func NewWireGuardManager(nodeIP net.IP, listenPort int, logger *zap.Logger) (*WireGuardManager, error) {
	m := &WireGuardManager{
		nodeIP:     nodeIP,
		listenPort: listenPort,
		ifaceName:  defaultIfaceName,
		logger:     logger,
		peers:      make(map[string]PeerInfo),
	}

	if err := m.createInterface(); err != nil {
		return nil, fmt.Errorf("wireguard: failed to create interface: %w", err)
	}

	if err := m.generateKeys(); err != nil {
		// Clean up the interface on key generation failure.
		_ = m.deleteInterface()
		return nil, fmt.Errorf("wireguard: failed to generate keys: %w", err)
	}

	if err := m.configureInterface(); err != nil {
		_ = m.deleteInterface()
		return nil, fmt.Errorf("wireguard: failed to configure interface: %w", err)
	}

	logger.Info("WireGuard manager initialized",
		zap.String("interface", m.ifaceName),
		zap.String("nodeIP", nodeIP.String()),
		zap.Int("listenPort", listenPort),
		zap.String("publicKey", m.publicKey),
	)

	return m, nil
}

// PublicKey returns the base64-encoded public key.
func (m *WireGuardManager) PublicKey() string {
	return m.publicKey
}

// AddPeer adds a WireGuard peer with the given public key, endpoint, and allowed IPs.
func (m *WireGuardManager) AddPeer(publicKey string, endpoint net.UDPAddr, allowedIPs []net.IPNet) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Build allowed-ips string.
	var allowedIPStrs []string
	for _, ipNet := range allowedIPs {
		allowedIPStrs = append(allowedIPStrs, ipNet.String())
	}

	args := []string{
		"set", m.ifaceName,
		"peer", publicKey,
		"endpoint", endpoint.String(),
		"allowed-ips", strings.Join(allowedIPStrs, ","),
		"persistent-keepalive", "25",
	}

	if err := runCmd("wg", args...); err != nil {
		return fmt.Errorf("wireguard: failed to add peer %s: %w", publicKey, err)
	}

	// Add routes for peer allowed IPs.
	for _, ipNet := range allowedIPs {
		if err := runCmd("ip", "route", "add", ipNet.String(), "dev", m.ifaceName); err != nil {
			m.logger.Warn("Failed to add route for peer",
				zap.String("peer", publicKey),
				zap.String("route", ipNet.String()),
				zap.Error(err),
			)
		}
	}

	m.peers[publicKey] = PeerInfo{
		PublicKey:  publicKey,
		Endpoint:  endpoint,
		AllowedIPs: allowedIPs,
	}

	m.logger.Info("Added WireGuard peer",
		zap.String("publicKey", publicKey),
		zap.String("endpoint", endpoint.String()),
		zap.Int("allowedIPs", len(allowedIPs)),
	)

	return nil
}

// RemovePeer removes a WireGuard peer by its public key.
func (m *WireGuardManager) RemovePeer(publicKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer, exists := m.peers[publicKey]
	if !exists {
		return fmt.Errorf("wireguard: peer %s not found", publicKey)
	}

	if err := runCmd("wg", "set", m.ifaceName, "peer", publicKey, "remove"); err != nil {
		return fmt.Errorf("wireguard: failed to remove peer %s: %w", publicKey, err)
	}

	// Remove routes for peer allowed IPs.
	for _, ipNet := range peer.AllowedIPs {
		if err := runCmd("ip", "route", "del", ipNet.String(), "dev", m.ifaceName); err != nil {
			m.logger.Warn("Failed to remove route for peer",
				zap.String("peer", publicKey),
				zap.String("route", ipNet.String()),
				zap.Error(err),
			)
		}
	}

	delete(m.peers, publicKey)

	m.logger.Info("Removed WireGuard peer",
		zap.String("publicKey", publicKey),
	)

	return nil
}

// ListPeers returns information about all configured peers.
func (m *WireGuardManager) ListPeers() []PeerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peers := make([]PeerInfo, 0, len(m.peers))
	for _, p := range m.peers {
		peers = append(peers, p)
	}
	return peers
}

// Close removes the WireGuard interface and cleans up resources.
func (m *WireGuardManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.deleteInterface(); err != nil {
		return fmt.Errorf("wireguard: failed to remove interface: %w", err)
	}

	m.logger.Info("WireGuard manager closed",
		zap.String("interface", m.ifaceName),
	)

	return nil
}

func (m *WireGuardManager) createInterface() error {
	// Remove any stale interface first.
	_ = runCmd("ip", "link", "del", m.ifaceName)

	if err := runCmd("ip", "link", "add", m.ifaceName, "type", "wireguard"); err != nil {
		return fmt.Errorf("failed to create wireguard interface: %w", err)
	}

	return runCmd("ip", "link", "set", m.ifaceName, "up")
}

func (m *WireGuardManager) deleteInterface() error {
	return runCmd("ip", "link", "del", m.ifaceName)
}

func (m *WireGuardManager) generateKeys() error {
	privKey, err := runCmdOutput("wg", "genkey")
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}
	m.privateKey = strings.TrimSpace(privKey)

	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(m.privateKey)
	var out bytes.Buffer
	cmd.Stdout = &out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to derive public key: %w (stderr: %s)", err, stderr.String())
	}
	m.publicKey = strings.TrimSpace(out.String())

	return nil
}

func (m *WireGuardManager) configureInterface() error {
	// Write private key to stdin of wg set command.
	cmd := exec.Command("wg", "set", m.ifaceName,
		"listen-port", fmt.Sprintf("%d", m.listenPort),
		"private-key", "/dev/stdin",
	)
	cmd.Stdin = strings.NewReader(m.privateKey)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to configure wireguard: %w (stderr: %s)", err, stderr.String())
	}
	return nil
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w (stderr: %s)", name, strings.Join(args, " "), err, stderr.String())
	}
	return nil
}

func runCmdOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %s: %w (stderr: %s)", name, strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String(), nil
}
