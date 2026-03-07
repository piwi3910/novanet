// Package encryption manages WireGuard interfaces for transparent
// inter-node encryption in NovaNet.
package encryption

import (
	"errors"
	"net"
)

// ErrNotSupported is returned when WireGuard operations are attempted on an unsupported platform.
var ErrNotSupported = errors.New("wireguard: not supported on this platform")

// PeerInfo holds information about a WireGuard peer.
type PeerInfo struct {
	PublicKey  string
	Endpoint   net.UDPAddr
	AllowedIPs []net.IPNet
}
