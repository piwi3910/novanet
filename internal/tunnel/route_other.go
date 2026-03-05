//go:build !linux

package tunnel

import (
	"errors"
	"net"
)

// Platform-specific sentinel errors for non-Linux builds.
var (
	errTunnelRoutesUnsupported    = errors.New("tunnel routes not supported on this platform")
	errBlackholeRoutesUnsupported = errors.New("blackhole routes not supported on this platform")
)

// IPToTunnelMAC derives a deterministic MAC from an IPv4 address.
func IPToTunnelMAC(ip net.IP) net.HardwareAddr {
	ip4 := ip.To4()
	if ip4 == nil {
		return net.HardwareAddr{0xaa, 0xbb, 0, 0, 0, 0}
	}
	return net.HardwareAddr{0xaa, 0xbb, ip4[0], ip4[1], ip4[2], ip4[3]}
}

// AddRoute is not supported on non-Linux platforms.
func AddRoute(_, _ string, _, _ net.IP, _ string) error {
	return errTunnelRoutesUnsupported
}

// AddBlackholeRoute is not supported on non-Linux platforms.
func AddBlackholeRoute(_ string) error {
	return errBlackholeRoutesUnsupported
}

// RemoveBlackholeRoute is not supported on non-Linux platforms.
func RemoveBlackholeRoute(_ string) error {
	return errBlackholeRoutesUnsupported
}

// RemoveRoute is not supported on non-Linux platforms.
func RemoveRoute(_ string) error {
	return errTunnelRoutesUnsupported
}

// AddLoopbackAddress is not supported on non-Linux platforms.
func AddLoopbackAddress(_ string) error {
	return errTunnelRoutesUnsupported
}

// RemoveLoopbackAddress is not supported on non-Linux platforms.
func RemoveLoopbackAddress(_ string) error {
	return errTunnelRoutesUnsupported
}
