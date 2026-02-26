//go:build !linux

package tunnel

import (
	"fmt"
	"net"
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
func AddRoute(cidr string, ifName string, srcIP net.IP, remoteNodeIP net.IP, protocol string) error {
	return fmt.Errorf("tunnel routes not supported on this platform")
}

// AddBlackholeRoute is not supported on non-Linux platforms.
func AddBlackholeRoute(cidr string) error {
	return fmt.Errorf("blackhole routes not supported on this platform")
}

// RemoveBlackholeRoute is not supported on non-Linux platforms.
func RemoveBlackholeRoute(cidr string) error {
	return fmt.Errorf("blackhole routes not supported on this platform")
}

// RemoveRoute is not supported on non-Linux platforms.
func RemoveRoute(cidr string) error {
	return fmt.Errorf("tunnel routes not supported on this platform")
}
