// Package webhook provides validating admission webhooks for NovaNet CRDs.
package webhook

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

var (
	// errInvalidCIDR is returned when a CIDR string is malformed.
	errInvalidCIDR = errors.New("invalid CIDR")

	// errNonCanonicalCIDR is returned when a CIDR is not in canonical form.
	errNonCanonicalCIDR = errors.New("CIDR is not in canonical form")

	// errInvalidIP is returned when a string is not a valid IP address.
	errInvalidIP = errors.New("invalid IP address")

	// errInvalidPort is returned when a port is outside the valid range.
	errInvalidPort = errors.New("port is out of valid range [1, 65535]")

	// errEndPortBeforePort is returned when endPort < port.
	errEndPortBeforePort = errors.New("endPort must be >= port")

	// errInvalidProtocol is returned when a protocol string is unrecognised.
	errInvalidProtocol = errors.New("invalid protocol, must be one of TCP, UDP, SCTP")
)

// validateCIDR checks that a string is a valid CIDR notation.
func validateCIDR(cidr string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("%w: %q: %w", errInvalidCIDR, cidr, err)
	}
	if ip.String() != ipNet.IP.String() {
		return fmt.Errorf("%w: %q, expected %s", errNonCanonicalCIDR, cidr, ipNet.String())
	}
	return nil
}

// validateIP checks that a string is a valid IP address.
func validateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("%w: %q", errInvalidIP, ip)
	}
	return nil
}

// validatePort checks that a port number is in the valid range [1, 65535].
func validatePort(port int32) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%w: %d", errInvalidPort, port)
	}
	return nil
}

// validatePortRange checks that a port range is valid (endPort >= port).
func validatePortRange(port, endPort int32) error {
	if err := validatePort(port); err != nil {
		return err
	}
	if err := validatePort(endPort); err != nil {
		return fmt.Errorf("endPort: %w", err)
	}
	if endPort < port {
		return fmt.Errorf("%w: %d < %d", errEndPortBeforePort, endPort, port)
	}
	return nil
}

// validProtocols is the set of accepted protocol values.
var validProtocols = map[string]bool{
	"TCP":  true,
	"UDP":  true,
	"SCTP": true,
}

// validateProtocol checks that a protocol string is one of the accepted values.
func validateProtocol(protocol string) error {
	upper := strings.ToUpper(protocol)
	if !validProtocols[upper] {
		return fmt.Errorf("%w: %q", errInvalidProtocol, protocol)
	}
	return nil
}

// cidrsOverlap checks whether two CIDR ranges overlap.
func cidrsOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// cidrContains checks whether parent fully contains child. Both the first and
// last addresses of child must be within parent's range.
func cidrContains(parent, child *net.IPNet) bool {
	// The child's network address must be within the parent.
	if !parent.Contains(child.IP) {
		return false
	}
	// Compute the last address of the child network and check containment.
	childLast := lastAddr(child)
	return parent.Contains(childLast)
}

// lastAddr returns the last (broadcast) address of a CIDR range.
func lastAddr(n *net.IPNet) net.IP {
	ip := make(net.IP, len(n.IP))
	for i := range n.IP {
		ip[i] = n.IP[i] | ^n.Mask[i]
	}
	return ip
}
