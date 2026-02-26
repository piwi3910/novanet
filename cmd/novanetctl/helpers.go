package main

import "fmt"

// protocolName returns a human-readable name for common IP protocol numbers.
// Returns "*" for protocol 0 (meaning "any"), numeric string for unknowns.
func protocolName(proto uint32) string {
	switch proto {
	case 0:
		return "*"
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 132:
		return "SCTP"
	default:
		return fmt.Sprintf("%d", proto)
	}
}
