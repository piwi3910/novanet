// Package constants provides shared constant values used across multiple
// NovaNet packages, eliminating duplication and ensuring consistency.
package constants

import corev1 "k8s.io/api/core/v1"

// IP protocol numbers used across policy, egress, and service packages.
const (
	ProtocolAny  uint8 = 0
	ProtocolTCP  uint8 = 6
	ProtocolUDP  uint8 = 17
	ProtocolSCTP uint8 = 132
)

// ProtocolToNumber converts a Kubernetes Protocol to its IP protocol number.
func ProtocolToNumber(proto corev1.Protocol) uint32 {
	switch proto {
	case corev1.ProtocolTCP:
		return uint32(ProtocolTCP)
	case corev1.ProtocolUDP:
		return uint32(ProtocolUDP)
	case corev1.ProtocolSCTP:
		return uint32(ProtocolSCTP)
	default:
		return uint32(ProtocolTCP) // default to TCP
	}
}
