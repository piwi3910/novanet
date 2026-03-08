// Package rtypes provides shared type definitions for the routing subsystem
// (BGP/BFD/OSPF via FRR). These replace the protobuf-generated types that
// were previously defined in the NovaRoute gRPC API.
package rtypes

// PeerType indicates whether a BGP peer is internal or external.
type PeerType int32

// PeerType constants for BGP peer classification.
const (
	PeerTypeUnspecified PeerType = 0
	PeerTypeExternal    PeerType = 1
	PeerTypeInternal    PeerType = 2
)

// AddressFamily indicates the BGP address family.
type AddressFamily int32

// AddressFamily constants for BGP address families.
const (
	AddressFamilyUnspecified AddressFamily = 0
	AddressFamilyIPv4Unicast AddressFamily = 1
	AddressFamilyIPv6Unicast AddressFamily = 2
)

// Protocol indicates the routing protocol.
type Protocol int32

// Protocol constants for routing protocol selection.
const (
	ProtocolUnspecified Protocol = 0
	ProtocolBGP         Protocol = 1
	ProtocolOSPF        Protocol = 2
)

// EventType indicates the type of routing event.
type EventType uint32

// EventType constants for routing event classification.
const (
	EventTypeUnspecified       EventType = 0
	EventTypePeerUp            EventType = 1
	EventTypePeerDown          EventType = 2
	EventTypePrefixAdvertised  EventType = 3
	EventTypePrefixWithdrawn   EventType = 4
	EventTypeBFDUp             EventType = 5
	EventTypeBFDDown           EventType = 6
	EventTypeOSPFNeighborUp    EventType = 7
	EventTypeOSPFNeighborDown  EventType = 8
	EventTypeFRRConnected      EventType = 9
	EventTypeFRRDisconnected   EventType = 10
	EventTypeOwnerRegistered   EventType = 11
	EventTypeOwnerDeregistered EventType = 12
	EventTypePolicyViolation   EventType = 13
	EventTypeBGPConfigChanged  EventType = 14
)
