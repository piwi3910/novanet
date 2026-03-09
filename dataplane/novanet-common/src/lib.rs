//! NovaNet common types shared between eBPF programs and the userspace dataplane.
//!
//! All types are `#[repr(C)]` so they can be safely used in eBPF maps from
//! both the aya (userspace) and aya-ebpf (kernel) sides. No external dependencies
//! are required — both libraries work with plain `repr(C)` types natively.

#![cfg_attr(not(feature = "userspace"), no_std)]

// When the "userspace" feature is enabled on Linux, implement aya::Pod for
// all map types so they can be used with aya's HashMap on the userspace side.
#[cfg(all(feature = "userspace", target_os = "linux"))]
macro_rules! impl_pod {
    ($($t:ty),+ $(,)?) => {
        $(
            // SAFETY: All types are #[repr(C)] with only primitive fields,
            // safe to interpret as raw bytes for BPF map operations.
            unsafe impl aya::Pod for $t {}
        )+
    };
}

// ---------------------------------------------------------------------------
// Endpoint map: pod IP → interface + identity info
// ---------------------------------------------------------------------------

/// Key for the endpoint map. Keyed by pod IPv4 address in network byte order.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointKey {
    /// IPv4 address in network byte order.
    pub ip: u32,
}

/// Value stored for each endpoint.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointValue {
    /// Interface index of the pod's veth on the host side.
    pub ifindex: u32,
    /// MAC address of the pod interface.
    pub mac: [u8; 6],
    /// Padding to maintain alignment.
    pub _pad: [u8; 2],
    /// Security identity assigned to this endpoint.
    pub identity: u32,
    /// IPv4 address (network byte order) of the node hosting this pod.
    pub node_ip: u32,
}

// ---------------------------------------------------------------------------
// Endpoint map (IPv6): pod IPv6 → interface + identity info (separate map)
// ---------------------------------------------------------------------------

/// Key for the IPv6 endpoint map. Keyed by pod IPv6 address.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointKeyV6 {
    /// IPv6 address (16 bytes, network byte order).
    pub ip: [u8; 16],
}

/// Value stored for each IPv6 endpoint.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointValueV6 {
    /// Interface index of the pod's veth on the host side.
    pub ifindex: u32,
    /// MAC address of the pod interface.
    pub mac: [u8; 6],
    /// Padding to maintain alignment.
    pub _pad: [u8; 2],
    /// Security identity assigned to this endpoint.
    pub identity: u32,
    /// IPv6 address of the node hosting this pod.
    pub node_ip: [u8; 16],
}

// ---------------------------------------------------------------------------
// Policy map: (src_identity, dst_identity, proto, port) → action
// ---------------------------------------------------------------------------

/// Key for the identity-based policy map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyKey {
    /// Source security identity.
    pub src_identity: u32,
    /// Destination security identity.
    pub dst_identity: u32,
    /// IP protocol number (6=TCP, 17=UDP, etc.).
    pub protocol: u8,
    /// Padding for alignment.
    pub _pad: [u8; 1],
    /// Destination port in host byte order.
    pub dst_port: u16,
}

/// Value for policy entries.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyValue {
    /// Action to take: ACTION_DENY (0) or ACTION_ALLOW (1).
    pub action: u8,
    /// Padding.
    pub _pad: [u8; 3],
}

// ---------------------------------------------------------------------------
// Tunnel map: remote node IP → tunnel interface info
// ---------------------------------------------------------------------------

/// Key for the tunnel map. Keyed by remote node IPv4 address.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunnelKey {
    /// Remote node IPv4 address in network byte order.
    pub node_ip: u32,
}

/// Tunnel endpoint information.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunnelValue {
    /// Interface index of the local tunnel device.
    pub ifindex: u32,
    /// Remote node IPv4 address in network byte order.
    pub remote_ip: u32,
    /// Virtual Network Identifier.
    pub vni: u32,
}

// ---------------------------------------------------------------------------
// Tunnel map (IPv6): remote node IPv6 → tunnel info (separate map)
// ---------------------------------------------------------------------------

/// Key for the IPv6 tunnel map. Keyed by remote node IPv6 address.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunnelKeyV6 {
    /// Remote node IPv6 address (16 bytes).
    pub node_ip: [u8; 16],
}

/// IPv6 tunnel endpoint information.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TunnelValueV6 {
    /// Interface index of the local tunnel device.
    pub ifindex: u32,
    /// Remote node IPv6 address (16 bytes).
    pub remote_ip: [u8; 16],
    /// Virtual Network Identifier.
    pub vni: u32,
}

// ---------------------------------------------------------------------------
// IPCache map: IP/CIDR prefix → security identity (LPM trie)
// ---------------------------------------------------------------------------

/// Key for the IPCache LPM trie map.
/// Uses 128-bit address to handle both IPv4 and IPv6 in a single map.
/// IPv4 addresses are stored as IPv4-mapped-IPv6 (::ffff:x.x.x.x).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IPCacheKey {
    /// LPM trie prefix length in bits (0-128).
    /// For IPv4: actual prefix + 96 (e.g., /24 becomes 120).
    pub prefix_len: u32,
    /// 128-bit address in network byte order.
    /// IPv4 uses last 4 bytes: [0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, a,b,c,d]
    pub addr: [u8; 16],
}

/// Value stored in the IPCache for each prefix.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IPCacheValue {
    /// Security identity assigned to this prefix.
    pub identity: u32,
    /// Flags (reserved for future use: tunnel endpoint, encrypted, etc.).
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// Host firewall policy map: (identity, direction, proto, port) → action (LPM trie)
// ---------------------------------------------------------------------------

/// Key for the host firewall policy LPM trie.
/// Prefix length controls wildcard matching:
///   - Full prefix (64 bits) = exact L4 match on identity + direction + protocol + port
///   - Protocol prefix (48 bits) = identity + direction + protocol, wildcard port
///   - Identity prefix (40 bits) = identity + direction only, wildcard all L4
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPolicyKey {
    /// LPM trie prefix length in bits.
    pub prefix_len: u32,
    /// Security identity of the remote peer.
    pub identity: u32,
    /// Direction: HOST_POLICY_INGRESS (0) or HOST_POLICY_EGRESS (1).
    pub direction: u8,
    /// IP protocol number (6=TCP, 17=UDP, 0=any).
    pub protocol: u8,
    /// Destination port in host byte order.
    pub dst_port: u16,
}

/// Value for a host firewall policy entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostPolicyValue {
    /// Action: ACTION_DENY (0) or ACTION_ALLOW (1).
    pub action: u8,
    /// Padding.
    pub _pad: [u8; 3],
}

// ---------------------------------------------------------------------------
// Egress policy map: (src_identity, dst_cidr) → action + optional SNAT
// ---------------------------------------------------------------------------

/// Key for egress policy lookups.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressKey {
    /// Source security identity.
    pub src_identity: u32,
    /// Destination IPv4 address (network prefix) in network byte order.
    pub dst_ip: u32,
    /// Prefix length for CIDR matching.
    pub dst_prefix_len: u8,
    /// Padding.
    pub _pad: [u8; 3],
}

/// Egress policy action.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressValue {
    /// Action: EGRESS_DENY (0), EGRESS_ALLOW (1), EGRESS_SNAT (2).
    pub action: u8,
    /// Padding.
    pub _pad: [u8; 3],
    /// Source NAT IPv4 address (only used when action == EGRESS_SNAT).
    pub snat_ip: u32,
}

// ---------------------------------------------------------------------------
// Egress policy map (IPv6): separate map for IPv6 destinations
// ---------------------------------------------------------------------------

/// Key for IPv6 egress policy lookups.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressKeyV6 {
    /// Source security identity.
    pub src_identity: u32,
    /// Destination IPv6 address (network prefix).
    pub dst_ip: [u8; 16],
    /// Prefix length for CIDR matching.
    pub dst_prefix_len: u8,
    /// Padding.
    pub _pad: [u8; 3],
}

/// IPv6 egress policy action.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressValueV6 {
    /// Action: EGRESS_DENY (0), EGRESS_ALLOW (1), EGRESS_SNAT (2).
    pub action: u8,
    /// Padding.
    pub _pad: [u8; 3],
    /// Source NAT IPv6 address (only used when action == EGRESS_SNAT).
    pub snat_ip: [u8; 16],
}

// ---------------------------------------------------------------------------
// Service map: Service VIP → backend selection info
// ---------------------------------------------------------------------------

/// Key for the service map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceKey {
    /// Service virtual IP in network byte order (0 for NodePort scope).
    pub ip: u32,
    /// Service port in host byte order.
    pub port: u16,
    /// IP protocol (6=TCP, 17=UDP, 132=SCTP).
    pub protocol: u8,
    /// Service scope: 0=ClusterIP, 1=NodePort, 2=ExternalIP, 3=LoadBalancer.
    pub scope: u8,
}

/// Value stored for each service.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceValue {
    /// Number of backends for this service.
    pub backend_count: u16,
    /// Starting index in the BACKENDS array.
    pub backend_offset: u16,
    /// Backend selection algorithm: 0=random, 1=round-robin, 2=maglev.
    pub algorithm: u8,
    /// Flags: bit 0 = session affinity, bit 1 = externalTrafficPolicy=Local.
    pub flags: u8,
    /// Session affinity timeout in seconds (0 = disabled).
    pub affinity_timeout: u16,
    /// Offset into MAGLEV lookup table (only when algorithm=2).
    pub maglev_offset: u32,
}

// ---------------------------------------------------------------------------
// Service map (IPv6): IPv6 Service VIP → backend selection info (separate map)
// ---------------------------------------------------------------------------

/// Key for the IPv6 service map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceKeyV6 {
    /// Service virtual IPv6 address.
    pub ip: [u8; 16],
    /// Service port in host byte order.
    pub port: u16,
    /// IP protocol (6=TCP, 17=UDP, 132=SCTP).
    pub protocol: u8,
    /// Service scope: 0=ClusterIP, 1=NodePort, 2=ExternalIP, 3=LoadBalancer.
    pub scope: u8,
}

// ---------------------------------------------------------------------------
// Backend map: flat array of backend endpoints
// ---------------------------------------------------------------------------

/// Backend endpoint entry (stored in a flat array, indexed by offset + selection).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendValue {
    /// Backend pod IPv4 address in network byte order.
    pub ip: u32,
    /// Backend target port in host byte order.
    pub port: u16,
    /// Padding for alignment.
    pub _pad: [u8; 2],
    /// Node IP hosting this backend (for externalTrafficPolicy: Local).
    pub node_ip: u32,
}

// ---------------------------------------------------------------------------
// Backend map (IPv6): flat array of IPv6 backend endpoints
// ---------------------------------------------------------------------------

/// IPv6 backend endpoint entry (stored in a flat array).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackendValueV6 {
    /// Backend pod IPv6 address.
    pub ip: [u8; 16],
    /// Backend target port in host byte order.
    pub port: u16,
    /// Padding for alignment.
    pub _pad: [u8; 2],
    /// Node IPv6 address hosting this backend.
    pub node_ip: [u8; 16],
}

// ---------------------------------------------------------------------------
// Conntrack map: connection tracking for NAT state
// ---------------------------------------------------------------------------

/// Key for the conntrack LRU map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtKey {
    /// Source IPv4 address in network byte order.
    pub src_ip: u32,
    /// Destination IPv4 address in network byte order (the original VIP).
    pub dst_ip: u32,
    /// Source port in host byte order.
    pub src_port: u16,
    /// Destination port in host byte order.
    pub dst_port: u16,
    /// IP protocol (6=TCP, 17=UDP).
    pub protocol: u8,
    /// Padding for alignment.
    pub _pad: [u8; 3],
}

/// Value stored in the conntrack map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtValue {
    /// Timestamp (bpf_ktime_get_ns, for session affinity).
    pub timestamp: u64,
    /// DNAT'd backend IP in network byte order.
    pub backend_ip: u32,
    /// Original service VIP in network byte order (for reverse SNAT).
    pub origin_ip: u32,
    /// DNAT'd backend port in host byte order.
    pub backend_port: u16,
    /// Original service port in host byte order (for reverse SNAT).
    pub origin_port: u16,
    /// TCP state flags for connection tracking.
    pub flags: u8,
    /// Padding.
    pub _pad: u8,
    /// Padding for alignment.
    pub _pad2: [u8; 2],
}

// ---------------------------------------------------------------------------
// Conntrack map (IPv6): connection tracking for IPv6 NAT state
// ---------------------------------------------------------------------------

/// Key for the IPv6 conntrack LRU map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtKeyV6 {
    /// Source IPv6 address.
    pub src_ip: [u8; 16],
    /// Destination IPv6 address (the original VIP).
    pub dst_ip: [u8; 16],
    /// Source port in host byte order.
    pub src_port: u16,
    /// Destination port in host byte order.
    pub dst_port: u16,
    /// IP protocol (6=TCP, 17=UDP).
    pub protocol: u8,
    /// Padding for alignment.
    pub _pad: [u8; 3],
}

/// Value stored in the IPv6 conntrack map.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CtValueV6 {
    /// Timestamp (bpf_ktime_get_ns, for session affinity).
    pub timestamp: u64,
    /// DNAT'd backend IPv6 address.
    pub backend_ip: [u8; 16],
    /// Original service VIP IPv6 address (for reverse SNAT).
    pub origin_ip: [u8; 16],
    /// DNAT'd backend port in host byte order.
    pub backend_port: u16,
    /// Original service port in host byte order (for reverse SNAT).
    pub origin_port: u16,
    /// TCP state flags for connection tracking.
    pub flags: u8,
    /// Padding.
    pub _pad: u8,
    /// Padding for alignment.
    pub _pad2: [u8; 2],
}

// ---------------------------------------------------------------------------
// Socket-LB origin map: socket cookie → original service destination
// ---------------------------------------------------------------------------

/// Stores the original ClusterIP destination before socket-LB rewrites it.
/// Used by recvmsg4/getpeername4 to reverse-translate back to the VIP.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockLbOrigin {
    /// Original service ClusterIP in network byte order.
    pub original_ip: u32,
    /// Original service port in host byte order.
    pub original_port: u16,
    /// IP protocol (6=TCP, 17=UDP).
    pub protocol: u8,
    /// Padding for alignment.
    pub _pad: u8,
}

// ---------------------------------------------------------------------------
// Socket-LB origin map (IPv6): socket cookie → original IPv6 service destination
// ---------------------------------------------------------------------------

/// Stores the original ClusterIP IPv6 destination before socket-LB rewrites it.
/// Used by recvmsg6/getpeername6 to reverse-translate back to the VIP.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockLbOriginV6 {
    /// Original service ClusterIP IPv6 address.
    pub original_ip: [u8; 16],
    /// Original service port in host byte order.
    pub original_port: u16,
    /// IP protocol (6=TCP, 17=UDP).
    pub protocol: u8,
    /// Padding for alignment.
    pub _pad: u8,
}

// ---------------------------------------------------------------------------
// Flow event: emitted to ring buffer for observability
// ---------------------------------------------------------------------------

/// Flow event emitted from eBPF programs to the ring buffer.
/// Uses 128-bit addresses to support both IPv4 and IPv6 in a single ring buffer.
/// The `family` field indicates AF_INET (2) or AF_INET6 (10).
/// For IPv4, the address is stored in the first 4 bytes of the 16-byte field.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowEvent {
    /// Address family: AF_INET (2) for IPv4, AF_INET6 (10) for IPv6.
    pub family: u8,
    /// Policy verdict: ACTION_DENY (0), ACTION_ALLOW (1).
    pub verdict: u8,
    /// Drop reason (non-zero if dropped). See DROP_REASON_* constants.
    pub drop_reason: u8,
    /// TCP flags (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04). Zero for non-TCP.
    pub tcp_flags: u8,
    /// Source security identity.
    pub src_identity: u32,
    /// Destination security identity.
    pub dst_identity: u32,
    /// IP protocol number.
    pub protocol: u8,
    /// Padding.
    pub _pad1: u8,
    /// Source port in host byte order.
    pub src_port: u16,
    /// Destination port in host byte order.
    pub dst_port: u16,
    /// Padding.
    pub _pad2: [u8; 2],
    /// Source IP address (4 bytes for IPv4 in first 4 bytes, or 16 bytes for IPv6).
    pub src_ip: [u8; 16],
    /// Destination IP address (4 bytes for IPv4 in first 4 bytes, or 16 bytes for IPv6).
    pub dst_ip: [u8; 16],
    /// Bytes in this flow.
    pub bytes: u64,
    /// Packets in this flow.
    pub packets: u64,
    /// Kernel timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

/// Address family constant: IPv4.
pub const AF_INET: u8 = 2;
/// Address family constant: IPv6.
pub const AF_INET6: u8 = 10;

// ---------------------------------------------------------------------------
// Config map keys (CONFIG map is HashMap<u32, u64>)
// ---------------------------------------------------------------------------

/// Routing mode: 0 = overlay, 1 = native.
pub const CONFIG_KEY_MODE: u32 = 0;
/// Tunnel type: 0 = Geneve, 1 = VXLAN.
pub const CONFIG_KEY_TUNNEL_TYPE: u32 = 1;
/// This node's IPv4 address in network byte order (stored as u64, use lower 32 bits).
pub const CONFIG_KEY_NODE_IP: u32 = 2;
/// Cluster CIDR IPv4 base address in network byte order (lower 32 bits of u64).
pub const CONFIG_KEY_CLUSTER_CIDR_IP: u32 = 3;
/// Cluster CIDR prefix length (e.g. 16 for /16).
pub const CONFIG_KEY_CLUSTER_CIDR_PREFIX_LEN: u32 = 4;
/// Default deny flag: 0 = default allow (Kubernetes default), 1 = default deny.
pub const CONFIG_KEY_DEFAULT_DENY: u32 = 5;
/// Masquerade enabled: 0 = off, 1 = on. Applies SNAT to traffic leaving the cluster.
pub const CONFIG_KEY_MASQUERADE_ENABLED: u32 = 6;
/// SNAT IPv4 address in network byte order (lower 32 bits of u64).
pub const CONFIG_KEY_SNAT_IP: u32 = 7;
/// Pod CIDR IPv4 base address in network byte order (lower 32 bits of u64).
pub const CONFIG_KEY_POD_CIDR_IP: u32 = 8;
/// Pod CIDR prefix length (e.g. 24 for /24).
pub const CONFIG_KEY_POD_CIDR_PREFIX_LEN: u32 = 9;
/// L4 LB enabled: 0 = off, 1 = on.
pub const CONFIG_KEY_L4LB_ENABLED: u32 = 10;

// IPv6 config keys (128-bit addresses stored across two consecutive u64 entries).
// For each IPv6 address: key N = upper 64 bits, key N+1 = lower 64 bits.

/// This node's IPv6 address, upper 64 bits.
pub const CONFIG_KEY_NODE_IPV6_HI: u32 = 20;
/// This node's IPv6 address, lower 64 bits.
pub const CONFIG_KEY_NODE_IPV6_LO: u32 = 21;
/// Cluster CIDR IPv6 base address, upper 64 bits.
pub const CONFIG_KEY_CLUSTER_CIDR_IPV6_HI: u32 = 22;
/// Cluster CIDR IPv6 base address, lower 64 bits.
pub const CONFIG_KEY_CLUSTER_CIDR_IPV6_LO: u32 = 23;
/// Cluster CIDR IPv6 prefix length (e.g. 48 for /48).
pub const CONFIG_KEY_CLUSTER_CIDR_PREFIX_V6: u32 = 24;
/// Pod CIDR IPv6 base address, upper 64 bits.
pub const CONFIG_KEY_POD_CIDR_IPV6_HI: u32 = 25;
/// Pod CIDR IPv6 base address, lower 64 bits.
pub const CONFIG_KEY_POD_CIDR_IPV6_LO: u32 = 26;
/// Pod CIDR IPv6 prefix length (e.g. 64 for /64).
pub const CONFIG_KEY_POD_CIDR_PREFIX_V6: u32 = 27;
/// SNAT IPv6 address, upper 64 bits.
pub const CONFIG_KEY_SNAT_IPV6_HI: u32 = 28;
/// SNAT IPv6 address, lower 64 bits.
pub const CONFIG_KEY_SNAT_IPV6_LO: u32 = 29;
/// IPv6 enabled: 0 = off, 1 = on.
pub const CONFIG_KEY_IPV6_ENABLED: u32 = 30;

// ---------------------------------------------------------------------------
// Action constants
// ---------------------------------------------------------------------------

/// Deny action — drop the packet.
pub const ACTION_DENY: u8 = 0;
/// Allow action — let the packet through.
pub const ACTION_ALLOW: u8 = 1;

// ---------------------------------------------------------------------------
// Egress action constants
// ---------------------------------------------------------------------------

/// Deny egress traffic.
pub const EGRESS_DENY: u8 = 0;
/// Allow egress traffic without modification.
pub const EGRESS_ALLOW: u8 = 1;
/// Allow egress traffic with source NAT.
pub const EGRESS_SNAT: u8 = 2;

// ---------------------------------------------------------------------------
// Service scope constants
// ---------------------------------------------------------------------------

/// ClusterIP service scope.
pub const SVC_SCOPE_CLUSTER_IP: u8 = 0;
/// NodePort service scope.
pub const SVC_SCOPE_NODE_PORT: u8 = 1;
/// ExternalIP service scope.
pub const SVC_SCOPE_EXTERNAL_IP: u8 = 2;
/// LoadBalancer service scope.
pub const SVC_SCOPE_LOAD_BALANCER: u8 = 3;

// ---------------------------------------------------------------------------
// Backend selection algorithm constants
// ---------------------------------------------------------------------------

/// Random backend selection (hash of 5-tuple).
pub const LB_ALG_RANDOM: u8 = 0;
/// Round-robin backend selection.
pub const LB_ALG_ROUND_ROBIN: u8 = 1;
/// Maglev consistent hashing.
pub const LB_ALG_MAGLEV: u8 = 2;

// ---------------------------------------------------------------------------
// Service flags
// ---------------------------------------------------------------------------

/// Session affinity enabled.
pub const SVC_FLAG_AFFINITY: u8 = 0x01;
/// externalTrafficPolicy: Local.
pub const SVC_FLAG_EXT_LOCAL: u8 = 0x02;

// ---------------------------------------------------------------------------
// Routing mode constants
// ---------------------------------------------------------------------------

/// Overlay routing mode: traffic between nodes goes through a tunnel.
pub const MODE_OVERLAY: u64 = 0;
/// Native routing mode: traffic between nodes is routed natively (via NovaRoute).
pub const MODE_NATIVE: u64 = 1;

// ---------------------------------------------------------------------------
// Tunnel type constants
// ---------------------------------------------------------------------------

/// Geneve tunnel (default). Identity carried in TLV option.
pub const TUNNEL_GENEVE: u64 = 0;
/// VXLAN tunnel (fallback). Identity resolved via endpoint map lookup.
pub const TUNNEL_VXLAN: u64 = 1;

// ---------------------------------------------------------------------------
// Drop reason constants (indices into DROP_COUNTERS per-CPU array)
// ---------------------------------------------------------------------------

/// No drop — packet was forwarded successfully.
pub const DROP_REASON_NONE: u8 = 0;
/// Dropped by policy (explicit deny rule matched).
pub const DROP_REASON_POLICY_DENIED: u8 = 1;
/// Dropped because source identity could not be resolved.
pub const DROP_REASON_NO_IDENTITY: u8 = 2;
/// Dropped because no route was found for the destination.
pub const DROP_REASON_NO_ROUTE: u8 = 3;
/// Dropped because no tunnel entry exists for the remote node.
pub const DROP_REASON_NO_TUNNEL: u8 = 4;
/// Dropped because IP TTL reached zero.
pub const DROP_REASON_TTL_EXCEEDED: u8 = 5;
/// Dropped by per-source-IP rate limiter.
pub const DROP_REASON_RATE_LIMITED: u8 = 6;
/// Total number of drop reasons (array size).
pub const DROP_REASON_MAX: u32 = 16;

// ---------------------------------------------------------------------------
// TC action return codes (from linux/pkt_cls.h)
// ---------------------------------------------------------------------------

/// TC_ACT_OK — accept the packet.
pub const TC_ACT_OK: i32 = 0;
/// TC_ACT_SHOT — drop the packet.
pub const TC_ACT_SHOT: i32 = 2;
/// TC_ACT_REDIRECT — redirect the packet (used with bpf_redirect).
pub const TC_ACT_REDIRECT: i32 = 7;

// ---------------------------------------------------------------------------
// Geneve TLV option class for NovaNet identity
// ---------------------------------------------------------------------------

/// Geneve option class for NovaNet (using experimental range 0xFFxx).
pub const GENEVE_OPT_CLASS_NOVANET: u16 = 0xFF01;
/// Geneve option type for security identity.
pub const GENEVE_OPT_TYPE_IDENTITY: u8 = 0x01;
/// Length of the identity TLV value in 4-byte multiples (1 = 4 bytes for u32).
pub const GENEVE_OPT_IDENTITY_LEN: u8 = 1;

// ---------------------------------------------------------------------------
// Network constants
// ---------------------------------------------------------------------------

/// Ethernet header size in bytes.
pub const ETH_HLEN: usize = 14;
/// IPv4 header minimum size in bytes.
pub const IPV4_HLEN_MIN: usize = 20;
/// IPv6 header size in bytes (fixed, no options in base header).
pub const IPV6_HLEN: usize = 40;
/// UDP header size in bytes.
pub const UDP_HLEN: usize = 8;
/// Geneve base header size in bytes (without options).
pub const GENEVE_HLEN: usize = 8;
/// Geneve identity TLV option size: 4 (header) + 4 (identity u32) = 8 bytes.
pub const GENEVE_IDENTITY_OPT_SIZE: usize = 8;
/// Geneve UDP destination port.
pub const GENEVE_PORT: u16 = 6081;
/// VXLAN UDP destination port.
pub const VXLAN_PORT: u16 = 4789;
/// VXLAN header size in bytes.
pub const VXLAN_HLEN: usize = 8;

// ---------------------------------------------------------------------------
// Map sizes
// ---------------------------------------------------------------------------

/// Maximum entries in the endpoint map.
pub const MAX_ENDPOINTS: u32 = 65536;
/// Maximum entries in the policy map.
pub const MAX_POLICIES: u32 = 65536;
/// Maximum entries in the tunnel map.
pub const MAX_TUNNELS: u32 = 1024;
/// Maximum entries in the egress policy map.
pub const MAX_EGRESS_POLICIES: u32 = 16384;
/// Maximum entries in the config map.
pub const MAX_CONFIG_ENTRIES: u32 = 32;
/// Size of the flow events ring buffer in bytes (8 MiB).
pub const FLOW_RING_BUF_SIZE: u32 = 8 * 1024 * 1024;
/// Maximum entries in the service map.
pub const MAX_SERVICES: u32 = 16384;
/// Maximum entries in the backend array.
pub const MAX_BACKENDS: u32 = 65536;
/// Maximum entries in the conntrack LRU map.
pub const MAX_CONNTRACK: u32 = 524288;
/// Maximum entries in the Maglev lookup table.
pub const MAX_MAGLEV: u32 = 1048576;
/// Maglev lookup table size per service.
pub const MAGLEV_TABLE_SIZE: u32 = 65537;
/// Maximum entries in the socket-LB origin tracking map.
pub const MAX_SOCK_LB_ORIGINS: u32 = 131072;
/// Maximum entries in the host firewall policy map.
pub const MAX_HOST_POLICIES: u32 = 16384;
/// Maximum entries in the IPCache map.
pub const MAX_IPCACHE_ENTRIES: u32 = 512000;

// ---------------------------------------------------------------------------
// Host policy direction constants
// ---------------------------------------------------------------------------

/// Host policy direction: ingress (traffic arriving at the host).
pub const HOST_POLICY_INGRESS: u8 = 0;
/// Host policy direction: egress (traffic leaving the host).
pub const HOST_POLICY_EGRESS: u8 = 1;

// ---------------------------------------------------------------------------
// Host policy prefix length constants
// ---------------------------------------------------------------------------

/// Full prefix length for host policy key (covers all fields after prefix_len).
/// identity(32) + direction(8) + protocol(8) + dst_port(16) = 64 bits.
pub const HOST_POLICY_FULL_PREFIX: u32 = 64;
/// Prefix covering identity + direction only (wildcard protocol + port).
pub const HOST_POLICY_IDENTITY_PREFIX: u32 = 40;
/// Prefix covering identity + direction + protocol (wildcard port).
pub const HOST_POLICY_PROTO_PREFIX: u32 = 48;

// ---------------------------------------------------------------------------
// Reserved identity constants
// ---------------------------------------------------------------------------

/// Reserved identity for the host node itself.
pub const IDENTITY_HOST: u32 = 1;
/// Reserved identity for the world (external traffic, default for unknown CIDRs).
pub const IDENTITY_WORLD: u32 = 2;

// ---------------------------------------------------------------------------
// SOCKMAP types
// ---------------------------------------------------------------------------

/// Key for SOCKMAP socket lookup — identifies a connection by 4-tuple + family.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SockKey {
    /// Source IPv4 address in network byte order.
    pub src_ip: u32,
    /// Destination IPv4 address in network byte order.
    pub dst_ip: u32,
    /// Source port in host byte order.
    pub src_port: u16,
    /// Destination port in host byte order.
    pub dst_port: u16,
    /// Address family (AF_INET=2, AF_INET6=10).
    pub family: u32,
}

/// Key for SOCKMAP endpoint registration — identifies a listening socket.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SockmapEndpointKey {
    /// IPv4 address in network byte order.
    pub ip: u32,
    /// Port (stored as u32 for alignment).
    pub port: u32,
}

// ---------------------------------------------------------------------------
// Mesh redirect types
// ---------------------------------------------------------------------------

/// Key for mesh service redirect map — identifies a service to intercept.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct MeshServiceKey {
    /// Service IPv4 address in network byte order.
    pub ip: u32,
    /// Service port (stored as u32 for alignment).
    pub port: u32,
}

/// Value for mesh service redirect — where to redirect traffic.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MeshRedirectValue {
    /// Port to redirect traffic to (e.g. sidecar proxy port).
    pub redirect_port: u32,
}

// ---------------------------------------------------------------------------
// Rate limiting types
// ---------------------------------------------------------------------------

/// Key for rate limit map — identifies a source by IPv4-mapped IPv6 address.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RateLimitKey {
    /// IPv4-mapped IPv6 address (16 bytes).
    pub addr: [u8; 16],
}

/// Per-source token bucket state for rate limiting.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct TokenBucketState {
    /// Current number of tokens available.
    pub tokens: u64,
    /// Timestamp (nanoseconds) of last token refill.
    pub last_refill_ns: u64,
}

/// Global rate limit configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RateLimitConfig {
    /// Tokens added per window.
    pub rate: u32,
    /// Maximum burst size.
    pub burst: u32,
    /// Window duration in nanoseconds.
    pub window_ns: u64,
}

// ---------------------------------------------------------------------------
// Backend health types
// ---------------------------------------------------------------------------

/// Key for backend health counters — identifies a backend by IP + port.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BackendHealthKey {
    /// Backend IPv4 address in network byte order.
    pub ip: u32,
    /// Backend port (stored as u32 for alignment).
    pub port: u32,
}

/// Per-backend connection health counters maintained in eBPF.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendHealthCounters {
    /// Total connection attempts.
    pub total_conns: u64,
    /// Failed connection attempts.
    pub failed_conns: u64,
    /// Timed-out connections.
    pub timeout_conns: u64,
    /// Successful connections.
    pub success_conns: u64,
    /// Timestamp (ns) of last successful connection.
    pub last_success_ns: u64,
    /// Timestamp (ns) of last failed connection.
    pub last_failure_ns: u64,
    /// Cumulative RTT in nanoseconds (divide by success_conns for average).
    pub total_rtt_ns: u64,
}

// ---------------------------------------------------------------------------
// IPv4/IPv6 address helpers
// ---------------------------------------------------------------------------

/// Convert a 4-byte IPv4 address to a `u32` in network byte order.
pub fn ipv4_to_u32(bytes: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*bytes)
}

/// Convert a `u32` in network byte order to 4 IPv4 bytes.
pub fn u32_to_ipv4(ip: u32) -> [u8; 4] {
    ip.to_be_bytes()
}

/// Split a 16-byte IPv6 address into upper and lower `u64` halves (big-endian).
/// Used for storing IPv6 addresses in the config map across two consecutive keys.
pub fn ipv6_to_u64_pair(addr: &[u8; 16]) -> (u64, u64) {
    let hi = u64::from_be_bytes([
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
    ]);
    let lo = u64::from_be_bytes([
        addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15],
    ]);
    (hi, lo)
}

/// Reconstruct a 16-byte IPv6 address from upper and lower `u64` halves.
pub fn u64_pair_to_ipv6(hi: u64, lo: u64) -> [u8; 16] {
    let h = hi.to_be_bytes();
    let l = lo.to_be_bytes();
    [
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], l[0], l[1], l[2], l[3], l[4], l[5], l[6],
        l[7],
    ]
}

// ---------------------------------------------------------------------------
// aya::Pod implementations for userspace map access
// ---------------------------------------------------------------------------

#[cfg(all(feature = "userspace", target_os = "linux"))]
impl_pod!(
    EndpointKey,
    EndpointValue,
    EndpointKeyV6,
    EndpointValueV6,
    PolicyKey,
    PolicyValue,
    TunnelKey,
    TunnelValue,
    TunnelKeyV6,
    TunnelValueV6,
    EgressKey,
    EgressValue,
    EgressKeyV6,
    EgressValueV6,
    ServiceKey,
    ServiceKeyV6,
    ServiceValue,
    BackendValue,
    BackendValueV6,
    CtKey,
    CtValue,
    CtKeyV6,
    CtValueV6,
    SockLbOrigin,
    SockLbOriginV6,
    IPCacheKey,
    IPCacheValue,
    HostPolicyKey,
    HostPolicyValue,
    SockKey,
    SockmapEndpointKey,
    MeshServiceKey,
    MeshRedirectValue,
    RateLimitKey,
    TokenBucketState,
    RateLimitConfig,
    BackendHealthKey,
    BackendHealthCounters,
);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(all(test, feature = "userspace"))]
mod tests {
    use super::*;
    use core::mem;

    // -- Type size tests (critical for eBPF map compatibility) --

    #[test]
    fn endpoint_key_size() {
        assert_eq!(mem::size_of::<EndpointKey>(), 4);
    }

    #[test]
    fn endpoint_value_size() {
        // ifindex(4) + mac(6) + pad(2) + identity(4) + node_ip(4) = 20
        assert_eq!(mem::size_of::<EndpointValue>(), 20);
    }

    #[test]
    fn policy_key_size() {
        // src_identity(4) + dst_identity(4) + protocol(1) + pad(1) + dst_port(2) = 12
        assert_eq!(mem::size_of::<PolicyKey>(), 12);
    }

    #[test]
    fn policy_value_size() {
        // action(1) + pad(3) = 4
        assert_eq!(mem::size_of::<PolicyValue>(), 4);
    }

    #[test]
    fn tunnel_key_size() {
        assert_eq!(mem::size_of::<TunnelKey>(), 4);
    }

    #[test]
    fn tunnel_value_size() {
        // ifindex(4) + remote_ip(4) + vni(4) = 12
        assert_eq!(mem::size_of::<TunnelValue>(), 12);
    }

    #[test]
    fn egress_key_size() {
        // src_identity(4) + dst_ip(4) + dst_prefix_len(1) + pad(3) = 12
        assert_eq!(mem::size_of::<EgressKey>(), 12);
    }

    #[test]
    fn egress_value_size() {
        // action(1) + pad(3) + snat_ip(4) = 8
        assert_eq!(mem::size_of::<EgressValue>(), 8);
    }

    #[test]
    fn service_key_size() {
        assert_eq!(mem::size_of::<ServiceKey>(), 8);
    }

    #[test]
    fn service_value_size() {
        assert_eq!(mem::size_of::<ServiceValue>(), 12);
    }

    #[test]
    fn backend_value_size() {
        assert_eq!(mem::size_of::<BackendValue>(), 12);
    }

    #[test]
    fn ct_key_size() {
        assert_eq!(mem::size_of::<CtKey>(), 16);
    }

    #[test]
    fn ct_value_size() {
        // timestamp(8) + backend_ip(4) + origin_ip(4) + backend_port(2) + origin_port(2) + flags(1) + pad(1) + pad2(2) = 24
        assert_eq!(mem::size_of::<CtValue>(), 24);
    }

    #[test]
    fn flow_event_size() {
        // family(1)+verdict(1)+drop_reason(1)+tcp_flags(1) + src_identity(4)+dst_identity(4)
        // + protocol(1)+pad(1)+src_port(2)+dst_port(2)+pad(2)
        // + src_ip(16)+dst_ip(16) + bytes(8)+packets(8)+timestamp(8) = 76
        // But with u64 alignment, there may be padding. Let's just verify it's reasonable.
        let size = mem::size_of::<FlowEvent>();
        assert_eq!(size, 80); // 4+4+4 + 1+1+2+2+2 + 16+16 + 8+8+8 = 76, aligned to 8 → 80
    }

    // -- Alignment tests (repr(C) types must be naturally aligned) --

    #[test]
    fn endpoint_key_alignment() {
        assert_eq!(mem::align_of::<EndpointKey>(), 4);
    }

    #[test]
    fn endpoint_value_alignment() {
        assert_eq!(mem::align_of::<EndpointValue>(), 4);
    }

    #[test]
    fn policy_key_alignment() {
        assert_eq!(mem::align_of::<PolicyKey>(), 4);
    }

    #[test]
    fn flow_event_alignment() {
        // Contains u64 fields (bytes, packets, timestamp_ns), so alignment should be 8.
        assert_eq!(mem::align_of::<FlowEvent>(), 8);
    }

    #[test]
    fn service_key_alignment() {
        assert_eq!(mem::align_of::<ServiceKey>(), 4);
    }

    #[test]
    fn service_value_alignment() {
        assert_eq!(mem::align_of::<ServiceValue>(), 4);
    }

    #[test]
    fn backend_value_alignment() {
        assert_eq!(mem::align_of::<BackendValue>(), 4);
    }

    #[test]
    fn ct_key_alignment() {
        assert_eq!(mem::align_of::<CtKey>(), 4);
    }

    #[test]
    fn ct_value_alignment() {
        assert_eq!(mem::align_of::<CtValue>(), 8);
    }

    // -- Type construction and field access --

    #[test]
    fn endpoint_key_roundtrip() {
        let key = EndpointKey { ip: 0x0A2A0501 };
        assert_eq!(key.ip, 0x0A2A0501);
        let copy = key;
        assert_eq!(key, copy);
    }

    #[test]
    fn endpoint_value_mac_and_identity() {
        let val = EndpointValue {
            ifindex: 42,
            mac: [0x02, 0xfe, 0x0a, 0x2a, 0x05, 0x01],
            _pad: [0; 2],
            identity: 100,
            node_ip: 0xC0A86411, // 192.168.100.17
        };
        assert_eq!(val.ifindex, 42);
        assert_eq!(val.mac[0], 0x02);
        assert_eq!(val.identity, 100);
        assert_eq!(val.node_ip, 0xC0A86411);
    }

    #[test]
    fn policy_key_fields() {
        let key = PolicyKey {
            src_identity: 1,
            dst_identity: 2,
            protocol: 6, // TCP
            _pad: [0],
            dst_port: 80,
        };
        assert_eq!(key.src_identity, 1);
        assert_eq!(key.dst_identity, 2);
        assert_eq!(key.protocol, 6);
        assert_eq!(key.dst_port, 80);
    }

    #[test]
    fn policy_value_allow_deny() {
        let allow = PolicyValue {
            action: ACTION_ALLOW,
            _pad: [0; 3],
        };
        let deny = PolicyValue {
            action: ACTION_DENY,
            _pad: [0; 3],
        };
        assert_eq!(allow.action, 1);
        assert_eq!(deny.action, 0);
        assert_ne!(allow, deny);
    }

    #[test]
    fn tunnel_value_fields() {
        let val = TunnelValue {
            ifindex: 10,
            remote_ip: 0xC0A86416, // 192.168.100.22
            vni: 1,
        };
        assert_eq!(val.ifindex, 10);
        assert_eq!(val.remote_ip, 0xC0A86416);
        assert_eq!(val.vni, 1);
    }

    #[test]
    fn egress_key_cidr_fields() {
        let key = EgressKey {
            src_identity: 5,
            dst_ip: 0x08080000, // 8.8.0.0
            dst_prefix_len: 16,
            _pad: [0; 3],
        };
        assert_eq!(key.src_identity, 5);
        assert_eq!(key.dst_prefix_len, 16);
    }

    #[test]
    fn egress_value_snat() {
        let val = EgressValue {
            action: EGRESS_SNAT,
            _pad: [0; 3],
            snat_ip: 0xC0A86401, // 192.168.100.1
        };
        assert_eq!(val.action, 2);
        assert_eq!(val.snat_ip, 0xC0A86401);
    }

    #[test]
    fn service_key_construction() {
        let key = ServiceKey {
            ip: 0x0A2B6449, // 10.43.100.73
            port: 8080,
            protocol: 6, // TCP
            scope: SVC_SCOPE_CLUSTER_IP,
        };
        assert_eq!(key.ip, 0x0A2B6449);
        assert_eq!(key.port, 8080);
        assert_eq!(key.protocol, 6);
        assert_eq!(key.scope, SVC_SCOPE_CLUSTER_IP);
    }

    #[test]
    fn ct_key_construction() {
        let key = CtKey {
            src_ip: 0x0A2A0401,
            dst_ip: 0x0A2B6449,
            src_port: 45678,
            dst_port: 8080,
            protocol: 6,
            _pad: [0; 3],
        };
        assert_eq!(key.src_ip, 0x0A2A0401);
        assert_eq!(key.dst_port, 8080);
    }

    #[test]
    fn flow_event_construction_v4() {
        let mut src = [0u8; 16];
        src[0..4].copy_from_slice(&[10, 42, 5, 1]);
        let mut dst = [0u8; 16];
        dst[0..4].copy_from_slice(&[10, 42, 5, 2]);
        let event = FlowEvent {
            family: AF_INET,
            verdict: ACTION_ALLOW,
            drop_reason: DROP_REASON_NONE,
            tcp_flags: 0,
            src_identity: 10,
            dst_identity: 20,
            protocol: 6,
            _pad1: 0,
            src_port: 12345,
            dst_port: 80,
            _pad2: [0; 2],
            src_ip: src,
            dst_ip: dst,
            bytes: 1500,
            packets: 1,
            timestamp_ns: 123456789,
        };
        assert_eq!(event.family, AF_INET);
        assert_eq!(event.src_ip[0], 10);
        assert_eq!(event.protocol, 6);
        assert_eq!(event.verdict, ACTION_ALLOW);
    }

    #[test]
    fn flow_event_construction_v6() {
        let src = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let event = FlowEvent {
            family: AF_INET6,
            verdict: ACTION_ALLOW,
            drop_reason: DROP_REASON_NONE,
            tcp_flags: 0,
            src_identity: 10,
            dst_identity: 20,
            protocol: 6,
            _pad1: 0,
            src_port: 12345,
            dst_port: 80,
            _pad2: [0; 2],
            src_ip: src,
            dst_ip: dst,
            bytes: 1500,
            packets: 1,
            timestamp_ns: 123456789,
        };
        assert_eq!(event.family, AF_INET6);
        assert_eq!(event.src_ip[0], 0xfd);
        assert_eq!(event.dst_ip[15], 2);
    }

    // -- Constant value tests --

    #[test]
    fn config_keys_are_sequential() {
        assert_eq!(CONFIG_KEY_MODE, 0);
        assert_eq!(CONFIG_KEY_TUNNEL_TYPE, 1);
        assert_eq!(CONFIG_KEY_NODE_IP, 2);
        assert_eq!(CONFIG_KEY_CLUSTER_CIDR_IP, 3);
        assert_eq!(CONFIG_KEY_CLUSTER_CIDR_PREFIX_LEN, 4);
        assert_eq!(CONFIG_KEY_DEFAULT_DENY, 5);
        assert_eq!(CONFIG_KEY_MASQUERADE_ENABLED, 6);
        assert_eq!(CONFIG_KEY_SNAT_IP, 7);
        assert_eq!(CONFIG_KEY_POD_CIDR_IP, 8);
        assert_eq!(CONFIG_KEY_POD_CIDR_PREFIX_LEN, 9);
        assert_eq!(CONFIG_KEY_L4LB_ENABLED, 10);
    }

    #[test]
    fn config_keys_fit_in_map() {
        // All config keys must be < MAX_CONFIG_ENTRIES.
        assert!(CONFIG_KEY_IPV6_ENABLED < MAX_CONFIG_ENTRIES);
    }

    #[test]
    fn action_constants() {
        assert_eq!(ACTION_DENY, 0);
        assert_eq!(ACTION_ALLOW, 1);
    }

    #[test]
    fn egress_action_constants() {
        assert_eq!(EGRESS_DENY, 0);
        assert_eq!(EGRESS_ALLOW, 1);
        assert_eq!(EGRESS_SNAT, 2);
    }

    #[test]
    fn mode_constants() {
        assert_eq!(MODE_OVERLAY, 0);
        assert_eq!(MODE_NATIVE, 1);
    }

    #[test]
    fn tunnel_type_constants() {
        assert_eq!(TUNNEL_GENEVE, 0);
        assert_eq!(TUNNEL_VXLAN, 1);
    }

    #[test]
    fn drop_reason_constants_in_range() {
        assert!(DROP_REASON_NONE < DROP_REASON_MAX as u8);
        assert!(DROP_REASON_POLICY_DENIED < DROP_REASON_MAX as u8);
        assert!(DROP_REASON_NO_IDENTITY < DROP_REASON_MAX as u8);
        assert!(DROP_REASON_NO_ROUTE < DROP_REASON_MAX as u8);
        assert!(DROP_REASON_NO_TUNNEL < DROP_REASON_MAX as u8);
        assert!(DROP_REASON_TTL_EXCEEDED < DROP_REASON_MAX as u8);
        assert!(DROP_REASON_RATE_LIMITED < DROP_REASON_MAX as u8);
    }

    #[test]
    fn tc_action_constants() {
        assert_eq!(TC_ACT_OK, 0);
        assert_eq!(TC_ACT_SHOT, 2);
        assert_eq!(TC_ACT_REDIRECT, 7);
    }

    #[test]
    fn geneve_constants() {
        assert_eq!(GENEVE_OPT_CLASS_NOVANET, 0xFF01);
        assert_eq!(GENEVE_OPT_TYPE_IDENTITY, 0x01);
        assert_eq!(GENEVE_OPT_IDENTITY_LEN, 1);
        assert_eq!(GENEVE_PORT, 6081);
    }

    #[test]
    fn vxlan_constants() {
        assert_eq!(VXLAN_PORT, 4789);
        assert_eq!(VXLAN_HLEN, 8);
    }

    #[test]
    fn network_header_sizes() {
        assert_eq!(ETH_HLEN, 14);
        assert_eq!(IPV4_HLEN_MIN, 20);
        assert_eq!(UDP_HLEN, 8);
        assert_eq!(GENEVE_HLEN, 8);
        assert_eq!(GENEVE_IDENTITY_OPT_SIZE, 8);
    }

    #[test]
    fn map_sizes_are_powers_of_two_or_reasonable() {
        assert!(MAX_ENDPOINTS.is_power_of_two());
        assert!(MAX_POLICIES.is_power_of_two());
        assert!(MAX_TUNNELS.is_power_of_two());
        assert!(MAX_EGRESS_POLICIES.is_power_of_two());
        assert!(MAX_CONFIG_ENTRIES.is_power_of_two());
    }

    #[test]
    fn flow_ring_buf_size() {
        assert_eq!(FLOW_RING_BUF_SIZE, 8 * 1024 * 1024);
        assert!(FLOW_RING_BUF_SIZE.is_power_of_two());
    }

    // -- Clone/Copy/Debug/Eq trait tests --

    #[test]
    fn types_are_copy() {
        let key = EndpointKey { ip: 1 };
        let key2 = key; // Copy
        assert_eq!(key, key2);
    }

    #[test]
    fn types_are_debug() {
        let key = EndpointKey { ip: 1 };
        let dbg = format!("{:?}", key);
        assert!(dbg.contains("EndpointKey"));
    }

    // -- Zero-initialization safety (important for eBPF) --

    #[test]
    fn zero_policy_value_is_deny() {
        let val = PolicyValue {
            action: 0,
            _pad: [0; 3],
        };
        assert_eq!(val.action, ACTION_DENY);
    }

    #[test]
    fn sock_lb_origin_size() {
        // original_ip(4) + original_port(2) + protocol(1) + pad(1) = 8
        assert_eq!(mem::size_of::<SockLbOrigin>(), 8);
    }

    #[test]
    fn sock_lb_origin_alignment() {
        assert_eq!(mem::align_of::<SockLbOrigin>(), 4);
    }

    #[test]
    fn zero_egress_value_is_deny() {
        let val = EgressValue {
            action: 0,
            _pad: [0; 3],
            snat_ip: 0,
        };
        assert_eq!(val.action, EGRESS_DENY);
    }

    // -- IPCache type tests --

    #[test]
    fn ipcache_key_size() {
        // prefix_len(4) + addr(16) = 20
        assert_eq!(mem::size_of::<IPCacheKey>(), 20);
    }

    #[test]
    fn ipcache_value_size() {
        // identity(4) + flags(4) = 8
        assert_eq!(mem::size_of::<IPCacheValue>(), 8);
    }

    #[test]
    fn ipcache_key_alignment() {
        assert_eq!(mem::align_of::<IPCacheKey>(), 4);
    }

    #[test]
    fn ipcache_key_ipv4_mapped() {
        let mut addr = [0u8; 16];
        addr[10] = 0xff;
        addr[11] = 0xff;
        addr[12] = 10;
        addr[13] = 0;
        addr[14] = 0;
        addr[15] = 1;
        let key = IPCacheKey {
            prefix_len: 128, // /32 + 96
            addr,
        };
        assert_eq!(key.addr[12], 10);
        assert_eq!(key.prefix_len, 128);
    }

    // -- Host policy type tests --

    #[test]
    fn host_policy_key_size() {
        // prefix_len(4) + identity(4) + direction(1) + protocol(1) + dst_port(2) = 12
        assert_eq!(mem::size_of::<HostPolicyKey>(), 12);
    }

    #[test]
    fn host_policy_value_size() {
        // action(1) + pad(3) = 4
        assert_eq!(mem::size_of::<HostPolicyValue>(), 4);
    }

    #[test]
    fn host_policy_key_alignment() {
        assert_eq!(mem::align_of::<HostPolicyKey>(), 4);
    }

    #[test]
    fn host_policy_prefix_constants() {
        // Full prefix covers all 64 bits after prefix_len field.
        assert_eq!(HOST_POLICY_FULL_PREFIX, 64);
        // Identity prefix = identity(32) + direction(8) = 40.
        assert_eq!(HOST_POLICY_IDENTITY_PREFIX, 40);
        // Proto prefix = identity(32) + direction(8) + protocol(8) = 48.
        assert_eq!(HOST_POLICY_PROTO_PREFIX, 48);
    }

    #[test]
    fn host_policy_direction_constants() {
        assert_eq!(HOST_POLICY_INGRESS, 0);
        assert_eq!(HOST_POLICY_EGRESS, 1);
    }

    #[test]
    fn zero_host_policy_value_is_deny() {
        let val = HostPolicyValue {
            action: 0,
            _pad: [0; 3],
        };
        assert_eq!(val.action, ACTION_DENY);
    }

    #[test]
    fn reserved_identity_constants() {
        assert_eq!(IDENTITY_HOST, 1);
        assert_eq!(IDENTITY_WORLD, 2);
    }

    // -- V6 type size tests --

    #[test]
    fn endpoint_key_v6_size() {
        assert_eq!(mem::size_of::<EndpointKeyV6>(), 16);
    }

    #[test]
    fn endpoint_value_v6_size() {
        // ifindex(4) + mac(6) + pad(2) + identity(4) + node_ip(16) = 32
        assert_eq!(mem::size_of::<EndpointValueV6>(), 32);
    }

    #[test]
    fn tunnel_key_v6_size() {
        assert_eq!(mem::size_of::<TunnelKeyV6>(), 16);
    }

    #[test]
    fn tunnel_value_v6_size() {
        // ifindex(4) + remote_ip(16) + vni(4) = 24
        assert_eq!(mem::size_of::<TunnelValueV6>(), 24);
    }

    #[test]
    fn egress_key_v6_size() {
        // src_identity(4) + dst_ip(16) + dst_prefix_len(1) + pad(3) = 24
        assert_eq!(mem::size_of::<EgressKeyV6>(), 24);
    }

    #[test]
    fn egress_value_v6_size() {
        // action(1) + pad(3) + snat_ip(16) = 20
        assert_eq!(mem::size_of::<EgressValueV6>(), 20);
    }

    #[test]
    fn service_key_v6_size() {
        // ip(16) + port(2) + protocol(1) + scope(1) = 20
        assert_eq!(mem::size_of::<ServiceKeyV6>(), 20);
    }

    #[test]
    fn backend_value_v6_size() {
        // ip(16) + port(2) + pad(2) + node_ip(16) = 36
        assert_eq!(mem::size_of::<BackendValueV6>(), 36);
    }

    #[test]
    fn ct_key_v6_size() {
        // src_ip(16) + dst_ip(16) + src_port(2) + dst_port(2) + protocol(1) + pad(3) = 40
        assert_eq!(mem::size_of::<CtKeyV6>(), 40);
    }

    #[test]
    fn ct_value_v6_size() {
        // timestamp(8) + backend_ip(16) + origin_ip(16) + backend_port(2) + origin_port(2) + flags(1) + pad(1) + pad2(2) = 48
        assert_eq!(mem::size_of::<CtValueV6>(), 48);
    }

    #[test]
    fn sock_lb_origin_v6_size() {
        // original_ip(16) + original_port(2) + protocol(1) + pad(1) = 20
        assert_eq!(mem::size_of::<SockLbOriginV6>(), 20);
    }

    // -- V6 alignment tests --

    #[test]
    fn endpoint_key_v6_alignment() {
        assert_eq!(mem::align_of::<EndpointKeyV6>(), 1);
    }

    #[test]
    fn endpoint_value_v6_alignment() {
        assert_eq!(mem::align_of::<EndpointValueV6>(), 4);
    }

    #[test]
    fn ct_key_v6_alignment() {
        assert_eq!(mem::align_of::<CtKeyV6>(), 2);
    }

    #[test]
    fn ct_value_v6_alignment() {
        assert_eq!(mem::align_of::<CtValueV6>(), 8);
    }

    // -- IPv6 config key tests --

    #[test]
    fn ipv6_config_keys_are_sequential() {
        assert_eq!(CONFIG_KEY_NODE_IPV6_HI, 20);
        assert_eq!(CONFIG_KEY_NODE_IPV6_LO, 21);
        assert_eq!(CONFIG_KEY_CLUSTER_CIDR_IPV6_HI, 22);
        assert_eq!(CONFIG_KEY_CLUSTER_CIDR_IPV6_LO, 23);
        assert_eq!(CONFIG_KEY_CLUSTER_CIDR_PREFIX_V6, 24);
        assert_eq!(CONFIG_KEY_POD_CIDR_IPV6_HI, 25);
        assert_eq!(CONFIG_KEY_POD_CIDR_IPV6_LO, 26);
        assert_eq!(CONFIG_KEY_POD_CIDR_PREFIX_V6, 27);
        assert_eq!(CONFIG_KEY_SNAT_IPV6_HI, 28);
        assert_eq!(CONFIG_KEY_SNAT_IPV6_LO, 29);
        assert_eq!(CONFIG_KEY_IPV6_ENABLED, 30);
    }

    // -- Helper function tests --

    #[test]
    fn ipv4_roundtrip() {
        let bytes = [10u8, 42, 5, 1];
        let ip = ipv4_to_u32(&bytes);
        assert_eq!(u32_to_ipv4(ip), bytes);
    }

    #[test]
    fn ipv6_u64_pair_roundtrip() {
        let addr: [u8; 16] = [
            0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let (hi, lo) = ipv6_to_u64_pair(&addr);
        assert_eq!(u64_pair_to_ipv6(hi, lo), addr);
    }

    #[test]
    fn af_inet_constants() {
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 10);
    }

    #[test]
    fn ipv6_hlen_constant() {
        assert_eq!(IPV6_HLEN, 40);
    }

    // -- SOCKMAP / mesh / rate-limit / health type size tests --

    #[test]
    fn sock_key_size() {
        // src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) + family(4) = 16
        assert_eq!(mem::size_of::<SockKey>(), 16);
    }

    #[test]
    fn sockmapendpoint_key_size() {
        // ip(4) + port(4) = 8
        assert_eq!(mem::size_of::<SockmapEndpointKey>(), 8);
    }

    #[test]
    fn mesh_service_key_size() {
        // ip(4) + port(4) = 8
        assert_eq!(mem::size_of::<MeshServiceKey>(), 8);
    }

    #[test]
    fn mesh_redirect_value_size() {
        // redirect_port(4) = 4
        assert_eq!(mem::size_of::<MeshRedirectValue>(), 4);
    }

    #[test]
    fn rate_limit_key_size() {
        // addr([u8;16]) = 16
        assert_eq!(mem::size_of::<RateLimitKey>(), 16);
    }

    #[test]
    fn token_bucket_state_size() {
        // tokens(8) + last_refill_ns(8) = 16
        assert_eq!(mem::size_of::<TokenBucketState>(), 16);
    }

    #[test]
    fn rate_limit_config_size() {
        // rate(4) + burst(4) + window_ns(8) = 16
        assert_eq!(mem::size_of::<RateLimitConfig>(), 16);
    }

    #[test]
    fn backend_health_key_size() {
        // ip(4) + port(4) = 8
        assert_eq!(mem::size_of::<BackendHealthKey>(), 8);
    }

    #[test]
    fn backend_health_counters_size() {
        // 7 * u64 = 56
        assert_eq!(mem::size_of::<BackendHealthCounters>(), 56);
    }
}
