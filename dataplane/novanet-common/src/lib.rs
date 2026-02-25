//! NovaNet common types shared between eBPF programs and the userspace dataplane.
//!
//! All types are `#[repr(C)]` so they can be used directly in eBPF maps from
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
// Flow event: emitted to ring buffer for observability
// ---------------------------------------------------------------------------

/// Flow event emitted from eBPF programs to the ring buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowEvent {
    /// Source IPv4 address in network byte order.
    pub src_ip: u32,
    /// Destination IPv4 address in network byte order.
    pub dst_ip: u32,
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
    /// Policy verdict: ACTION_DENY (0), ACTION_ALLOW (1).
    pub verdict: u8,
    /// Drop reason (non-zero if dropped). See DROP_REASON_* constants.
    pub drop_reason: u8,
    /// Padding.
    pub _pad3: [u8; 2],
    /// Bytes in this flow.
    pub bytes: u64,
    /// Packets in this flow.
    pub packets: u64,
    /// Kernel timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

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

/// EtherType for IPv4.
pub const ETH_P_IP: u16 = 0x0800;

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

// ---------------------------------------------------------------------------
// aya::Pod implementations for userspace map access
// ---------------------------------------------------------------------------

#[cfg(all(feature = "userspace", target_os = "linux"))]
impl_pod!(
    EndpointKey,
    EndpointValue,
    PolicyKey,
    PolicyValue,
    TunnelKey,
    TunnelValue,
    EgressKey,
    EgressValue,
);
