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
    /// TCP flags (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04). Zero for non-TCP.
    pub tcp_flags: u8,
    /// Padding.
    pub _pad3: u8,
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
/// Pod CIDR IPv4 base address in network byte order (lower 32 bits of u64).
pub const CONFIG_KEY_POD_CIDR_IP: u32 = 8;
/// Pod CIDR prefix length (e.g. 24 for /24).
pub const CONFIG_KEY_POD_CIDR_PREFIX_LEN: u32 = 9;

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
    fn flow_event_size() {
        // Contains u64 fields so struct is aligned to 8 bytes.
        // 4+4+4+4 + 1+1+2+2+2 + 1+1+2 + (4 pad for u64 alignment) + 8+8+8 = 56
        let size = mem::size_of::<FlowEvent>();
        assert_eq!(size, 56);
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
        // Contains u64 fields, so alignment should be 8.
        assert_eq!(mem::align_of::<FlowEvent>(), 8);
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
        let allow = PolicyValue { action: ACTION_ALLOW, _pad: [0; 3] };
        let deny = PolicyValue { action: ACTION_DENY, _pad: [0; 3] };
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
    fn flow_event_construction() {
        let event = FlowEvent {
            src_ip: 0x0A2A0501,
            dst_ip: 0x0A2A0502,
            src_identity: 10,
            dst_identity: 20,
            protocol: 6,
            _pad1: 0,
            src_port: 12345,
            dst_port: 80,
            _pad2: [0; 2],
            verdict: ACTION_ALLOW,
            drop_reason: DROP_REASON_NONE,
            _pad3: [0; 2],
            bytes: 1500,
            packets: 1,
            timestamp_ns: 123456789,
        };
        assert_eq!(event.src_ip, 0x0A2A0501);
        assert_eq!(event.protocol, 6);
        assert_eq!(event.verdict, ACTION_ALLOW);
        assert_eq!(event.drop_reason, DROP_REASON_NONE);
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
    }

    #[test]
    fn config_keys_fit_in_map() {
        // All config keys must be < MAX_CONFIG_ENTRIES.
        assert!(CONFIG_KEY_POD_CIDR_PREFIX_LEN < MAX_CONFIG_ENTRIES);
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
        let val = PolicyValue { action: 0, _pad: [0; 3] };
        assert_eq!(val.action, ACTION_DENY);
    }

    #[test]
    fn zero_egress_value_is_deny() {
        let val = EgressValue { action: 0, _pad: [0; 3], snat_ip: 0 };
        assert_eq!(val.action, EGRESS_DENY);
    }
}
