//! NovaNet eBPF programs for TC-based packet processing.
//!
//! This binary contains four TC classifier programs:
//!   - `tc_ingress`: pod veth — traffic arriving at pod (K8s ingress)
//!   - `tc_egress`: pod veth — traffic leaving pod (K8s egress)
//!   - `tc_tunnel_ingress`: tunnel interface ingress (decap + policy)
//!   - `tc_tunnel_egress`: tunnel interface egress (encap identity)
//!
//! Compiled with `--target bpfel-unknown-none -Z build-std=core` on Linux only.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK as BPF_TC_ACT_OK,
    bindings::TC_ACT_SHOT as BPF_TC_ACT_SHOT,
    helpers::bpf_redirect,
    macros::{classifier, map},
    maps::{HashMap, PerCpuArray, RingBuf},
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    tcp::TcpHdr,
    udp::UdpHdr,
};
use novanet_common::*;

// ---------------------------------------------------------------------------
// eBPF Maps
// ---------------------------------------------------------------------------

#[map]
static ENDPOINTS: HashMap<EndpointKey, EndpointValue> =
    HashMap::with_max_entries(MAX_ENDPOINTS, 0);

#[map]
static POLICIES: HashMap<PolicyKey, PolicyValue> = HashMap::with_max_entries(MAX_POLICIES, 0);

#[map]
static TUNNELS: HashMap<TunnelKey, TunnelValue> = HashMap::with_max_entries(MAX_TUNNELS, 0);

#[map]
static EGRESS_POLICIES: HashMap<EgressKey, EgressValue> =
    HashMap::with_max_entries(MAX_EGRESS_POLICIES, 0);

#[map]
static CONFIG: HashMap<u32, u64> = HashMap::with_max_entries(MAX_CONFIG_ENTRIES, 0);

#[map]
static FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(FLOW_RING_BUF_SIZE, 0);

#[map]
static DROP_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(DROP_REASON_MAX, 0);

// ---------------------------------------------------------------------------
// Helper: read config value
// ---------------------------------------------------------------------------

#[inline(always)]
fn get_config(key: u32) -> u64 {
    unsafe { CONFIG.get(&key).copied().unwrap_or(0) }
}

// ---------------------------------------------------------------------------
// Helper: check identity-based policy
// Returns: Some(action) if a policy entry exists, None otherwise
// ---------------------------------------------------------------------------

#[inline(always)]
fn check_policy(src_id: u32, dst_id: u32, proto: u8, dst_port: u16) -> Option<u8> {
    // Try exact match first (specific port).
    let key = PolicyKey {
        src_identity: src_id,
        dst_identity: dst_id,
        protocol: proto,
        _pad: [0],
        dst_port,
    };
    if let Some(val) = unsafe { POLICIES.get(&key) } {
        return Some(val.action);
    }

    // Try wildcard port (dst_port == 0 means "any port").
    let key_any_port = PolicyKey {
        src_identity: src_id,
        dst_identity: dst_id,
        protocol: proto,
        _pad: [0],
        dst_port: 0,
    };
    if let Some(val) = unsafe { POLICIES.get(&key_any_port) } {
        return Some(val.action);
    }

    // Try wildcard protocol + port.
    let key_any_proto = PolicyKey {
        src_identity: src_id,
        dst_identity: dst_id,
        protocol: 0,
        _pad: [0],
        dst_port: 0,
    };
    if let Some(val) = unsafe { POLICIES.get(&key_any_proto) } {
        return Some(val.action);
    }

    None
}

// ---------------------------------------------------------------------------
// Helper: increment drop counter
// ---------------------------------------------------------------------------

#[inline(always)]
fn inc_drop_counter(reason: u8) {
    let idx = reason as u32;
    if let Some(counter) = unsafe { DROP_COUNTERS.get_ptr_mut(idx) } {
        unsafe {
            *counter += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: emit flow event to ring buffer
// ---------------------------------------------------------------------------

#[inline(always)]
fn emit_flow_event(
    src_ip: u32,
    dst_ip: u32,
    src_identity: u32,
    dst_identity: u32,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    verdict: u8,
    drop_reason: u8,
    tcp_flags: u8,
    bytes: u64,
) {
    if let Some(mut entry) = FLOW_EVENTS.reserve::<FlowEvent>(0) {
        let event = FlowEvent {
            src_ip,
            dst_ip,
            src_identity,
            dst_identity,
            protocol,
            _pad1: 0,
            src_port,
            dst_port,
            _pad2: [0; 2],
            verdict,
            drop_reason,
            tcp_flags,
            _pad3: 0,
            bytes,
            packets: 1,
            timestamp_ns: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
        };
        unsafe {
            entry.write(event);
        }
        entry.submit(0);
    }
}

// ---------------------------------------------------------------------------
// Helper: parse L4 ports and TCP flags from IPv4 packet
// Returns (src_port, dst_port, tcp_flags) or (0, 0, 0) if not TCP/UDP
// ---------------------------------------------------------------------------

#[inline(always)]
fn parse_l4_ports(ctx: &TcContext, l4_offset: usize, protocol: u8) -> (u16, u16, u8) {
    match protocol {
        6 => {
            // TCP: extract ports and flags
            if let Ok(tcp) = ctx.load::<TcpHdr>(l4_offset) {
                let src = tcp.source;
                let dst = tcp.dest;
                // TCP flags are in byte 13 of the TCP header (offset 13 from l4_offset).
                let flags = if let Ok(f) = ctx.load::<u8>(l4_offset + 13) {
                    f
                } else {
                    0
                };
                (u16::from_be(src), u16::from_be(dst), flags)
            } else {
                (0, 0, 0)
            }
        }
        17 => {
            // UDP
            if let Ok(udp) = ctx.load::<UdpHdr>(l4_offset) {
                let src = udp.source;
                let dst = udp.dest;
                (u16::from_be(src), u16::from_be(dst), 0)
            } else {
                (0, 0, 0)
            }
        }
        _ => (0, 0, 0),
    }
}

// ---------------------------------------------------------------------------
// Helper: check if IP is within cluster CIDR
// ---------------------------------------------------------------------------

#[inline(always)]
fn is_cluster_ip(ip: u32) -> bool {
    let cidr_ip = get_config(CONFIG_KEY_CLUSTER_CIDR_IP) as u32;
    let prefix_len = get_config(CONFIG_KEY_CLUSTER_CIDR_PREFIX_LEN) as u32;
    if prefix_len == 0 || prefix_len > 32 {
        return false;
    }
    let mask = if prefix_len == 32 {
        0xFFFF_FFFFu32
    } else {
        !((1u32 << (32 - prefix_len)) - 1)
    };
    // Both ip and cidr_ip are in canonical big-endian format (matching
    // Go's binary.BigEndian.Uint32). The prefix mask works directly
    // since MSBs in big-endian correspond to the network prefix.
    (ip & mask) == (cidr_ip & mask)
}

// ---------------------------------------------------------------------------
// Helper: lookup endpoint and get identity
// ---------------------------------------------------------------------------

#[inline(always)]
fn lookup_identity(ip: u32) -> Option<(u32, &'static EndpointValue)> {
    let key = EndpointKey { ip };
    unsafe { ENDPOINTS.get(&key).map(|v| (v.identity, v)) }
}

// ---------------------------------------------------------------------------
// Helper: check egress policy for external traffic
// Returns: true if traffic should be allowed
// ---------------------------------------------------------------------------

#[inline(always)]
fn check_egress_policy(src_identity: u32, dst_ip: u32) -> (bool, u32) {
    // Try /32 first (most specific), then /24, /16, /8, /0 (least specific).
    // This is a simple linear scan — eBPF LPM trie would be more efficient
    // but we keep it simple for now with a small number of prefix lengths.
    let prefix_lengths: [u8; 5] = [32, 24, 16, 8, 0];

    for &plen in prefix_lengths.iter() {
        let mask = if plen == 0 {
            0u32
        } else if plen == 32 {
            0xFFFF_FFFFu32
        } else {
            !((1u32 << (32 - plen)) - 1)
        };
        // dst_ip is in canonical big-endian format; mask works directly.
        let masked_ip = dst_ip & mask;

        let key = EgressKey {
            src_identity,
            dst_ip: masked_ip,
            dst_prefix_len: plen,
            _pad: [0; 3],
        };
        if let Some(val) = unsafe { EGRESS_POLICIES.get(&key) } {
            return match val.action {
                EGRESS_DENY => (false, 0),
                EGRESS_ALLOW => (true, 0),
                EGRESS_SNAT => (true, val.snat_ip),
                _ => (false, 0),
            };
        }
    }

    // No egress policy found — default allow for external traffic.
    (true, 0)
}

// ===========================================================================
// TC PROGRAM: tc_ingress
// Traffic arriving at the pod from the network (K8s ingress).
// Attached to TC egress hook on host veth (packets leaving host → pod).
// Enforces inbound policy in native mode. In overlay mode, policy was
// already checked by tc_tunnel_ingress, so we pass through.
// ===========================================================================

#[classifier]
pub fn tc_ingress(ctx: TcContext) -> i32 {
    match try_tc_ingress(&ctx) {
        Ok(action) => action,
        Err(_) => BPF_TC_ACT_OK as i32,
    }
}

#[inline(always)]
fn try_tc_ingress(ctx: &TcContext) -> Result<i32, ()> {
    // Parse Ethernet header.
    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    let ether_type = eth.ether_type;
    if ether_type != EtherType::Ipv4 {
        return Ok(BPF_TC_ACT_OK as i32);
    }

    // Parse IPv4 header.
    let ipv4: Ipv4Hdr = ctx.load(ETH_HLEN).map_err(|_| ())?;
    // Convert IPs from raw packet bytes to canonical big-endian u32.
    // This matches Go's binary.BigEndian.Uint32() used for map keys.
    // u32::to_be() is a no-op on big-endian and a byte-swap on little-endian,
    // so it works correctly on both ARM64 and AMD64.
    let src_ip = u32::to_be(ipv4.src_addr);
    let dst_ip = u32::to_be(ipv4.dst_addr);
    let protocol = ipv4.proto as u8;
    let ihl = (ipv4.ihl() as usize) * 4;
    let l4_offset = ETH_HLEN + ihl;
    let tot_len = ipv4.tot_len;
    let total_len = u16::from_be(tot_len) as u64;

    let (src_port, dst_port, tcp_flags) = parse_l4_ports(ctx, l4_offset, protocol);

    let mode = get_config(CONFIG_KEY_MODE);

    if mode == MODE_OVERLAY {
        // In overlay mode, tunnel decapsulation has already happened and identity
        // was resolved by tc_tunnel_ingress. Policy was checked there too.
        // Here we just pass through.
        return Ok(BPF_TC_ACT_OK as i32);
    }

    // Native mode: resolve source identity and enforce inbound policy.
    let src_identity = match lookup_identity(src_ip) {
        Some((id, _)) => id,
        None => {
            // Unknown source — could be external traffic or cross-node
            // pod traffic (remote pod not in local endpoint map).
            // Check if we're in default-deny mode.
            let default_deny = get_config(CONFIG_KEY_DEFAULT_DENY);
            if default_deny == 1 {
                inc_drop_counter(DROP_REASON_NO_IDENTITY);
                emit_flow_event(
                    src_ip, dst_ip, 0, 0, protocol, src_port, dst_port,
                    ACTION_DENY, DROP_REASON_NO_IDENTITY, tcp_flags, total_len,
                );
                return Ok(BPF_TC_ACT_SHOT as i32);
            }
            return Ok(BPF_TC_ACT_OK as i32);
        }
    };

    // Resolve destination identity.
    let dst_identity = lookup_identity(dst_ip).map(|(id, _)| id).unwrap_or(0);

    // Check policy.
    match check_policy(src_identity, dst_identity, protocol, dst_port) {
        Some(ACTION_DENY) => {
            inc_drop_counter(DROP_REASON_POLICY_DENIED);
            emit_flow_event(
                src_ip, dst_ip, src_identity, dst_identity, protocol,
                src_port, dst_port, ACTION_DENY, DROP_REASON_POLICY_DENIED, tcp_flags, total_len,
            );
            Ok(BPF_TC_ACT_SHOT as i32)
        }
        Some(ACTION_ALLOW) => {
            emit_flow_event(
                src_ip, dst_ip, src_identity, dst_identity, protocol,
                src_port, dst_port, ACTION_ALLOW, DROP_REASON_NONE, tcp_flags, total_len,
            );
            Ok(BPF_TC_ACT_OK as i32)
        }
        _ => {
            // No policy entry — check default deny flag.
            let default_deny = get_config(CONFIG_KEY_DEFAULT_DENY);
            if default_deny == 1 {
                inc_drop_counter(DROP_REASON_POLICY_DENIED);
                emit_flow_event(
                    src_ip, dst_ip, src_identity, dst_identity, protocol,
                    src_port, dst_port, ACTION_DENY, DROP_REASON_POLICY_DENIED, tcp_flags, total_len,
                );
                Ok(BPF_TC_ACT_SHOT as i32)
            } else {
                Ok(BPF_TC_ACT_OK as i32)
            }
        }
    }
}

// ===========================================================================
// TC PROGRAM: tc_egress
// Traffic leaving the pod toward the network (K8s egress).
// Attached to TC ingress hook on host veth (packets arriving from pod → host).
// Makes routing decisions: same-node redirect, overlay tunnel, native routing,
// and enforces egress policy for external destinations.
// ===========================================================================

#[classifier]
pub fn tc_egress(ctx: TcContext) -> i32 {
    match try_tc_egress(&ctx) {
        Ok(action) => action,
        Err(_) => BPF_TC_ACT_OK as i32,
    }
}

#[inline(always)]
fn try_tc_egress(ctx: &TcContext) -> Result<i32, ()> {
    // Parse Ethernet header.
    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    let ether_type = eth.ether_type;
    if ether_type != EtherType::Ipv4 {
        return Ok(BPF_TC_ACT_OK as i32);
    }

    // Parse IPv4 header.
    let ipv4: Ipv4Hdr = ctx.load(ETH_HLEN).map_err(|_| ())?;
    let src_ip = u32::to_be(ipv4.src_addr);
    let dst_ip = u32::to_be(ipv4.dst_addr);
    let protocol = ipv4.proto as u8;
    let ihl = (ipv4.ihl() as usize) * 4;
    let l4_offset = ETH_HLEN + ihl;
    let tot_len = ipv4.tot_len;
    let total_len = u16::from_be(tot_len) as u64;

    let (src_port, dst_port, tcp_flags) = parse_l4_ports(ctx, l4_offset, protocol);

    // Resolve source identity (the pod sending traffic).
    let src_identity = lookup_identity(src_ip).map(|(id, _)| id).unwrap_or(0);

    // Check if destination is a local endpoint (same-node).
    if let Some((dst_identity, dst_ep)) = lookup_identity(dst_ip) {
        let node_ip = get_config(CONFIG_KEY_NODE_IP) as u32;
        if dst_ep.node_ip == node_ip || dst_ep.node_ip == 0 {
            // Same-node pod-to-pod: check policy, then let kernel route it.
            // We use TC_ACT_OK instead of bpf_redirect because redirect
            // would skip L2 header rewriting (MAC addresses), causing the
            // destination pod to drop the packet. Kernel routing handles
            // neighbor resolution and proper L2 headers automatically.
            match check_policy(src_identity, dst_identity, protocol, dst_port) {
                Some(ACTION_DENY) => {
                    inc_drop_counter(DROP_REASON_POLICY_DENIED);
                    emit_flow_event(
                        src_ip, dst_ip, src_identity, dst_identity, protocol,
                        src_port, dst_port, ACTION_DENY, DROP_REASON_POLICY_DENIED, tcp_flags, total_len,
                    );
                    return Ok(BPF_TC_ACT_SHOT as i32);
                }
                Some(ACTION_ALLOW) => {
                    emit_flow_event(
                        src_ip, dst_ip, src_identity, dst_identity, protocol,
                        src_port, dst_port, ACTION_ALLOW, DROP_REASON_NONE, tcp_flags, total_len,
                    );
                    return Ok(BPF_TC_ACT_OK as i32);
                }
                _ => {
                    // No explicit policy. Check default deny.
                    let default_deny = get_config(CONFIG_KEY_DEFAULT_DENY);
                    if default_deny == 1 {
                        inc_drop_counter(DROP_REASON_POLICY_DENIED);
                        emit_flow_event(
                            src_ip, dst_ip, src_identity, dst_identity, protocol,
                            src_port, dst_port, ACTION_DENY, DROP_REASON_POLICY_DENIED, tcp_flags, total_len,
                        );
                        return Ok(BPF_TC_ACT_SHOT as i32);
                    }
                    return Ok(BPF_TC_ACT_OK as i32);
                }
            }
        }

        // Remote node endpoint — handle via overlay or native routing.
        let mode = get_config(CONFIG_KEY_MODE);
        if mode == MODE_OVERLAY {
            // Look up tunnel for the remote node.
            let tunnel_key = TunnelKey {
                node_ip: dst_ep.node_ip,
            };
            if let Some(tunnel) = unsafe { TUNNELS.get(&tunnel_key) } {
                // Redirect to tunnel interface for kernel encapsulation.
                // Identity is resolved on the receiving side via endpoint map lookup.
                emit_flow_event(
                    src_ip, dst_ip, src_identity, dst_identity, protocol,
                    src_port, dst_port, ACTION_ALLOW, DROP_REASON_NONE, tcp_flags, total_len,
                );
                unsafe {
                    return Ok(bpf_redirect(tunnel.ifindex, 0) as i32);
                }
            } else {
                // No tunnel entry for remote node.
                inc_drop_counter(DROP_REASON_NO_TUNNEL);
                emit_flow_event(
                    src_ip, dst_ip, src_identity, dst_identity, protocol,
                    src_port, dst_port, ACTION_DENY, DROP_REASON_NO_TUNNEL, tcp_flags, total_len,
                );
                return Ok(BPF_TC_ACT_SHOT as i32);
            }
        }

        // Native mode: policy check only, let kernel route to the remote node.
        match check_policy(src_identity, dst_identity, protocol, dst_port) {
            Some(ACTION_DENY) => {
                inc_drop_counter(DROP_REASON_POLICY_DENIED);
                emit_flow_event(
                    src_ip, dst_ip, src_identity, dst_identity, protocol,
                    src_port, dst_port, ACTION_DENY, DROP_REASON_POLICY_DENIED, tcp_flags, total_len,
                );
                return Ok(BPF_TC_ACT_SHOT as i32);
            }
            Some(ACTION_ALLOW) => {
                emit_flow_event(
                    src_ip, dst_ip, src_identity, dst_identity, protocol,
                    src_port, dst_port, ACTION_ALLOW, DROP_REASON_NONE, tcp_flags, total_len,
                );
                return Ok(BPF_TC_ACT_OK as i32);
            }
            _ => {
                let default_deny = get_config(CONFIG_KEY_DEFAULT_DENY);
                if default_deny == 1 {
                    inc_drop_counter(DROP_REASON_POLICY_DENIED);
                    emit_flow_event(
                        src_ip, dst_ip, src_identity, dst_identity, protocol,
                        src_port, dst_port, ACTION_DENY, DROP_REASON_POLICY_DENIED, tcp_flags, total_len,
                    );
                    return Ok(BPF_TC_ACT_SHOT as i32);
                }
                return Ok(BPF_TC_ACT_OK as i32);
            }
        }
    }

    // Destination not in endpoint map — external traffic.
    if !is_cluster_ip(dst_ip) {
        // Egress to outside the cluster. Check egress policy.
        let (allowed, _snat_ip) = check_egress_policy(src_identity, dst_ip);
        if !allowed {
            inc_drop_counter(DROP_REASON_POLICY_DENIED);
            emit_flow_event(
                src_ip, dst_ip, src_identity, 0, protocol,
                src_port, dst_port, ACTION_DENY, DROP_REASON_POLICY_DENIED, tcp_flags, total_len,
            );
            return Ok(BPF_TC_ACT_SHOT as i32);
        }

        // SNAT is handled by netfilter/iptables in userspace for now.
        // We just allow the traffic through.
        emit_flow_event(
            src_ip, dst_ip, src_identity, 0, protocol,
            src_port, dst_port, ACTION_ALLOW, DROP_REASON_NONE, tcp_flags, total_len,
        );
        return Ok(BPF_TC_ACT_OK as i32);
    }

    // Destination is a cluster IP but not in our endpoint map.
    // In overlay mode, this means we don't know the remote node — drop.
    let mode = get_config(CONFIG_KEY_MODE);
    if mode == MODE_OVERLAY {
        inc_drop_counter(DROP_REASON_NO_ROUTE);
        emit_flow_event(
            src_ip, dst_ip, src_identity, 0, protocol,
            src_port, dst_port, ACTION_DENY, DROP_REASON_NO_ROUTE, tcp_flags, total_len,
        );
        return Ok(BPF_TC_ACT_SHOT as i32);
    }

    // Native mode: let kernel route it.
    Ok(BPF_TC_ACT_OK as i32)
}

// ===========================================================================
// TC PROGRAM: tc_tunnel_ingress
// Attached to tunnel interface (Geneve/VXLAN) ingress direction.
// Decapsulates tunnel headers and resolves identity from:
//   - Geneve TLV option (preferred)
//   - Endpoint map lookup by source IP (VXLAN fallback)
// ===========================================================================

#[classifier]
pub fn tc_tunnel_ingress(ctx: TcContext) -> i32 {
    match try_tc_tunnel_ingress(&ctx) {
        Ok(action) => action,
        Err(_) => BPF_TC_ACT_OK as i32,
    }
}

/// Geneve header layout (8 bytes base):
///   bits 0-1:   version (2 bits)
///   bits 2-7:   opt_len (6 bits, in 4-byte units)
///   bit 8:      O (OAM)
///   bit 9:      C (critical)
///   bits 10-15: reserved (6 bits)
///   bits 16-31: protocol type (EtherType of inner frame)
///   bits 32-55: VNI (24 bits)
///   bits 56-63: reserved (8 bits)
#[repr(C)]
#[derive(Clone, Copy)]
struct GeneveHdr {
    /// First two bytes: version(2) + opt_len(6) + flags(8)
    ver_opt_len_flags: u16,
    /// Protocol type of encapsulated frame (EtherType).
    proto_type: u16,
    /// VNI (24 bits) + reserved (8 bits), network byte order.
    vni_reserved: u32,
}

/// Geneve TLV option header (4 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct GeneveTlvHdr {
    /// Option class.
    opt_class: u16,
    /// Type.
    opt_type: u8,
    /// Flags (3 bits) + length (5 bits, in 4-byte units).
    flags_len: u8,
}

/// VXLAN header layout (8 bytes):
///   bits 0-7:   flags (bit 3 = I flag, must be 1)
///   bits 8-31:  reserved
///   bits 32-55: VNI (24 bits)
///   bits 56-63: reserved
#[repr(C)]
#[derive(Clone, Copy)]
struct VxlanHdr {
    flags_reserved: u32,
    vni_reserved: u32,
}

#[inline(always)]
fn try_tc_tunnel_ingress(ctx: &TcContext) -> Result<i32, ()> {
    // The tunnel interface receives the outer packet. The kernel has already
    // stripped the outer Ethernet + IP + UDP headers for us on a GENEVE/VXLAN
    // tunnel device. What we see starts at the tunnel-specific header.
    //
    // However, on some setups the outer headers may still be present. We need
    // to handle the case where we see the full outer packet.
    //
    // Parse outer Ethernet.
    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    let ether_type = eth.ether_type;
    if ether_type != EtherType::Ipv4 {
        // Not IPv4 outer — might be inner frame directly. Pass through.
        return Ok(BPF_TC_ACT_OK as i32);
    }

    // Parse outer IPv4.
    let outer_ipv4: Ipv4Hdr = ctx.load(ETH_HLEN).map_err(|_| ())?;
    let _outer_src_ip = outer_ipv4.src_addr;
    let outer_protocol = outer_ipv4.proto as u8;

    // Must be UDP for tunnel traffic.
    if outer_protocol != 17 {
        return Ok(BPF_TC_ACT_OK as i32);
    }

    let outer_ihl = (outer_ipv4.ihl() as usize) * 4;
    let udp_offset = ETH_HLEN + outer_ihl;

    // Parse outer UDP.
    let outer_udp: UdpHdr = ctx.load(udp_offset).map_err(|_| ())?;
    let udp_dest = outer_udp.dest;
    let dst_port = u16::from_be(udp_dest);

    let tunnel_type = get_config(CONFIG_KEY_TUNNEL_TYPE);
    let tunnel_hdr_offset = udp_offset + UDP_HLEN;

    let mut resolved_identity: u32 = 0;

    if dst_port == GENEVE_PORT && tunnel_type == TUNNEL_GENEVE {
        // Parse Geneve header.
        let geneve: GeneveHdr = ctx.load(tunnel_hdr_offset).map_err(|_| ())?;
        let ver_opt = u16::from_be(geneve.ver_opt_len_flags);
        let opt_len_words = ((ver_opt >> 8) & 0x3F) as usize; // 6-bit field, in 4-byte units
        let opt_len_bytes = opt_len_words * 4;

        // Scan Geneve TLV options for NovaNet identity.
        let opts_start = tunnel_hdr_offset + GENEVE_HLEN;
        let opts_end = opts_start + opt_len_bytes;
        let mut offset = opts_start;

        // Bounded loop for eBPF verifier — max 8 options.
        let mut i = 0u32;
        while i < 8 && offset + 4 <= opts_end {
            let tlv: GeneveTlvHdr = ctx.load(offset).map_err(|_| ())?;
            let opt_class = u16::from_be(tlv.opt_class);
            let opt_type = tlv.opt_type;
            let opt_data_len = ((tlv.flags_len & 0x1F) as usize) * 4;

            if opt_class == GENEVE_OPT_CLASS_NOVANET && opt_type == GENEVE_OPT_TYPE_IDENTITY {
                // Found identity TLV. Read the 4-byte identity value.
                if offset + 4 + 4 <= opts_end {
                    let identity_ne: u32 = ctx.load(offset + 4).map_err(|_| ())?;
                    resolved_identity = u32::from_be(identity_ne);
                }
                break;
            }

            offset += 4 + opt_data_len;
            i += 1;
        }

        // Inner frame starts after Geneve header + options.
        // Parse inner Ethernet + IPv4 to get flow info.
        let inner_eth_offset = opts_end;
        let inner_eth: EthHdr = ctx.load(inner_eth_offset).map_err(|_| ())?;
        let inner_ether_type = inner_eth.ether_type;
        if inner_ether_type != EtherType::Ipv4 {
            return Ok(BPF_TC_ACT_OK as i32);
        }

        let inner_ip_offset = inner_eth_offset + ETH_HLEN;
        let inner_ipv4: Ipv4Hdr = ctx.load(inner_ip_offset).map_err(|_| ())?;
        let inner_src_ip = u32::to_be(inner_ipv4.src_addr);
        let inner_dst_ip = u32::to_be(inner_ipv4.dst_addr);
        let inner_proto = inner_ipv4.proto as u8;
        let inner_ihl = (inner_ipv4.ihl() as usize) * 4;
        let inner_l4_offset = inner_ip_offset + inner_ihl;
        let inner_tot_len = inner_ipv4.tot_len;
        let inner_total_len = u16::from_be(inner_tot_len) as u64;

        let (inner_src_port, inner_dst_port, inner_tcp_flags) = parse_l4_ports(ctx, inner_l4_offset, inner_proto);

        // If we didn't find identity in TLV, fall back to endpoint lookup.
        if resolved_identity == 0 {
            resolved_identity = lookup_identity(inner_src_ip).map(|(id, _)| id).unwrap_or(0);
        }

        // Resolve destination identity.
        let dst_identity = lookup_identity(inner_dst_ip).map(|(id, _)| id).unwrap_or(0);

        // Enforce policy.
        return enforce_tunnel_policy(
            ctx,
            inner_src_ip,
            inner_dst_ip,
            resolved_identity,
            dst_identity,
            inner_proto,
            inner_src_port,
            inner_dst_port,
            inner_tcp_flags,
            inner_total_len,
        );
    } else if dst_port == VXLAN_PORT && tunnel_type == TUNNEL_VXLAN {
        // Parse VXLAN header.
        let _vxlan: VxlanHdr = ctx.load(tunnel_hdr_offset).map_err(|_| ())?;

        let inner_eth_offset = tunnel_hdr_offset + VXLAN_HLEN;
        let inner_eth: EthHdr = ctx.load(inner_eth_offset).map_err(|_| ())?;
        let inner_ether_type = inner_eth.ether_type;
        if inner_ether_type != EtherType::Ipv4 {
            return Ok(BPF_TC_ACT_OK as i32);
        }

        let inner_ip_offset = inner_eth_offset + ETH_HLEN;
        let inner_ipv4: Ipv4Hdr = ctx.load(inner_ip_offset).map_err(|_| ())?;
        let inner_src_ip = u32::to_be(inner_ipv4.src_addr);
        let inner_dst_ip = u32::to_be(inner_ipv4.dst_addr);
        let inner_proto = inner_ipv4.proto as u8;
        let inner_ihl = (inner_ipv4.ihl() as usize) * 4;
        let inner_l4_offset = inner_ip_offset + inner_ihl;
        let inner_tot_len = inner_ipv4.tot_len;
        let inner_total_len = u16::from_be(inner_tot_len) as u64;

        let (inner_src_port, inner_dst_port, inner_tcp_flags) = parse_l4_ports(ctx, inner_l4_offset, inner_proto);

        // VXLAN has no identity TLV — look up source IP in endpoint map.
        resolved_identity = lookup_identity(inner_src_ip).map(|(id, _)| id).unwrap_or(0);
        let dst_identity = lookup_identity(inner_dst_ip).map(|(id, _)| id).unwrap_or(0);

        return enforce_tunnel_policy(
            ctx,
            inner_src_ip,
            inner_dst_ip,
            resolved_identity,
            dst_identity,
            inner_proto,
            inner_src_port,
            inner_dst_port,
            inner_tcp_flags,
            inner_total_len,
        );
    }

    // Not a recognized tunnel port — pass through.
    Ok(BPF_TC_ACT_OK as i32)
}

/// Shared policy enforcement for tunnel ingress (both Geneve and VXLAN paths).
#[inline(always)]
fn enforce_tunnel_policy(
    _ctx: &TcContext,
    src_ip: u32,
    dst_ip: u32,
    src_identity: u32,
    dst_identity: u32,
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    total_len: u64,
) -> Result<i32, ()> {
    if src_identity == 0 {
        let default_deny = get_config(CONFIG_KEY_DEFAULT_DENY);
        if default_deny == 1 {
            inc_drop_counter(DROP_REASON_NO_IDENTITY);
            emit_flow_event(
                src_ip, dst_ip, 0, dst_identity, protocol,
                src_port, dst_port, ACTION_DENY, DROP_REASON_NO_IDENTITY, tcp_flags, total_len,
            );
            return Ok(BPF_TC_ACT_SHOT as i32);
        }
        return Ok(BPF_TC_ACT_OK as i32);
    }

    match check_policy(src_identity, dst_identity, protocol, dst_port) {
        Some(ACTION_DENY) => {
            inc_drop_counter(DROP_REASON_POLICY_DENIED);
            emit_flow_event(
                src_ip, dst_ip, src_identity, dst_identity, protocol,
                src_port, dst_port, ACTION_DENY, DROP_REASON_POLICY_DENIED, tcp_flags, total_len,
            );
            Ok(BPF_TC_ACT_SHOT as i32)
        }
        Some(ACTION_ALLOW) => {
            emit_flow_event(
                src_ip, dst_ip, src_identity, dst_identity, protocol,
                src_port, dst_port, ACTION_ALLOW, DROP_REASON_NONE, tcp_flags, total_len,
            );
            // Look up destination endpoint to redirect to pod veth.
            if let Some((_, dst_ep)) = lookup_identity(dst_ip) {
                unsafe {
                    return Ok(bpf_redirect(dst_ep.ifindex, 0) as i32);
                }
            }
            Ok(BPF_TC_ACT_OK as i32)
        }
        _ => {
            let default_deny = get_config(CONFIG_KEY_DEFAULT_DENY);
            if default_deny == 1 {
                inc_drop_counter(DROP_REASON_POLICY_DENIED);
                emit_flow_event(
                    src_ip, dst_ip, src_identity, dst_identity, protocol,
                    src_port, dst_port, ACTION_DENY, DROP_REASON_POLICY_DENIED, tcp_flags, total_len,
                );
                Ok(BPF_TC_ACT_SHOT as i32)
            } else {
                // Default allow — redirect to destination pod.
                if let Some((_, dst_ep)) = lookup_identity(dst_ip) {
                    unsafe {
                        return Ok(bpf_redirect(dst_ep.ifindex, 0) as i32);
                    }
                }
                Ok(BPF_TC_ACT_OK as i32)
            }
        }
    }
}

// ===========================================================================
// TC PROGRAM: tc_tunnel_egress
// Attached to tunnel interface egress direction.
//
// The kernel handles Geneve/VXLAN encapsulation — tc_egress on the pod veth
// redirects cross-node packets to the tunnel interface via bpf_redirect(),
// and the kernel's tunnel module adds the outer headers.
//
// On the receiving side, tc_tunnel_ingress resolves identity via:
//   1. Geneve TLV option (if present)
//   2. Endpoint map lookup by inner source IP (always works)
//
// This program is a pass-through. A future optimization could inject the
// source pod's identity into a Geneve TLV here using bpf_skb_set_tunnel_opt,
// avoiding the endpoint map lookup on the receiving side. This is not
// required for correctness — the fallback path works for all cases.
// ===========================================================================

#[classifier]
pub fn tc_tunnel_egress(ctx: TcContext) -> i32 {
    match try_tc_tunnel_egress(&ctx) {
        Ok(action) => action,
        Err(_) => BPF_TC_ACT_OK as i32,
    }
}

#[inline(always)]
fn try_tc_tunnel_egress(_ctx: &TcContext) -> Result<i32, ()> {
    // Pass through — kernel handles encapsulation.
    // See tc_tunnel_ingress for the receiving side.
    Ok(BPF_TC_ACT_OK as i32)
}

// ---------------------------------------------------------------------------
// Panic handler (required for #![no_std])
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
