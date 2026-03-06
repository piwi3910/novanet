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
    bindings::{bpf_tunnel_key, BPF_F_ZERO_CSUM_TX},
    helpers::{bpf_redirect, bpf_skb_set_tunnel_key},
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
static ENDPOINTS: HashMap<EndpointKey, EndpointValue> = HashMap::with_max_entries(MAX_ENDPOINTS, 0);

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
    // SAFETY: eBPF map access via aya-ebpf; safety guaranteed by BPF verifier at load time.
    unsafe { CONFIG.get(&key).copied().unwrap_or(0) }
}

// ---------------------------------------------------------------------------
// Helper: check identity-based policy
// Returns: Some(action) if a policy entry exists, None otherwise
// ---------------------------------------------------------------------------

#[inline(always)]
fn check_policy(src_id: u32, dst_id: u32, proto: u8, dst_port: u16) -> Option<u8> {
    // Try identity pairs: (exact, exact), then (exact, wildcard), then (wildcard, exact).
    // For each pair, try port specificity: (proto, port), (proto, 0), (0, 0).
    let id_pairs: [(u32, u32); 3] = [
        (src_id, dst_id), // exact match
        (src_id, 0),      // wildcard destination (egress deny-all)
        (0, dst_id),      // wildcard source (ingress deny-all)
    ];

    // SAFETY: All POLICIES.get() calls below are eBPF map lookups via aya-ebpf;
    // safety is guaranteed by the BPF verifier at program load time.
    for &(src, dst) in id_pairs.iter() {
        // Try exact port match.
        let key = PolicyKey {
            src_identity: src,
            dst_identity: dst,
            protocol: proto,
            _pad: [0],
            dst_port,
        };
        if let Some(val) = unsafe { POLICIES.get(&key) } {
            return Some(val.action);
        }

        // Try wildcard port.
        if dst_port != 0 {
            let key_any_port = PolicyKey {
                src_identity: src,
                dst_identity: dst,
                protocol: proto,
                _pad: [0],
                dst_port: 0,
            };
            if let Some(val) = unsafe { POLICIES.get(&key_any_port) } {
                return Some(val.action);
            }
        }

        // Try wildcard protocol + port.
        if proto != 0 {
            let key_any_proto = PolicyKey {
                src_identity: src,
                dst_identity: dst,
                protocol: 0,
                _pad: [0],
                dst_port: 0,
            };
            if let Some(val) = unsafe { POLICIES.get(&key_any_proto) } {
                return Some(val.action);
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Helper: increment drop counter
// ---------------------------------------------------------------------------

#[inline(always)]
fn inc_drop_counter(reason: u8) {
    let idx = reason as u32;
    // SAFETY: eBPF per-CPU array access; the BPF verifier ensures bounds checking.
    // Writing through the raw pointer is safe because per-CPU arrays give exclusive access.
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
            // SAFETY: BPF helper call; always available in TC programs.
            timestamp_ns: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
        };
        // SAFETY: Writing to a ring buffer entry reserved above; entry is valid.
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
    // SAFETY: eBPF map lookup; safety guaranteed by BPF verifier.
    unsafe { ENDPOINTS.get(&key).map(|v| (v.identity, v)) }
}

// ---------------------------------------------------------------------------
// Helper: check egress policy for external traffic
// Returns: true if traffic should be allowed
// ---------------------------------------------------------------------------

#[inline(always)]
fn check_egress_policy(src_identity: u32, dst_ip: u32) -> (bool, u32) {
    // SAFETY: All EGRESS_POLICIES.get() calls below are eBPF map lookups;
    // safety is guaranteed by the BPF verifier at program load time.
    //
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

/// Derive a deterministic tunnel MAC address from an IPv4 address.
/// Format: `aa:bb:IP[0]:IP[1]:IP[2]:IP[3]` — matches Go's IPToTunnelMAC.
/// The IP must be in network byte order (big-endian).
#[inline(always)]
fn ip_to_tunnel_mac(ip: u64) -> [u8; 6] {
    let ip_bytes = (ip as u32).to_be_bytes();
    [
        0xaa,
        0xbb,
        ip_bytes[0],
        ip_bytes[1],
        ip_bytes[2],
        ip_bytes[3],
    ]
}

// ---------------------------------------------------------------------------
// Helper: set tunnel key metadata on skb for collect-metadata tunnel devices
// ---------------------------------------------------------------------------

/// Sets tunnel encapsulation metadata on the skb so a collect-metadata
/// (external/FlowBased) tunnel device can perform encapsulation.
/// This is the same approach used by Cilium and Calico:
///   1. Call bpf_skb_set_tunnel_key with remote_ipv4, tunnel_id (VNI), TTL
///   2. bpf_redirect to the tunnel ifindex
///   3. Kernel reads metadata from skb and encapsulates (Geneve/VXLAN)
#[inline(always)]
fn set_tunnel_key(ctx: &mut TcContext, remote_ip: u32, vni: u32) -> i64 {
    let mut key: bpf_tunnel_key = unsafe { core::mem::zeroed() };
    key.tunnel_id = vni;
    key.__bindgen_anon_1.remote_ipv4 = remote_ip;
    key.tunnel_ttl = 64;

    unsafe {
        bpf_skb_set_tunnel_key(
            ctx.skb.skb,
            &mut key as *mut bpf_tunnel_key,
            core::mem::size_of::<bpf_tunnel_key>() as u32,
            BPF_F_ZERO_CSUM_TX as u64,
        )
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
                    src_ip,
                    dst_ip,
                    0,
                    0,
                    protocol,
                    src_port,
                    dst_port,
                    ACTION_DENY,
                    DROP_REASON_NO_IDENTITY,
                    tcp_flags,
                    total_len,
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
                src_ip,
                dst_ip,
                src_identity,
                dst_identity,
                protocol,
                src_port,
                dst_port,
                ACTION_DENY,
                DROP_REASON_POLICY_DENIED,
                tcp_flags,
                total_len,
            );
            Ok(BPF_TC_ACT_SHOT as i32)
        }
        Some(ACTION_ALLOW) => {
            emit_flow_event(
                src_ip,
                dst_ip,
                src_identity,
                dst_identity,
                protocol,
                src_port,
                dst_port,
                ACTION_ALLOW,
                DROP_REASON_NONE,
                tcp_flags,
                total_len,
            );
            Ok(BPF_TC_ACT_OK as i32)
        }
        _ => {
            // No policy entry — check default deny flag.
            let default_deny = get_config(CONFIG_KEY_DEFAULT_DENY);
            if default_deny == 1 {
                inc_drop_counter(DROP_REASON_POLICY_DENIED);
                emit_flow_event(
                    src_ip,
                    dst_ip,
                    src_identity,
                    dst_identity,
                    protocol,
                    src_port,
                    dst_port,
                    ACTION_DENY,
                    DROP_REASON_POLICY_DENIED,
                    tcp_flags,
                    total_len,
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
pub fn tc_egress(mut ctx: TcContext) -> i32 {
    match try_tc_egress(&mut ctx) {
        Ok(action) => action,
        Err(_) => BPF_TC_ACT_OK as i32,
    }
}

#[inline(always)]
fn try_tc_egress(ctx: &mut TcContext) -> Result<i32, ()> {
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
                        src_ip,
                        dst_ip,
                        src_identity,
                        dst_identity,
                        protocol,
                        src_port,
                        dst_port,
                        ACTION_DENY,
                        DROP_REASON_POLICY_DENIED,
                        tcp_flags,
                        total_len,
                    );
                    return Ok(BPF_TC_ACT_SHOT as i32);
                }
                Some(ACTION_ALLOW) => {
                    emit_flow_event(
                        src_ip,
                        dst_ip,
                        src_identity,
                        dst_identity,
                        protocol,
                        src_port,
                        dst_port,
                        ACTION_ALLOW,
                        DROP_REASON_NONE,
                        tcp_flags,
                        total_len,
                    );
                    return Ok(BPF_TC_ACT_OK as i32);
                }
                _ => {
                    // No explicit policy. Check default deny.
                    let default_deny = get_config(CONFIG_KEY_DEFAULT_DENY);
                    if default_deny == 1 {
                        inc_drop_counter(DROP_REASON_POLICY_DENIED);
                        emit_flow_event(
                            src_ip,
                            dst_ip,
                            src_identity,
                            dst_identity,
                            protocol,
                            src_port,
                            dst_port,
                            ACTION_DENY,
                            DROP_REASON_POLICY_DENIED,
                            tcp_flags,
                            total_len,
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
                // Policy check before encapsulation.
                match check_policy(src_identity, dst_identity, protocol, dst_port) {
                    Some(ACTION_DENY) => {
                        inc_drop_counter(DROP_REASON_POLICY_DENIED);
                        emit_flow_event(
                            src_ip,
                            dst_ip,
                            src_identity,
                            dst_identity,
                            protocol,
                            src_port,
                            dst_port,
                            ACTION_DENY,
                            DROP_REASON_POLICY_DENIED,
                            tcp_flags,
                            total_len,
                        );
                        return Ok(BPF_TC_ACT_SHOT as i32);
                    }
                    Some(ACTION_ALLOW) => {
                        // Explicit allow — proceed to encapsulation.
                    }
                    _ => {
                        // No policy matched — check default deny.
                        let default_deny = get_config(CONFIG_KEY_DEFAULT_DENY);
                        if default_deny == 1 {
                            inc_drop_counter(DROP_REASON_POLICY_DENIED);
                            emit_flow_event(
                                src_ip,
                                dst_ip,
                                src_identity,
                                dst_identity,
                                protocol,
                                src_port,
                                dst_port,
                                ACTION_DENY,
                                DROP_REASON_POLICY_DENIED,
                                tcp_flags,
                                total_len,
                            );
                            return Ok(BPF_TC_ACT_SHOT as i32);
                        }
                    }
                }

                // Set tunnel metadata on the skb so the kernel's collect-metadata
                // tunnel device performs proper encapsulation (like Cilium/Calico).
                // The tunnel device reads remote_ipv4/tunnel_id/ttl from skb metadata
                // set by bpf_skb_set_tunnel_key, then encapsulates and transmits.
                let ret = set_tunnel_key(ctx, tunnel.remote_ip, tunnel.vni);
                if ret < 0 {
                    inc_drop_counter(DROP_REASON_NO_TUNNEL);
                    return Ok(BPF_TC_ACT_SHOT as i32);
                }

                emit_flow_event(
                    src_ip,
                    dst_ip,
                    src_identity,
                    dst_identity,
                    protocol,
                    src_port,
                    dst_port,
                    ACTION_ALLOW,
                    DROP_REASON_NONE,
                    tcp_flags,
                    total_len,
                );
                // Redirect to the tunnel interface. The kernel will read the
                // tunnel metadata we just set and do Geneve/VXLAN encapsulation.
                unsafe {
                    return Ok(bpf_redirect(tunnel.ifindex, 0) as i32);
                }
            } else {
                // No tunnel entry for remote node.
                inc_drop_counter(DROP_REASON_NO_TUNNEL);
                emit_flow_event(
                    src_ip,
                    dst_ip,
                    src_identity,
                    dst_identity,
                    protocol,
                    src_port,
                    dst_port,
                    ACTION_DENY,
                    DROP_REASON_NO_TUNNEL,
                    tcp_flags,
                    total_len,
                );
                return Ok(BPF_TC_ACT_SHOT as i32);
            }
        }

        // Native mode: policy check only, let kernel route to the remote node.
        match check_policy(src_identity, dst_identity, protocol, dst_port) {
            Some(ACTION_DENY) => {
                inc_drop_counter(DROP_REASON_POLICY_DENIED);
                emit_flow_event(
                    src_ip,
                    dst_ip,
                    src_identity,
                    dst_identity,
                    protocol,
                    src_port,
                    dst_port,
                    ACTION_DENY,
                    DROP_REASON_POLICY_DENIED,
                    tcp_flags,
                    total_len,
                );
                return Ok(BPF_TC_ACT_SHOT as i32);
            }
            Some(ACTION_ALLOW) => {
                emit_flow_event(
                    src_ip,
                    dst_ip,
                    src_identity,
                    dst_identity,
                    protocol,
                    src_port,
                    dst_port,
                    ACTION_ALLOW,
                    DROP_REASON_NONE,
                    tcp_flags,
                    total_len,
                );
                return Ok(BPF_TC_ACT_OK as i32);
            }
            _ => {
                let default_deny = get_config(CONFIG_KEY_DEFAULT_DENY);
                if default_deny == 1 {
                    inc_drop_counter(DROP_REASON_POLICY_DENIED);
                    emit_flow_event(
                        src_ip,
                        dst_ip,
                        src_identity,
                        dst_identity,
                        protocol,
                        src_port,
                        dst_port,
                        ACTION_DENY,
                        DROP_REASON_POLICY_DENIED,
                        tcp_flags,
                        total_len,
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
                src_ip,
                dst_ip,
                src_identity,
                0,
                protocol,
                src_port,
                dst_port,
                ACTION_DENY,
                DROP_REASON_POLICY_DENIED,
                tcp_flags,
                total_len,
            );
            return Ok(BPF_TC_ACT_SHOT as i32);
        }

        // SNAT is handled by netfilter/iptables in userspace for now.
        // We just allow the traffic through.
        emit_flow_event(
            src_ip,
            dst_ip,
            src_identity,
            0,
            protocol,
            src_port,
            dst_port,
            ACTION_ALLOW,
            DROP_REASON_NONE,
            tcp_flags,
            total_len,
        );
        return Ok(BPF_TC_ACT_OK as i32);
    }

    // Destination is a cluster IP but not in our endpoint map.
    // Let the kernel route it — in native mode the kernel routes via BGP.
    // In overlay mode, unknown destinations are dropped since eBPF handles
    // all tunnel encapsulation via bpf_skb_set_tunnel_key + bpf_redirect.
    let mode = get_config(CONFIG_KEY_MODE);
    if mode == MODE_OVERLAY {
        inc_drop_counter(DROP_REASON_NO_ROUTE);
        emit_flow_event(
            src_ip,
            dst_ip,
            src_identity,
            0,
            protocol,
            src_port,
            dst_port,
            ACTION_DENY,
            DROP_REASON_NO_ROUTE,
            tcp_flags,
            total_len,
        );
        Ok(BPF_TC_ACT_SHOT as i32)
    } else {
        Ok(BPF_TC_ACT_OK as i32)
    }
}

// ===========================================================================
// TC PROGRAM: tc_tunnel_ingress
// Attached to tunnel interface (Geneve/VXLAN) ingress direction.
// Decapsulates tunnel headers and resolves identity from:
//   - Geneve TLV option (preferred)
//   - Endpoint map lookup by source IP (VXLAN fallback)
// ===========================================================================

#[classifier]
pub fn tc_tunnel_ingress(mut ctx: TcContext) -> i32 {
    match try_tc_tunnel_ingress(&mut ctx) {
        Ok(action) => action,
        Err(_) => BPF_TC_ACT_OK as i32,
    }
}

#[inline(always)]
fn try_tc_tunnel_ingress(ctx: &mut TcContext) -> Result<i32, ()> {
    // Mark ALL traffic arriving on tunnel interfaces so iptables KUBE-FORWARD
    // accepts it. bpf_redirect on the sending side bypasses conntrack, so
    // replies arrive as ctstate INVALID. The 0x4000 mark matches the
    // KUBE-FORWARD "mark match 0x4000/0x4000 → ACCEPT" rule.
    ctx.set_mark(0x4000);

    // On FlowBased (collect-metadata) tunnel devices, the kernel has already
    // stripped the outer headers (Ethernet + IP + UDP + Geneve/VXLAN).
    // What we receive at offset 0 is the inner Ethernet frame.
    //
    // We parse the inner frame, resolve identities, enforce policy,
    // and redirect to the destination pod's veth interface.
    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    let ether_type = eth.ether_type;
    if ether_type != EtherType::Ipv4 {
        return Ok(BPF_TC_ACT_OK as i32);
    }

    let ipv4: Ipv4Hdr = ctx.load(ETH_HLEN).map_err(|_| ())?;
    let src_ip = u32::to_be(ipv4.src_addr);
    let dst_ip = u32::to_be(ipv4.dst_addr);
    let protocol = ipv4.proto as u8;
    let ihl = (ipv4.ihl() as usize) * 4;
    let l4_offset = ETH_HLEN + ihl;
    let tot_len = ipv4.tot_len;
    let total_len = u16::from_be(tot_len) as u64;

    let (src_port, dst_port, tcp_flags) = parse_l4_ports(ctx, l4_offset, protocol);

    // Rewrite the inner Ethernet dst MAC to match the destination pod's
    // interface MAC. The CNI assigns MACs as 02:fe:IP[0]:IP[1]:IP[2]:IP[3].
    // Without this rewrite, the pod's kernel drops the frame because the
    // dst MAC (from the source node) doesn't match the pod's eth0 MAC.
    let dst_ip_bytes = dst_ip.to_be_bytes();
    let pod_mac: [u8; 6] = [
        0x02,
        0xfe,
        dst_ip_bytes[0],
        dst_ip_bytes[1],
        dst_ip_bytes[2],
        dst_ip_bytes[3],
    ];
    // Overwrite dst MAC at offset 0 in the Ethernet header.
    let _ = ctx.store(0, &pod_mac, 0);

    // Resolve source identity from endpoint map. Remote pods won't be
    // found (they're on another node), so src_identity may be 0.
    let src_identity = lookup_identity(src_ip).map(|(id, _)| id).unwrap_or(0);
    let dst_identity = lookup_identity(dst_ip).map(|(id, _)| id).unwrap_or(0);

    enforce_tunnel_policy(
        ctx,
        src_ip,
        dst_ip,
        src_identity,
        dst_identity,
        protocol,
        src_port,
        dst_port,
        tcp_flags,
        total_len,
    )
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
                src_ip,
                dst_ip,
                0,
                dst_identity,
                protocol,
                src_port,
                dst_port,
                ACTION_DENY,
                DROP_REASON_NO_IDENTITY,
                tcp_flags,
                total_len,
            );
            return Ok(BPF_TC_ACT_SHOT as i32);
        }
        // Default allow — redirect to destination pod's veth.
        if let Some((_, dst_ep)) = lookup_identity(dst_ip) {
            unsafe {
                return Ok(bpf_redirect(dst_ep.ifindex, 0) as i32);
            }
        }
        return Ok(BPF_TC_ACT_OK as i32);
    }

    match check_policy(src_identity, dst_identity, protocol, dst_port) {
        Some(ACTION_DENY) => {
            inc_drop_counter(DROP_REASON_POLICY_DENIED);
            emit_flow_event(
                src_ip,
                dst_ip,
                src_identity,
                dst_identity,
                protocol,
                src_port,
                dst_port,
                ACTION_DENY,
                DROP_REASON_POLICY_DENIED,
                tcp_flags,
                total_len,
            );
            Ok(BPF_TC_ACT_SHOT as i32)
        }
        Some(ACTION_ALLOW) => {
            emit_flow_event(
                src_ip,
                dst_ip,
                src_identity,
                dst_identity,
                protocol,
                src_port,
                dst_port,
                ACTION_ALLOW,
                DROP_REASON_NONE,
                tcp_flags,
                total_len,
            );
            // Look up destination endpoint to redirect to pod veth.
            if let Some((_, dst_ep)) = lookup_identity(dst_ip) {
                // SAFETY: BPF helper call; safety guaranteed by verifier.
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
                    src_ip,
                    dst_ip,
                    src_identity,
                    dst_identity,
                    protocol,
                    src_port,
                    dst_port,
                    ACTION_DENY,
                    DROP_REASON_POLICY_DENIED,
                    tcp_flags,
                    total_len,
                );
                Ok(BPF_TC_ACT_SHOT as i32)
            } else {
                // Default allow — redirect to destination pod.
                if let Some((_, dst_ep)) = lookup_identity(dst_ip) {
                    // SAFETY: BPF helper call; safety guaranteed by verifier.
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
