//! NovaNet eBPF programs for packet processing and socket-level load balancing.
//!
//! TC classifier programs (attached to network interfaces):
//!   - `tc_ingress`: pod veth — traffic arriving at pod (K8s ingress)
//!   - `tc_egress`: pod veth — traffic leaving pod (K8s egress)
//!   - `tc_tunnel_ingress`: tunnel interface ingress (decap + policy)
//!   - `tc_tunnel_egress`: tunnel interface egress (encap identity)
//!   - `tc_host_ingress`: host interface ingress (NodePort/ExternalIP L4 LB)
//!
//! Cgroup socket-LB programs (attached to root cgroup):
//!   - `sock_connect4`: TCP ClusterIP DNAT at connect() time
//!   - `sock_sendmsg4`: UDP ClusterIP DNAT per sendmsg()
//!   - `sock_recvmsg4`: reverse-translate UDP reply source to ClusterIP
//!   - `sock_getpeername4`: return original ClusterIP for getpeername()
//!
//! Compiled with `--target bpfel-unknown-none -Z build-std=core` on Linux only.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_OK as BPF_TC_ACT_OK,
    bindings::TC_ACT_SHOT as BPF_TC_ACT_SHOT,
    bindings::{bpf_tunnel_key, BPF_F_ZERO_CSUM_TX, BPF_SK_LOOKUP_F_REPLACE},
    helpers::gen::{bpf_sk_assign, bpf_sk_lookup_tcp, bpf_sk_release},
    helpers::{bpf_get_socket_cookie, bpf_redirect, bpf_skb_set_tunnel_key},
    macros::{cgroup_sock_addr, classifier, map, sk_lookup, sk_msg, sock_ops},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, PerCpuHashMap, RingBuf, SockHash},
    programs::{SkLookupContext, SkMsgContext, SockAddrContext, SockOpsContext, TcContext},
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

#[map]
static SERVICES: HashMap<ServiceKey, ServiceValue> = HashMap::with_max_entries(MAX_SERVICES, 0);

#[map]
static BACKENDS: Array<BackendValue> = Array::with_max_entries(MAX_BACKENDS, 0);

#[map]
static CONNTRACK: LruHashMap<CtKey, CtValue> = LruHashMap::with_max_entries(MAX_CONNTRACK, 0);

#[map]
static MAGLEV: Array<u32> = Array::with_max_entries(MAX_MAGLEV, 0);

#[map]
static RR_COUNTERS: PerCpuArray<u32> = PerCpuArray::with_max_entries(MAX_SERVICES, 0);

#[map]
static SOCK_LB_ORIGINS: LruHashMap<u64, SockLbOrigin> =
    LruHashMap::with_max_entries(MAX_SOCK_LB_ORIGINS, 0);

// ---------------------------------------------------------------------------
// SOCKMAP maps — same-node socket bypass
// ---------------------------------------------------------------------------

/// Hash map of sockets keyed by 5-tuple for SOCKMAP redirect.
#[map]
static SOCK_HASH: SockHash<SockKey> = SockHash::with_max_entries(65536, 0);

/// Endpoints registered for SOCKMAP bypass (pod IPs + ports).
#[map]
static SOCKMAP_ENDPOINTS: HashMap<SockmapEndpointKey, u32> = HashMap::with_max_entries(4096, 0);

/// Per-CPU stats: [0] = redirected count, [1] = fallback count.
#[map]
static SOCKMAP_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(2, 0);

// ---------------------------------------------------------------------------
// Mesh redirect maps — SK_LOOKUP service mesh interception
// ---------------------------------------------------------------------------

/// Mesh services to intercept via SK_LOOKUP (service IP+port → redirect port).
#[map]
static MESH_SERVICES: HashMap<MeshServiceKey, MeshRedirectValue> =
    HashMap::with_max_entries(4096, 0);

// ---------------------------------------------------------------------------
// Rate limiting maps — per-source-IP token bucket
// ---------------------------------------------------------------------------

/// Per-source token bucket state (LRU to handle large IP spaces).
#[map]
static RL_TOKENS: LruHashMap<RateLimitKey, TokenBucketState> =
    LruHashMap::with_max_entries(100000, 0);

/// Global rate limit configuration (single entry at index 0).
#[map]
static RL_CONFIG: Array<RateLimitConfig> = Array::with_max_entries(1, 0);

// ---------------------------------------------------------------------------
// Backend health maps — passive TCP health monitoring
// ---------------------------------------------------------------------------

/// Per-backend TCP connection health counters (per-CPU for lock-free updates).
#[map]
static BACKEND_HEALTH: PerCpuHashMap<BackendHealthKey, BackendHealthCounters> =
    PerCpuHashMap::with_max_entries(4096, 0);

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
    if let Some(counter) = DROP_COUNTERS.get_ptr_mut(idx) {
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
        // Convert IPv4 u32 addresses to [u8; 16] (first 4 bytes, rest zeroed).
        let mut src_ip_bytes = [0u8; 16];
        src_ip_bytes[0] = (src_ip >> 24) as u8;
        src_ip_bytes[1] = (src_ip >> 16) as u8;
        src_ip_bytes[2] = (src_ip >> 8) as u8;
        src_ip_bytes[3] = src_ip as u8;

        let mut dst_ip_bytes = [0u8; 16];
        dst_ip_bytes[0] = (dst_ip >> 24) as u8;
        dst_ip_bytes[1] = (dst_ip >> 16) as u8;
        dst_ip_bytes[2] = (dst_ip >> 8) as u8;
        dst_ip_bytes[3] = dst_ip as u8;

        let event = FlowEvent {
            family: AF_INET,
            verdict,
            drop_reason,
            tcp_flags,
            src_identity,
            dst_identity,
            protocol,
            _pad1: 0,
            src_port,
            dst_port,
            _pad2: [0; 2],
            src_ip: src_ip_bytes,
            dst_ip: dst_ip_bytes,
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
// Helper: FNV-1a hash of 5-tuple for backend selection
// ---------------------------------------------------------------------------

#[inline(always)]
fn hash_5tuple(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8) -> u32 {
    let mut h: u32 = 2166136261;
    h ^= src_ip;
    h = h.wrapping_mul(16777619);
    h ^= dst_ip;
    h = h.wrapping_mul(16777619);
    h ^= src_port as u32;
    h = h.wrapping_mul(16777619);
    h ^= dst_port as u32;
    h = h.wrapping_mul(16777619);
    h ^= proto as u32;
    h = h.wrapping_mul(16777619);
    h
}

// ---------------------------------------------------------------------------
// Helper: service lookup + backend selection
// Returns (backend_ip, backend_port, origin_vip, origin_port) if found.
// ---------------------------------------------------------------------------

#[inline(always)]
fn service_lookup(
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
    src_ip: u32,
    src_port: u16,
    scope: u8,
) -> Option<(u32, u16, u32, u16)> {
    if get_config(CONFIG_KEY_L4LB_ENABLED) == 0 {
        return None;
    }

    // Check conntrack for existing connection.
    let ct_key = CtKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        _pad: [0; 3],
    };
    // SAFETY: eBPF map lookup; safety guaranteed by BPF verifier.
    if let Some(ct) = unsafe { CONNTRACK.get(&ct_key) } {
        let backend_ip = ct.backend_ip;
        let backend_port = ct.backend_port;
        let origin_ip = ct.origin_ip;
        let origin_port = ct.origin_port;
        return Some((backend_ip, backend_port, origin_ip, origin_port));
    }

    // Look up service.
    let svc_key = ServiceKey {
        ip: dst_ip,
        port: dst_port,
        protocol,
        scope,
    };
    // SAFETY: eBPF map lookup; safety guaranteed by BPF verifier.
    let svc = unsafe { SERVICES.get(&svc_key) }?;

    let count = svc.backend_count;
    if count == 0 {
        return None;
    }
    let offset = svc.backend_offset;
    let algorithm = svc.algorithm;

    // Select backend index.
    let idx = match algorithm {
        LB_ALG_ROUND_ROBIN => {
            // SAFETY: eBPF per-CPU array access; BPF verifier ensures bounds.
            if let Some(c) = RR_COUNTERS.get_ptr_mut(offset as u32) {
                let val = unsafe { *c };
                unsafe { *c = val.wrapping_add(1) };
                val % (count as u32)
            } else {
                0
            }
        }
        LB_ALG_MAGLEV => {
            let hash = hash_5tuple(src_ip, dst_ip, src_port, dst_port, protocol);
            let maglev_offset = svc.maglev_offset;
            let maglev_idx = maglev_offset + (hash % MAGLEV_TABLE_SIZE);
            // SAFETY: eBPF array lookup; safety guaranteed by BPF verifier.
            if let Some(backend_idx) = MAGLEV.get(maglev_idx) {
                *backend_idx
            } else {
                0
            }
        }
        _ => {
            // Random (default): hash-based selection.
            let hash = hash_5tuple(src_ip, dst_ip, src_port, dst_port, protocol);
            hash % (count as u32)
        }
    };

    let backend_array_idx = (offset as u32) + idx;
    // SAFETY: eBPF array lookup; safety guaranteed by BPF verifier.
    let backend = BACKENDS.get(backend_array_idx)?;
    let backend_ip = backend.ip;
    let backend_port = backend.port;

    // Create forward conntrack entry.
    let ct_val = CtValue {
        timestamp: 0,
        backend_ip,
        origin_ip: dst_ip,
        backend_port,
        origin_port: dst_port,
        flags: 0,
        _pad: 0,
        _pad2: [0; 2],
    };
    // SAFETY: eBPF map insert; safety guaranteed by BPF verifier.
    let _ = CONNTRACK.insert(&ct_key, &ct_val, 0);

    // Create reverse conntrack entry for return traffic SNAT.
    let rev_ct_key = CtKey {
        src_ip: backend_ip,
        dst_ip: src_ip,
        src_port: backend_port,
        dst_port: src_port,
        protocol,
        _pad: [0; 3],
    };
    let rev_ct_val = CtValue {
        timestamp: 0,
        backend_ip: 0,
        origin_ip: dst_ip,
        backend_port: 0,
        origin_port: dst_port,
        flags: 0,
        _pad: 0,
        _pad2: [0; 2],
    };
    // SAFETY: eBPF map insert; safety guaranteed by BPF verifier.
    let _ = CONNTRACK.insert(&rev_ct_key, &rev_ct_val, 0);

    Some((backend_ip, backend_port, dst_ip, dst_port))
}

// ---------------------------------------------------------------------------
// Helper: socket-LB service lookup + backend selection
// Returns (backend_ip, backend_port) if dst is a ClusterIP service.
// Unlike TC service_lookup, this doesn't create conntrack entries.
// ---------------------------------------------------------------------------

#[inline(always)]
fn sock_service_lookup(dst_ip: u32, dst_port: u16, protocol: u8) -> Option<(u32, u16)> {
    if get_config(CONFIG_KEY_L4LB_ENABLED) == 0 {
        return None;
    }

    let svc_key = ServiceKey {
        ip: dst_ip,
        port: dst_port,
        protocol,
        scope: SVC_SCOPE_CLUSTER_IP,
    };
    // SAFETY: eBPF map lookup; safety guaranteed by BPF verifier.
    let svc = unsafe { SERVICES.get(&svc_key) }?;

    let count = svc.backend_count;
    if count == 0 {
        return None;
    }
    let offset = svc.backend_offset;
    let algorithm = svc.algorithm;

    // Select backend. Note: src_port is unknown at connect() time,
    // so we use a 3-tuple hash (dst_ip, dst_port, protocol) for
    // Maglev/random, and the same RR counter for round-robin.
    let idx = match algorithm {
        LB_ALG_ROUND_ROBIN => {
            // SAFETY: eBPF per-CPU array access; BPF verifier ensures bounds.
            if let Some(c) = RR_COUNTERS.get_ptr_mut(offset as u32) {
                let val = unsafe { *c };
                unsafe { *c = val.wrapping_add(1) };
                val % (count as u32)
            } else {
                0
            }
        }
        LB_ALG_MAGLEV => {
            let mut h: u32 = 2166136261;
            h ^= dst_ip;
            h = h.wrapping_mul(16777619);
            h ^= dst_port as u32;
            h = h.wrapping_mul(16777619);
            h ^= protocol as u32;
            h = h.wrapping_mul(16777619);

            let maglev_offset = svc.maglev_offset;
            let maglev_idx = maglev_offset + (h % MAGLEV_TABLE_SIZE);
            // SAFETY: eBPF array lookup; safety guaranteed by BPF verifier.
            if let Some(backend_idx) = MAGLEV.get(maglev_idx) {
                *backend_idx
            } else {
                0
            }
        }
        _ => {
            // Random: use 3-tuple hash.
            let mut h: u32 = 2166136261;
            h ^= dst_ip;
            h = h.wrapping_mul(16777619);
            h ^= dst_port as u32;
            h = h.wrapping_mul(16777619);
            h ^= protocol as u32;
            h = h.wrapping_mul(16777619);
            h % (count as u32)
        }
    };

    let backend_array_idx = (offset as u32) + idx;
    // SAFETY: eBPF array lookup; safety guaranteed by BPF verifier.
    let backend = BACKENDS.get(backend_array_idx)?;

    Some((backend.ip, backend.port))
}

// ---------------------------------------------------------------------------
// Helper: perform DNAT — rewrite destination IP and port with incremental
// checksum updates.
// ---------------------------------------------------------------------------

#[inline(always)]
fn perform_dnat(
    ctx: &mut TcContext,
    l4_offset: usize,
    protocol: u8,
    old_ip: u32,
    new_ip: u32,
    old_port: u16,
    new_port: u16,
) -> Result<(), ()> {
    let old_ip_be = old_ip.to_be();
    let new_ip_be = new_ip.to_be();

    // Update IP header checksum for dst IP change.
    ctx.l3_csum_replace(ETH_HLEN + 10, old_ip_be as u64, new_ip_be as u64, 4)
        .map_err(|_| ())?;

    // Write new destination IP (offset ETH_HLEN + 16).
    ctx.store(ETH_HLEN + 16, &new_ip_be, 0).map_err(|_| ())?;

    if protocol == 6 || protocol == 17 {
        let l4_csum_offset = if protocol == 6 {
            l4_offset + 16
        } else {
            l4_offset + 6
        };

        // Update L4 checksum for IP change (BPF_F_PSEUDO_HDR = 0x10).
        ctx.l4_csum_replace(l4_csum_offset, old_ip_be as u64, new_ip_be as u64, 0x14)
            .map_err(|_| ())?;

        // Rewrite destination port (l4_offset + 2).
        let old_port_be = old_port.to_be();
        let new_port_be = new_port.to_be();

        ctx.l4_csum_replace(l4_csum_offset, old_port_be as u64, new_port_be as u64, 2)
            .map_err(|_| ())?;

        ctx.store(l4_offset + 2, &new_port_be, 0).map_err(|_| ())?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: perform reverse SNAT — rewrite source IP and port back to VIP
// ---------------------------------------------------------------------------

#[inline(always)]
fn perform_snat(
    ctx: &mut TcContext,
    l4_offset: usize,
    protocol: u8,
    old_ip: u32,
    new_ip: u32,
    old_port: u16,
    new_port: u16,
) -> Result<(), ()> {
    let old_ip_be = old_ip.to_be();
    let new_ip_be = new_ip.to_be();

    // Update IP header checksum for src IP change.
    ctx.l3_csum_replace(ETH_HLEN + 10, old_ip_be as u64, new_ip_be as u64, 4)
        .map_err(|_| ())?;

    // Write new source IP (offset ETH_HLEN + 12).
    ctx.store(ETH_HLEN + 12, &new_ip_be, 0).map_err(|_| ())?;

    if protocol == 6 || protocol == 17 {
        let l4_csum_offset = if protocol == 6 {
            l4_offset + 16
        } else {
            l4_offset + 6
        };

        // Update L4 checksum for IP change (BPF_F_PSEUDO_HDR = 0x10).
        ctx.l4_csum_replace(l4_csum_offset, old_ip_be as u64, new_ip_be as u64, 0x14)
            .map_err(|_| ())?;

        // Rewrite source port (l4_offset + 0).
        let old_port_be = old_port.to_be();
        let new_port_be = new_port.to_be();

        ctx.l4_csum_replace(l4_csum_offset, old_port_be as u64, new_port_be as u64, 2)
            .map_err(|_| ())?;

        ctx.store(l4_offset, &new_port_be, 0).map_err(|_| ())?;
    }

    Ok(())
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

// ---------------------------------------------------------------------------
// Helper: per-source-IP rate limiting (token bucket)
// Returns true if packet is allowed, false if rate-limited.
// ---------------------------------------------------------------------------

#[inline(always)]
fn check_rate_limit(src_ip: u32) -> bool {
    // Read global rate limit configuration.
    let cfg = match RL_CONFIG.get(0) {
        Some(c) => c,
        None => return true, // No config → allow all
    };
    if cfg.rate == 0 {
        return true; // Rate limiting disabled
    }

    // Build key from source IP (IPv4-mapped IPv6 format).
    let mut addr = [0u8; 16];
    addr[0] = (src_ip >> 24) as u8;
    addr[1] = (src_ip >> 16) as u8;
    addr[2] = (src_ip >> 8) as u8;
    addr[3] = src_ip as u8;
    let key = RateLimitKey { addr };

    // SAFETY: BPF helper call; always available in TC programs.
    let now_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };

    // Look up existing token bucket state.
    // SAFETY: eBPF map lookup; safety guaranteed by BPF verifier.
    if let Some(state) = unsafe { RL_TOKENS.get(&key) } {
        let mut tokens = state.tokens;
        let elapsed = now_ns.saturating_sub(state.last_refill_ns);

        // Refill tokens based on elapsed time.
        if elapsed >= cfg.window_ns && cfg.window_ns > 0 {
            let windows = elapsed / cfg.window_ns;
            tokens = tokens.saturating_add(windows * cfg.rate as u64);
            if tokens > cfg.burst as u64 {
                tokens = cfg.burst as u64;
            }
        }

        if tokens > 0 {
            // Consume a token.
            let new_state = TokenBucketState {
                tokens: tokens - 1,
                last_refill_ns: now_ns,
            };
            let _ = RL_TOKENS.insert(&key, &new_state, 0);
            true
        } else {
            false
        }
    } else {
        // First packet from this source — initialize with burst - 1 tokens.
        let new_state = TokenBucketState {
            tokens: if cfg.burst > 0 {
                cfg.burst as u64 - 1
            } else {
                0
            },
            last_refill_ns: now_ns,
        };
        let _ = RL_TOKENS.insert(&key, &new_state, 0);
        true
    }
}

// ---------------------------------------------------------------------------
// Helper: track backend health from TCP flags (passive monitoring)
// ---------------------------------------------------------------------------

#[inline(always)]
fn track_backend_health(dst_ip: u32, dst_port: u16, tcp_flags: u8) {
    // Only track TCP packets with meaningful flags.
    // SYN=0x02, SYN-ACK=0x12, RST=0x04, FIN=0x01
    if tcp_flags == 0 {
        return;
    }

    let key = BackendHealthKey {
        ip: dst_ip,
        port: dst_port as u32,
    };

    if let Some(counters) = BACKEND_HEALTH.get_ptr_mut(&key) {
        // SYN (0x02) without ACK = new connection attempt.
        if tcp_flags & 0x02 != 0 && tcp_flags & 0x10 == 0 {
            unsafe { (*counters).total_conns += 1 };
        }

        // SYN-ACK (0x12) = successful connection establishment.
        if tcp_flags & 0x12 == 0x12 {
            unsafe {
                (*counters).success_conns += 1;
                (*counters).last_success_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
            };
        }

        // RST (0x04) = connection failure/reset.
        if tcp_flags & 0x04 != 0 {
            unsafe {
                (*counters).failed_conns += 1;
                (*counters).last_failure_ns = aya_ebpf::helpers::bpf_ktime_get_ns();
            };
        }
    } else {
        // First time seeing this backend — initialize counters.
        let mut new_counters = BackendHealthCounters {
            total_conns: 0,
            failed_conns: 0,
            timeout_conns: 0,
            success_conns: 0,
            last_success_ns: 0,
            last_failure_ns: 0,
            total_rtt_ns: 0,
        };

        if tcp_flags & 0x02 != 0 && tcp_flags & 0x10 == 0 {
            new_counters.total_conns = 1;
        }
        if tcp_flags & 0x12 == 0x12 {
            new_counters.success_conns = 1;
            // SAFETY: BPF helper call.
            new_counters.last_success_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        }
        if tcp_flags & 0x04 != 0 {
            new_counters.failed_conns = 1;
            // SAFETY: BPF helper call.
            new_counters.last_failure_ns = unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() };
        }

        let _ = BACKEND_HEALTH.insert(&key, &new_counters, 0);
    }
}

// ===========================================================================
// TC PROGRAM: tc_ingress
// Traffic arriving at the pod from the network (K8s ingress).
// Attached to TC egress hook on host veth (packets leaving host → pod).
// Enforces inbound policy in native mode. In overlay mode, policy was
// already checked by tc_tunnel_ingress, so we pass through.
// ===========================================================================

#[classifier]
pub fn tc_ingress(mut ctx: TcContext) -> i32 {
    match try_tc_ingress(&mut ctx) {
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
fn try_tc_ingress(ctx: &mut TcContext) -> Result<i32, ()> {
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

    // Rate limiting: check per-source-IP token bucket before any other processing.
    if !check_rate_limit(src_ip) {
        inc_drop_counter(DROP_REASON_RATE_LIMITED);
        return Ok(BPF_TC_ACT_SHOT as i32);
    }

    // Passive backend health monitoring: track TCP SYN/SYN-ACK/RST events.
    if protocol == 6 {
        track_backend_health(dst_ip, dst_port, tcp_flags);
    }

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

    // --- L4 LB: Reverse SNAT on return traffic ---
    if get_config(CONFIG_KEY_L4LB_ENABLED) != 0 {
        let rev_key = CtKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            _pad: [0; 3],
        };
        // SAFETY: eBPF map lookup; safety guaranteed by BPF verifier.
        if let Some(ct) = unsafe { CONNTRACK.get(&rev_key) } {
            let origin_ip = ct.origin_ip;
            let origin_port = ct.origin_port;
            if origin_ip != 0 {
                let _ = perform_snat(
                    ctx,
                    l4_offset,
                    protocol,
                    src_ip,
                    origin_ip,
                    src_port,
                    origin_port,
                );
            }
        }
    }

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

// ===========================================================================
// TC PROGRAM: tc_host_ingress
// Attached to the host physical interface (e.g., eth0) ingress direction.
// Handles NodePort and ExternalIP service traffic arriving from outside the
// cluster. Performs service lookup + DNAT for matching packets, and reverse
// SNAT on return traffic via conntrack.
// ===========================================================================

#[classifier]
pub fn tc_host_ingress(mut ctx: TcContext) -> i32 {
    match try_tc_host_ingress(&mut ctx) {
        Ok(action) => action,
        Err(_) => BPF_TC_ACT_OK as i32,
    }
}

#[inline(always)]
fn try_tc_host_ingress(ctx: &mut TcContext) -> Result<i32, ()> {
    if get_config(CONFIG_KEY_L4LB_ENABLED) == 0 {
        return Ok(BPF_TC_ACT_OK as i32);
    }

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

    let (src_port, dst_port, _tcp_flags) = parse_l4_ports(ctx, l4_offset, protocol);

    // Check conntrack first (return traffic).
    let ct_key = CtKey {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        _pad: [0; 3],
    };
    // SAFETY: eBPF map lookup; safety guaranteed by BPF verifier.
    if let Some(ct) = unsafe { CONNTRACK.get(&ct_key) } {
        let origin_ip = ct.origin_ip;
        let origin_port = ct.origin_port;
        if origin_ip != 0 {
            let _ = perform_snat(
                ctx,
                l4_offset,
                protocol,
                src_ip,
                origin_ip,
                src_port,
                origin_port,
            );
        }
        return Ok(BPF_TC_ACT_OK as i32);
    }

    // Check NodePort (ip=0 matches any node IP).
    if let Some((backend_ip, backend_port, _, _)) =
        service_lookup(0, dst_port, protocol, src_ip, src_port, SVC_SCOPE_NODE_PORT)
    {
        let _ = perform_dnat(
            ctx,
            l4_offset,
            protocol,
            dst_ip,
            backend_ip,
            dst_port,
            backend_port,
        );
        return Ok(BPF_TC_ACT_OK as i32);
    }

    // Check ExternalIP.
    if let Some((backend_ip, backend_port, _, _)) = service_lookup(
        dst_ip,
        dst_port,
        protocol,
        src_ip,
        src_port,
        SVC_SCOPE_EXTERNAL_IP,
    ) {
        let _ = perform_dnat(
            ctx,
            l4_offset,
            protocol,
            dst_ip,
            backend_ip,
            dst_port,
            backend_port,
        );
        return Ok(BPF_TC_ACT_OK as i32);
    }

    Ok(BPF_TC_ACT_OK as i32)
}

// ===========================================================================
// Socket-LB: cgroup/connect4 — TCP ClusterIP DNAT at connect() time
// ===========================================================================

#[cgroup_sock_addr(connect4)]
pub fn sock_connect4(ctx: SockAddrContext) -> i32 {
    match try_sock_connect4(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1, // 1 = allow (don't block on error)
    }
}

#[inline(always)]
fn try_sock_connect4(ctx: &SockAddrContext) -> Result<i32, i64> {
    // SAFETY: bpf_sock_addr pointer is valid in cgroup_sock_addr context.
    let dst_ip = unsafe { (*ctx.sock_addr).user_ip4 };
    // user_port is __be16 stored in a u32; convert to host order.
    let dst_port_raw = unsafe { (*ctx.sock_addr).user_port };
    let dst_port = u16::from_be(dst_port_raw as u16);

    // TCP protocol = 6
    if let Some((backend_ip, backend_port)) = sock_service_lookup(dst_ip, dst_port, 6) {
        // Store original destination keyed by socket cookie.
        let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) };
        let origin = SockLbOrigin {
            original_ip: dst_ip,
            original_port: dst_port,
            protocol: 6,
            _pad: 0,
        };
        // SAFETY: eBPF map insert; safety guaranteed by BPF verifier.
        let _ = SOCK_LB_ORIGINS.insert(&cookie, &origin, 0);

        // Rewrite destination to backend.
        unsafe {
            (*ctx.sock_addr).user_ip4 = backend_ip;
            (*ctx.sock_addr).user_port = (backend_port.to_be()) as u32;
        }
    }

    Ok(1) // 1 = allow connection
}

// ===========================================================================
// Socket-LB: cgroup/sendmsg4 — UDP ClusterIP DNAT per sendmsg()
// ===========================================================================

#[cgroup_sock_addr(sendmsg4)]
pub fn sock_sendmsg4(ctx: SockAddrContext) -> i32 {
    match try_sock_sendmsg4(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_sock_sendmsg4(ctx: &SockAddrContext) -> Result<i32, i64> {
    // SAFETY: bpf_sock_addr pointer is valid in cgroup_sock_addr context.
    let dst_ip = unsafe { (*ctx.sock_addr).user_ip4 };
    let dst_port_raw = unsafe { (*ctx.sock_addr).user_port };
    let dst_port = u16::from_be(dst_port_raw as u16);

    // UDP protocol = 17
    if let Some((backend_ip, backend_port)) = sock_service_lookup(dst_ip, dst_port, 17) {
        let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) };
        let origin = SockLbOrigin {
            original_ip: dst_ip,
            original_port: dst_port,
            protocol: 17,
            _pad: 0,
        };
        let _ = SOCK_LB_ORIGINS.insert(&cookie, &origin, 0);

        unsafe {
            (*ctx.sock_addr).user_ip4 = backend_ip;
            (*ctx.sock_addr).user_port = (backend_port.to_be()) as u32;
        }
    }

    Ok(1)
}

// ===========================================================================
// Socket-LB: cgroup/recvmsg4 — reverse-translate UDP reply source
// ===========================================================================

#[cgroup_sock_addr(recvmsg4)]
pub fn sock_recvmsg4(ctx: SockAddrContext) -> i32 {
    match try_sock_recvmsg4(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_sock_recvmsg4(ctx: &SockAddrContext) -> Result<i32, i64> {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) };

    // SAFETY: eBPF map lookup; safety guaranteed by BPF verifier.
    if let Some(origin) = unsafe { SOCK_LB_ORIGINS.get(&cookie) } {
        let original_ip = origin.original_ip;
        let original_port = origin.original_port;
        // Rewrite source address back to original ClusterIP.
        unsafe {
            (*ctx.sock_addr).user_ip4 = original_ip;
            (*ctx.sock_addr).user_port = (original_port.to_be()) as u32;
        }
    }

    Ok(1)
}

// ===========================================================================
// Socket-LB: cgroup/getpeername4 — return original ClusterIP for getpeername()
// ===========================================================================

#[cgroup_sock_addr(getpeername4)]
pub fn sock_getpeername4(ctx: SockAddrContext) -> i32 {
    match try_sock_getpeername4(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_sock_getpeername4(ctx: &SockAddrContext) -> Result<i32, i64> {
    let cookie = unsafe { bpf_get_socket_cookie(ctx.sock_addr as *mut _) };

    // SAFETY: eBPF map lookup; safety guaranteed by BPF verifier.
    if let Some(origin) = unsafe { SOCK_LB_ORIGINS.get(&cookie) } {
        let original_ip = origin.original_ip;
        let original_port = origin.original_port;
        unsafe {
            (*ctx.sock_addr).user_ip4 = original_ip;
            (*ctx.sock_addr).user_port = (original_port.to_be()) as u32;
        }
    }

    Ok(1)
}

// ===========================================================================
// SOCKMAP PROGRAM: sock_ops — capture established connections into SOCK_HASH
// ===========================================================================

#[sock_ops]
pub fn sockops_sockmap(ctx: SockOpsContext) -> u32 {
    match try_sockops_sockmap(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[inline(always)]
fn try_sockops_sockmap(ctx: SockOpsContext) -> Result<u32, i64> {
    let op = ctx.op();

    // Only handle established connections (active and passive).
    // BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB = 4, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB = 5
    if op != 4 && op != 5 {
        return Ok(0);
    }

    let src_ip = ctx.local_ip4();
    let dst_ip = ctx.remote_ip4();
    let src_port = ctx.local_port() as u16;
    // remote_port() returns network byte order in sock_ops context.
    let dst_port = u16::from_be(ctx.remote_port() as u16);

    // Check if both endpoints are registered for SOCKMAP bypass.
    let src_key = SockmapEndpointKey {
        ip: src_ip,
        port: src_port as u32,
    };
    let dst_key = SockmapEndpointKey {
        ip: dst_ip,
        port: dst_port as u32,
    };

    // SAFETY: eBPF map lookups; safety guaranteed by BPF verifier.
    let src_local = unsafe { SOCKMAP_ENDPOINTS.get(&src_key) }.is_some();
    let dst_local = unsafe { SOCKMAP_ENDPOINTS.get(&dst_key) }.is_some();

    if src_local && dst_local {
        let key = SockKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            family: 2, // AF_INET
        };

        // Insert socket into SOCK_HASH for later redirect by sk_msg program.
        let mut key = key;
        // SAFETY: ctx.ops is the raw bpf_sock_ops pointer required by bpf_sock_hash_update.
        let _ = SOCK_HASH.update(&mut key, unsafe { &mut *ctx.ops }, 0);
    }

    Ok(0)
}

// ===========================================================================
// SK_MSG PROGRAM: sk_msg — redirect messages between SOCKMAP sockets
// ===========================================================================

#[sk_msg]
pub fn sk_msg_sockmap(ctx: SkMsgContext) -> u32 {
    match try_sk_msg_sockmap(ctx) {
        Ok(ret) => ret,
        Err(_) => {
            // Fallback: increment fallback counter and let message pass normally.
            if let Some(counter) = SOCKMAP_STATS.get_ptr_mut(1) {
                unsafe { *counter += 1 };
            }
            1 // SK_PASS
        }
    }
}

#[inline(always)]
fn try_sk_msg_sockmap(ctx: SkMsgContext) -> Result<u32, i64> {
    // Build the reverse key to find the peer socket.
    // SAFETY: Accessing sk_msg_md fields via raw pointer; BPF verifier ensures validity.
    let src_ip = unsafe { (*ctx.msg).local_ip4 };
    let dst_ip = unsafe { (*ctx.msg).remote_ip4 };
    let src_port = unsafe { (*ctx.msg).local_port } as u16;
    let dst_port = u16::from_be(unsafe { (*ctx.msg).remote_port } as u16);

    let mut peer_key = SockKey {
        src_ip: dst_ip,
        dst_ip: src_ip,
        src_port: dst_port,
        dst_port: src_port,
        family: 2, // AF_INET
    };

    // Redirect the message to the peer socket via SOCK_HASH.
    // bpf_msg_redirect_hash redirects the message to the socket matching peer_key.
    let ret = SOCK_HASH.redirect_msg(&ctx, &mut peer_key, 0);
    if ret == 1 {
        // SK_PASS with redirect — increment redirected counter.
        if let Some(counter) = SOCKMAP_STATS.get_ptr_mut(0) {
            unsafe { *counter += 1 };
        }
    } else {
        // Redirect failed — increment fallback counter.
        if let Some(counter) = SOCKMAP_STATS.get_ptr_mut(1) {
            unsafe { *counter += 1 };
        }
    }
    // Always return SK_PASS — if redirect succeeded the kernel handles it,
    // otherwise the message passes through the normal stack.
    Ok(1)
}

// ===========================================================================
// SK_LOOKUP PROGRAM: mesh service redirect
// Intercepts service-destined connections and redirects to sidecar proxy.
//
// When a TCP connection targets a ClusterIP:port registered in the
// MESH_SERVICES map, this program looks up a listening socket on
// 127.0.0.1:<redirect_port> and assigns it via bpf_sk_assign(). This
// replaces nftables/iptables NAT REDIRECT rules entirely, eliminating
// conntrack overhead and kube-proxy priority ordering issues.
// ===========================================================================

// For BPF_PROG_TYPE_SK_LOOKUP, return 0 means "proceed with lookup" (pass),
// return 1 means "drop the connection". This is DIFFERENT from sk_action::SK_PASS (1)
// / sk_action::SK_DROP (0) used in sk_msg/sk_skb programs. Do not confuse them.
// See kernel: include/uapi/linux/bpf.h, net/core/sock_map.c:sock_map_lookup_prog_run().
const SK_PASS: u32 = 0;
#[allow(dead_code)] // Defined for completeness; used when we add drop-on-policy-deny.
const SK_DROP: u32 = 1;

#[sk_lookup]
pub fn sk_lookup_mesh(ctx: SkLookupContext) -> u32 {
    match unsafe { try_sk_lookup_mesh(&ctx) } {
        Ok(ret) => ret,
        Err(_) => SK_PASS, // On error, don't interfere — let normal lookup proceed
    }
}

/// Look up the destination in the MESH_SERVICES map. If found, find a
/// listening socket on 127.0.0.1:<redirect_port> and assign it so the
/// kernel delivers the connection directly to the mesh transparent listener.
unsafe fn try_sk_lookup_mesh(ctx: &SkLookupContext) -> Result<u32, i64> {
    let lookup = &*ctx.lookup;

    // Only handle IPv4 TCP for now.
    if lookup.family != 2 || lookup.protocol != 6 {
        // AF_INET = 2, IPPROTO_TCP = 6
        return Ok(SK_PASS);
    }

    // local_ip4/local_port are the destination (the ClusterIP:port being connected to).
    // NOTE: In struct bpf_sk_lookup, `local_port` is a __u32 in HOST byte order
    // (unlike `remote_port` which is __be16 in network byte order). This is
    // documented in include/uapi/linux/bpf.h and verified in kernel source
    // net/core/filter.c:bpf_sk_lookup_convert_ctx_access().
    let dst_ip = lookup.local_ip4;
    let dst_port = lookup.local_port;

    let key = MeshServiceKey {
        ip: dst_ip,
        port: dst_port,
    };

    let redirect = match MESH_SERVICES.get(&key) {
        Some(v) => v,
        None => return Ok(SK_PASS), // Not a mesh service — pass through
    };

    // Build a socket tuple to look up the listening socket on
    // 127.0.0.1:<redirect_port>. We set saddr/sport to 0 because we
    // want to find a wildcard listener, not a connected socket.
    let mut tuple: aya_ebpf::bindings::bpf_sock_tuple = core::mem::zeroed();
    // daddr = 127.0.0.1 in network byte order = 0x0100007f
    tuple.__bindgen_anon_1.ipv4.daddr = 0x0100007fu32;
    tuple.__bindgen_anon_1.ipv4.dport = (redirect.redirect_port as u16).to_be();

    // BPF_F_CURRENT_NETNS is defined as ((__u64)(-1)) in include/uapi/linux/bpf.h,
    // which equals u64::MAX (0xFFFFFFFFFFFFFFFF). The aya binding exports it as
    // c_int (-1), so we cast explicitly to u64 for the helper signature.
    let sk = bpf_sk_lookup_tcp(
        ctx.as_ptr(),
        &mut tuple as *mut _,
        core::mem::size_of::<aya_ebpf::bindings::bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1>()
            as u32,
        aya_ebpf::bindings::BPF_F_CURRENT_NETNS as u64,
        0,
    );

    if sk.is_null() {
        // No listening socket found — pass through to normal lookup.
        return Ok(SK_PASS);
    }

    // Assign the found socket to this connection. BPF_SK_LOOKUP_F_REPLACE
    // allows overriding any previous assignment by another sk_lookup program.
    let ret = bpf_sk_assign(ctx.as_ptr(), sk as *mut _, BPF_SK_LOOKUP_F_REPLACE as u64);

    // Always release the socket reference from bpf_sk_lookup_tcp.
    bpf_sk_release(sk as *mut _);

    if ret != 0 {
        return Err(ret);
    }

    Ok(SK_PASS) // Socket assigned — kernel will deliver to the mesh listener
}

// ---------------------------------------------------------------------------
// Panic handler (required for #![no_std])
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
