//! eBPF program loader.
//!
//! Loads the compiled eBPF object file using aya and returns map handles
//! wrapped in a `MapManager`. Only compiles on Linux.

#[cfg(target_os = "linux")]
use crate::maps::{MapManager, RealMaps};
#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use aya::maps::{
    lpm_trie::LpmTrie, Array, HashMap, MapData, PerCpuArray, PerCpuHashMap, RingBuf, SockHash,
};
#[cfg(target_os = "linux")]
use aya::programs::SchedClassifier;
#[cfg(target_os = "linux")]
use aya::Ebpf;
#[cfg(target_os = "linux")]
use novanet_common::*;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use tracing::{info, warn};

/// Load eBPF programs from the compiled object file.
///
/// Returns a `MapManager` wrapping real aya map handles, and optionally a
/// `RingBuf` handle for reading flow events. The ring buffer is returned
/// separately because it needs to be polled in a dedicated task.
#[cfg(target_os = "linux")]
pub fn load_ebpf(bpf_object_path: &Path) -> Result<(MapManager, Option<RingBuf<MapData>>)> {
    let mut ebpf = Ebpf::load_file(bpf_object_path).context("Failed to load eBPF object file")?;

    // Initialize aya-log for eBPF program logging.
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        tracing::warn!("Failed to initialize eBPF logger: {}", e);
    }

    // Load all TC programs (but don't attach yet — that's done via gRPC).
    for prog_name in &[
        "tc_ingress",
        "tc_egress",
        "tc_tunnel_ingress",
        "tc_tunnel_egress",
    ] {
        let prog: &mut SchedClassifier = ebpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("Program '{}' not found in eBPF object", prog_name))?
            .try_into()
            .context(format!("Program '{}' is not a SchedClassifier", prog_name))?;

        prog.load()
            .context(format!("Failed to load program '{}'", prog_name))?;

        info!(program = prog_name, "Loaded eBPF program");
    }

    // Load cgroup socket-LB programs (but don't attach yet — done after maps are ready).
    for prog_name in &[
        "sock_connect4",
        "sock_sendmsg4",
        "sock_recvmsg4",
        "sock_getpeername4",
    ] {
        let prog: &mut aya::programs::CgroupSockAddr = ebpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("Program '{}' not found in eBPF object", prog_name))?
            .try_into()
            .context(format!("Program '{}' is not a CgroupSockAddr", prog_name))?;

        prog.load()
            .context(format!("Failed to load program '{}'", prog_name))?;

        info!(program = prog_name, "Loaded eBPF program");
    }

    // Extract map handles.
    let endpoints: HashMap<MapData, EndpointKey, EndpointValue> = ebpf
        .take_map("ENDPOINTS")
        .ok_or_else(|| anyhow::anyhow!("Map 'ENDPOINTS' not found"))?
        .try_into()
        .context("Failed to convert ENDPOINTS map")?;

    let policies: HashMap<MapData, PolicyKey, PolicyValue> = ebpf
        .take_map("POLICIES")
        .ok_or_else(|| anyhow::anyhow!("Map 'POLICIES' not found"))?
        .try_into()
        .context("Failed to convert POLICIES map")?;

    let tunnels: HashMap<MapData, TunnelKey, TunnelValue> = ebpf
        .take_map("TUNNELS")
        .ok_or_else(|| anyhow::anyhow!("Map 'TUNNELS' not found"))?
        .try_into()
        .context("Failed to convert TUNNELS map")?;

    let config: HashMap<MapData, u32, u64> = ebpf
        .take_map("CONFIG")
        .ok_or_else(|| anyhow::anyhow!("Map 'CONFIG' not found"))?
        .try_into()
        .context("Failed to convert CONFIG map")?;

    let egress: HashMap<MapData, EgressKey, EgressValue> = ebpf
        .take_map("EGRESS_POLICIES")
        .ok_or_else(|| anyhow::anyhow!("Map 'EGRESS_POLICIES' not found"))?
        .try_into()
        .context("Failed to convert EGRESS_POLICIES map")?;

    let services: HashMap<MapData, ServiceKey, ServiceValue> = ebpf
        .take_map("SERVICES")
        .ok_or_else(|| anyhow::anyhow!("Map 'SERVICES' not found"))?
        .try_into()
        .context("Failed to convert SERVICES map")?;

    let backends: Array<MapData, BackendValue> = ebpf
        .take_map("BACKENDS")
        .ok_or_else(|| anyhow::anyhow!("Map 'BACKENDS' not found"))?
        .try_into()
        .context("Failed to convert BACKENDS map")?;

    let maglev: Array<MapData, u32> = ebpf
        .take_map("MAGLEV")
        .ok_or_else(|| anyhow::anyhow!("Map 'MAGLEV' not found"))?
        .try_into()
        .context("Failed to convert MAGLEV map")?;

    let drop_counters: PerCpuArray<MapData, u64> = ebpf
        .take_map("DROP_COUNTERS")
        .ok_or_else(|| anyhow::anyhow!("Map 'DROP_COUNTERS' not found"))?
        .try_into()
        .context("Failed to convert DROP_COUNTERS map")?;

    let flow_ring: RingBuf<MapData> = ebpf
        .take_map("FLOW_EVENTS")
        .ok_or_else(|| anyhow::anyhow!("Map 'FLOW_EVENTS' not found"))?
        .try_into()
        .context("Failed to convert FLOW_EVENTS ring buffer")?;

    // Optional maps — host firewall and IPCache (LPM tries).
    // These are not required; if the eBPF object doesn't contain them,
    // host firewall operations will return errors at runtime.
    let ipcache: Option<
        LpmTrie<MapData, novanet_common::IPCacheKey, novanet_common::IPCacheValue>,
    > = match ebpf.take_map("IPCACHE") {
        Some(map) => match map.try_into() {
            Ok(trie) => {
                info!("Loaded IPCACHE LPM trie map");
                Some(trie)
            }
            Err(e) => {
                warn!(
                    "Failed to convert IPCACHE map: {} — host firewall disabled",
                    e
                );
                None
            }
        },
        None => {
            warn!("IPCACHE map not found — identity-based host firewall disabled");
            None
        }
    };

    let host_policies: Option<
        LpmTrie<MapData, novanet_common::HostPolicyKey, novanet_common::HostPolicyValue>,
    > = match ebpf.take_map("HOST_POLICIES") {
        Some(map) => match map.try_into() {
            Ok(trie) => {
                info!("Loaded HOST_POLICIES LPM trie map");
                Some(trie)
            }
            Err(e) => {
                warn!(
                    "Failed to convert HOST_POLICIES map: {} — host firewall disabled",
                    e
                );
                None
            }
        },
        None => {
            warn!("HOST_POLICIES map not found — host firewall disabled");
            None
        }
    };

    // Optional IPv6 maps — these won't exist until eBPF programs support IPv6.
    let endpoints_v6: Option<HashMap<MapData, EndpointKeyV6, EndpointValueV6>> =
        match ebpf.take_map("ENDPOINTS_V6") {
            Some(map) => match map.try_into() {
                Ok(m) => {
                    info!("Loaded ENDPOINTS_V6 map");
                    Some(m)
                }
                Err(e) => {
                    warn!(
                        "Failed to convert ENDPOINTS_V6: {} — IPv6 endpoints disabled",
                        e
                    );
                    None
                }
            },
            None => {
                warn!("ENDPOINTS_V6 not found — IPv6 endpoints disabled");
                None
            }
        };

    let tunnels_v6: Option<HashMap<MapData, TunnelKeyV6, TunnelValueV6>> =
        match ebpf.take_map("TUNNELS_V6") {
            Some(map) => match map.try_into() {
                Ok(m) => {
                    info!("Loaded TUNNELS_V6 map");
                    Some(m)
                }
                Err(e) => {
                    warn!(
                        "Failed to convert TUNNELS_V6: {} — IPv6 tunnels disabled",
                        e
                    );
                    None
                }
            },
            None => {
                warn!("TUNNELS_V6 not found — IPv6 tunnels disabled");
                None
            }
        };

    let egress_v6: Option<HashMap<MapData, EgressKeyV6, EgressValueV6>> =
        match ebpf.take_map("EGRESS_POLICIES_V6") {
            Some(map) => match map.try_into() {
                Ok(m) => {
                    info!("Loaded EGRESS_POLICIES_V6 map");
                    Some(m)
                }
                Err(e) => {
                    warn!(
                        "Failed to convert EGRESS_POLICIES_V6: {} — IPv6 egress disabled",
                        e
                    );
                    None
                }
            },
            None => {
                warn!("EGRESS_POLICIES_V6 not found — IPv6 egress disabled");
                None
            }
        };

    let services_v6: Option<HashMap<MapData, ServiceKeyV6, ServiceValue>> =
        match ebpf.take_map("SERVICES_V6") {
            Some(map) => match map.try_into() {
                Ok(m) => {
                    info!("Loaded SERVICES_V6 map");
                    Some(m)
                }
                Err(e) => {
                    warn!(
                        "Failed to convert SERVICES_V6: {} — IPv6 services disabled",
                        e
                    );
                    None
                }
            },
            None => {
                warn!("SERVICES_V6 not found — IPv6 services disabled");
                None
            }
        };

    let backends_v6: Option<Array<MapData, BackendValueV6>> = match ebpf.take_map("BACKENDS_V6") {
        Some(map) => match map.try_into() {
            Ok(m) => {
                info!("Loaded BACKENDS_V6 map");
                Some(m)
            }
            Err(e) => {
                warn!(
                    "Failed to convert BACKENDS_V6: {} — IPv6 backends disabled",
                    e
                );
                None
            }
        },
        None => {
            warn!("BACKENDS_V6 not found — IPv6 backends disabled");
            None
        }
    };

    // -- New eBPF Services API maps (optional — not all eBPF objects contain them) --

    let sock_hash: Option<SockHash<MapData, SockKey>> = match ebpf.take_map("SOCK_HASH") {
        Some(map) => match map.try_into() {
            Ok(m) => {
                info!("Loaded SOCK_HASH map");
                Some(m)
            }
            Err(e) => {
                warn!(
                    "Failed to convert SOCK_HASH: {} — SOCKMAP bypass disabled",
                    e
                );
                None
            }
        },
        None => {
            warn!("SOCK_HASH not found — SOCKMAP bypass disabled");
            None
        }
    };

    let sockmap_endpoints: Option<HashMap<MapData, SockmapEndpointKey, u32>> =
        match ebpf.take_map("SOCKMAP_ENDPOINTS") {
            Some(map) => match map.try_into() {
                Ok(m) => {
                    info!("Loaded SOCKMAP_ENDPOINTS map");
                    Some(m)
                }
                Err(e) => {
                    warn!(
                        "Failed to convert SOCKMAP_ENDPOINTS: {} — SOCKMAP bypass disabled",
                        e
                    );
                    None
                }
            },
            None => {
                warn!("SOCKMAP_ENDPOINTS not found — SOCKMAP bypass disabled");
                None
            }
        };

    let sockmap_stats: Option<PerCpuArray<MapData, u64>> = match ebpf.take_map("SOCKMAP_STATS") {
        Some(map) => match map.try_into() {
            Ok(m) => {
                info!("Loaded SOCKMAP_STATS map");
                Some(m)
            }
            Err(e) => {
                warn!("Failed to convert SOCKMAP_STATS: {}", e);
                None
            }
        },
        None => None,
    };

    let mesh_services: Option<HashMap<MapData, MeshServiceKey, MeshRedirectValue>> =
        match ebpf.take_map("MESH_SERVICES") {
            Some(map) => match map.try_into() {
                Ok(m) => {
                    info!("Loaded MESH_SERVICES map");
                    Some(m)
                }
                Err(e) => {
                    warn!(
                        "Failed to convert MESH_SERVICES: {} — mesh redirect disabled",
                        e
                    );
                    None
                }
            },
            None => {
                warn!("MESH_SERVICES not found — mesh redirect disabled");
                None
            }
        };

    let rl_tokens: Option<aya::maps::LruHashMap<MapData, RateLimitKey, TokenBucketState>> =
        match ebpf.take_map("RL_TOKENS") {
            Some(map) => match map.try_into() {
                Ok(m) => {
                    info!("Loaded RL_TOKENS map");
                    Some(m)
                }
                Err(e) => {
                    warn!(
                        "Failed to convert RL_TOKENS: {} — rate limiting disabled",
                        e
                    );
                    None
                }
            },
            None => {
                warn!("RL_TOKENS not found — rate limiting disabled");
                None
            }
        };

    let rl_config: Option<Array<MapData, RateLimitConfig>> = match ebpf.take_map("RL_CONFIG") {
        Some(map) => match map.try_into() {
            Ok(m) => {
                info!("Loaded RL_CONFIG map");
                Some(m)
            }
            Err(e) => {
                warn!(
                    "Failed to convert RL_CONFIG: {} — rate limiting disabled",
                    e
                );
                None
            }
        },
        None => {
            warn!("RL_CONFIG not found — rate limiting disabled");
            None
        }
    };

    let backend_health: Option<PerCpuHashMap<MapData, BackendHealthKey, BackendHealthCounters>> =
        match ebpf.take_map("BACKEND_HEALTH") {
            Some(map) => match map.try_into() {
                Ok(m) => {
                    info!("Loaded BACKEND_HEALTH map");
                    Some(m)
                }
                Err(e) => {
                    warn!(
                        "Failed to convert BACKEND_HEALTH: {} — health monitoring disabled",
                        e
                    );
                    None
                }
            },
            None => {
                warn!("BACKEND_HEALTH not found — health monitoring disabled");
                None
            }
        };

    // Load sock_ops and sk_msg programs if present (SOCKMAP bypass).
    for prog_name in &["sockops_sockmap", "sk_msg_sockmap"] {
        if let Some(prog) = ebpf.program_mut(prog_name) {
            match prog_name {
                &"sockops_sockmap" => match <&mut aya::programs::SockOps>::try_from(prog) {
                    Ok(p) => match p.load() {
                        Ok(()) => info!(program = *prog_name, "Loaded sock_ops program"),
                        Err(e) => warn!(
                            "Failed to load {}: {} — SOCKMAP bypass disabled",
                            prog_name, e
                        ),
                    },
                    Err(e) => warn!("{} is not a SockOps program: {}", prog_name, e),
                },
                &"sk_msg_sockmap" => match <&mut aya::programs::SkMsg>::try_from(prog) {
                    Ok(p) => match p.load() {
                        Ok(()) => info!(program = *prog_name, "Loaded sk_msg program"),
                        Err(e) => warn!(
                            "Failed to load {}: {} — SOCKMAP bypass disabled",
                            prog_name, e
                        ),
                    },
                    Err(e) => warn!("{} is not a SkMsg program: {}", prog_name, e),
                },
                _ => {}
            }
        }
    }

    // Optional XDP program — load but don't attach (attachment is via gRPC).
    if let Some(prog) = ebpf.program_mut("xdp_pass") {
        match <&mut aya::programs::Xdp>::try_from(prog) {
            Ok(xdp) => match xdp.load() {
                Ok(()) => info!(program = "xdp_pass", "Loaded XDP program"),
                Err(e) => warn!(
                    "Failed to load XDP program: {} — XDP acceleration disabled",
                    e
                ),
            },
            Err(e) => warn!(
                "xdp_pass is not an XDP program: {} — XDP acceleration disabled",
                e
            ),
        }
    } else {
        warn!("XDP program 'xdp_pass' not found — XDP acceleration disabled");
    }

    let real_maps = RealMaps::new(
        endpoints,
        endpoints_v6,
        policies,
        tunnels,
        tunnels_v6,
        config,
        egress,
        egress_v6,
        services,
        services_v6,
        backends,
        backends_v6,
        maglev,
        drop_counters,
        ipcache,
        host_policies,
        sock_hash,
        sockmap_endpoints,
        sockmap_stats,
        mesh_services,
        rl_tokens,
        rl_config,
        backend_health,
        ebpf,
    );

    let manager = MapManager::new_real(real_maps);

    info!("All eBPF maps initialized");

    Ok((manager, Some(flow_ring)))
}

// Non-Linux stub to keep the module importable on macOS.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn load_ebpf(
    _bpf_object_path: &std::path::Path,
) -> anyhow::Result<(crate::maps::MapManager, Option<()>)> {
    anyhow::bail!("eBPF loading is only supported on Linux")
}
