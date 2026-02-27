//! eBPF program loader.
//!
//! Loads the compiled eBPF object file using aya and returns map handles
//! wrapped in a `MapManager`. Only compiles on Linux.

#[cfg(target_os = "linux")]
use crate::maps::{MapManager, RealMaps};
#[cfg(target_os = "linux")]
use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use aya::maps::{HashMap, MapData, PerCpuArray, RingBuf};
#[cfg(target_os = "linux")]
use aya::programs::SchedClassifier;
#[cfg(target_os = "linux")]
use aya::Ebpf;
#[cfg(target_os = "linux")]
use novanet_common::*;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use tracing::info;

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

    let real_maps = RealMaps::new(
        endpoints,
        policies,
        tunnels,
        config,
        egress,
        drop_counters,
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
