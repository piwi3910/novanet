//! eBPF map management layer.
//!
//! Provides a `MapManager` that abstracts over real aya map handles (Linux)
//! and in-memory mock maps (macOS / standalone mode). The gRPC server calls
//! into MapManager for all map operations.

use novanet_common::*;
use std::collections::HashMap as StdHashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// MapManager — the public interface used by the gRPC server
// ---------------------------------------------------------------------------

/// Manages all eBPF maps. On Linux this wraps real aya map handles; on macOS
/// or in standalone mode it uses in-memory hash maps.
pub struct MapManager {
    inner: MapManagerInner,
}

#[allow(clippy::large_enum_variant)]
enum MapManagerInner {
    Mock(MockMaps),
    #[cfg(target_os = "linux")]
    Real(RealMaps),
}

impl MapManager {
    /// Create a mock map manager for development / standalone mode.
    pub fn new_mock() -> Self {
        info!("Initializing mock map manager");
        Self {
            inner: MapManagerInner::Mock(MockMaps::new()),
        }
    }

    /// Create a real map manager from aya map handles.
    #[cfg(target_os = "linux")]
    pub fn new_real(maps: RealMaps) -> Self {
        info!("Initializing real eBPF map manager");
        Self {
            inner: MapManagerInner::Real(maps),
        }
    }

    // -- Endpoint operations --

    pub fn upsert_endpoint(&self, key: EndpointKey, value: EndpointValue) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_endpoint(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_endpoint(key, value),
        }
    }

    pub fn delete_endpoint(&self, key: &EndpointKey) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_endpoint(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_endpoint(key),
        }
    }

    pub fn endpoint_count(&self) -> usize {
        match &self.inner {
            MapManagerInner::Mock(m) => m.endpoint_count(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.endpoint_count(),
        }
    }

    // -- Endpoint V6 operations --

    pub fn upsert_endpoint_v6(
        &self,
        key: EndpointKeyV6,
        value: EndpointValueV6,
    ) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_endpoint_v6(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_endpoint_v6(key, value),
        }
    }

    pub fn delete_endpoint_v6(&self, key: &EndpointKeyV6) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_endpoint_v6(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_endpoint_v6(key),
        }
    }

    // -- Policy operations --

    pub fn upsert_policy(&self, key: PolicyKey, value: PolicyValue) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_policy(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_policy(key, value),
        }
    }

    pub fn delete_policy(&self, key: &PolicyKey) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_policy(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_policy(key),
        }
    }

    /// Look up a single policy entry. Currently used by tests only.
    #[cfg(test)]
    pub fn get_policy(&self, key: &PolicyKey) -> anyhow::Result<Option<PolicyValue>> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.get_policy(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(_) => unimplemented!("get_policy not used with real maps"),
        }
    }

    pub fn policy_count(&self) -> usize {
        match &self.inner {
            MapManagerInner::Mock(m) => m.policy_count(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.policy_count(),
        }
    }

    /// Sync policies: replace the entire policy map with the given entries.
    /// Returns (added, removed, updated) counts.
    pub fn sync_policies(
        &self,
        new_policies: Vec<(PolicyKey, PolicyValue)>,
    ) -> anyhow::Result<(u32, u32, u32)> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.sync_policies(new_policies),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.sync_policies(new_policies),
        }
    }

    // -- Tunnel operations --

    pub fn upsert_tunnel(&self, key: TunnelKey, value: TunnelValue) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_tunnel(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_tunnel(key, value),
        }
    }

    pub fn delete_tunnel(&self, key: &TunnelKey) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_tunnel(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_tunnel(key),
        }
    }

    pub fn tunnel_count(&self) -> usize {
        match &self.inner {
            MapManagerInner::Mock(m) => m.tunnel_count(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.tunnel_count(),
        }
    }

    // -- Tunnel V6 operations --

    pub fn upsert_tunnel_v6(&self, key: TunnelKeyV6, value: TunnelValueV6) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_tunnel_v6(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_tunnel_v6(key, value),
        }
    }

    pub fn delete_tunnel_v6(&self, key: &TunnelKeyV6) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_tunnel_v6(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_tunnel_v6(key),
        }
    }

    // -- Config operations --

    pub fn update_config(&self, entries: StdHashMap<u32, u64>) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.update_config(entries),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.update_config(entries),
        }
    }

    pub fn get_config(&self, key: u32) -> anyhow::Result<Option<u64>> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.get_config(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.get_config(key),
        }
    }

    // -- Egress policy operations --

    pub fn upsert_egress_policy(&self, key: EgressKey, value: EgressValue) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_egress_policy(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_egress_policy(key, value),
        }
    }

    pub fn delete_egress_policy(&self, key: &EgressKey) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_egress_policy(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_egress_policy(key),
        }
    }

    // -- Egress V6 operations --

    pub fn upsert_egress_policy_v6(
        &self,
        key: EgressKeyV6,
        value: EgressValueV6,
    ) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_egress_policy_v6(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_egress_policy_v6(key, value),
        }
    }

    pub fn delete_egress_policy_v6(&self, key: &EgressKeyV6) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_egress_policy_v6(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_egress_policy_v6(key),
        }
    }

    // -- Service operations --

    pub fn upsert_service(&self, key: ServiceKey, value: ServiceValue) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_service(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_service(key, value),
        }
    }

    pub fn delete_service(&self, key: &ServiceKey) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_service(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_service(key),
        }
    }

    pub fn service_count(&self) -> usize {
        match &self.inner {
            MapManagerInner::Mock(m) => m.service_count(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.service_count(),
        }
    }

    pub fn upsert_backend(&self, index: u32, value: BackendValue) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_backend(index, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_backend(index, value),
        }
    }

    // -- Service V6 operations --

    pub fn upsert_service_v6(&self, key: ServiceKeyV6, value: ServiceValue) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_service_v6(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_service_v6(key, value),
        }
    }

    pub fn delete_service_v6(&self, key: &ServiceKeyV6) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_service_v6(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_service_v6(key),
        }
    }

    // -- Backend V6 operations --

    pub fn upsert_backend_v6(&self, index: u32, value: BackendValueV6) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_backend_v6(index, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_backend_v6(index, value),
        }
    }

    pub fn upsert_maglev_entry(&self, index: u32, value: u32) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_maglev_entry(index, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_maglev_entry(index, value),
        }
    }

    pub fn clear_services(&self) {
        match &self.inner {
            MapManagerInner::Mock(m) => m.clear_services(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.clear_services(),
        }
    }

    pub fn clear_backends(&self) {
        match &self.inner {
            MapManagerInner::Mock(m) => m.clear_backends(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.clear_backends(),
        }
    }

    // -- Program attach/detach --

    pub fn attached_programs(&self) -> Vec<AttachedProgramInfo> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.attached_programs(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.attached_programs(),
        }
    }

    pub fn attach_program(
        &self,
        interface: &str,
        attach_type: AttachDirection,
    ) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.attach_program(interface, attach_type),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.attach_program(interface, attach_type),
        }
    }

    pub fn detach_program(
        &self,
        interface: &str,
        attach_type: AttachDirection,
    ) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.detach_program(interface, attach_type),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.detach_program(interface, attach_type),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn attach_cgroup_programs(&self) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(_) => {
                info!("mock: skipping cgroup program attachment");
                Ok(())
            }
            MapManagerInner::Real(m) => m.attach_cgroup_programs(),
        }
    }

    // -- Mode info --

    pub fn mode_string(&self) -> String {
        let mode = self.get_config(CONFIG_KEY_MODE).ok().flatten().unwrap_or(0);
        match mode {
            MODE_OVERLAY => "overlay".to_string(),
            MODE_NATIVE => "native".to_string(),
            _ => "unknown".to_string(),
        }
    }

    pub fn tunnel_protocol_string(&self) -> String {
        let tt = self
            .get_config(CONFIG_KEY_TUNNEL_TYPE)
            .ok()
            .flatten()
            .unwrap_or(0);
        match tt {
            TUNNEL_GENEVE => "geneve".to_string(),
            TUNNEL_VXLAN => "vxlan".to_string(),
            _ => "unknown".to_string(),
        }
    }

    // -- IPCache operations --

    pub fn upsert_ipcache(&self, key: IPCacheKey, value: IPCacheValue) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_ipcache(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_ipcache(key, value),
        }
    }

    #[allow(dead_code)]
    pub fn delete_ipcache(&self, key: &IPCacheKey) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_ipcache(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_ipcache(key),
        }
    }

    // -- Host firewall policy operations --

    pub fn upsert_host_policy(
        &self,
        key: HostPolicyKey,
        value: HostPolicyValue,
    ) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_host_policy(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_host_policy(key, value),
        }
    }

    pub fn delete_host_policy(&self, key: &HostPolicyKey) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_host_policy(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_host_policy(key),
        }
    }

    #[allow(dead_code)]
    pub fn host_policy_count(&self) -> usize {
        match &self.inner {
            MapManagerInner::Mock(m) => m.host_policy_count(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.host_policy_count(),
        }
    }

    pub fn sync_host_policies(
        &self,
        new_policies: Vec<(HostPolicyKey, HostPolicyValue)>,
    ) -> anyhow::Result<(u32, u32)> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.sync_host_policies(new_policies),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.sync_host_policies(new_policies),
        }
    }

    // -- XDP program attach/detach --

    pub fn attach_xdp(&self, interface: &str, native: bool) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.attach_xdp(interface, native),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.attach_xdp(interface, native),
        }
    }

    pub fn detach_xdp(&self, interface: &str) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.detach_xdp(interface),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.detach_xdp(interface),
        }
    }

    // -- Drop counters --

    /// Read drop counters from the eBPF PerCpuArray, summing values across all CPUs.
    /// Returns a map of drop_reason_index → total_count.
    pub fn get_drop_counters(&self) -> StdHashMap<u32, u64> {
        match &self.inner {
            MapManagerInner::Mock(_) => StdHashMap::new(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.get_drop_counters(),
        }
    }

    // -- SOCKMAP endpoint operations --

    pub fn upsert_sockmap_endpoint(
        &self,
        key: SockmapEndpointKey,
        value: u32,
    ) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_sockmap_endpoint(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_sockmap_endpoint(key, value),
        }
    }

    pub fn delete_sockmap_endpoint(&self, key: &SockmapEndpointKey) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_sockmap_endpoint(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_sockmap_endpoint(key),
        }
    }

    pub fn count_sockmap_endpoints(&self) -> anyhow::Result<usize> {
        match &self.inner {
            MapManagerInner::Mock(m) => Ok(m.count_sockmap_endpoints()),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.count_sockmap_endpoints(),
        }
    }

    pub fn get_sockmap_stats(&self) -> (u64, u64) {
        match &self.inner {
            MapManagerInner::Mock(m) => m.get_sockmap_stats(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.get_sockmap_stats(),
        }
    }

    // -- Mesh service operations --

    pub fn upsert_mesh_service(
        &self,
        key: MeshServiceKey,
        value: MeshRedirectValue,
    ) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_mesh_service(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_mesh_service(key, value),
        }
    }

    pub fn delete_mesh_service(&self, key: &MeshServiceKey) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_mesh_service(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_mesh_service(key),
        }
    }

    pub fn list_mesh_services(&self) -> anyhow::Result<Vec<(MeshServiceKey, MeshRedirectValue)>> {
        match &self.inner {
            MapManagerInner::Mock(m) => Ok(m.list_mesh_services()),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.list_mesh_services(),
        }
    }

    #[allow(dead_code)]
    pub fn count_mesh_services(&self) -> anyhow::Result<usize> {
        match &self.inner {
            MapManagerInner::Mock(m) => Ok(m.count_mesh_services()),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.count_mesh_services(),
        }
    }

    // -- Rate limit operations --

    pub fn update_rate_limit_config(&self, config: RateLimitConfig) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.update_rate_limit_config(config),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.update_rate_limit_config(config),
        }
    }

    #[allow(dead_code)]
    pub fn get_rate_limit_config(&self) -> Option<RateLimitConfig> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.get_rate_limit_config(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.get_rate_limit_config(),
        }
    }

    pub fn get_rate_limit_stats(&self) -> (u64, u64) {
        match &self.inner {
            MapManagerInner::Mock(m) => m.get_rate_limit_stats(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.get_rate_limit_stats(),
        }
    }

    // -- Backend health operations --

    pub fn get_backend_health(&self, key: &BackendHealthKey) -> Option<BackendHealthCounters> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.get_backend_health(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.get_backend_health(key),
        }
    }

    pub fn get_all_backend_health(&self) -> Vec<(BackendHealthKey, BackendHealthCounters)> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.get_all_backend_health(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.get_all_backend_health(),
        }
    }

    #[allow(dead_code)]
    pub fn count_backend_health(&self) -> usize {
        match &self.inner {
            MapManagerInner::Mock(m) => m.count_backend_health(),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.count_backend_health(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helper types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct AttachedProgramInfo {
    pub interface: String,
    pub attach_type: String,
    pub program_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachDirection {
    Ingress,
    Egress,
}

// ---------------------------------------------------------------------------
// Mock implementation (in-memory, works on any platform)
// ---------------------------------------------------------------------------

struct MockMaps {
    endpoints: RwLock<StdHashMap<u32, EndpointValue>>,
    endpoints_v6: RwLock<StdHashMap<[u8; 16], EndpointValueV6>>,
    policies: RwLock<StdHashMap<PolicyKeyFlat, PolicyValue>>,
    tunnels: RwLock<StdHashMap<u32, TunnelValue>>,
    tunnels_v6: RwLock<StdHashMap<[u8; 16], TunnelValueV6>>,
    config: RwLock<StdHashMap<u32, u64>>,
    egress: RwLock<StdHashMap<EgressKeyFlat, EgressValue>>,
    egress_v6: RwLock<StdHashMap<EgressKeyV6Flat, EgressValueV6>>,
    services: RwLock<StdHashMap<ServiceKeyFlat, ServiceValue>>,
    services_v6: RwLock<StdHashMap<ServiceKeyV6Flat, ServiceValue>>,
    backends: RwLock<StdHashMap<u32, BackendValue>>,
    backends_v6: RwLock<StdHashMap<u32, BackendValueV6>>,
    maglev: RwLock<StdHashMap<u32, u32>>,
    attached: RwLock<Vec<AttachedProgramInfo>>,
    next_prog_id: RwLock<u32>,
    ipcache: RwLock<StdHashMap<[u8; 16], (u32, IPCacheValue)>>,
    host_policies: RwLock<StdHashMap<HostPolicyKeyFlat, HostPolicyValue>>,
    sockmap_endpoints: RwLock<StdHashMap<SockmapEndpointKey, u32>>,
    mesh_services: RwLock<StdHashMap<MeshServiceKey, MeshRedirectValue>>,
    rate_limit_config: RwLock<Option<RateLimitConfig>>,
    backend_health: RwLock<StdHashMap<BackendHealthKey, BackendHealthCounters>>,
    sockmap_stats_redirected: AtomicU64,
    sockmap_stats_fallback: AtomicU64,
    rate_limit_stats_allowed: AtomicU64,
    rate_limit_stats_denied: AtomicU64,
}

/// Flattened policy key for use as HashMap key (needs Hash + Eq).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PolicyKeyFlat {
    src_identity: u32,
    dst_identity: u32,
    protocol: u8,
    dst_port: u16,
}

impl From<&PolicyKey> for PolicyKeyFlat {
    fn from(k: &PolicyKey) -> Self {
        Self {
            src_identity: k.src_identity,
            dst_identity: k.dst_identity,
            protocol: k.protocol,
            dst_port: k.dst_port,
        }
    }
}

impl From<&PolicyKeyFlat> for PolicyKey {
    fn from(k: &PolicyKeyFlat) -> Self {
        Self {
            src_identity: k.src_identity,
            dst_identity: k.dst_identity,
            protocol: k.protocol,
            _pad: [0],
            dst_port: k.dst_port,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct EgressKeyFlat {
    src_identity: u32,
    dst_ip: u32,
    dst_prefix_len: u8,
}

impl From<&EgressKey> for EgressKeyFlat {
    fn from(k: &EgressKey) -> Self {
        Self {
            src_identity: k.src_identity,
            dst_ip: k.dst_ip,
            dst_prefix_len: k.dst_prefix_len,
        }
    }
}

/// Flattened IPv6 egress key for use as HashMap key (needs Hash + Eq).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct EgressKeyV6Flat {
    src_identity: u32,
    dst_ip: [u8; 16],
    dst_prefix_len: u8,
}

impl From<&EgressKeyV6> for EgressKeyV6Flat {
    fn from(k: &EgressKeyV6) -> Self {
        Self {
            src_identity: k.src_identity,
            dst_ip: k.dst_ip,
            dst_prefix_len: k.dst_prefix_len,
        }
    }
}

/// Flattened service key for use as HashMap key (needs Hash + Eq).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ServiceKeyFlat {
    ip: u32,
    port: u16,
    protocol: u8,
    scope: u8,
}

impl From<&ServiceKey> for ServiceKeyFlat {
    fn from(k: &ServiceKey) -> Self {
        Self {
            ip: k.ip,
            port: k.port,
            protocol: k.protocol,
            scope: k.scope,
        }
    }
}

/// Flattened IPv6 service key for use as HashMap key (needs Hash + Eq).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct ServiceKeyV6Flat {
    ip: [u8; 16],
    port: u16,
    protocol: u8,
    scope: u8,
}

impl From<&ServiceKeyV6> for ServiceKeyV6Flat {
    fn from(k: &ServiceKeyV6) -> Self {
        Self {
            ip: k.ip,
            port: k.port,
            protocol: k.protocol,
            scope: k.scope,
        }
    }
}

/// Flattened host policy key for use as HashMap key (needs Hash + Eq).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct HostPolicyKeyFlat {
    identity: u32,
    direction: u8,
    protocol: u8,
    dst_port: u16,
    prefix_len: u32,
}

impl From<&HostPolicyKey> for HostPolicyKeyFlat {
    fn from(k: &HostPolicyKey) -> Self {
        Self {
            identity: k.identity,
            direction: k.direction,
            protocol: k.protocol,
            dst_port: k.dst_port,
            prefix_len: k.prefix_len,
        }
    }
}

impl MockMaps {
    fn new() -> Self {
        Self {
            endpoints: RwLock::new(StdHashMap::new()),
            endpoints_v6: RwLock::new(StdHashMap::new()),
            policies: RwLock::new(StdHashMap::new()),
            tunnels: RwLock::new(StdHashMap::new()),
            tunnels_v6: RwLock::new(StdHashMap::new()),
            config: RwLock::new(StdHashMap::new()),
            egress: RwLock::new(StdHashMap::new()),
            egress_v6: RwLock::new(StdHashMap::new()),
            services: RwLock::new(StdHashMap::new()),
            services_v6: RwLock::new(StdHashMap::new()),
            backends: RwLock::new(StdHashMap::new()),
            backends_v6: RwLock::new(StdHashMap::new()),
            maglev: RwLock::new(StdHashMap::new()),
            attached: RwLock::new(Vec::new()),
            next_prog_id: RwLock::new(1),
            ipcache: RwLock::new(StdHashMap::new()),
            host_policies: RwLock::new(StdHashMap::new()),
            sockmap_endpoints: RwLock::new(StdHashMap::new()),
            mesh_services: RwLock::new(StdHashMap::new()),
            rate_limit_config: RwLock::new(None),
            backend_health: RwLock::new(StdHashMap::new()),
            sockmap_stats_redirected: AtomicU64::new(0),
            sockmap_stats_fallback: AtomicU64::new(0),
            rate_limit_stats_allowed: AtomicU64::new(0),
            rate_limit_stats_denied: AtomicU64::new(0),
        }
    }

    fn upsert_endpoint(&self, key: EndpointKey, value: EndpointValue) -> anyhow::Result<()> {
        debug!(
            ip = key.ip,
            identity = value.identity,
            "mock: upsert endpoint"
        );
        self.endpoints
            .write()
            .expect("endpoints lock poisoned")
            .insert(key.ip, value);
        Ok(())
    }

    fn delete_endpoint(&self, key: &EndpointKey) -> anyhow::Result<()> {
        debug!(ip = key.ip, "mock: delete endpoint");
        self.endpoints
            .write()
            .expect("endpoints lock poisoned")
            .remove(&key.ip);
        Ok(())
    }

    fn endpoint_count(&self) -> usize {
        self.endpoints
            .read()
            .expect("endpoints lock poisoned")
            .len()
    }

    fn upsert_endpoint_v6(&self, key: EndpointKeyV6, value: EndpointValueV6) -> anyhow::Result<()> {
        debug!(identity = value.identity, "mock: upsert endpoint v6");
        self.endpoints_v6
            .write()
            .expect("endpoints_v6 lock poisoned")
            .insert(key.ip, value);
        Ok(())
    }

    fn delete_endpoint_v6(&self, key: &EndpointKeyV6) -> anyhow::Result<()> {
        debug!("mock: delete endpoint v6");
        self.endpoints_v6
            .write()
            .expect("endpoints_v6 lock poisoned")
            .remove(&key.ip);
        Ok(())
    }

    fn upsert_policy(&self, key: PolicyKey, value: PolicyValue) -> anyhow::Result<()> {
        debug!(
            src = key.src_identity,
            dst = key.dst_identity,
            proto = key.protocol,
            port = key.dst_port,
            action = value.action,
            "mock: upsert policy"
        );
        let flat: PolicyKeyFlat = (&key).into();
        self.policies
            .write()
            .expect("policies lock poisoned")
            .insert(flat, value);
        Ok(())
    }

    fn delete_policy(&self, key: &PolicyKey) -> anyhow::Result<()> {
        debug!(
            src = key.src_identity,
            dst = key.dst_identity,
            "mock: delete policy"
        );
        let flat: PolicyKeyFlat = key.into();
        self.policies
            .write()
            .expect("policies lock poisoned")
            .remove(&flat);
        Ok(())
    }

    #[cfg(test)]
    fn get_policy(&self, key: &PolicyKey) -> anyhow::Result<Option<PolicyValue>> {
        let flat: PolicyKeyFlat = key.into();
        Ok(self
            .policies
            .read()
            .expect("policies lock poisoned")
            .get(&flat)
            .copied())
    }

    fn policy_count(&self) -> usize {
        self.policies.read().expect("policies lock poisoned").len()
    }

    fn sync_policies(
        &self,
        new_policies: Vec<(PolicyKey, PolicyValue)>,
    ) -> anyhow::Result<(u32, u32, u32)> {
        let mut map = self.policies.write().expect("policies lock poisoned");
        let old_keys: std::collections::HashSet<PolicyKeyFlat> = map.keys().cloned().collect();
        let mut new_keys = std::collections::HashSet::new();
        let mut added = 0u32;
        let mut updated = 0u32;

        for (key, value) in &new_policies {
            let flat: PolicyKeyFlat = key.into();
            new_keys.insert(flat);
            match map.get(&flat) {
                Some(existing) if existing.action == value.action => {
                    // No change.
                }
                Some(_) => {
                    map.insert(flat, *value);
                    updated += 1;
                }
                None => {
                    map.insert(flat, *value);
                    added += 1;
                }
            }
        }

        let mut removed = 0u32;
        for old_key in &old_keys {
            if !new_keys.contains(old_key) {
                map.remove(old_key);
                removed += 1;
            }
        }

        info!(added, removed, updated, "mock: synced policies");
        Ok((added, removed, updated))
    }

    fn upsert_tunnel(&self, key: TunnelKey, value: TunnelValue) -> anyhow::Result<()> {
        debug!(
            node_ip = key.node_ip,
            vni = value.vni,
            "mock: upsert tunnel"
        );
        self.tunnels
            .write()
            .expect("tunnels lock poisoned")
            .insert(key.node_ip, value);
        Ok(())
    }

    fn delete_tunnel(&self, key: &TunnelKey) -> anyhow::Result<()> {
        debug!(node_ip = key.node_ip, "mock: delete tunnel");
        self.tunnels
            .write()
            .expect("tunnels lock poisoned")
            .remove(&key.node_ip);
        Ok(())
    }

    fn tunnel_count(&self) -> usize {
        self.tunnels.read().expect("tunnels lock poisoned").len()
    }

    fn upsert_tunnel_v6(&self, key: TunnelKeyV6, value: TunnelValueV6) -> anyhow::Result<()> {
        debug!(vni = value.vni, "mock: upsert tunnel v6");
        self.tunnels_v6
            .write()
            .expect("tunnels_v6 lock poisoned")
            .insert(key.node_ip, value);
        Ok(())
    }

    fn delete_tunnel_v6(&self, key: &TunnelKeyV6) -> anyhow::Result<()> {
        debug!("mock: delete tunnel v6");
        self.tunnels_v6
            .write()
            .expect("tunnels_v6 lock poisoned")
            .remove(&key.node_ip);
        Ok(())
    }

    fn update_config(&self, entries: StdHashMap<u32, u64>) -> anyhow::Result<()> {
        let mut config = self.config.write().expect("config lock poisoned");
        for (k, v) in entries {
            debug!(key = k, value = v, "mock: update config");
            config.insert(k, v);
        }
        Ok(())
    }

    fn get_config(&self, key: u32) -> anyhow::Result<Option<u64>> {
        Ok(self
            .config
            .read()
            .expect("config lock poisoned")
            .get(&key)
            .copied())
    }

    fn upsert_egress_policy(&self, key: EgressKey, value: EgressValue) -> anyhow::Result<()> {
        debug!(
            src_identity = key.src_identity,
            dst_ip = key.dst_ip,
            prefix_len = key.dst_prefix_len,
            action = value.action,
            "mock: upsert egress policy"
        );
        let flat: EgressKeyFlat = (&key).into();
        self.egress
            .write()
            .expect("egress lock poisoned")
            .insert(flat, value);
        Ok(())
    }

    fn delete_egress_policy(&self, key: &EgressKey) -> anyhow::Result<()> {
        debug!(
            src_identity = key.src_identity,
            dst_ip = key.dst_ip,
            "mock: delete egress policy"
        );
        let flat: EgressKeyFlat = key.into();
        self.egress
            .write()
            .expect("egress lock poisoned")
            .remove(&flat);
        Ok(())
    }

    fn upsert_egress_policy_v6(
        &self,
        key: EgressKeyV6,
        value: EgressValueV6,
    ) -> anyhow::Result<()> {
        debug!(
            src_identity = key.src_identity,
            prefix_len = key.dst_prefix_len,
            action = value.action,
            "mock: upsert egress policy v6"
        );
        let flat: EgressKeyV6Flat = (&key).into();
        self.egress_v6
            .write()
            .expect("egress_v6 lock poisoned")
            .insert(flat, value);
        Ok(())
    }

    fn delete_egress_policy_v6(&self, key: &EgressKeyV6) -> anyhow::Result<()> {
        debug!(
            src_identity = key.src_identity,
            "mock: delete egress policy v6"
        );
        let flat: EgressKeyV6Flat = key.into();
        self.egress_v6
            .write()
            .expect("egress_v6 lock poisoned")
            .remove(&flat);
        Ok(())
    }

    fn upsert_service(&self, key: ServiceKey, value: ServiceValue) -> anyhow::Result<()> {
        debug!(
            ip = key.ip,
            port = key.port,
            protocol = key.protocol,
            scope = key.scope,
            "mock: upsert service"
        );
        let flat: ServiceKeyFlat = (&key).into();
        self.services
            .write()
            .expect("services lock poisoned")
            .insert(flat, value);
        Ok(())
    }

    fn delete_service(&self, key: &ServiceKey) -> anyhow::Result<()> {
        debug!(ip = key.ip, port = key.port, "mock: delete service");
        let flat: ServiceKeyFlat = key.into();
        self.services
            .write()
            .expect("services lock poisoned")
            .remove(&flat);
        Ok(())
    }

    fn service_count(&self) -> usize {
        self.services.read().expect("services lock poisoned").len()
    }

    fn upsert_backend(&self, index: u32, value: BackendValue) -> anyhow::Result<()> {
        debug!(
            index = index,
            ip = value.ip,
            port = value.port,
            "mock: upsert backend"
        );
        self.backends
            .write()
            .expect("backends lock poisoned")
            .insert(index, value);
        Ok(())
    }

    fn upsert_service_v6(&self, key: ServiceKeyV6, value: ServiceValue) -> anyhow::Result<()> {
        debug!(
            port = key.port,
            protocol = key.protocol,
            scope = key.scope,
            "mock: upsert service v6"
        );
        let flat: ServiceKeyV6Flat = (&key).into();
        self.services_v6
            .write()
            .expect("services_v6 lock poisoned")
            .insert(flat, value);
        Ok(())
    }

    fn delete_service_v6(&self, key: &ServiceKeyV6) -> anyhow::Result<()> {
        debug!(port = key.port, "mock: delete service v6");
        let flat: ServiceKeyV6Flat = key.into();
        self.services_v6
            .write()
            .expect("services_v6 lock poisoned")
            .remove(&flat);
        Ok(())
    }

    fn upsert_backend_v6(&self, index: u32, value: BackendValueV6) -> anyhow::Result<()> {
        debug!(index = index, port = value.port, "mock: upsert backend v6");
        self.backends_v6
            .write()
            .expect("backends_v6 lock poisoned")
            .insert(index, value);
        Ok(())
    }

    fn upsert_maglev_entry(&self, index: u32, value: u32) -> anyhow::Result<()> {
        debug!(index = index, value = value, "mock: upsert maglev entry");
        self.maglev
            .write()
            .expect("maglev lock poisoned")
            .insert(index, value);
        Ok(())
    }

    fn clear_services(&self) {
        self.services
            .write()
            .expect("services lock poisoned")
            .clear();
    }

    fn clear_backends(&self) {
        self.backends
            .write()
            .expect("backends lock poisoned")
            .clear();
    }

    fn attached_programs(&self) -> Vec<AttachedProgramInfo> {
        self.attached
            .read()
            .expect("attached lock poisoned")
            .clone()
    }

    fn attach_program(&self, interface: &str, attach_type: AttachDirection) -> anyhow::Result<()> {
        let type_str = match attach_type {
            AttachDirection::Ingress => "ingress",
            AttachDirection::Egress => "egress",
        };
        let mut attached = self.attached.write().expect("attached lock poisoned");
        let mut prog_id = self
            .next_prog_id
            .write()
            .expect("next_prog_id lock poisoned");

        // Check if already attached.
        if attached
            .iter()
            .any(|p| p.interface == interface && p.attach_type == type_str)
        {
            warn!(
                interface,
                attach_type = type_str,
                "mock: program already attached"
            );
            return Ok(());
        }

        let id = *prog_id;
        *prog_id += 1;
        attached.push(AttachedProgramInfo {
            interface: interface.to_string(),
            attach_type: type_str.to_string(),
            program_id: id,
        });
        info!(
            interface,
            attach_type = type_str,
            program_id = id,
            "mock: attached program"
        );
        Ok(())
    }

    fn detach_program(&self, interface: &str, attach_type: AttachDirection) -> anyhow::Result<()> {
        let type_str = match attach_type {
            AttachDirection::Ingress => "ingress",
            AttachDirection::Egress => "egress",
        };
        let mut attached = self.attached.write().expect("attached lock poisoned");
        let before = attached.len();
        attached.retain(|p| !(p.interface == interface && p.attach_type == type_str));
        let after = attached.len();
        if before == after {
            warn!(
                interface,
                attach_type = type_str,
                "mock: program not found for detach"
            );
        } else {
            info!(interface, attach_type = type_str, "mock: detached program");
        }
        Ok(())
    }

    // -- IPCache operations --

    fn upsert_ipcache(&self, key: IPCacheKey, value: IPCacheValue) -> anyhow::Result<()> {
        debug!(
            prefix_len = key.prefix_len,
            identity = value.identity,
            "mock: upsert ipcache"
        );
        self.ipcache
            .write()
            .expect("ipcache lock poisoned")
            .insert(key.addr, (key.prefix_len, value));
        Ok(())
    }

    fn delete_ipcache(&self, key: &IPCacheKey) -> anyhow::Result<()> {
        debug!(prefix_len = key.prefix_len, "mock: delete ipcache");
        self.ipcache
            .write()
            .expect("ipcache lock poisoned")
            .remove(&key.addr);
        Ok(())
    }

    // -- Host firewall policy operations --

    fn upsert_host_policy(&self, key: HostPolicyKey, value: HostPolicyValue) -> anyhow::Result<()> {
        debug!(
            identity = key.identity,
            direction = key.direction,
            protocol = key.protocol,
            port = key.dst_port,
            action = value.action,
            "mock: upsert host policy"
        );
        let flat: HostPolicyKeyFlat = (&key).into();
        self.host_policies
            .write()
            .expect("host_policies lock poisoned")
            .insert(flat, value);
        Ok(())
    }

    fn delete_host_policy(&self, key: &HostPolicyKey) -> anyhow::Result<()> {
        debug!(
            identity = key.identity,
            direction = key.direction,
            "mock: delete host policy"
        );
        let flat: HostPolicyKeyFlat = key.into();
        self.host_policies
            .write()
            .expect("host_policies lock poisoned")
            .remove(&flat);
        Ok(())
    }

    fn host_policy_count(&self) -> usize {
        self.host_policies
            .read()
            .expect("host_policies lock poisoned")
            .len()
    }

    fn sync_host_policies(
        &self,
        new_policies: Vec<(HostPolicyKey, HostPolicyValue)>,
    ) -> anyhow::Result<(u32, u32)> {
        let mut map = self
            .host_policies
            .write()
            .expect("host_policies lock poisoned");
        let old_count = map.len() as u32;
        map.clear();
        for (key, value) in &new_policies {
            let flat: HostPolicyKeyFlat = key.into();
            map.insert(flat, *value);
        }
        let new_count = map.len() as u32;
        let removed = old_count;
        let added = new_count;
        info!(added, removed, "mock: synced host policies");
        Ok((added, removed))
    }

    // -- XDP operations --

    fn attach_xdp(&self, interface: &str, native: bool) -> anyhow::Result<()> {
        let mode_str = if native { "native" } else { "skb" };
        let type_str = format!("xdp_{}", mode_str);
        let mut attached = self.attached.write().expect("attached lock poisoned");
        let mut prog_id = self
            .next_prog_id
            .write()
            .expect("next_prog_id lock poisoned");

        // Check if already attached.
        if attached
            .iter()
            .any(|p| p.interface == interface && p.attach_type.starts_with("xdp"))
        {
            warn!(interface, mode = mode_str, "mock: XDP already attached");
            return Ok(());
        }

        let id = *prog_id;
        *prog_id += 1;
        attached.push(AttachedProgramInfo {
            interface: interface.to_string(),
            attach_type: type_str.clone(),
            program_id: id,
        });
        info!(
            interface,
            mode = mode_str,
            program_id = id,
            "mock: attached XDP program"
        );
        Ok(())
    }

    fn detach_xdp(&self, interface: &str) -> anyhow::Result<()> {
        let mut attached = self.attached.write().expect("attached lock poisoned");
        let before = attached.len();
        attached.retain(|p| !(p.interface == interface && p.attach_type.starts_with("xdp")));
        let after = attached.len();
        if before == after {
            warn!(interface, "mock: XDP program not found for detach");
        } else {
            info!(interface, "mock: detached XDP program");
        }
        Ok(())
    }

    // -- SOCKMAP endpoint operations --

    fn upsert_sockmap_endpoint(&self, key: SockmapEndpointKey, value: u32) -> anyhow::Result<()> {
        debug!(
            ip = key.ip,
            port = key.port,
            "mock: upsert sockmap endpoint"
        );
        self.sockmap_endpoints
            .write()
            .expect("sockmap_endpoints lock poisoned")
            .insert(key, value);
        Ok(())
    }

    fn delete_sockmap_endpoint(&self, key: &SockmapEndpointKey) -> anyhow::Result<()> {
        debug!(
            ip = key.ip,
            port = key.port,
            "mock: delete sockmap endpoint"
        );
        self.sockmap_endpoints
            .write()
            .expect("sockmap_endpoints lock poisoned")
            .remove(key);
        Ok(())
    }

    fn count_sockmap_endpoints(&self) -> usize {
        self.sockmap_endpoints
            .read()
            .expect("sockmap_endpoints lock poisoned")
            .len()
    }

    fn get_sockmap_stats(&self) -> (u64, u64) {
        (
            self.sockmap_stats_redirected.load(Ordering::Relaxed),
            self.sockmap_stats_fallback.load(Ordering::Relaxed),
        )
    }

    // -- Mesh service operations --

    fn upsert_mesh_service(
        &self,
        key: MeshServiceKey,
        value: MeshRedirectValue,
    ) -> anyhow::Result<()> {
        debug!(
            ip = key.ip,
            port = key.port,
            redirect_port = value.redirect_port,
            "mock: upsert mesh service"
        );
        self.mesh_services
            .write()
            .expect("mesh_services lock poisoned")
            .insert(key, value);
        Ok(())
    }

    fn delete_mesh_service(&self, key: &MeshServiceKey) -> anyhow::Result<()> {
        debug!(ip = key.ip, port = key.port, "mock: delete mesh service");
        self.mesh_services
            .write()
            .expect("mesh_services lock poisoned")
            .remove(key);
        Ok(())
    }

    fn list_mesh_services(&self) -> Vec<(MeshServiceKey, MeshRedirectValue)> {
        self.mesh_services
            .read()
            .expect("mesh_services lock poisoned")
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    fn count_mesh_services(&self) -> usize {
        self.mesh_services
            .read()
            .expect("mesh_services lock poisoned")
            .len()
    }

    // -- Rate limit operations --

    fn update_rate_limit_config(&self, config: RateLimitConfig) -> anyhow::Result<()> {
        debug!(
            rate = config.rate,
            burst = config.burst,
            window_ns = config.window_ns,
            "mock: update rate limit config"
        );
        *self
            .rate_limit_config
            .write()
            .expect("rate_limit_config lock poisoned") = Some(config);
        Ok(())
    }

    fn get_rate_limit_config(&self) -> Option<RateLimitConfig> {
        *self
            .rate_limit_config
            .read()
            .expect("rate_limit_config lock poisoned")
    }

    fn get_rate_limit_stats(&self) -> (u64, u64) {
        (
            self.rate_limit_stats_allowed.load(Ordering::Relaxed),
            self.rate_limit_stats_denied.load(Ordering::Relaxed),
        )
    }

    // -- Backend health operations --

    fn get_backend_health(&self, key: &BackendHealthKey) -> Option<BackendHealthCounters> {
        self.backend_health
            .read()
            .expect("backend_health lock poisoned")
            .get(key)
            .copied()
    }

    fn get_all_backend_health(&self) -> Vec<(BackendHealthKey, BackendHealthCounters)> {
        self.backend_health
            .read()
            .expect("backend_health lock poisoned")
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }

    fn count_backend_health(&self) -> usize {
        self.backend_health
            .read()
            .expect("backend_health lock poisoned")
            .len()
    }
}

// ---------------------------------------------------------------------------
// Tests (use mock maps — exercises same API as real eBPF maps)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_manager() -> MapManager {
        MapManager::new_mock()
    }

    // -- Endpoint tests --

    #[test]
    fn endpoint_upsert_and_count() {
        let mgr = mock_manager();
        assert_eq!(mgr.endpoint_count(), 0);

        mgr.upsert_endpoint(
            EndpointKey { ip: 0x0A2A0501 },
            EndpointValue {
                ifindex: 10,
                mac: [0x02, 0xfe, 0x0a, 0x2a, 0x05, 0x01],
                _pad: [0; 2],
                identity: 100,
                node_ip: 0xC0A86411,
            },
        )
        .unwrap();
        assert_eq!(mgr.endpoint_count(), 1);

        // Upsert same key overwrites.
        mgr.upsert_endpoint(
            EndpointKey { ip: 0x0A2A0501 },
            EndpointValue {
                ifindex: 11,
                mac: [0x02, 0xfe, 0x0a, 0x2a, 0x05, 0x01],
                _pad: [0; 2],
                identity: 200,
                node_ip: 0xC0A86411,
            },
        )
        .unwrap();
        assert_eq!(mgr.endpoint_count(), 1);
    }

    #[test]
    fn endpoint_delete() {
        let mgr = mock_manager();
        let key = EndpointKey { ip: 0x0A2A0501 };
        mgr.upsert_endpoint(
            key,
            EndpointValue {
                ifindex: 10,
                mac: [0; 6],
                _pad: [0; 2],
                identity: 1,
                node_ip: 0,
            },
        )
        .unwrap();
        assert_eq!(mgr.endpoint_count(), 1);

        mgr.delete_endpoint(&key).unwrap();
        assert_eq!(mgr.endpoint_count(), 0);
    }

    #[test]
    fn endpoint_multiple_entries() {
        let mgr = mock_manager();
        for i in 1..=10u32 {
            mgr.upsert_endpoint(
                EndpointKey { ip: i },
                EndpointValue {
                    ifindex: i,
                    mac: [0; 6],
                    _pad: [0; 2],
                    identity: i,
                    node_ip: 0,
                },
            )
            .unwrap();
        }
        assert_eq!(mgr.endpoint_count(), 10);
    }

    // -- Policy tests --

    #[test]
    fn policy_upsert_and_count() {
        let mgr = mock_manager();
        assert_eq!(mgr.policy_count(), 0);

        mgr.upsert_policy(
            PolicyKey {
                src_identity: 1,
                dst_identity: 2,
                protocol: 6,
                _pad: [0],
                dst_port: 80,
            },
            PolicyValue {
                action: ACTION_ALLOW,
                _pad: [0; 3],
            },
        )
        .unwrap();
        assert_eq!(mgr.policy_count(), 1);
    }

    #[test]
    fn policy_get_existing() {
        let mgr = mock_manager();
        let key = PolicyKey {
            src_identity: 1,
            dst_identity: 2,
            protocol: 6,
            _pad: [0],
            dst_port: 443,
        };
        let val = PolicyValue {
            action: ACTION_ALLOW,
            _pad: [0; 3],
        };
        mgr.upsert_policy(key, val).unwrap();

        let result = mgr.get_policy(&key).unwrap();
        assert_eq!(result, Some(val));
    }

    #[test]
    fn policy_get_missing() {
        let mgr = mock_manager();
        let key = PolicyKey {
            src_identity: 99,
            dst_identity: 99,
            protocol: 17,
            _pad: [0],
            dst_port: 53,
        };
        let result = mgr.get_policy(&key).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn policy_delete() {
        let mgr = mock_manager();
        let key = PolicyKey {
            src_identity: 1,
            dst_identity: 2,
            protocol: 6,
            _pad: [0],
            dst_port: 80,
        };
        mgr.upsert_policy(
            key,
            PolicyValue {
                action: ACTION_ALLOW,
                _pad: [0; 3],
            },
        )
        .unwrap();
        assert_eq!(mgr.policy_count(), 1);

        mgr.delete_policy(&key).unwrap();
        assert_eq!(mgr.policy_count(), 0);
    }

    #[test]
    fn policy_sync_add_remove_update() {
        let mgr = mock_manager();

        // Initial sync: add 3 policies.
        let initial = vec![
            (
                PolicyKey {
                    src_identity: 1,
                    dst_identity: 2,
                    protocol: 6,
                    _pad: [0],
                    dst_port: 80,
                },
                PolicyValue {
                    action: ACTION_ALLOW,
                    _pad: [0; 3],
                },
            ),
            (
                PolicyKey {
                    src_identity: 1,
                    dst_identity: 3,
                    protocol: 6,
                    _pad: [0],
                    dst_port: 443,
                },
                PolicyValue {
                    action: ACTION_ALLOW,
                    _pad: [0; 3],
                },
            ),
            (
                PolicyKey {
                    src_identity: 2,
                    dst_identity: 3,
                    protocol: 17,
                    _pad: [0],
                    dst_port: 53,
                },
                PolicyValue {
                    action: ACTION_DENY,
                    _pad: [0; 3],
                },
            ),
        ];
        let (added, removed, updated) = mgr.sync_policies(initial).unwrap();
        assert_eq!(added, 3);
        assert_eq!(removed, 0);
        assert_eq!(updated, 0);
        assert_eq!(mgr.policy_count(), 3);

        // Second sync: keep first, update second, remove third, add new.
        let second = vec![
            (
                PolicyKey {
                    src_identity: 1,
                    dst_identity: 2,
                    protocol: 6,
                    _pad: [0],
                    dst_port: 80,
                },
                PolicyValue {
                    action: ACTION_ALLOW,
                    _pad: [0; 3],
                },
            ),
            (
                PolicyKey {
                    src_identity: 1,
                    dst_identity: 3,
                    protocol: 6,
                    _pad: [0],
                    dst_port: 443,
                },
                PolicyValue {
                    action: ACTION_DENY,
                    _pad: [0; 3],
                },
            ),
            (
                PolicyKey {
                    src_identity: 5,
                    dst_identity: 6,
                    protocol: 6,
                    _pad: [0],
                    dst_port: 8080,
                },
                PolicyValue {
                    action: ACTION_ALLOW,
                    _pad: [0; 3],
                },
            ),
        ];
        let (added, removed, updated) = mgr.sync_policies(second).unwrap();
        assert_eq!(added, 1);
        assert_eq!(removed, 1);
        assert_eq!(updated, 1);
        assert_eq!(mgr.policy_count(), 3);
    }

    // -- Tunnel tests --

    #[test]
    fn tunnel_upsert_and_count() {
        let mgr = mock_manager();
        assert_eq!(mgr.tunnel_count(), 0);

        mgr.upsert_tunnel(
            TunnelKey {
                node_ip: 0xC0A86416,
            },
            TunnelValue {
                ifindex: 5,
                remote_ip: 0xC0A86416,
                vni: 1,
            },
        )
        .unwrap();
        assert_eq!(mgr.tunnel_count(), 1);
    }

    #[test]
    fn tunnel_delete() {
        let mgr = mock_manager();
        let key = TunnelKey {
            node_ip: 0xC0A86416,
        };
        mgr.upsert_tunnel(
            key,
            TunnelValue {
                ifindex: 5,
                remote_ip: key.node_ip,
                vni: 1,
            },
        )
        .unwrap();
        mgr.delete_tunnel(&key).unwrap();
        assert_eq!(mgr.tunnel_count(), 0);
    }

    // -- Config tests --

    #[test]
    fn config_update_and_get() {
        let mgr = mock_manager();

        let mut entries = StdHashMap::new();
        entries.insert(CONFIG_KEY_MODE, MODE_NATIVE);
        entries.insert(CONFIG_KEY_NODE_IP, 0xC0A86411);
        mgr.update_config(entries).unwrap();

        assert_eq!(mgr.get_config(CONFIG_KEY_MODE).unwrap(), Some(MODE_NATIVE));
        assert_eq!(
            mgr.get_config(CONFIG_KEY_NODE_IP).unwrap(),
            Some(0xC0A86411)
        );
        assert_eq!(mgr.get_config(CONFIG_KEY_SNAT_IP).unwrap(), None);
    }

    #[test]
    fn config_mode_string() {
        let mgr = mock_manager();
        assert_eq!(mgr.mode_string(), "overlay");

        let mut entries = StdHashMap::new();
        entries.insert(CONFIG_KEY_MODE, MODE_NATIVE);
        mgr.update_config(entries).unwrap();
        assert_eq!(mgr.mode_string(), "native");
    }

    #[test]
    fn config_tunnel_protocol_string() {
        let mgr = mock_manager();
        assert_eq!(mgr.tunnel_protocol_string(), "geneve");

        let mut entries = StdHashMap::new();
        entries.insert(CONFIG_KEY_TUNNEL_TYPE, TUNNEL_VXLAN);
        mgr.update_config(entries).unwrap();
        assert_eq!(mgr.tunnel_protocol_string(), "vxlan");
    }

    // -- Egress policy tests --

    #[test]
    fn egress_policy_upsert_and_delete() {
        let mgr = mock_manager();
        let key = EgressKey {
            src_identity: 1,
            dst_ip: 0x08080000,
            dst_prefix_len: 16,
            _pad: [0; 3],
        };
        mgr.upsert_egress_policy(
            key,
            EgressValue {
                action: EGRESS_SNAT,
                _pad: [0; 3],
                snat_ip: 0xC0A86401,
            },
        )
        .unwrap();
        mgr.delete_egress_policy(&key).unwrap();
    }

    // -- Program attach/detach tests --

    #[test]
    fn attach_and_list_programs() {
        let mgr = mock_manager();
        assert_eq!(mgr.attached_programs().len(), 0);

        mgr.attach_program("nv12345678901", AttachDirection::Ingress)
            .unwrap();
        mgr.attach_program("nv12345678901", AttachDirection::Egress)
            .unwrap();

        let progs = mgr.attached_programs();
        assert_eq!(progs.len(), 2);
        assert_eq!(progs[0].interface, "nv12345678901");
        assert_eq!(progs[0].attach_type, "ingress");
        assert_eq!(progs[1].attach_type, "egress");
        assert_ne!(progs[0].program_id, progs[1].program_id);
    }

    #[test]
    fn attach_duplicate_is_idempotent() {
        let mgr = mock_manager();
        mgr.attach_program("eth0", AttachDirection::Ingress)
            .unwrap();
        mgr.attach_program("eth0", AttachDirection::Ingress)
            .unwrap();
        assert_eq!(mgr.attached_programs().len(), 1);
    }

    #[test]
    fn detach_program_removes_entry() {
        let mgr = mock_manager();
        mgr.attach_program("nv12345678901", AttachDirection::Ingress)
            .unwrap();
        mgr.attach_program("nv12345678901", AttachDirection::Egress)
            .unwrap();
        assert_eq!(mgr.attached_programs().len(), 2);

        mgr.detach_program("nv12345678901", AttachDirection::Ingress)
            .unwrap();
        let progs = mgr.attached_programs();
        assert_eq!(progs.len(), 1);
        assert_eq!(progs[0].attach_type, "egress");
    }

    #[test]
    fn detach_nonexistent_is_ok() {
        let mgr = mock_manager();
        mgr.detach_program("nonexistent", AttachDirection::Ingress)
            .unwrap();
    }

    // -- Full lifecycle test --

    #[test]
    fn full_lifecycle() {
        let mgr = mock_manager();

        // Config.
        let mut cfg = StdHashMap::new();
        cfg.insert(CONFIG_KEY_MODE, MODE_NATIVE);
        cfg.insert(CONFIG_KEY_NODE_IP, 0xC0A8640B);
        cfg.insert(CONFIG_KEY_CLUSTER_CIDR_IP, 0x0A2A0000);
        cfg.insert(CONFIG_KEY_CLUSTER_CIDR_PREFIX_LEN, 16);
        mgr.update_config(cfg).unwrap();
        assert_eq!(mgr.mode_string(), "native");

        // Endpoints.
        mgr.upsert_endpoint(
            EndpointKey { ip: 0x0A2A0501 },
            EndpointValue {
                ifindex: 10,
                mac: [0x02, 0xfe, 0x0a, 0x2a, 0x05, 0x01],
                _pad: [0; 2],
                identity: 100,
                node_ip: 0xC0A8640B,
            },
        )
        .unwrap();
        mgr.upsert_endpoint(
            EndpointKey { ip: 0x0A2A0502 },
            EndpointValue {
                ifindex: 11,
                mac: [0x02, 0xfe, 0x0a, 0x2a, 0x05, 0x02],
                _pad: [0; 2],
                identity: 100,
                node_ip: 0xC0A8640B,
            },
        )
        .unwrap();
        assert_eq!(mgr.endpoint_count(), 2);

        // Policy.
        mgr.upsert_policy(
            PolicyKey {
                src_identity: 100,
                dst_identity: 100,
                protocol: 0,
                _pad: [0],
                dst_port: 0,
            },
            PolicyValue {
                action: ACTION_ALLOW,
                _pad: [0; 3],
            },
        )
        .unwrap();
        assert_eq!(mgr.policy_count(), 1);

        // Attach programs.
        mgr.attach_program("nv12345678901", AttachDirection::Ingress)
            .unwrap();
        mgr.attach_program("nv12345678901", AttachDirection::Egress)
            .unwrap();
        assert_eq!(mgr.attached_programs().len(), 2);

        // Clean up.
        mgr.delete_endpoint(&EndpointKey { ip: 0x0A2A0501 })
            .unwrap();
        assert_eq!(mgr.endpoint_count(), 1);
        mgr.detach_program("nv12345678901", AttachDirection::Ingress)
            .unwrap();
        mgr.detach_program("nv12345678901", AttachDirection::Egress)
            .unwrap();
        assert_eq!(mgr.attached_programs().len(), 0);
    }

    // -- SOCKMAP endpoint tests --

    #[test]
    fn sockmap_endpoint_crud() {
        let mgr = mock_manager();
        let key = SockmapEndpointKey {
            ip: 0x0A2A0105,
            port: 8080,
        };
        mgr.upsert_sockmap_endpoint(key, 1).unwrap();
        assert_eq!(mgr.count_sockmap_endpoints().unwrap(), 1);
        mgr.delete_sockmap_endpoint(&key).unwrap();
        assert_eq!(mgr.count_sockmap_endpoints().unwrap(), 0);
    }

    #[test]
    fn sockmap_stats_default_zero() {
        let mgr = mock_manager();
        let (redirected, fallback) = mgr.get_sockmap_stats();
        assert_eq!(redirected, 0);
        assert_eq!(fallback, 0);
    }

    // -- Mesh service tests --

    #[test]
    fn mesh_service_crud() {
        let mgr = mock_manager();
        let key = MeshServiceKey {
            ip: 0x0A2A0105,
            port: 8080,
        };
        let val = MeshRedirectValue {
            redirect_port: 15001,
        };
        mgr.upsert_mesh_service(key, val).unwrap();
        let services = mgr.list_mesh_services().unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].0, key);
        assert_eq!(services[0].1.redirect_port, 15001);
        assert_eq!(mgr.count_mesh_services().unwrap(), 1);

        mgr.delete_mesh_service(&key).unwrap();
        assert_eq!(mgr.count_mesh_services().unwrap(), 0);
    }

    #[test]
    fn mesh_service_upsert_overwrites() {
        let mgr = mock_manager();
        let key = MeshServiceKey {
            ip: 0x0A2A0105,
            port: 8080,
        };
        mgr.upsert_mesh_service(
            key,
            MeshRedirectValue {
                redirect_port: 15001,
            },
        )
        .unwrap();
        mgr.upsert_mesh_service(
            key,
            MeshRedirectValue {
                redirect_port: 15006,
            },
        )
        .unwrap();
        assert_eq!(mgr.count_mesh_services().unwrap(), 1);
        let services = mgr.list_mesh_services().unwrap();
        assert_eq!(services[0].1.redirect_port, 15006);
    }

    // -- Rate limit tests --

    #[test]
    fn rate_limit_config_crud() {
        let mgr = mock_manager();
        assert!(mgr.get_rate_limit_config().is_none());

        let config = RateLimitConfig {
            rate: 100,
            burst: 200,
            window_ns: 1_000_000_000,
        };
        mgr.update_rate_limit_config(config).unwrap();
        let got = mgr.get_rate_limit_config().unwrap();
        assert_eq!(got.rate, 100);
        assert_eq!(got.burst, 200);
        assert_eq!(got.window_ns, 1_000_000_000);
    }

    #[test]
    fn rate_limit_stats_default_zero() {
        let mgr = mock_manager();
        let (allowed, denied) = mgr.get_rate_limit_stats();
        assert_eq!(allowed, 0);
        assert_eq!(denied, 0);
    }

    // -- Backend health tests --

    #[test]
    fn backend_health_empty() {
        let mgr = mock_manager();
        let key = BackendHealthKey {
            ip: 0x0A2A0105,
            port: 8080,
        };
        assert!(mgr.get_backend_health(&key).is_none());
        assert_eq!(mgr.count_backend_health(), 0);
        assert!(mgr.get_all_backend_health().is_empty());
    }
}

// ---------------------------------------------------------------------------
// Real eBPF map implementation (Linux only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub struct RealMaps {
    endpoints: RwLock<aya::maps::HashMap<aya::maps::MapData, EndpointKey, EndpointValue>>,
    endpoints_v6:
        Option<RwLock<aya::maps::HashMap<aya::maps::MapData, EndpointKeyV6, EndpointValueV6>>>,
    policies: RwLock<aya::maps::HashMap<aya::maps::MapData, PolicyKey, PolicyValue>>,
    tunnels: RwLock<aya::maps::HashMap<aya::maps::MapData, TunnelKey, TunnelValue>>,
    tunnels_v6: Option<RwLock<aya::maps::HashMap<aya::maps::MapData, TunnelKeyV6, TunnelValueV6>>>,
    config: RwLock<aya::maps::HashMap<aya::maps::MapData, u32, u64>>,
    egress: RwLock<aya::maps::HashMap<aya::maps::MapData, EgressKey, EgressValue>>,
    egress_v6: Option<RwLock<aya::maps::HashMap<aya::maps::MapData, EgressKeyV6, EgressValueV6>>>,
    services: RwLock<aya::maps::HashMap<aya::maps::MapData, ServiceKey, ServiceValue>>,
    services_v6: Option<RwLock<aya::maps::HashMap<aya::maps::MapData, ServiceKeyV6, ServiceValue>>>,
    backends: RwLock<aya::maps::Array<aya::maps::MapData, BackendValue>>,
    backends_v6: Option<RwLock<aya::maps::Array<aya::maps::MapData, BackendValueV6>>>,
    maglev: RwLock<aya::maps::Array<aya::maps::MapData, u32>>,
    drop_counters: RwLock<aya::maps::PerCpuArray<aya::maps::MapData, u64>>,
    ipcache:
        Option<RwLock<aya::maps::lpm_trie::LpmTrie<aya::maps::MapData, IPCacheKey, IPCacheValue>>>,
    host_policies: Option<
        RwLock<aya::maps::lpm_trie::LpmTrie<aya::maps::MapData, HostPolicyKey, HostPolicyValue>>,
    >,
    // -- eBPF Services API maps --
    #[allow(dead_code)]
    sock_hash: Option<aya::maps::SockHash<aya::maps::MapData, SockKey>>,
    sockmap_endpoints:
        Option<RwLock<aya::maps::HashMap<aya::maps::MapData, SockmapEndpointKey, u32>>>,
    sockmap_stats: Option<RwLock<aya::maps::PerCpuArray<aya::maps::MapData, u64>>>,
    mesh_services:
        Option<RwLock<aya::maps::HashMap<aya::maps::MapData, MeshServiceKey, MeshRedirectValue>>>,
    _rl_tokens:
        Option<RwLock<aya::maps::HashMap<aya::maps::MapData, RateLimitKey, TokenBucketState>>>,
    rl_config: Option<RwLock<aya::maps::Array<aya::maps::MapData, RateLimitConfig>>>,
    backend_health: Option<
        RwLock<
            aya::maps::PerCpuHashMap<aya::maps::MapData, BackendHealthKey, BackendHealthCounters>,
        >,
    >,
    // -- infrastructure --
    attached: RwLock<Vec<AttachedProgramInfo>>,
    /// Holds TC program links so they stay attached (aya auto-detaches on drop).
    /// Tuples of (interface_name, attach_type, link) for targeted detach.
    _tc_links: std::sync::Mutex<Vec<(String, String, aya::programs::tc::SchedClassifierLink)>>,
    /// Holds cgroup program links so they stay attached.
    _cgroup_links: std::sync::Mutex<Vec<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>>,
    /// Holds XDP program links so they stay attached.
    _xdp_links: std::sync::Mutex<Vec<(String, aya::programs::xdp::XdpLink)>>,
    /// Holds the sk_lookup link so the mesh redirect program stays attached.
    _sk_lookup_link: Option<aya::programs::sk_lookup::SkLookupLink>,
    /// Holds references to the loaded eBPF object so programs stay loaded.
    _ebpf: std::sync::Mutex<aya::Ebpf>,
}

#[cfg(target_os = "linux")]
impl RealMaps {
    /// Create a new RealMaps from aya map handles and the loaded eBPF object.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoints: aya::maps::HashMap<aya::maps::MapData, EndpointKey, EndpointValue>,
        endpoints_v6: Option<
            aya::maps::HashMap<aya::maps::MapData, EndpointKeyV6, EndpointValueV6>,
        >,
        policies: aya::maps::HashMap<aya::maps::MapData, PolicyKey, PolicyValue>,
        tunnels: aya::maps::HashMap<aya::maps::MapData, TunnelKey, TunnelValue>,
        tunnels_v6: Option<aya::maps::HashMap<aya::maps::MapData, TunnelKeyV6, TunnelValueV6>>,
        config: aya::maps::HashMap<aya::maps::MapData, u32, u64>,
        egress: aya::maps::HashMap<aya::maps::MapData, EgressKey, EgressValue>,
        egress_v6: Option<aya::maps::HashMap<aya::maps::MapData, EgressKeyV6, EgressValueV6>>,
        services: aya::maps::HashMap<aya::maps::MapData, ServiceKey, ServiceValue>,
        services_v6: Option<aya::maps::HashMap<aya::maps::MapData, ServiceKeyV6, ServiceValue>>,
        backends: aya::maps::Array<aya::maps::MapData, BackendValue>,
        backends_v6: Option<aya::maps::Array<aya::maps::MapData, BackendValueV6>>,
        maglev: aya::maps::Array<aya::maps::MapData, u32>,
        drop_counters: aya::maps::PerCpuArray<aya::maps::MapData, u64>,
        ipcache: Option<aya::maps::lpm_trie::LpmTrie<aya::maps::MapData, IPCacheKey, IPCacheValue>>,
        host_policies: Option<
            aya::maps::lpm_trie::LpmTrie<aya::maps::MapData, HostPolicyKey, HostPolicyValue>,
        >,
        sock_hash: Option<aya::maps::SockHash<aya::maps::MapData, SockKey>>,
        sockmap_endpoints: Option<aya::maps::HashMap<aya::maps::MapData, SockmapEndpointKey, u32>>,
        sockmap_stats: Option<aya::maps::PerCpuArray<aya::maps::MapData, u64>>,
        mesh_services: Option<
            aya::maps::HashMap<aya::maps::MapData, MeshServiceKey, MeshRedirectValue>,
        >,
        rl_tokens: Option<aya::maps::HashMap<aya::maps::MapData, RateLimitKey, TokenBucketState>>,
        rl_config: Option<aya::maps::Array<aya::maps::MapData, RateLimitConfig>>,
        backend_health: Option<
            aya::maps::PerCpuHashMap<aya::maps::MapData, BackendHealthKey, BackendHealthCounters>,
        >,
        sk_lookup_link: Option<aya::programs::sk_lookup::SkLookupLink>,
        ebpf: aya::Ebpf,
    ) -> Self {
        Self {
            endpoints: RwLock::new(endpoints),
            endpoints_v6: endpoints_v6.map(RwLock::new),
            policies: RwLock::new(policies),
            tunnels: RwLock::new(tunnels),
            tunnels_v6: tunnels_v6.map(RwLock::new),
            config: RwLock::new(config),
            egress: RwLock::new(egress),
            egress_v6: egress_v6.map(RwLock::new),
            services: RwLock::new(services),
            services_v6: services_v6.map(RwLock::new),
            backends: RwLock::new(backends),
            backends_v6: backends_v6.map(RwLock::new),
            maglev: RwLock::new(maglev),
            drop_counters: RwLock::new(drop_counters),
            ipcache: ipcache.map(RwLock::new),
            host_policies: host_policies.map(RwLock::new),
            sock_hash,
            sockmap_endpoints: sockmap_endpoints.map(RwLock::new),
            sockmap_stats: sockmap_stats.map(RwLock::new),
            mesh_services: mesh_services.map(RwLock::new),
            _rl_tokens: rl_tokens.map(RwLock::new),
            rl_config: rl_config.map(RwLock::new),
            backend_health: backend_health.map(RwLock::new),
            attached: RwLock::new(Vec::new()),
            _tc_links: std::sync::Mutex::new(Vec::new()),
            _cgroup_links: std::sync::Mutex::new(Vec::new()),
            _xdp_links: std::sync::Mutex::new(Vec::new()),
            _sk_lookup_link: sk_lookup_link,
            _ebpf: std::sync::Mutex::new(ebpf),
        }
    }

    fn upsert_endpoint(&self, key: EndpointKey, value: EndpointValue) -> anyhow::Result<()> {
        debug!(ip = key.ip, identity = value.identity, "upsert endpoint");
        let mut map = self.endpoints.write().expect("endpoints lock poisoned");
        map.insert(key, value, 0)?;
        Ok(())
    }

    fn delete_endpoint(&self, key: &EndpointKey) -> anyhow::Result<()> {
        debug!(ip = key.ip, "delete endpoint");
        let mut map = self.endpoints.write().expect("endpoints lock poisoned");
        map.remove(key)?;
        Ok(())
    }

    fn endpoint_count(&self) -> usize {
        let map = self.endpoints.read().expect("endpoints lock poisoned");
        map.iter().count()
    }

    fn upsert_endpoint_v6(&self, key: EndpointKeyV6, value: EndpointValueV6) -> anyhow::Result<()> {
        debug!(identity = value.identity, "upsert endpoint v6");
        let map_lock = self
            .endpoints_v6
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ENDPOINTS_V6 map not loaded"))?;
        let mut map = map_lock.write().expect("endpoints_v6 lock poisoned");
        map.insert(key, value, 0)?;
        Ok(())
    }

    fn delete_endpoint_v6(&self, key: &EndpointKeyV6) -> anyhow::Result<()> {
        debug!("delete endpoint v6");
        let map_lock = self
            .endpoints_v6
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("ENDPOINTS_V6 map not loaded"))?;
        let mut map = map_lock.write().expect("endpoints_v6 lock poisoned");
        map.remove(key)?;
        Ok(())
    }

    fn upsert_policy(&self, key: PolicyKey, value: PolicyValue) -> anyhow::Result<()> {
        debug!(
            src = key.src_identity,
            dst = key.dst_identity,
            proto = key.protocol,
            port = key.dst_port,
            action = value.action,
            "upsert policy"
        );
        let mut map = self.policies.write().expect("policies lock poisoned");
        map.insert(key, value, 0)?;
        Ok(())
    }

    fn delete_policy(&self, key: &PolicyKey) -> anyhow::Result<()> {
        let mut map = self.policies.write().expect("policies lock poisoned");
        map.remove(key)?;
        Ok(())
    }

    fn policy_count(&self) -> usize {
        let map = self.policies.read().expect("policies lock poisoned");
        map.iter().count()
    }

    fn sync_policies(
        &self,
        new_policies: Vec<(PolicyKey, PolicyValue)>,
    ) -> anyhow::Result<(u32, u32, u32)> {
        let mut map = self.policies.write().expect("policies lock poisoned");

        // Collect existing keys.
        let existing: StdHashMap<Vec<u8>, PolicyValue> = map
            .iter()
            .filter_map(|res| res.ok())
            .map(|(k, v)| {
                // SAFETY: PolicyKey is #[repr(C)] with no padding, so reading
                // its raw bytes is safe for equality comparison. The pointer
                // is valid for size_of::<PolicyKey>() bytes.
                let key_bytes = unsafe {
                    core::slice::from_raw_parts(
                        &k as *const PolicyKey as *const u8,
                        core::mem::size_of::<PolicyKey>(),
                    )
                    .to_vec()
                };
                (key_bytes, v)
            })
            .collect();

        let mut added = 0u32;
        let mut updated = 0u32;
        let mut new_key_bytes_set = std::collections::HashSet::new();

        for (key, value) in &new_policies {
            // SAFETY: Same as above — PolicyKey is #[repr(C)], pointer is
            // valid for size_of::<PolicyKey>() bytes.
            let key_bytes = unsafe {
                core::slice::from_raw_parts(
                    key as *const PolicyKey as *const u8,
                    core::mem::size_of::<PolicyKey>(),
                )
                .to_vec()
            };
            new_key_bytes_set.insert(key_bytes.clone());

            match existing.get(&key_bytes) {
                Some(existing_val) if existing_val.action == value.action => {
                    // No change.
                }
                Some(_) => {
                    map.insert(*key, *value, 0)?;
                    updated += 1;
                }
                None => {
                    map.insert(*key, *value, 0)?;
                    added += 1;
                }
            }
        }

        // Remove entries not in new set.
        let mut removed = 0u32;
        let keys_to_remove: Vec<PolicyKey> = existing
            .keys()
            .filter(|kb| !new_key_bytes_set.contains(*kb))
            .filter_map(|kb| {
                if kb.len() == core::mem::size_of::<PolicyKey>() {
                    // SAFETY: Length check guarantees the buffer holds a
                    // complete PolicyKey. PolicyKey is #[repr(C)] and Copy.
                    Some(unsafe { *(kb.as_ptr() as *const PolicyKey) })
                } else {
                    None
                }
            })
            .collect();

        for key in keys_to_remove {
            if map.remove(&key).is_ok() {
                removed += 1;
            }
        }

        info!(added, removed, updated, "synced policies");
        Ok((added, removed, updated))
    }

    fn upsert_tunnel(&self, key: TunnelKey, value: TunnelValue) -> anyhow::Result<()> {
        debug!(node_ip = key.node_ip, vni = value.vni, "upsert tunnel");
        let mut map = self.tunnels.write().expect("tunnels lock poisoned");
        map.insert(key, value, 0)?;
        Ok(())
    }

    fn delete_tunnel(&self, key: &TunnelKey) -> anyhow::Result<()> {
        let mut map = self.tunnels.write().expect("tunnels lock poisoned");
        map.remove(key)?;
        Ok(())
    }

    fn tunnel_count(&self) -> usize {
        let map = self.tunnels.read().expect("tunnels lock poisoned");
        map.iter().count()
    }

    fn upsert_tunnel_v6(&self, key: TunnelKeyV6, value: TunnelValueV6) -> anyhow::Result<()> {
        debug!(vni = value.vni, "upsert tunnel v6");
        let map_lock = self
            .tunnels_v6
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TUNNELS_V6 map not loaded"))?;
        let mut map = map_lock.write().expect("tunnels_v6 lock poisoned");
        map.insert(key, value, 0)?;
        Ok(())
    }

    fn delete_tunnel_v6(&self, key: &TunnelKeyV6) -> anyhow::Result<()> {
        debug!("delete tunnel v6");
        let map_lock = self
            .tunnels_v6
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TUNNELS_V6 map not loaded"))?;
        let mut map = map_lock.write().expect("tunnels_v6 lock poisoned");
        map.remove(key)?;
        Ok(())
    }

    fn update_config(&self, entries: StdHashMap<u32, u64>) -> anyhow::Result<()> {
        let mut map = self.config.write().expect("config lock poisoned");
        for (k, v) in entries {
            debug!(key = k, value = v, "update config");
            map.insert(k, v, 0)?;
        }
        Ok(())
    }

    fn get_config(&self, key: u32) -> anyhow::Result<Option<u64>> {
        let map = self.config.read().expect("config lock poisoned");
        match map.get(&key, 0) {
            Ok(val) => Ok(Some(val)),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn upsert_egress_policy(&self, key: EgressKey, value: EgressValue) -> anyhow::Result<()> {
        debug!(
            src_identity = key.src_identity,
            dst_ip = key.dst_ip,
            prefix_len = key.dst_prefix_len,
            action = value.action,
            "upsert egress policy"
        );
        let mut map = self.egress.write().expect("egress lock poisoned");
        map.insert(key, value, 0)?;
        Ok(())
    }

    fn delete_egress_policy(&self, key: &EgressKey) -> anyhow::Result<()> {
        let mut map = self.egress.write().expect("egress lock poisoned");
        map.remove(key)?;
        Ok(())
    }

    fn upsert_egress_policy_v6(
        &self,
        key: EgressKeyV6,
        value: EgressValueV6,
    ) -> anyhow::Result<()> {
        debug!(
            src_identity = key.src_identity,
            prefix_len = key.dst_prefix_len,
            action = value.action,
            "upsert egress policy v6"
        );
        let map_lock = self
            .egress_v6
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("EGRESS_POLICIES_V6 map not loaded"))?;
        let mut map = map_lock.write().expect("egress_v6 lock poisoned");
        map.insert(key, value, 0)?;
        Ok(())
    }

    fn delete_egress_policy_v6(&self, key: &EgressKeyV6) -> anyhow::Result<()> {
        debug!(src_identity = key.src_identity, "delete egress policy v6");
        let map_lock = self
            .egress_v6
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("EGRESS_POLICIES_V6 map not loaded"))?;
        let mut map = map_lock.write().expect("egress_v6 lock poisoned");
        map.remove(key)?;
        Ok(())
    }

    fn upsert_service(&self, key: ServiceKey, value: ServiceValue) -> anyhow::Result<()> {
        debug!(
            ip = key.ip,
            port = key.port,
            protocol = key.protocol,
            scope = key.scope,
            "upsert service"
        );
        let mut map = self.services.write().expect("services lock poisoned");
        map.insert(key, value, 0)?;
        Ok(())
    }

    fn delete_service(&self, key: &ServiceKey) -> anyhow::Result<()> {
        debug!(ip = key.ip, port = key.port, "delete service");
        let mut map = self.services.write().expect("services lock poisoned");
        map.remove(key)?;
        Ok(())
    }

    fn service_count(&self) -> usize {
        let map = self.services.read().expect("services lock poisoned");
        map.iter().count()
    }

    fn upsert_service_v6(&self, key: ServiceKeyV6, value: ServiceValue) -> anyhow::Result<()> {
        debug!(
            port = key.port,
            protocol = key.protocol,
            scope = key.scope,
            "upsert service v6"
        );
        let map_lock = self
            .services_v6
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SERVICES_V6 map not loaded"))?;
        let mut map = map_lock.write().expect("services_v6 lock poisoned");
        map.insert(key, value, 0)?;
        Ok(())
    }

    fn delete_service_v6(&self, key: &ServiceKeyV6) -> anyhow::Result<()> {
        debug!(port = key.port, "delete service v6");
        let map_lock = self
            .services_v6
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SERVICES_V6 map not loaded"))?;
        let mut map = map_lock.write().expect("services_v6 lock poisoned");
        map.remove(key)?;
        Ok(())
    }

    fn upsert_backend(&self, index: u32, value: BackendValue) -> anyhow::Result<()> {
        debug!(
            index = index,
            ip = value.ip,
            port = value.port,
            "upsert backend"
        );
        let mut map = self.backends.write().expect("backends lock poisoned");
        map.set(index, value, 0)?;
        Ok(())
    }

    fn upsert_backend_v6(&self, index: u32, value: BackendValueV6) -> anyhow::Result<()> {
        debug!(index = index, port = value.port, "upsert backend v6");
        let map_lock = self
            .backends_v6
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("BACKENDS_V6 map not loaded"))?;
        let mut map = map_lock.write().expect("backends_v6 lock poisoned");
        map.set(index, value, 0)?;
        Ok(())
    }

    fn upsert_maglev_entry(&self, index: u32, value: u32) -> anyhow::Result<()> {
        debug!(index = index, value = value, "upsert maglev entry");
        let mut map = self.maglev.write().expect("maglev lock poisoned");
        map.set(index, value, 0)?;
        Ok(())
    }

    fn clear_services(&self) {
        let mut map = self.services.write().expect("services lock poisoned");
        // Collect keys first, then remove them.
        let keys: Vec<ServiceKey> = map
            .iter()
            .filter_map(|res| res.ok())
            .map(|(k, _)| k)
            .collect();
        for key in keys {
            let _ = map.remove(&key);
        }
    }

    fn clear_backends(&self) {
        // Array maps cannot be "cleared" — we zero out entries by writing default values.
        // This is a best-effort operation; the actual cleanup happens when services
        // are re-synced and backend offsets are reassigned.
        debug!("clear backends (no-op for array map, entries will be overwritten)");
    }

    fn get_drop_counters(&self) -> StdHashMap<u32, u64> {
        let map = self
            .drop_counters
            .read()
            .expect("drop_counters lock poisoned");
        let mut result = StdHashMap::new();
        for idx in 0..DROP_REASON_MAX {
            match map.get(&idx, 0) {
                Ok(values) => {
                    let total: u64 = values.iter().sum();
                    if total > 0 {
                        result.insert(idx, total);
                    }
                }
                Err(aya::maps::MapError::KeyNotFound) => {}
                Err(e) => {
                    tracing::warn!(index = idx, error = %e, "failed to read drop counter");
                }
            }
        }
        result
    }

    fn attached_programs(&self) -> Vec<AttachedProgramInfo> {
        self.attached
            .read()
            .expect("attached lock poisoned")
            .clone()
    }

    fn attach_program(&self, interface: &str, attach_type: AttachDirection) -> anyhow::Result<()> {
        use aya::programs::{tc, SchedClassifier, TcAttachType};

        let type_str = match attach_type {
            AttachDirection::Ingress => "ingress",
            AttachDirection::Egress => "egress",
        };

        let tc_attach_type = match attach_type {
            AttachDirection::Ingress => TcAttachType::Ingress,
            AttachDirection::Egress => TcAttachType::Egress,
        };

        // Determine which eBPF program to attach based on interface and TC hook direction.
        //
        // For tunnel interfaces, TC hook direction matches program name directly.
        //
        // For pod veths, program names use K8s perspective (ingress = to pod,
        // egress = from pod), but TC hooks use interface perspective (ingress =
        // arriving at host veth from pod, egress = leaving host veth toward pod).
        // So we swap: TC ingress hook → tc_egress program (handles pod egress),
        //             TC egress hook → tc_ingress program (handles pod ingress).
        let prog_name = if interface.starts_with("geneve")
            || interface.starts_with("vxlan")
            || interface.starts_with("nv_")
            || interface.starts_with("nvx")
        {
            match attach_type {
                AttachDirection::Ingress => "tc_tunnel_ingress",
                AttachDirection::Egress => "tc_tunnel_egress",
            }
        } else {
            match attach_type {
                AttachDirection::Ingress => "tc_egress", // TC ingress = from pod = K8s egress
                AttachDirection::Egress => "tc_ingress", // TC egress = to pod = K8s ingress
            }
        };

        let mut ebpf = self._ebpf.lock().expect("ebpf lock poisoned");
        let prog: &mut SchedClassifier = ebpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("eBPF program '{}' not found", prog_name))?
            .try_into()?;

        // Add clsact qdisc if not already present (may already exist).
        if let Err(e) = tc::qdisc_add_clsact(interface) {
            debug!(interface, error = %e, "qdisc_add_clsact failed (may already exist)");
        }

        let link_id = prog.attach(interface, tc_attach_type)?;
        let prog_id = prog.info()?.id();

        // Take ownership of the link so it lives as long as RealMaps.
        // Without this, the link is stored inside the Program object and
        // could be dropped when the Ebpf mutex guard is released.
        let link = prog.take_link(link_id)?;
        self._tc_links
            .lock()
            .expect("tc_links lock poisoned")
            .push((interface.to_string(), type_str.to_string(), link));

        let mut attached = self.attached.write().expect("attached lock poisoned");
        attached.push(AttachedProgramInfo {
            interface: interface.to_string(),
            attach_type: type_str.to_string(),
            program_id: prog_id,
        });

        info!(
            interface,
            attach_type = type_str,
            program = prog_name,
            program_id = prog_id,
            "attached TC program"
        );

        Ok(())
    }

    fn detach_program(&self, interface: &str, attach_type: AttachDirection) -> anyhow::Result<()> {
        let type_str = match attach_type {
            AttachDirection::Ingress => "ingress",
            AttachDirection::Egress => "egress",
        };

        // Remove from tracking list.
        let mut attached = self.attached.write().expect("attached lock poisoned");
        let before = attached.len();
        attached.retain(|p| !(p.interface == interface && p.attach_type == type_str));
        let after = attached.len();

        // Remove and drop the TC link, which triggers actual detach via aya.
        let mut links = self._tc_links.lock().expect("tc_links lock poisoned");
        links.retain(|(iface, at, _link)| !(iface == interface && at == type_str));

        if before == after {
            warn!(
                interface,
                attach_type = type_str,
                "program not found for detach"
            );
        } else {
            info!(
                interface,
                attach_type = type_str,
                "detached program (link dropped)"
            );
        }

        Ok(())
    }

    // -- IPCache operations --

    fn upsert_ipcache(&self, key: IPCacheKey, value: IPCacheValue) -> anyhow::Result<()> {
        use aya::maps::lpm_trie::Key;
        let trie = self
            .ipcache
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("IPCACHE map not available"))?;
        let mut map = trie.write().expect("ipcache lock poisoned");
        map.insert(&Key::new(key.prefix_len, key), value, 0)?;
        debug!(
            prefix_len = key.prefix_len,
            identity = value.identity,
            "upsert ipcache"
        );
        Ok(())
    }

    fn delete_ipcache(&self, key: &IPCacheKey) -> anyhow::Result<()> {
        use aya::maps::lpm_trie::Key;
        let trie = self
            .ipcache
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("IPCACHE map not available"))?;
        let mut map = trie.write().expect("ipcache lock poisoned");
        map.remove(&Key::new(key.prefix_len, *key))?;
        debug!(prefix_len = key.prefix_len, "delete ipcache");
        Ok(())
    }

    // -- Host firewall policy operations --

    fn upsert_host_policy(&self, key: HostPolicyKey, value: HostPolicyValue) -> anyhow::Result<()> {
        use aya::maps::lpm_trie::Key;
        let trie = self
            .host_policies
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HOST_POLICIES map not available"))?;
        let mut map = trie.write().expect("host_policies lock poisoned");
        map.insert(&Key::new(key.prefix_len, key), value, 0)?;
        debug!(
            identity = key.identity,
            direction = key.direction,
            protocol = key.protocol,
            port = key.dst_port,
            action = value.action,
            "upsert host policy"
        );
        Ok(())
    }

    fn delete_host_policy(&self, key: &HostPolicyKey) -> anyhow::Result<()> {
        use aya::maps::lpm_trie::Key;
        let trie = self
            .host_policies
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HOST_POLICIES map not available"))?;
        let mut map = trie.write().expect("host_policies lock poisoned");
        map.remove(&Key::new(key.prefix_len, *key))?;
        debug!(
            identity = key.identity,
            direction = key.direction,
            "delete host policy"
        );
        Ok(())
    }

    fn host_policy_count(&self) -> usize {
        match &self.host_policies {
            Some(trie) => {
                let map = trie.read().expect("host_policies lock poisoned");
                map.iter().count()
            }
            None => 0,
        }
    }

    fn sync_host_policies(
        &self,
        new_policies: Vec<(HostPolicyKey, HostPolicyValue)>,
    ) -> anyhow::Result<(u32, u32)> {
        use aya::maps::lpm_trie::Key;
        let trie = self
            .host_policies
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HOST_POLICIES map not available"))?;
        let mut map = trie.write().expect("host_policies lock poisoned");

        // Collect existing entries to remove.
        let existing: Vec<Key<HostPolicyKey>> = map
            .iter()
            .filter_map(|res| res.ok())
            .map(|(k, _v)| k)
            .collect();

        let mut removed = 0u32;
        for key in &existing {
            if map.remove(key).is_ok() {
                removed += 1;
            }
        }

        let mut added = 0u32;
        for (key, value) in &new_policies {
            map.insert(&Key::new(key.prefix_len, *key), *value, 0)?;
            added += 1;
        }

        info!(added, removed, "synced host policies");
        Ok((added, removed))
    }

    // -- XDP operations --

    fn attach_xdp(&self, interface: &str, native: bool) -> anyhow::Result<()> {
        use aya::programs::{Xdp, XdpFlags};

        let flags = if native {
            XdpFlags::DRV_MODE
        } else {
            XdpFlags::SKB_MODE
        };
        let mode_str = if native { "native" } else { "skb" };

        let mut ebpf = self._ebpf.lock().expect("ebpf lock poisoned");
        let prog: &mut Xdp = match ebpf.program_mut("xdp_pass") {
            Some(p) => p.try_into()?,
            None => {
                anyhow::bail!("XDP program 'xdp_pass' not found in eBPF object");
            }
        };

        let link_id = prog.attach(interface, flags)?;
        let prog_id = prog.info()?.id();
        let link = prog.take_link(link_id)?;

        self._xdp_links
            .lock()
            .expect("xdp_links lock poisoned")
            .push((interface.to_string(), link));

        let mut attached = self.attached.write().expect("attached lock poisoned");
        attached.push(AttachedProgramInfo {
            interface: interface.to_string(),
            attach_type: format!("xdp_{}", mode_str),
            program_id: prog_id,
        });

        info!(
            interface,
            mode = mode_str,
            program_id = prog_id,
            "attached XDP program"
        );
        Ok(())
    }

    fn detach_xdp(&self, interface: &str) -> anyhow::Result<()> {
        // Remove and drop XDP link, which triggers actual detach.
        let mut links = self._xdp_links.lock().expect("xdp_links lock poisoned");
        links.retain(|(iface, _link)| iface != interface);

        let mut attached = self.attached.write().expect("attached lock poisoned");
        let before = attached.len();
        attached.retain(|p| !(p.interface == interface && p.attach_type.starts_with("xdp")));
        let after = attached.len();

        if before == after {
            warn!(interface, "XDP program not found for detach");
        } else {
            info!(interface, "detached XDP program (link dropped)");
        }
        Ok(())
    }

    fn attach_cgroup_programs(&self) -> anyhow::Result<()> {
        use anyhow::Context;
        use aya::programs::{CgroupAttachMode, CgroupSockAddr};

        let cgroup = std::fs::File::open("/sys/fs/cgroup")
            .context("Failed to open root cgroup for socket-LB")?;

        let mut ebpf = self._ebpf.lock().expect("ebpf lock poisoned");
        let mut links = self
            ._cgroup_links
            .lock()
            .expect("cgroup_links lock poisoned");

        for prog_name in &[
            "sock_connect4",
            "sock_sendmsg4",
            "sock_recvmsg4",
            "sock_getpeername4",
        ] {
            let prog: &mut CgroupSockAddr = ebpf
                .program_mut(prog_name)
                .ok_or_else(|| anyhow::anyhow!("Program '{}' not found", prog_name))?
                .try_into()?;

            let link_id = prog.attach(&cgroup, CgroupAttachMode::Single)?;
            let link = prog.take_link(link_id)?;
            links.push(link);

            info!(program = prog_name, "attached cgroup socket-LB program");
        }

        Ok(())
    }

    // -- SOCKMAP endpoint operations --

    fn upsert_sockmap_endpoint(&self, key: SockmapEndpointKey, value: u32) -> anyhow::Result<()> {
        let map_lock = self
            .sockmap_endpoints
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SOCKMAP_ENDPOINTS map not loaded"))?;
        let mut map = map_lock.write().expect("sockmap_endpoints lock poisoned");
        map.insert(key, value, 0)?;
        debug!(ip = key.ip, port = key.port, "upsert sockmap endpoint");
        Ok(())
    }

    fn delete_sockmap_endpoint(&self, key: &SockmapEndpointKey) -> anyhow::Result<()> {
        let map_lock = self
            .sockmap_endpoints
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SOCKMAP_ENDPOINTS map not loaded"))?;
        let mut map = map_lock.write().expect("sockmap_endpoints lock poisoned");
        map.remove(key)?;
        debug!(ip = key.ip, port = key.port, "delete sockmap endpoint");
        Ok(())
    }

    fn count_sockmap_endpoints(&self) -> anyhow::Result<usize> {
        let map_lock = self
            .sockmap_endpoints
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SOCKMAP_ENDPOINTS map not loaded"))?;
        let map = map_lock.read().expect("sockmap_endpoints lock poisoned");
        Ok(map.iter().count())
    }

    fn get_sockmap_stats(&self) -> (u64, u64) {
        let map_lock = match self.sockmap_stats.as_ref() {
            Some(m) => m,
            None => return (0, 0),
        };
        let map = map_lock.read().expect("sockmap_stats lock poisoned");
        let redirected = map
            .get(&0, 0)
            .ok()
            .map(|vals| vals.iter().copied().sum::<u64>())
            .unwrap_or(0);
        let fallback = map
            .get(&1, 0)
            .ok()
            .map(|vals| vals.iter().copied().sum::<u64>())
            .unwrap_or(0);
        (redirected, fallback)
    }

    // -- Mesh service operations --

    fn upsert_mesh_service(
        &self,
        key: MeshServiceKey,
        value: MeshRedirectValue,
    ) -> anyhow::Result<()> {
        let map_lock = self
            .mesh_services
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MESH_SERVICES map not loaded"))?;
        let mut map = map_lock.write().expect("mesh_services lock poisoned");
        map.insert(key, value, 0)?;
        debug!(
            ip = key.ip,
            port = key.port,
            redirect_port = value.redirect_port,
            "upsert mesh service"
        );
        Ok(())
    }

    fn delete_mesh_service(&self, key: &MeshServiceKey) -> anyhow::Result<()> {
        let map_lock = self
            .mesh_services
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MESH_SERVICES map not loaded"))?;
        let mut map = map_lock.write().expect("mesh_services lock poisoned");
        map.remove(key)?;
        debug!(ip = key.ip, port = key.port, "delete mesh service");
        Ok(())
    }

    fn list_mesh_services(&self) -> anyhow::Result<Vec<(MeshServiceKey, MeshRedirectValue)>> {
        let map_lock = self
            .mesh_services
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MESH_SERVICES map not loaded"))?;
        let map = map_lock.read().expect("mesh_services lock poisoned");
        Ok(map.iter().filter_map(|res| res.ok()).collect())
    }

    fn count_mesh_services(&self) -> anyhow::Result<usize> {
        let map_lock = self
            .mesh_services
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MESH_SERVICES map not loaded"))?;
        let map = map_lock.read().expect("mesh_services lock poisoned");
        Ok(map.iter().count())
    }

    // -- Rate limit operations --

    fn update_rate_limit_config(&self, config: RateLimitConfig) -> anyhow::Result<()> {
        let map_lock = self
            .rl_config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("RL_CONFIG map not loaded"))?;
        let mut map = map_lock.write().expect("rl_config lock poisoned");
        map.set(0, config, 0)?;
        debug!(
            rate = config.rate,
            burst = config.burst,
            window_ns = config.window_ns,
            "updated rate limit config"
        );
        Ok(())
    }

    fn get_rate_limit_config(&self) -> Option<RateLimitConfig> {
        let map_lock = self.rl_config.as_ref()?;
        let map = map_lock.read().expect("rl_config lock poisoned");
        map.get(&0, 0).ok()
    }

    fn get_rate_limit_stats(&self) -> (u64, u64) {
        // Rate limit stats are not tracked in a dedicated map in eBPF;
        // they would need a separate per-CPU array. Return zeros for now.
        // TODO: Add RL_STATS per-CPU array to eBPF programs for allowed/denied counts.
        (0, 0)
    }

    // -- Backend health operations --

    fn get_backend_health(&self, key: &BackendHealthKey) -> Option<BackendHealthCounters> {
        let map_lock = self.backend_health.as_ref()?;
        let map = map_lock.read().expect("backend_health lock poisoned");
        match map.get(key, 0) {
            Ok(per_cpu_vals) => {
                // Sum counters across all CPUs.
                let mut combined = BackendHealthCounters::default();
                for v in per_cpu_vals.iter() {
                    combined.total_conns += v.total_conns;
                    combined.failed_conns += v.failed_conns;
                    combined.timeout_conns += v.timeout_conns;
                    combined.success_conns += v.success_conns;
                    if v.last_success_ns > combined.last_success_ns {
                        combined.last_success_ns = v.last_success_ns;
                    }
                    if v.last_failure_ns > combined.last_failure_ns {
                        combined.last_failure_ns = v.last_failure_ns;
                    }
                    combined.total_rtt_ns += v.total_rtt_ns;
                }
                Some(combined)
            }
            Err(_) => None,
        }
    }

    fn get_all_backend_health(&self) -> Vec<(BackendHealthKey, BackendHealthCounters)> {
        let map_lock = match self.backend_health.as_ref() {
            Some(m) => m,
            None => return Vec::new(),
        };
        let map = map_lock.read().expect("backend_health lock poisoned");
        map.iter()
            .filter_map(|res| {
                let (key, per_cpu_vals) = res.ok()?;
                let mut combined = BackendHealthCounters::default();
                for v in per_cpu_vals.iter() {
                    combined.total_conns += v.total_conns;
                    combined.failed_conns += v.failed_conns;
                    combined.timeout_conns += v.timeout_conns;
                    combined.success_conns += v.success_conns;
                    if v.last_success_ns > combined.last_success_ns {
                        combined.last_success_ns = v.last_success_ns;
                    }
                    if v.last_failure_ns > combined.last_failure_ns {
                        combined.last_failure_ns = v.last_failure_ns;
                    }
                    combined.total_rtt_ns += v.total_rtt_ns;
                }
                Some((key, combined))
            })
            .collect()
    }

    fn count_backend_health(&self) -> usize {
        let map_lock = match self.backend_health.as_ref() {
            Some(m) => m,
            None => return 0,
        };
        let map = map_lock.read().expect("backend_health lock poisoned");
        map.iter().count()
    }
}
