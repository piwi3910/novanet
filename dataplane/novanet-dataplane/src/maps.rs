//! eBPF map management layer.
//!
//! Provides a `MapManager` that abstracts over real aya map handles (Linux)
//! and in-memory mock maps (macOS / standalone mode). The gRPC server calls
//! into MapManager for all map operations.

use novanet_common::*;
use std::collections::HashMap as StdHashMap;
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

    #[allow(dead_code)]
    pub fn get_policy(&self, key: &PolicyKey) -> anyhow::Result<Option<PolicyValue>> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.get_policy(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.get_policy(key),
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

    #[allow(dead_code)]
    pub fn upsert_egress_policy(
        &self,
        key: EgressKey,
        value: EgressValue,
    ) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.upsert_egress_policy(key, value),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.upsert_egress_policy(key, value),
        }
    }

    #[allow(dead_code)]
    pub fn delete_egress_policy(&self, key: &EgressKey) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(m) => m.delete_egress_policy(key),
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.delete_egress_policy(key),
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
    policies: RwLock<StdHashMap<PolicyKeyFlat, PolicyValue>>,
    tunnels: RwLock<StdHashMap<u32, TunnelValue>>,
    config: RwLock<StdHashMap<u32, u64>>,
    egress: RwLock<StdHashMap<EgressKeyFlat, EgressValue>>,
    attached: RwLock<Vec<AttachedProgramInfo>>,
    next_prog_id: RwLock<u32>,
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

impl MockMaps {
    fn new() -> Self {
        Self {
            endpoints: RwLock::new(StdHashMap::new()),
            policies: RwLock::new(StdHashMap::new()),
            tunnels: RwLock::new(StdHashMap::new()),
            config: RwLock::new(StdHashMap::new()),
            egress: RwLock::new(StdHashMap::new()),
            attached: RwLock::new(Vec::new()),
            next_prog_id: RwLock::new(1),
        }
    }

    fn upsert_endpoint(&self, key: EndpointKey, value: EndpointValue) -> anyhow::Result<()> {
        debug!(ip = key.ip, identity = value.identity, "mock: upsert endpoint");
        self.endpoints.write().unwrap().insert(key.ip, value);
        Ok(())
    }

    fn delete_endpoint(&self, key: &EndpointKey) -> anyhow::Result<()> {
        debug!(ip = key.ip, "mock: delete endpoint");
        self.endpoints.write().unwrap().remove(&key.ip);
        Ok(())
    }

    fn endpoint_count(&self) -> usize {
        self.endpoints.read().unwrap().len()
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
        self.policies.write().unwrap().insert(flat, value);
        Ok(())
    }

    fn delete_policy(&self, key: &PolicyKey) -> anyhow::Result<()> {
        debug!(
            src = key.src_identity,
            dst = key.dst_identity,
            "mock: delete policy"
        );
        let flat: PolicyKeyFlat = key.into();
        self.policies.write().unwrap().remove(&flat);
        Ok(())
    }

    fn get_policy(&self, key: &PolicyKey) -> anyhow::Result<Option<PolicyValue>> {
        let flat: PolicyKeyFlat = key.into();
        Ok(self.policies.read().unwrap().get(&flat).copied())
    }

    fn policy_count(&self) -> usize {
        self.policies.read().unwrap().len()
    }

    fn sync_policies(
        &self,
        new_policies: Vec<(PolicyKey, PolicyValue)>,
    ) -> anyhow::Result<(u32, u32, u32)> {
        let mut map = self.policies.write().unwrap();
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
        debug!(node_ip = key.node_ip, vni = value.vni, "mock: upsert tunnel");
        self.tunnels.write().unwrap().insert(key.node_ip, value);
        Ok(())
    }

    fn delete_tunnel(&self, key: &TunnelKey) -> anyhow::Result<()> {
        debug!(node_ip = key.node_ip, "mock: delete tunnel");
        self.tunnels.write().unwrap().remove(&key.node_ip);
        Ok(())
    }

    fn tunnel_count(&self) -> usize {
        self.tunnels.read().unwrap().len()
    }

    fn update_config(&self, entries: StdHashMap<u32, u64>) -> anyhow::Result<()> {
        let mut config = self.config.write().unwrap();
        for (k, v) in entries {
            debug!(key = k, value = v, "mock: update config");
            config.insert(k, v);
        }
        Ok(())
    }

    fn get_config(&self, key: u32) -> anyhow::Result<Option<u64>> {
        Ok(self.config.read().unwrap().get(&key).copied())
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
        self.egress.write().unwrap().insert(flat, value);
        Ok(())
    }

    fn delete_egress_policy(&self, key: &EgressKey) -> anyhow::Result<()> {
        debug!(
            src_identity = key.src_identity,
            dst_ip = key.dst_ip,
            "mock: delete egress policy"
        );
        let flat: EgressKeyFlat = key.into();
        self.egress.write().unwrap().remove(&flat);
        Ok(())
    }

    fn attached_programs(&self) -> Vec<AttachedProgramInfo> {
        self.attached.read().unwrap().clone()
    }

    fn attach_program(
        &self,
        interface: &str,
        attach_type: AttachDirection,
    ) -> anyhow::Result<()> {
        let type_str = match attach_type {
            AttachDirection::Ingress => "ingress",
            AttachDirection::Egress => "egress",
        };
        let mut attached = self.attached.write().unwrap();
        let mut prog_id = self.next_prog_id.write().unwrap();

        // Check if already attached.
        if attached
            .iter()
            .any(|p| p.interface == interface && p.attach_type == type_str)
        {
            warn!(interface, attach_type = type_str, "mock: program already attached");
            return Ok(());
        }

        let id = *prog_id;
        *prog_id += 1;
        attached.push(AttachedProgramInfo {
            interface: interface.to_string(),
            attach_type: type_str.to_string(),
            program_id: id,
        });
        info!(interface, attach_type = type_str, program_id = id, "mock: attached program");
        Ok(())
    }

    fn detach_program(
        &self,
        interface: &str,
        attach_type: AttachDirection,
    ) -> anyhow::Result<()> {
        let type_str = match attach_type {
            AttachDirection::Ingress => "ingress",
            AttachDirection::Egress => "egress",
        };
        let mut attached = self.attached.write().unwrap();
        let before = attached.len();
        attached.retain(|p| !(p.interface == interface && p.attach_type == type_str));
        let after = attached.len();
        if before == after {
            warn!(interface, attach_type = type_str, "mock: program not found for detach");
        } else {
            info!(interface, attach_type = type_str, "mock: detached program");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Real eBPF map implementation (Linux only)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub struct RealMaps {
    endpoints: RwLock<aya::maps::HashMap<aya::maps::MapData, EndpointKey, EndpointValue>>,
    policies: RwLock<aya::maps::HashMap<aya::maps::MapData, PolicyKey, PolicyValue>>,
    tunnels: RwLock<aya::maps::HashMap<aya::maps::MapData, TunnelKey, TunnelValue>>,
    config: RwLock<aya::maps::HashMap<aya::maps::MapData, u32, u64>>,
    egress: RwLock<aya::maps::HashMap<aya::maps::MapData, EgressKey, EgressValue>>,
    attached: RwLock<Vec<AttachedProgramInfo>>,
    /// Holds references to the loaded eBPF object so programs stay loaded.
    _ebpf: std::sync::Mutex<aya::Ebpf>,
}

#[cfg(target_os = "linux")]
impl RealMaps {
    fn upsert_endpoint(&self, key: EndpointKey, value: EndpointValue) -> anyhow::Result<()> {
        debug!(ip = key.ip, identity = value.identity, "upsert endpoint");
        let mut map = self.endpoints.write().unwrap();
        map.insert(key, value, 0)?;
        Ok(())
    }

    fn delete_endpoint(&self, key: &EndpointKey) -> anyhow::Result<()> {
        debug!(ip = key.ip, "delete endpoint");
        let mut map = self.endpoints.write().unwrap();
        map.remove(key)?;
        Ok(())
    }

    fn endpoint_count(&self) -> usize {
        let map = self.endpoints.read().unwrap();
        map.iter().count()
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
        let mut map = self.policies.write().unwrap();
        map.insert(key, value, 0)?;
        Ok(())
    }

    fn delete_policy(&self, key: &PolicyKey) -> anyhow::Result<()> {
        let mut map = self.policies.write().unwrap();
        map.remove(key)?;
        Ok(())
    }

    fn get_policy(&self, key: &PolicyKey) -> anyhow::Result<Option<PolicyValue>> {
        let map = self.policies.read().unwrap();
        match map.get(key, 0) {
            Ok(val) => Ok(Some(val)),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn policy_count(&self) -> usize {
        let map = self.policies.read().unwrap();
        map.iter().count()
    }

    fn sync_policies(
        &self,
        new_policies: Vec<(PolicyKey, PolicyValue)>,
    ) -> anyhow::Result<(u32, u32, u32)> {
        let mut map = self.policies.write().unwrap();

        // Collect existing keys.
        let existing: StdHashMap<Vec<u8>, PolicyValue> = map
            .iter()
            .filter_map(|res| res.ok())
            .map(|(k, v)| {
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
        let mut map = self.tunnels.write().unwrap();
        map.insert(key, value, 0)?;
        Ok(())
    }

    fn delete_tunnel(&self, key: &TunnelKey) -> anyhow::Result<()> {
        let mut map = self.tunnels.write().unwrap();
        map.remove(key)?;
        Ok(())
    }

    fn tunnel_count(&self) -> usize {
        let map = self.tunnels.read().unwrap();
        map.iter().count()
    }

    fn update_config(&self, entries: StdHashMap<u32, u64>) -> anyhow::Result<()> {
        let mut map = self.config.write().unwrap();
        for (k, v) in entries {
            debug!(key = k, value = v, "update config");
            map.insert(k, v, 0)?;
        }
        Ok(())
    }

    fn get_config(&self, key: u32) -> anyhow::Result<Option<u64>> {
        let map = self.config.read().unwrap();
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
        let mut map = self.egress.write().unwrap();
        map.insert(key, value, 0)?;
        Ok(())
    }

    fn delete_egress_policy(&self, key: &EgressKey) -> anyhow::Result<()> {
        let mut map = self.egress.write().unwrap();
        map.remove(key)?;
        Ok(())
    }

    fn attached_programs(&self) -> Vec<AttachedProgramInfo> {
        self.attached.read().unwrap().clone()
    }

    fn attach_program(
        &self,
        interface: &str,
        attach_type: AttachDirection,
    ) -> anyhow::Result<()> {
        use aya::programs::{tc, SchedClassifier, TcAttachType};

        let type_str = match attach_type {
            AttachDirection::Ingress => "ingress",
            AttachDirection::Egress => "egress",
        };

        let tc_attach_type = match attach_type {
            AttachDirection::Ingress => TcAttachType::Ingress,
            AttachDirection::Egress => TcAttachType::Egress,
        };

        // Determine which program to attach based on interface name and direction.
        let prog_name = if interface.starts_with("geneve") || interface.starts_with("vxlan") {
            match attach_type {
                AttachDirection::Ingress => "tc_tunnel_ingress",
                AttachDirection::Egress => "tc_tunnel_egress",
            }
        } else {
            match attach_type {
                AttachDirection::Ingress => "tc_ingress",
                AttachDirection::Egress => "tc_egress",
            }
        };

        let mut ebpf = self._ebpf.lock().unwrap();
        let prog: &mut SchedClassifier = ebpf
            .program_mut(prog_name)
            .ok_or_else(|| anyhow::anyhow!("eBPF program '{}' not found", prog_name))?
            .try_into()?;

        // Add clsact qdisc if not already present.
        let _ = tc::qdisc_add_clsact(interface);

        let _link_id = prog.attach(interface, tc_attach_type)?;
        let prog_id = prog.info()?.id();

        let mut attached = self.attached.write().unwrap();
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

    fn detach_program(
        &self,
        interface: &str,
        attach_type: AttachDirection,
    ) -> anyhow::Result<()> {
        let type_str = match attach_type {
            AttachDirection::Ingress => "ingress",
            AttachDirection::Egress => "egress",
        };

        let mut attached = self.attached.write().unwrap();
        let before = attached.len();
        attached.retain(|p| !(p.interface == interface && p.attach_type == type_str));
        let after = attached.len();

        if before == after {
            warn!(interface, attach_type = type_str, "program not found for detach");
        } else {
            info!(interface, attach_type = type_str, "detached program");
        }

        // Note: In a full implementation, we would also need to detach the TC
        // program via netlink. For now, removing from our tracking list is
        // sufficient since the program detaches when the link is dropped.
        Ok(())
    }
}
