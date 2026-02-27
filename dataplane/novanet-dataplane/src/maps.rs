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

    /// Look up a single policy entry. Currently used by tests only.
    #[cfg(test)]
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
        self.endpoints.write().expect("endpoints lock poisoned").insert(key.ip, value);
        Ok(())
    }

    fn delete_endpoint(&self, key: &EndpointKey) -> anyhow::Result<()> {
        debug!(ip = key.ip, "mock: delete endpoint");
        self.endpoints.write().expect("endpoints lock poisoned").remove(&key.ip);
        Ok(())
    }

    fn endpoint_count(&self) -> usize {
        self.endpoints.read().expect("endpoints lock poisoned").len()
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
        self.policies.write().expect("policies lock poisoned").insert(flat, value);
        Ok(())
    }

    fn delete_policy(&self, key: &PolicyKey) -> anyhow::Result<()> {
        debug!(
            src = key.src_identity,
            dst = key.dst_identity,
            "mock: delete policy"
        );
        let flat: PolicyKeyFlat = key.into();
        self.policies.write().expect("policies lock poisoned").remove(&flat);
        Ok(())
    }

    #[cfg(test)]
    fn get_policy(&self, key: &PolicyKey) -> anyhow::Result<Option<PolicyValue>> {
        let flat: PolicyKeyFlat = key.into();
        Ok(self.policies.read().expect("policies lock poisoned").get(&flat).copied())
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
        debug!(node_ip = key.node_ip, vni = value.vni, "mock: upsert tunnel");
        self.tunnels.write().expect("tunnels lock poisoned").insert(key.node_ip, value);
        Ok(())
    }

    fn delete_tunnel(&self, key: &TunnelKey) -> anyhow::Result<()> {
        debug!(node_ip = key.node_ip, "mock: delete tunnel");
        self.tunnels.write().expect("tunnels lock poisoned").remove(&key.node_ip);
        Ok(())
    }

    fn tunnel_count(&self) -> usize {
        self.tunnels.read().expect("tunnels lock poisoned").len()
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
        Ok(self.config.read().expect("config lock poisoned").get(&key).copied())
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
        self.egress.write().expect("egress lock poisoned").insert(flat, value);
        Ok(())
    }

    fn delete_egress_policy(&self, key: &EgressKey) -> anyhow::Result<()> {
        debug!(
            src_identity = key.src_identity,
            dst_ip = key.dst_ip,
            "mock: delete egress policy"
        );
        let flat: EgressKeyFlat = key.into();
        self.egress.write().expect("egress lock poisoned").remove(&flat);
        Ok(())
    }

    fn attached_programs(&self) -> Vec<AttachedProgramInfo> {
        self.attached.read().expect("attached lock poisoned").clone()
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
        let mut attached = self.attached.write().expect("attached lock poisoned");
        let mut prog_id = self.next_prog_id.write().expect("next_prog_id lock poisoned");

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
        let mut attached = self.attached.write().expect("attached lock poisoned");
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
        mgr.upsert_policy(key, PolicyValue { action: ACTION_ALLOW, _pad: [0; 3] })
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
                PolicyKey { src_identity: 1, dst_identity: 2, protocol: 6, _pad: [0], dst_port: 80 },
                PolicyValue { action: ACTION_ALLOW, _pad: [0; 3] },
            ),
            (
                PolicyKey { src_identity: 1, dst_identity: 3, protocol: 6, _pad: [0], dst_port: 443 },
                PolicyValue { action: ACTION_ALLOW, _pad: [0; 3] },
            ),
            (
                PolicyKey { src_identity: 2, dst_identity: 3, protocol: 17, _pad: [0], dst_port: 53 },
                PolicyValue { action: ACTION_DENY, _pad: [0; 3] },
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
                PolicyKey { src_identity: 1, dst_identity: 2, protocol: 6, _pad: [0], dst_port: 80 },
                PolicyValue { action: ACTION_ALLOW, _pad: [0; 3] },
            ),
            (
                PolicyKey { src_identity: 1, dst_identity: 3, protocol: 6, _pad: [0], dst_port: 443 },
                PolicyValue { action: ACTION_DENY, _pad: [0; 3] },
            ),
            (
                PolicyKey { src_identity: 5, dst_identity: 6, protocol: 6, _pad: [0], dst_port: 8080 },
                PolicyValue { action: ACTION_ALLOW, _pad: [0; 3] },
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
            TunnelKey { node_ip: 0xC0A86416 },
            TunnelValue { ifindex: 5, remote_ip: 0xC0A86416, vni: 1 },
        )
        .unwrap();
        assert_eq!(mgr.tunnel_count(), 1);
    }

    #[test]
    fn tunnel_delete() {
        let mgr = mock_manager();
        let key = TunnelKey { node_ip: 0xC0A86416 };
        mgr.upsert_tunnel(key, TunnelValue { ifindex: 5, remote_ip: key.node_ip, vni: 1 })
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
        assert_eq!(mgr.get_config(CONFIG_KEY_NODE_IP).unwrap(), Some(0xC0A86411));
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
            EgressValue { action: EGRESS_SNAT, _pad: [0; 3], snat_ip: 0xC0A86401 },
        )
        .unwrap();
        mgr.delete_egress_policy(&key).unwrap();
    }

    // -- Program attach/detach tests --

    #[test]
    fn attach_and_list_programs() {
        let mgr = mock_manager();
        assert_eq!(mgr.attached_programs().len(), 0);

        mgr.attach_program("nv12345678901", AttachDirection::Ingress).unwrap();
        mgr.attach_program("nv12345678901", AttachDirection::Egress).unwrap();

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
        mgr.attach_program("eth0", AttachDirection::Ingress).unwrap();
        mgr.attach_program("eth0", AttachDirection::Ingress).unwrap();
        assert_eq!(mgr.attached_programs().len(), 1);
    }

    #[test]
    fn detach_program_removes_entry() {
        let mgr = mock_manager();
        mgr.attach_program("nv12345678901", AttachDirection::Ingress).unwrap();
        mgr.attach_program("nv12345678901", AttachDirection::Egress).unwrap();
        assert_eq!(mgr.attached_programs().len(), 2);

        mgr.detach_program("nv12345678901", AttachDirection::Ingress).unwrap();
        let progs = mgr.attached_programs();
        assert_eq!(progs.len(), 1);
        assert_eq!(progs[0].attach_type, "egress");
    }

    #[test]
    fn detach_nonexistent_is_ok() {
        let mgr = mock_manager();
        mgr.detach_program("nonexistent", AttachDirection::Ingress).unwrap();
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
            PolicyValue { action: ACTION_ALLOW, _pad: [0; 3] },
        )
        .unwrap();
        assert_eq!(mgr.policy_count(), 1);

        // Attach programs.
        mgr.attach_program("nv12345678901", AttachDirection::Ingress).unwrap();
        mgr.attach_program("nv12345678901", AttachDirection::Egress).unwrap();
        assert_eq!(mgr.attached_programs().len(), 2);

        // Clean up.
        mgr.delete_endpoint(&EndpointKey { ip: 0x0A2A0501 }).unwrap();
        assert_eq!(mgr.endpoint_count(), 1);
        mgr.detach_program("nv12345678901", AttachDirection::Ingress).unwrap();
        mgr.detach_program("nv12345678901", AttachDirection::Egress).unwrap();
        assert_eq!(mgr.attached_programs().len(), 0);
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
    drop_counters: RwLock<aya::maps::PerCpuArray<aya::maps::MapData, u64>>,
    attached: RwLock<Vec<AttachedProgramInfo>>,
    /// Holds TC program links so they stay attached (aya auto-detaches on drop).
    /// Tuples of (interface_name, attach_type, link) for targeted detach.
    _tc_links: std::sync::Mutex<Vec<(String, String, aya::programs::tc::SchedClassifierLink)>>,
    /// Holds references to the loaded eBPF object so programs stay loaded.
    _ebpf: std::sync::Mutex<aya::Ebpf>,
}

#[cfg(target_os = "linux")]
impl RealMaps {
    /// Create a new RealMaps from aya map handles and the loaded eBPF object.
    pub fn new(
        endpoints: aya::maps::HashMap<aya::maps::MapData, EndpointKey, EndpointValue>,
        policies: aya::maps::HashMap<aya::maps::MapData, PolicyKey, PolicyValue>,
        tunnels: aya::maps::HashMap<aya::maps::MapData, TunnelKey, TunnelValue>,
        config: aya::maps::HashMap<aya::maps::MapData, u32, u64>,
        egress: aya::maps::HashMap<aya::maps::MapData, EgressKey, EgressValue>,
        drop_counters: aya::maps::PerCpuArray<aya::maps::MapData, u64>,
        ebpf: aya::Ebpf,
    ) -> Self {
        Self {
            endpoints: RwLock::new(endpoints),
            policies: RwLock::new(policies),
            tunnels: RwLock::new(tunnels),
            config: RwLock::new(config),
            egress: RwLock::new(egress),
            drop_counters: RwLock::new(drop_counters),
            attached: RwLock::new(Vec::new()),
            _tc_links: std::sync::Mutex::new(Vec::new()),
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

    fn get_policy(&self, key: &PolicyKey) -> anyhow::Result<Option<PolicyValue>> {
        let map = self.policies.read().expect("policies lock poisoned");
        match map.get(key, 0) {
            Ok(val) => Ok(Some(val)),
            Err(aya::maps::MapError::KeyNotFound) => Ok(None),
            Err(e) => Err(e.into()),
        }
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

    fn get_drop_counters(&self) -> StdHashMap<u32, u64> {
        let map = self.drop_counters.read().expect("drop_counters lock poisoned");
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
        self.attached.read().expect("attached lock poisoned").clone()
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

        // Determine which eBPF program to attach based on interface and TC hook direction.
        //
        // For tunnel interfaces, TC hook direction matches program name directly.
        //
        // For pod veths, program names use K8s perspective (ingress = to pod,
        // egress = from pod), but TC hooks use interface perspective (ingress =
        // arriving at host veth from pod, egress = leaving host veth toward pod).
        // So we swap: TC ingress hook → tc_egress program (handles pod egress),
        //             TC egress hook → tc_ingress program (handles pod ingress).
        let prog_name = if interface.starts_with("geneve") || interface.starts_with("vxlan") {
            match attach_type {
                AttachDirection::Ingress => "tc_tunnel_ingress",
                AttachDirection::Egress => "tc_tunnel_egress",
            }
        } else {
            match attach_type {
                AttachDirection::Ingress => "tc_egress",  // TC ingress = from pod = K8s egress
                AttachDirection::Egress => "tc_ingress",  // TC egress = to pod = K8s ingress
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
        self._tc_links.lock().expect("tc_links lock poisoned").push((interface.to_string(), type_str.to_string(), link));

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

    fn detach_program(
        &self,
        interface: &str,
        attach_type: AttachDirection,
    ) -> anyhow::Result<()> {
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
            warn!(interface, attach_type = type_str, "program not found for detach");
        } else {
            info!(interface, attach_type = type_str, "detached program (link dropped)");
        }

        Ok(())
    }
}
