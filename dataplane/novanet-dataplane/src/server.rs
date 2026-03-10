//! gRPC server implementing the `DataplaneControl` service.
//!
//! This is the internal API between the Go management agent and the Rust
//! eBPF dataplane. The Go agent is the client; this daemon is the server.

use crate::flows;
use crate::maps::{AttachDirection, MapManager};
use crate::proto;
use novanet_common::*;
use std::collections::HashMap as StdHashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use tokio_stream::{wrappers::BroadcastStream, Stream, StreamExt};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

/// Tracks the eBPF map keys associated with a host firewall rule_id,
/// enabling deletion by rule_id alone.
struct HostRuleInfo {
    /// IPCache key for the CIDR associated with this rule.
    /// Tracked for potential future cleanup during sync operations.
    #[allow(dead_code)]
    ipcache_key: IPCacheKey,
    policy_keys: Vec<HostPolicyKey>,
}

/// The DataplaneControl gRPC service implementation.
pub struct DataplaneService {
    maps: Arc<MapManager>,
    /// Maps rule_id -> key info needed for deletion.
    host_rules: RwLock<StdHashMap<String, HostRuleInfo>>,
}

impl DataplaneService {
    pub fn new(maps: MapManager) -> Self {
        Self {
            maps: Arc::new(maps),
            host_rules: RwLock::new(StdHashMap::new()),
        }
    }
}

/// Convert proto cidr_ip bytes (4 or 16) to IPCacheKey.
/// IPv4 (4 bytes) -> mapped to ::ffff:x.x.x.x with prefix += 96.
/// IPv6 (16 bytes) -> used directly.
#[allow(clippy::result_large_err)]
fn cidr_to_ipcache_key(cidr_ip: &[u8], prefix_len: u32) -> Result<IPCacheKey, Status> {
    let mut addr = [0u8; 16];
    let adjusted_prefix = match cidr_ip.len() {
        4 => {
            addr[10] = 0xff;
            addr[11] = 0xff;
            addr[12..16].copy_from_slice(cidr_ip);
            prefix_len + 96
        }
        16 => {
            addr.copy_from_slice(cidr_ip);
            prefix_len
        }
        _ => return Err(Status::invalid_argument("cidr_ip must be 4 or 16 bytes")),
    };
    Ok(IPCacheKey {
        prefix_len: adjusted_prefix,
        addr,
    })
}

/// Derive a deterministic security identity for a CIDR range using FNV-1a hash.
/// Returns identity >= 1000 (below 1000 is reserved).
fn identity_for_cidr(cidr_ip: &[u8], prefix_len: u32) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for byte in cidr_ip {
        h ^= *byte as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    for byte in &prefix_len.to_le_bytes() {
        h ^= *byte as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    1000 + (h % (u32::MAX - 1000))
}

/// Build a HostPolicyKey with appropriate prefix_len based on which fields are specified.
fn build_host_policy_key(identity: u32, direction: u8, protocol: u8, port: u16) -> HostPolicyKey {
    let prefix_len = if port > 0 {
        HOST_POLICY_FULL_PREFIX
    } else if protocol > 0 {
        HOST_POLICY_PROTO_PREFIX
    } else {
        HOST_POLICY_IDENTITY_PREFIX
    };
    HostPolicyKey {
        prefix_len,
        identity,
        direction,
        protocol,
        dst_port: port,
    }
}

/// Parse an IP string from proto and return the parsed IpAddr.
#[allow(clippy::result_large_err)]
fn parse_ip(s: &str) -> Result<IpAddr, Status> {
    s.parse::<IpAddr>()
        .map_err(|e| Status::invalid_argument(format!("invalid IP '{}': {}", s, e)))
}

/// Convert BackendHealthCounters to the proto response message.
fn health_counters_to_proto(
    ip: &str,
    port: u32,
    counters: &BackendHealthCounters,
) -> proto::InternalBackendHealthInfo {
    let avg_rtt_ns = counters
        .total_rtt_ns
        .checked_div(counters.success_conns)
        .unwrap_or(0);
    let failure_rate = if counters.total_conns > 0 {
        counters.failed_conns as f64 / counters.total_conns as f64
    } else {
        0.0
    };
    proto::InternalBackendHealthInfo {
        ip: ip.to_string(),
        port,
        total_conns: counters.total_conns,
        failed_conns: counters.failed_conns,
        timeout_conns: counters.timeout_conns,
        success_conns: counters.success_conns,
        avg_rtt_ns,
        failure_rate,
    }
}

#[tonic::async_trait]
impl proto::dataplane_control_server::DataplaneControl for DataplaneService {
    // -----------------------------------------------------------------------
    // Endpoint management
    // -----------------------------------------------------------------------

    async fn upsert_endpoint(
        &self,
        request: Request<proto::UpsertEndpointRequest>,
    ) -> Result<Response<proto::UpsertEndpointResponse>, Status> {
        let req = request.into_inner();

        // Parse MAC address from bytes (must be exactly 6 bytes).
        let mac: [u8; 6] = req
            .mac
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("MAC address must be exactly 6 bytes"))?;

        let ip = parse_ip(&req.ip)?;
        let node_ip = parse_ip(&req.node_ip)?;

        match (ip, node_ip) {
            (IpAddr::V4(v4), IpAddr::V4(node_v4)) => {
                let key = EndpointKey { ip: u32::from(v4) };
                let value = EndpointValue {
                    ifindex: req.ifindex,
                    mac,
                    _pad: [0; 2],
                    identity: req.identity_id,
                    node_ip: u32::from(node_v4),
                };
                self.maps
                    .upsert_endpoint(key, value)
                    .map_err(|e| Status::internal(format!("Failed to upsert endpoint: {}", e)))?;
            }
            (IpAddr::V6(v6), IpAddr::V6(node_v6)) => {
                let key = EndpointKeyV6 { ip: v6.octets() };
                let value = EndpointValueV6 {
                    ifindex: req.ifindex,
                    mac,
                    _pad: [0; 2],
                    identity: req.identity_id,
                    node_ip: node_v6.octets(),
                };
                self.maps.upsert_endpoint_v6(key, value).map_err(|e| {
                    Status::internal(format!("Failed to upsert endpoint v6: {}", e))
                })?;
            }
            _ => {
                return Err(Status::invalid_argument(
                    "ip and node_ip must be the same address family",
                ));
            }
        }

        debug!(
            ip = %req.ip,
            ifindex = req.ifindex,
            identity = req.identity_id,
            pod = %req.pod_name,
            ns = %req.namespace,
            "Upserted endpoint"
        );

        Ok(Response::new(proto::UpsertEndpointResponse {}))
    }

    async fn delete_endpoint(
        &self,
        request: Request<proto::DeleteEndpointRequest>,
    ) -> Result<Response<proto::DeleteEndpointResponse>, Status> {
        let req = request.into_inner();
        let ip = parse_ip(&req.ip)?;

        match ip {
            IpAddr::V4(v4) => {
                let key = EndpointKey { ip: u32::from(v4) };
                self.maps
                    .delete_endpoint(&key)
                    .map_err(|e| Status::internal(format!("Failed to delete endpoint: {}", e)))?;
            }
            IpAddr::V6(v6) => {
                let key = EndpointKeyV6 { ip: v6.octets() };
                self.maps.delete_endpoint_v6(&key).map_err(|e| {
                    Status::internal(format!("Failed to delete endpoint v6: {}", e))
                })?;
            }
        }

        debug!(ip = %req.ip, "Deleted endpoint");

        Ok(Response::new(proto::DeleteEndpointResponse {}))
    }

    // -----------------------------------------------------------------------
    // Policy management
    // -----------------------------------------------------------------------

    async fn upsert_policy(
        &self,
        request: Request<proto::UpsertPolicyRequest>,
    ) -> Result<Response<proto::UpsertPolicyResponse>, Status> {
        let req = request.into_inner();

        let key = PolicyKey {
            src_identity: req.src_identity,
            dst_identity: req.dst_identity,
            protocol: req.protocol as u8,
            _pad: [0],
            dst_port: req.dst_port as u16,
        };

        let action = match proto::PolicyAction::try_from(req.action) {
            Ok(proto::PolicyAction::Allow) => ACTION_ALLOW,
            Ok(proto::PolicyAction::Deny) => ACTION_DENY,
            _ => ACTION_DENY,
        };

        let value = PolicyValue {
            action,
            _pad: [0; 3],
        };

        self.maps
            .upsert_policy(key, value)
            .map_err(|e| Status::internal(format!("Failed to upsert policy: {}", e)))?;

        debug!(
            src = req.src_identity,
            dst = req.dst_identity,
            proto = req.protocol,
            port = req.dst_port,
            action = action,
            "Upserted policy"
        );

        Ok(Response::new(proto::UpsertPolicyResponse {}))
    }

    async fn delete_policy(
        &self,
        request: Request<proto::DeletePolicyRequest>,
    ) -> Result<Response<proto::DeletePolicyResponse>, Status> {
        let req = request.into_inner();

        let key = PolicyKey {
            src_identity: req.src_identity,
            dst_identity: req.dst_identity,
            protocol: req.protocol as u8,
            _pad: [0],
            dst_port: req.dst_port as u16,
        };

        self.maps
            .delete_policy(&key)
            .map_err(|e| Status::internal(format!("Failed to delete policy: {}", e)))?;

        debug!(
            src = req.src_identity,
            dst = req.dst_identity,
            "Deleted policy"
        );

        Ok(Response::new(proto::DeletePolicyResponse {}))
    }

    async fn sync_policies(
        &self,
        request: Request<proto::SyncPoliciesRequest>,
    ) -> Result<Response<proto::SyncPoliciesResponse>, Status> {
        let req = request.into_inner();

        let policies: Vec<(PolicyKey, PolicyValue)> = req
            .policies
            .iter()
            .map(|entry| {
                let key = PolicyKey {
                    src_identity: entry.src_identity,
                    dst_identity: entry.dst_identity,
                    protocol: entry.protocol as u8,
                    _pad: [0],
                    dst_port: entry.dst_port as u16,
                };
                let action = match proto::PolicyAction::try_from(entry.action) {
                    Ok(proto::PolicyAction::Allow) => ACTION_ALLOW,
                    _ => ACTION_DENY,
                };
                let value = PolicyValue {
                    action,
                    _pad: [0; 3],
                };
                (key, value)
            })
            .collect();

        let (added, removed, updated) = self
            .maps
            .sync_policies(policies)
            .map_err(|e| Status::internal(format!("Failed to sync policies: {}", e)))?;

        info!(added, removed, updated, "Synced policies");

        Ok(Response::new(proto::SyncPoliciesResponse {
            added,
            removed,
            updated,
        }))
    }

    // -----------------------------------------------------------------------
    // Egress policy management
    // -----------------------------------------------------------------------

    async fn upsert_egress_policy(
        &self,
        request: Request<proto::UpsertEgressPolicyRequest>,
    ) -> Result<Response<proto::UpsertEgressPolicyResponse>, Status> {
        let req = request.into_inner();

        let action = match proto::EgressAction::try_from(req.action) {
            Ok(proto::EgressAction::Allow) => EGRESS_ALLOW,
            Ok(proto::EgressAction::Snat) => EGRESS_SNAT,
            Ok(proto::EgressAction::Deny) => EGRESS_DENY,
            _ => EGRESS_DENY,
        };

        // Parse dst_cidr (may be bare IP or CIDR notation; strip prefix if present).
        let cidr_str = req.dst_cidr.split('/').next().unwrap_or(&req.dst_cidr);
        let dst_ip = parse_ip(cidr_str)?;
        let snat_ip = parse_ip(&req.snat_ip)?;

        match (dst_ip, snat_ip) {
            (IpAddr::V4(dst_v4), IpAddr::V4(snat_v4)) => {
                let key = EgressKey {
                    src_identity: req.src_identity,
                    dst_ip: u32::from(dst_v4),
                    dst_prefix_len: req.dst_cidr_prefix_len as u8,
                    _pad: [0; 3],
                };
                let value = EgressValue {
                    action,
                    _pad: [0; 3],
                    snat_ip: u32::from(snat_v4),
                };
                self.maps.upsert_egress_policy(key, value).map_err(|e| {
                    Status::internal(format!("Failed to upsert egress policy: {}", e))
                })?;
            }
            (IpAddr::V6(dst_v6), IpAddr::V6(snat_v6)) => {
                let key = EgressKeyV6 {
                    src_identity: req.src_identity,
                    dst_ip: dst_v6.octets(),
                    dst_prefix_len: req.dst_cidr_prefix_len as u8,
                    _pad: [0; 3],
                };
                let value = EgressValueV6 {
                    action,
                    _pad: [0; 3],
                    snat_ip: snat_v6.octets(),
                };
                self.maps.upsert_egress_policy_v6(key, value).map_err(|e| {
                    Status::internal(format!("Failed to upsert egress policy v6: {}", e))
                })?;
            }
            _ => {
                return Err(Status::invalid_argument(
                    "dst_cidr and snat_ip must be the same address family",
                ));
            }
        }

        debug!(
            src_identity = req.src_identity,
            dst_cidr = %req.dst_cidr,
            prefix_len = req.dst_cidr_prefix_len,
            action = action,
            "Upserted egress policy"
        );

        Ok(Response::new(proto::UpsertEgressPolicyResponse {}))
    }

    async fn delete_egress_policy(
        &self,
        request: Request<proto::DeleteEgressPolicyRequest>,
    ) -> Result<Response<proto::DeleteEgressPolicyResponse>, Status> {
        let req = request.into_inner();

        let cidr_str = req.dst_cidr.split('/').next().unwrap_or(&req.dst_cidr);
        let dst_ip = parse_ip(cidr_str)?;

        match dst_ip {
            IpAddr::V4(dst_v4) => {
                let key = EgressKey {
                    src_identity: req.src_identity,
                    dst_ip: u32::from(dst_v4),
                    dst_prefix_len: req.dst_cidr_prefix_len as u8,
                    _pad: [0; 3],
                };
                self.maps.delete_egress_policy(&key).map_err(|e| {
                    Status::internal(format!("Failed to delete egress policy: {}", e))
                })?;
            }
            IpAddr::V6(dst_v6) => {
                let key = EgressKeyV6 {
                    src_identity: req.src_identity,
                    dst_ip: dst_v6.octets(),
                    dst_prefix_len: req.dst_cidr_prefix_len as u8,
                    _pad: [0; 3],
                };
                self.maps.delete_egress_policy_v6(&key).map_err(|e| {
                    Status::internal(format!("Failed to delete egress policy v6: {}", e))
                })?;
            }
        }

        debug!(
            src_identity = req.src_identity,
            dst_cidr = %req.dst_cidr,
            "Deleted egress policy"
        );

        Ok(Response::new(proto::DeleteEgressPolicyResponse {}))
    }

    // -----------------------------------------------------------------------
    // L4 Load Balancer
    // -----------------------------------------------------------------------

    async fn upsert_service(
        &self,
        request: Request<proto::UpsertServiceRequest>,
    ) -> Result<Response<proto::UpsertServiceResponse>, Status> {
        let req = request.into_inner();

        let ip = parse_ip(&req.ip)?;

        match ip {
            IpAddr::V4(v4) => {
                let key = ServiceKey {
                    ip: u32::from(v4),
                    port: req.port as u16,
                    protocol: req.protocol as u8,
                    scope: req.scope as u8,
                };
                let value = ServiceValue {
                    backend_count: req.backend_count as u16,
                    backend_offset: req.backend_offset as u16,
                    algorithm: req.algorithm as u8,
                    flags: req.flags as u8,
                    affinity_timeout: req.affinity_timeout as u16,
                    maglev_offset: req.maglev_offset,
                };
                self.maps
                    .upsert_service(key, value)
                    .map_err(|e| Status::internal(format!("Failed to upsert service: {}", e)))?;
            }
            IpAddr::V6(v6) => {
                let key = ServiceKeyV6 {
                    ip: v6.octets(),
                    port: req.port as u16,
                    protocol: req.protocol as u8,
                    scope: req.scope as u8,
                };
                let value = ServiceValue {
                    backend_count: req.backend_count as u16,
                    backend_offset: req.backend_offset as u16,
                    algorithm: req.algorithm as u8,
                    flags: req.flags as u8,
                    affinity_timeout: req.affinity_timeout as u16,
                    maglev_offset: req.maglev_offset,
                };
                self.maps
                    .upsert_service_v6(key, value)
                    .map_err(|e| Status::internal(format!("Failed to upsert service v6: {}", e)))?;
            }
        }

        debug!(
            ip = %req.ip,
            port = req.port,
            protocol = req.protocol,
            scope = req.scope,
            backends = req.backend_count,
            "Upserted service"
        );

        Ok(Response::new(proto::UpsertServiceResponse {}))
    }

    async fn delete_service(
        &self,
        request: Request<proto::DeleteServiceRequest>,
    ) -> Result<Response<proto::DeleteServiceResponse>, Status> {
        let req = request.into_inner();

        let ip = parse_ip(&req.ip)?;

        match ip {
            IpAddr::V4(v4) => {
                let key = ServiceKey {
                    ip: u32::from(v4),
                    port: req.port as u16,
                    protocol: req.protocol as u8,
                    scope: req.scope as u8,
                };
                self.maps
                    .delete_service(&key)
                    .map_err(|e| Status::internal(format!("Failed to delete service: {}", e)))?;
            }
            IpAddr::V6(v6) => {
                let key = ServiceKeyV6 {
                    ip: v6.octets(),
                    port: req.port as u16,
                    protocol: req.protocol as u8,
                    scope: req.scope as u8,
                };
                self.maps
                    .delete_service_v6(&key)
                    .map_err(|e| Status::internal(format!("Failed to delete service v6: {}", e)))?;
            }
        }

        debug!(ip = %req.ip, port = req.port, "Deleted service");

        Ok(Response::new(proto::DeleteServiceResponse {}))
    }

    async fn upsert_backends(
        &self,
        request: Request<proto::UpsertBackendsRequest>,
    ) -> Result<Response<proto::UpsertBackendsResponse>, Status> {
        let req = request.into_inner();

        for entry in &req.backends {
            let ip = parse_ip(&entry.ip)?;
            let node_ip = parse_ip(&entry.node_ip)?;

            match (ip, node_ip) {
                (IpAddr::V4(v4), IpAddr::V4(node_v4)) => {
                    let value = BackendValue {
                        ip: u32::from(v4),
                        port: entry.port as u16,
                        _pad: [0; 2],
                        node_ip: u32::from(node_v4),
                    };
                    self.maps.upsert_backend(entry.index, value).map_err(|e| {
                        Status::internal(format!(
                            "Failed to upsert backend at index {}: {}",
                            entry.index, e
                        ))
                    })?;
                }
                (IpAddr::V6(v6), IpAddr::V6(node_v6)) => {
                    let value = BackendValueV6 {
                        ip: v6.octets(),
                        port: entry.port as u16,
                        _pad: [0; 2],
                        node_ip: node_v6.octets(),
                    };
                    self.maps
                        .upsert_backend_v6(entry.index, value)
                        .map_err(|e| {
                            Status::internal(format!(
                                "Failed to upsert backend v6 at index {}: {}",
                                entry.index, e
                            ))
                        })?;
                }
                _ => {
                    return Err(Status::invalid_argument(format!(
                        "backend at index {}: ip and node_ip must be the same address family",
                        entry.index
                    )));
                }
            }
        }

        debug!(count = req.backends.len(), "Upserted backends");

        Ok(Response::new(proto::UpsertBackendsResponse {}))
    }

    async fn sync_services(
        &self,
        request: Request<proto::SyncServicesRequest>,
    ) -> Result<Response<proto::SyncServicesResponse>, Status> {
        let req = request.into_inner();

        // Clear existing services and backends.
        self.maps.clear_services();
        self.maps.clear_backends();

        // Insert all services.
        for entry in &req.services {
            let ip = parse_ip(&entry.ip)?;

            match ip {
                IpAddr::V4(v4) => {
                    let key = ServiceKey {
                        ip: u32::from(v4),
                        port: entry.port as u16,
                        protocol: entry.protocol as u8,
                        scope: entry.scope as u8,
                    };
                    let value = ServiceValue {
                        backend_count: entry.backend_count as u16,
                        backend_offset: entry.backend_offset as u16,
                        algorithm: entry.algorithm as u8,
                        flags: entry.flags as u8,
                        affinity_timeout: entry.affinity_timeout as u16,
                        maglev_offset: entry.maglev_offset,
                    };
                    self.maps.upsert_service(key, value).map_err(|e| {
                        Status::internal(format!("Failed to upsert service: {}", e))
                    })?;
                }
                IpAddr::V6(v6) => {
                    let key = ServiceKeyV6 {
                        ip: v6.octets(),
                        port: entry.port as u16,
                        protocol: entry.protocol as u8,
                        scope: entry.scope as u8,
                    };
                    let value = ServiceValue {
                        backend_count: entry.backend_count as u16,
                        backend_offset: entry.backend_offset as u16,
                        algorithm: entry.algorithm as u8,
                        flags: entry.flags as u8,
                        affinity_timeout: entry.affinity_timeout as u16,
                        maglev_offset: entry.maglev_offset,
                    };
                    self.maps.upsert_service_v6(key, value).map_err(|e| {
                        Status::internal(format!("Failed to upsert service v6: {}", e))
                    })?;
                }
            }
        }

        // Insert all backends.
        for entry in &req.backends {
            let ip = parse_ip(&entry.ip)?;
            let node_ip = parse_ip(&entry.node_ip)?;

            match (ip, node_ip) {
                (IpAddr::V4(v4), IpAddr::V4(node_v4)) => {
                    let value = BackendValue {
                        ip: u32::from(v4),
                        port: entry.port as u16,
                        _pad: [0; 2],
                        node_ip: u32::from(node_v4),
                    };
                    self.maps.upsert_backend(entry.index, value).map_err(|e| {
                        Status::internal(format!(
                            "Failed to upsert backend at index {}: {}",
                            entry.index, e
                        ))
                    })?;
                }
                (IpAddr::V6(v6), IpAddr::V6(node_v6)) => {
                    let value = BackendValueV6 {
                        ip: v6.octets(),
                        port: entry.port as u16,
                        _pad: [0; 2],
                        node_ip: node_v6.octets(),
                    };
                    self.maps
                        .upsert_backend_v6(entry.index, value)
                        .map_err(|e| {
                            Status::internal(format!(
                                "Failed to upsert backend v6 at index {}: {}",
                                entry.index, e
                            ))
                        })?;
                }
                _ => {
                    return Err(Status::invalid_argument(format!(
                        "backend at index {}: ip and node_ip must be the same address family",
                        entry.index
                    )));
                }
            }
        }

        let services_synced = req.services.len() as u32;
        let backends_synced = req.backends.len() as u32;

        info!(
            services_synced,
            backends_synced, "Synced services and backends"
        );

        Ok(Response::new(proto::SyncServicesResponse {
            services_synced,
            backends_synced,
        }))
    }

    async fn upsert_maglev_table(
        &self,
        request: Request<proto::UpsertMaglevTableRequest>,
    ) -> Result<Response<proto::UpsertMaglevTableResponse>, Status> {
        let req = request.into_inner();

        for (i, &backend_index) in req.entries.iter().enumerate() {
            let map_index = req.offset + i as u32;
            self.maps
                .upsert_maglev_entry(map_index, backend_index)
                .map_err(|e| {
                    Status::internal(format!(
                        "Failed to upsert maglev entry at index {}: {}",
                        map_index, e
                    ))
                })?;
        }

        debug!(
            offset = req.offset,
            count = req.entries.len(),
            "Upserted maglev table entries"
        );

        Ok(Response::new(proto::UpsertMaglevTableResponse {}))
    }

    // -----------------------------------------------------------------------
    // Tunnel management
    // -----------------------------------------------------------------------

    async fn upsert_tunnel(
        &self,
        request: Request<proto::UpsertTunnelRequest>,
    ) -> Result<Response<proto::UpsertTunnelResponse>, Status> {
        let req = request.into_inner();

        let node_ip = parse_ip(&req.node_ip)?;

        match node_ip {
            IpAddr::V4(v4) => {
                let ip_u32 = u32::from(v4);
                let key = TunnelKey { node_ip: ip_u32 };
                let value = TunnelValue {
                    ifindex: req.tunnel_ifindex,
                    remote_ip: ip_u32,
                    vni: req.vni,
                };
                self.maps
                    .upsert_tunnel(key, value)
                    .map_err(|e| Status::internal(format!("Failed to upsert tunnel: {}", e)))?;
            }
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                let key = TunnelKeyV6 { node_ip: octets };
                let value = TunnelValueV6 {
                    ifindex: req.tunnel_ifindex,
                    remote_ip: octets,
                    vni: req.vni,
                };
                self.maps
                    .upsert_tunnel_v6(key, value)
                    .map_err(|e| Status::internal(format!("Failed to upsert tunnel v6: {}", e)))?;
            }
        }

        debug!(
            node_ip = %req.node_ip,
            ifindex = req.tunnel_ifindex,
            vni = req.vni,
            "Upserted tunnel"
        );

        Ok(Response::new(proto::UpsertTunnelResponse {}))
    }

    async fn delete_tunnel(
        &self,
        request: Request<proto::DeleteTunnelRequest>,
    ) -> Result<Response<proto::DeleteTunnelResponse>, Status> {
        let req = request.into_inner();

        let node_ip = parse_ip(&req.node_ip)?;

        match node_ip {
            IpAddr::V4(v4) => {
                let key = TunnelKey {
                    node_ip: u32::from(v4),
                };
                self.maps
                    .delete_tunnel(&key)
                    .map_err(|e| Status::internal(format!("Failed to delete tunnel: {}", e)))?;
            }
            IpAddr::V6(v6) => {
                let key = TunnelKeyV6 {
                    node_ip: v6.octets(),
                };
                self.maps
                    .delete_tunnel_v6(&key)
                    .map_err(|e| Status::internal(format!("Failed to delete tunnel v6: {}", e)))?;
            }
        }

        debug!(node_ip = %req.node_ip, "Deleted tunnel");

        Ok(Response::new(proto::DeleteTunnelResponse {}))
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------

    async fn update_config(
        &self,
        request: Request<proto::UpdateConfigRequest>,
    ) -> Result<Response<proto::UpdateConfigResponse>, Status> {
        let req = request.into_inner();

        self.maps
            .update_config(req.entries)
            .map_err(|e| Status::internal(format!("Failed to update config: {}", e)))?;

        debug!("Updated config");

        Ok(Response::new(proto::UpdateConfigResponse {}))
    }

    // -----------------------------------------------------------------------
    // TC program lifecycle
    // -----------------------------------------------------------------------

    async fn attach_program(
        &self,
        request: Request<proto::AttachProgramRequest>,
    ) -> Result<Response<proto::AttachProgramResponse>, Status> {
        let req = request.into_inner();

        let direction = match proto::AttachType::try_from(req.attach_type) {
            Ok(proto::AttachType::AttachTcIngress) => AttachDirection::Ingress,
            Ok(proto::AttachType::AttachTcEgress) => AttachDirection::Egress,
            Err(_) => return Err(Status::invalid_argument("Invalid attach type")),
        };

        self.maps
            .attach_program(&req.interface_name, direction)
            .map_err(|e| Status::internal(format!("Failed to attach program: {}", e)))?;

        info!(
            interface = %req.interface_name,
            direction = ?direction,
            "Attached TC program"
        );

        Ok(Response::new(proto::AttachProgramResponse {}))
    }

    async fn detach_program(
        &self,
        request: Request<proto::DetachProgramRequest>,
    ) -> Result<Response<proto::DetachProgramResponse>, Status> {
        let req = request.into_inner();

        let direction = match proto::AttachType::try_from(req.attach_type) {
            Ok(proto::AttachType::AttachTcIngress) => AttachDirection::Ingress,
            Ok(proto::AttachType::AttachTcEgress) => AttachDirection::Egress,
            Err(_) => return Err(Status::invalid_argument("Invalid attach type")),
        };

        self.maps
            .detach_program(&req.interface_name, direction)
            .map_err(|e| Status::internal(format!("Failed to detach program: {}", e)))?;

        info!(
            interface = %req.interface_name,
            direction = ?direction,
            "Detached TC program"
        );

        Ok(Response::new(proto::DetachProgramResponse {}))
    }

    // -----------------------------------------------------------------------
    // Observability
    // -----------------------------------------------------------------------

    type StreamFlowsStream =
        Pin<Box<dyn Stream<Item = Result<proto::FlowEvent, Status>> + Send + 'static>>;

    async fn stream_flows(
        &self,
        request: Request<proto::StreamFlowsRequest>,
    ) -> Result<Response<Self::StreamFlowsStream>, Status> {
        let req = request.into_inner();
        let identity_filter = req.identity_filter;

        info!(identity_filter, "New flow stream subscriber");

        let rx = flows::subscribe_flows();
        let stream = BroadcastStream::new(rx).filter_map(move |result| {
            match result {
                Ok(event) => {
                    // Apply identity filter: if non-zero, only emit events
                    // matching the source or destination identity.
                    if identity_filter != 0
                        && event.src_identity != identity_filter
                        && event.dst_identity != identity_filter
                    {
                        return None;
                    }
                    Some(Ok(event))
                }
                Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
                    warn!(skipped = n, "Flow stream subscriber lagged");
                    None
                }
            }
        });

        Ok(Response::new(Box::pin(stream)))
    }

    async fn get_dataplane_status(
        &self,
        _request: Request<proto::GetDataplaneStatusRequest>,
    ) -> Result<Response<proto::GetDataplaneStatusResponse>, Status> {
        let attached = self.maps.attached_programs();
        let programs: Vec<proto::AttachedProgram> = attached
            .iter()
            .map(|p| proto::AttachedProgram {
                interface_name: p.interface.clone(),
                attach_type: p.attach_type.clone(),
                program_id: p.program_id,
            })
            .collect();

        let resp = proto::GetDataplaneStatusResponse {
            endpoint_count: self.maps.endpoint_count() as u32,
            policy_count: self.maps.policy_count() as u32,
            tunnel_count: self.maps.tunnel_count() as u32,
            programs,
            mode: self.maps.mode_string(),
            tunnel_protocol: self.maps.tunnel_protocol_string(),
            drop_counters: self.maps.get_drop_counters(),
            service_count: self.maps.service_count() as u32,
            conntrack_count: 0, // Conntrack is managed by eBPF LRU map; count not yet exposed.
        };

        Ok(Response::new(resp))
    }

    // -----------------------------------------------------------------------
    // Host firewall policy management
    // -----------------------------------------------------------------------

    async fn upsert_host_policy(
        &self,
        request: Request<proto::UpsertHostPolicyRequest>,
    ) -> Result<Response<proto::UpsertHostPolicyResponse>, Status> {
        let req = request.into_inner();

        if req.cidr_ip.is_empty() {
            return Err(Status::invalid_argument("cidr_ip is required"));
        }

        let direction = match proto::HostPolicyDirection::try_from(req.direction) {
            Ok(proto::HostPolicyDirection::HostPolicyIngress) => HOST_POLICY_INGRESS,
            Ok(proto::HostPolicyDirection::HostPolicyEgress) => HOST_POLICY_EGRESS,
            Err(_) => return Err(Status::invalid_argument("Invalid host policy direction")),
        };

        let action = match proto::PolicyAction::try_from(req.action) {
            Ok(proto::PolicyAction::Allow) => ACTION_ALLOW,
            Ok(proto::PolicyAction::Deny) => ACTION_DENY,
            _ => ACTION_DENY,
        };

        let protocol = req.protocol as u8;
        let port = req.port as u16;
        let end_port = req.end_port as u16;

        // Derive identity for the CIDR.
        let identity = identity_for_cidr(&req.cidr_ip, req.cidr_prefix_len);

        // Insert CIDR -> identity into IPCache.
        let ipcache_key = cidr_to_ipcache_key(&req.cidr_ip, req.cidr_prefix_len)?;
        self.maps
            .upsert_ipcache(ipcache_key, IPCacheValue { identity, flags: 0 })
            .map_err(|e| Status::internal(format!("Failed to upsert ipcache: {}", e)))?;

        // Build and insert host policy entries.
        let value = HostPolicyValue {
            action,
            _pad: [0; 3],
        };

        let mut policy_keys = Vec::new();

        if end_port > port && end_port > 0 {
            // Port range: one entry per port.
            let range_size = (end_port - port + 1) as u32;
            if range_size > 1024 {
                return Err(Status::invalid_argument(
                    "Port range too large (max 1024 ports per rule to prevent map exhaustion)",
                ));
            }
            for p in port..=end_port {
                let key = build_host_policy_key(identity, direction, protocol, p);
                self.maps.upsert_host_policy(key, value).map_err(|e| {
                    Status::internal(format!("Failed to upsert host policy: {}", e))
                })?;
                policy_keys.push(key);
            }
        } else {
            let key = build_host_policy_key(identity, direction, protocol, port);
            self.maps
                .upsert_host_policy(key, value)
                .map_err(|e| Status::internal(format!("Failed to upsert host policy: {}", e)))?;
            policy_keys.push(key);
        }

        // Track rule_id -> key mapping for deletion.
        {
            let mut rules = self.host_rules.write().expect("host_rules lock poisoned");
            rules.insert(
                req.rule_id.clone(),
                HostRuleInfo {
                    ipcache_key,
                    policy_keys,
                },
            );
        }

        debug!(
            rule_id = %req.rule_id,
            identity = identity,
            direction = direction,
            protocol = protocol,
            port = port,
            action = action,
            "Upserted host policy"
        );

        Ok(Response::new(proto::UpsertHostPolicyResponse {}))
    }

    async fn delete_host_policy(
        &self,
        request: Request<proto::DeleteHostPolicyRequest>,
    ) -> Result<Response<proto::DeleteHostPolicyResponse>, Status> {
        let req = request.into_inner();

        let rule_info = {
            let mut rules = self.host_rules.write().expect("host_rules lock poisoned");
            rules.remove(&req.rule_id)
        };

        match rule_info {
            Some(info) => {
                // Delete all policy entries for this rule.
                for key in &info.policy_keys {
                    if let Err(e) = self.maps.delete_host_policy(key) {
                        warn!(
                            rule_id = %req.rule_id,
                            error = %e,
                            "Failed to delete host policy entry (may already be removed)"
                        );
                    }
                }

                // Note: We don't delete the IPCache entry because other rules
                // may reference the same CIDR. IPCache entries are cleaned up
                // during sync_host_policies.

                debug!(rule_id = %req.rule_id, "Deleted host policy");
            }
            None => {
                warn!(
                    rule_id = %req.rule_id,
                    "Host policy rule_id not found for deletion"
                );
            }
        }

        Ok(Response::new(proto::DeleteHostPolicyResponse {}))
    }

    async fn sync_host_policies(
        &self,
        request: Request<proto::SyncHostPoliciesRequest>,
    ) -> Result<Response<proto::SyncHostPoliciesResponse>, Status> {
        let req = request.into_inner();

        let mut all_policy_entries = Vec::new();
        let mut new_rules = StdHashMap::new();

        for entry in &req.policies {
            if entry.cidr_ip.is_empty() {
                continue;
            }

            let direction = match proto::HostPolicyDirection::try_from(entry.direction) {
                Ok(proto::HostPolicyDirection::HostPolicyIngress) => HOST_POLICY_INGRESS,
                Ok(proto::HostPolicyDirection::HostPolicyEgress) => HOST_POLICY_EGRESS,
                Err(_) => continue,
            };

            let action = match proto::PolicyAction::try_from(entry.action) {
                Ok(proto::PolicyAction::Allow) => ACTION_ALLOW,
                _ => ACTION_DENY,
            };

            let protocol = entry.protocol as u8;
            let port = entry.port as u16;
            let end_port = entry.end_port as u16;

            let identity = identity_for_cidr(&entry.cidr_ip, entry.cidr_prefix_len);

            // Insert CIDR -> identity into IPCache.
            let ipcache_key = match cidr_to_ipcache_key(&entry.cidr_ip, entry.cidr_prefix_len) {
                Ok(k) => k,
                Err(_) => continue,
            };
            self.maps
                .upsert_ipcache(ipcache_key, IPCacheValue { identity, flags: 0 })
                .map_err(|e| Status::internal(format!("Failed to upsert ipcache: {}", e)))?;

            let value = HostPolicyValue {
                action,
                _pad: [0; 3],
            };

            let mut policy_keys = Vec::new();

            if end_port > port && end_port > 0 {
                let range_size = (end_port - port + 1) as u32;
                if range_size > 1024 {
                    warn!(
                        rule_id = %entry.rule_id,
                        "Port range too large, skipping (max 1024)"
                    );
                    continue;
                }
                for p in port..=end_port {
                    let key = build_host_policy_key(identity, direction, protocol, p);
                    all_policy_entries.push((key, value));
                    policy_keys.push(key);
                }
            } else {
                let key = build_host_policy_key(identity, direction, protocol, port);
                all_policy_entries.push((key, value));
                policy_keys.push(key);
            }

            new_rules.insert(
                entry.rule_id.clone(),
                HostRuleInfo {
                    ipcache_key,
                    policy_keys,
                },
            );
        }

        let (added, removed) = self
            .maps
            .sync_host_policies(all_policy_entries)
            .map_err(|e| Status::internal(format!("Failed to sync host policies: {}", e)))?;

        // Replace the rule tracking map.
        {
            let mut rules = self.host_rules.write().expect("host_rules lock poisoned");
            *rules = new_rules;
        }

        info!(added, removed, "Synced host policies");

        Ok(Response::new(proto::SyncHostPoliciesResponse {
            added,
            removed,
        }))
    }

    // -----------------------------------------------------------------------
    // XDP management
    // -----------------------------------------------------------------------

    async fn attach_xdp(
        &self,
        request: Request<proto::AttachXdpRequest>,
    ) -> Result<Response<proto::AttachXdpResponse>, Status> {
        let req = request.into_inner();

        let native = match proto::XdpMode::try_from(req.mode) {
            Ok(proto::XdpMode::Native) => true,
            Ok(proto::XdpMode::Skb) => false,
            Err(_) => return Err(Status::invalid_argument("Invalid XDP mode")),
        };

        self.maps
            .attach_xdp(&req.interface_name, native)
            .map_err(|e| Status::internal(format!("Failed to attach XDP: {}", e)))?;

        info!(
            interface = %req.interface_name,
            native = native,
            "Attached XDP program"
        );

        Ok(Response::new(proto::AttachXdpResponse {}))
    }

    async fn detach_xdp(
        &self,
        request: Request<proto::DetachXdpRequest>,
    ) -> Result<Response<proto::DetachXdpResponse>, Status> {
        let req = request.into_inner();

        self.maps
            .detach_xdp(&req.interface_name)
            .map_err(|e| Status::internal(format!("Failed to detach XDP: {}", e)))?;

        info!(interface = %req.interface_name, "Detached XDP program");

        Ok(Response::new(proto::DetachXdpResponse {}))
    }

    // -----------------------------------------------------------------------
    // SOCKMAP endpoint management
    // -----------------------------------------------------------------------

    async fn upsert_sockmap_endpoint(
        &self,
        request: Request<proto::UpsertSockmapEndpointRequest>,
    ) -> Result<Response<proto::UpsertSockmapEndpointResponse>, Status> {
        let req = request.into_inner();
        let ip = parse_ip(&req.ip)?;

        let key = SockmapEndpointKey {
            ip: match ip {
                IpAddr::V4(v4) => u32::from(v4),
                _ => {
                    return Err(Status::invalid_argument(
                        "IPv6 not yet supported for SOCKMAP",
                    ))
                }
            },
            port: req.port,
        };

        self.maps
            .upsert_sockmap_endpoint(key, 1)
            .map_err(|e| Status::internal(format!("Failed to upsert sockmap endpoint: {}", e)))?;

        debug!(ip = %req.ip, port = req.port, "Upserted SOCKMAP endpoint");

        Ok(Response::new(proto::UpsertSockmapEndpointResponse {}))
    }

    async fn delete_sockmap_endpoint(
        &self,
        request: Request<proto::DeleteSockmapEndpointRequest>,
    ) -> Result<Response<proto::DeleteSockmapEndpointResponse>, Status> {
        let req = request.into_inner();
        let ip = parse_ip(&req.ip)?;

        let key = SockmapEndpointKey {
            ip: match ip {
                IpAddr::V4(v4) => u32::from(v4),
                _ => {
                    return Err(Status::invalid_argument(
                        "IPv6 not yet supported for SOCKMAP",
                    ))
                }
            },
            port: req.port,
        };

        self.maps
            .delete_sockmap_endpoint(&key)
            .map_err(|e| Status::internal(format!("Failed to delete sockmap endpoint: {}", e)))?;

        debug!(ip = %req.ip, port = req.port, "Deleted SOCKMAP endpoint");

        Ok(Response::new(proto::DeleteSockmapEndpointResponse {}))
    }

    async fn get_sockmap_stats(
        &self,
        _request: Request<proto::GetInternalSockmapStatsRequest>,
    ) -> Result<Response<proto::GetInternalSockmapStatsResponse>, Status> {
        let (redirected, fallback) = self.maps.get_sockmap_stats();
        let active_endpoints =
            self.maps.count_sockmap_endpoints().map_err(|e| {
                Status::internal(format!("Failed to count sockmap endpoints: {}", e))
            })? as u32;

        Ok(Response::new(proto::GetInternalSockmapStatsResponse {
            redirected,
            fallback,
            active_endpoints,
        }))
    }

    // -----------------------------------------------------------------------
    // Mesh redirect management
    // -----------------------------------------------------------------------

    async fn upsert_mesh_service(
        &self,
        request: Request<proto::UpsertMeshServiceRequest>,
    ) -> Result<Response<proto::UpsertMeshServiceResponse>, Status> {
        let req = request.into_inner();
        let ip = parse_ip(&req.ip)?;

        let key = MeshServiceKey {
            ip: match ip {
                IpAddr::V4(v4) => u32::from(v4),
                _ => {
                    return Err(Status::invalid_argument(
                        "IPv6 not yet supported for mesh redirect",
                    ))
                }
            },
            port: req.port,
        };

        let value = MeshRedirectValue {
            redirect_port: req.redirect_port,
        };

        self.maps
            .upsert_mesh_service(key, value)
            .map_err(|e| Status::internal(format!("Failed to upsert mesh service: {}", e)))?;

        debug!(
            ip = %req.ip,
            port = req.port,
            redirect_port = req.redirect_port,
            "Upserted mesh service"
        );

        Ok(Response::new(proto::UpsertMeshServiceResponse {}))
    }

    async fn delete_mesh_service(
        &self,
        request: Request<proto::DeleteMeshServiceRequest>,
    ) -> Result<Response<proto::DeleteMeshServiceResponse>, Status> {
        let req = request.into_inner();
        let ip = parse_ip(&req.ip)?;

        let key = MeshServiceKey {
            ip: match ip {
                IpAddr::V4(v4) => u32::from(v4),
                _ => {
                    return Err(Status::invalid_argument(
                        "IPv6 not yet supported for mesh redirect",
                    ))
                }
            },
            port: req.port,
        };

        self.maps
            .delete_mesh_service(&key)
            .map_err(|e| Status::internal(format!("Failed to delete mesh service: {}", e)))?;

        debug!(ip = %req.ip, port = req.port, "Deleted mesh service");

        Ok(Response::new(proto::DeleteMeshServiceResponse {}))
    }

    async fn list_mesh_services(
        &self,
        _request: Request<proto::ListInternalMeshServicesRequest>,
    ) -> Result<Response<proto::ListInternalMeshServicesResponse>, Status> {
        let entries = self
            .maps
            .list_mesh_services()
            .map_err(|e| Status::internal(format!("Failed to list mesh services: {}", e)))?;

        let proto_entries: Vec<proto::InternalMeshServiceEntry> = entries
            .iter()
            .map(|(key, value)| {
                let ip = std::net::Ipv4Addr::from(key.ip);
                proto::InternalMeshServiceEntry {
                    ip: ip.to_string(),
                    port: key.port,
                    redirect_port: value.redirect_port,
                }
            })
            .collect();

        Ok(Response::new(proto::ListInternalMeshServicesResponse {
            entries: proto_entries,
        }))
    }

    // -----------------------------------------------------------------------
    // Rate limiting
    // -----------------------------------------------------------------------

    async fn update_rate_limit_config(
        &self,
        request: Request<proto::UpdateRateLimitConfigRequest>,
    ) -> Result<Response<proto::UpdateRateLimitConfigResponse>, Status> {
        let req = request.into_inner();

        let config = RateLimitConfig {
            rate: req.rate,
            burst: req.burst,
            window_ns: req.window_ns,
        };

        self.maps
            .update_rate_limit_config(config)
            .map_err(|e| Status::internal(format!("Failed to update rate limit config: {}", e)))?;

        debug!(
            rate = req.rate,
            burst = req.burst,
            window_ns = req.window_ns,
            "Updated rate limit config"
        );

        Ok(Response::new(proto::UpdateRateLimitConfigResponse {}))
    }

    async fn get_internal_rate_limit_stats(
        &self,
        _request: Request<proto::GetInternalRateLimitStatsRequest>,
    ) -> Result<Response<proto::GetInternalRateLimitStatsResponse>, Status> {
        let (allowed, denied) = self.maps.get_rate_limit_stats();

        Ok(Response::new(proto::GetInternalRateLimitStatsResponse {
            allowed,
            denied,
        }))
    }

    // -----------------------------------------------------------------------
    // Backend health monitoring
    // -----------------------------------------------------------------------

    async fn get_backend_health_stats(
        &self,
        request: Request<proto::GetBackendHealthStatsRequest>,
    ) -> Result<Response<proto::GetBackendHealthStatsResponse>, Status> {
        let req = request.into_inner();

        let backends: Vec<proto::InternalBackendHealthInfo> = if !req.ip.is_empty() {
            // Filter by specific backend.
            let ip = parse_ip(&req.ip)?;
            let key = BackendHealthKey {
                ip: match ip {
                    IpAddr::V4(v4) => u32::from(v4),
                    _ => {
                        return Err(Status::invalid_argument(
                            "IPv6 not yet supported for backend health",
                        ))
                    }
                },
                port: req.port,
            };

            match self.maps.get_backend_health(&key) {
                Some(counters) => vec![health_counters_to_proto(&req.ip, req.port, &counters)],
                None => vec![],
            }
        } else {
            // Return all backends.
            self.maps
                .get_all_backend_health()
                .iter()
                .map(|(key, counters)| {
                    let ip = std::net::Ipv4Addr::from(key.ip).to_string();
                    health_counters_to_proto(&ip, key.port, counters)
                })
                .collect()
        };

        Ok(Response::new(proto::GetBackendHealthStatsResponse {
            backends,
        }))
    }
}
