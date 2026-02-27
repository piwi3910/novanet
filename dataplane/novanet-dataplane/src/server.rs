//! gRPC server implementing the `DataplaneControl` service.
//!
//! This is the internal API between the Go management agent and the Rust
//! eBPF dataplane. The Go agent is the client; this daemon is the server.

use crate::flows;
use crate::maps::{AttachDirection, MapManager};
use crate::proto;
use novanet_common::*;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::{wrappers::BroadcastStream, Stream, StreamExt};
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

/// The DataplaneControl gRPC service implementation.
pub struct DataplaneService {
    maps: Arc<MapManager>,
}

impl DataplaneService {
    pub fn new(maps: MapManager) -> Self {
        Self {
            maps: Arc::new(maps),
        }
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

        let key = EndpointKey { ip: req.ip };
        let value = EndpointValue {
            ifindex: req.ifindex,
            mac,
            _pad: [0; 2],
            identity: req.identity_id,
            node_ip: req.node_ip,
        };

        self.maps
            .upsert_endpoint(key, value)
            .map_err(|e| Status::internal(format!("Failed to upsert endpoint: {}", e)))?;

        debug!(
            ip = req.ip,
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
        let key = EndpointKey { ip: req.ip };

        self.maps
            .delete_endpoint(&key)
            .map_err(|e| Status::internal(format!("Failed to delete endpoint: {}", e)))?;

        debug!(ip = req.ip, "Deleted endpoint");

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

        let key = EgressKey {
            src_identity: req.src_identity,
            dst_ip: req.dst_cidr_ip,
            dst_prefix_len: req.dst_cidr_prefix_len as u8,
            _pad: [0; 3],
        };

        let value = EgressValue {
            action,
            _pad: [0; 3],
            snat_ip: req.snat_ip,
        };

        self.maps
            .upsert_egress_policy(key, value)
            .map_err(|e| Status::internal(format!("Failed to upsert egress policy: {}", e)))?;

        debug!(
            src_identity = req.src_identity,
            dst_cidr_ip = req.dst_cidr_ip,
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

        let key = EgressKey {
            src_identity: req.src_identity,
            dst_ip: req.dst_cidr_ip,
            dst_prefix_len: req.dst_cidr_prefix_len as u8,
            _pad: [0; 3],
        };

        self.maps
            .delete_egress_policy(&key)
            .map_err(|e| Status::internal(format!("Failed to delete egress policy: {}", e)))?;

        debug!(
            src_identity = req.src_identity,
            dst_cidr_ip = req.dst_cidr_ip,
            "Deleted egress policy"
        );

        Ok(Response::new(proto::DeleteEgressPolicyResponse {}))
    }

    // -----------------------------------------------------------------------
    // Tunnel management
    // -----------------------------------------------------------------------

    async fn upsert_tunnel(
        &self,
        request: Request<proto::UpsertTunnelRequest>,
    ) -> Result<Response<proto::UpsertTunnelResponse>, Status> {
        let req = request.into_inner();

        let key = TunnelKey {
            node_ip: req.node_ip,
        };
        let value = TunnelValue {
            ifindex: req.tunnel_ifindex,
            remote_ip: req.node_ip,
            vni: req.vni,
        };

        self.maps
            .upsert_tunnel(key, value)
            .map_err(|e| Status::internal(format!("Failed to upsert tunnel: {}", e)))?;

        debug!(
            node_ip = req.node_ip,
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
        let key = TunnelKey {
            node_ip: req.node_ip,
        };

        self.maps
            .delete_tunnel(&key)
            .map_err(|e| Status::internal(format!("Failed to delete tunnel: {}", e)))?;

        debug!(node_ip = req.node_ip, "Deleted tunnel");

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
        };

        Ok(Response::new(resp))
    }
}
