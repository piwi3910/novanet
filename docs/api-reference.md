# NovaNet API Reference

NovaNet uses gRPC over Unix domain sockets for all inter-component communication. This document covers the two gRPC services and the eBPF map schemas.

---

## gRPC Services

### DataplaneControl (Rust server, Go client)

**Socket:** `/run/novanet/dataplane.sock`

The Go agent calls these RPCs to manage eBPF maps and programs.

#### Endpoint Management

| RPC | Description |
|-----|-------------|
| `UpsertEndpoint` | Add or update a pod in the ENDPOINTS eBPF map |
| `DeleteEndpoint` | Remove a pod from the ENDPOINTS map |

**UpsertEndpointRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `ip` | `uint32` | Pod IPv4 address (network byte order) |
| `ifindex` | `uint32` | Host-side veth interface index |
| `mac` | `bytes` | Pod MAC address (6 bytes) |
| `identity_id` | `uint32` | Security identity ID |
| `pod_name` | `string` | Pod name (metadata only) |
| `namespace` | `string` | Pod namespace (metadata only) |
| `node_ip` | `uint32` | Node IP where pod runs (for remote endpoints) |

#### Policy Management

| RPC | Description |
|-----|-------------|
| `UpsertPolicy` | Add or update a single policy rule |
| `DeletePolicy` | Remove a single policy rule |
| `SyncPolicies` | Atomically replace all policy rules |

**UpsertPolicyRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `src_identity` | `uint32` | Source identity (0 = wildcard) |
| `dst_identity` | `uint32` | Destination identity |
| `protocol` | `uint32` | IP protocol (6=TCP, 17=UDP, 0=any) |
| `dst_port` | `uint32` | Destination port (0 = any) |
| `action` | `PolicyAction` | `ALLOW` or `DENY` |

**SyncPoliciesRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `policies` | `repeated PolicyEntry` | Complete set of desired policy rules |

The sync operation computes a diff against the current map and applies only the necessary insertions, updates, and deletions.

#### Tunnel Management (Overlay Mode)

| RPC | Description |
|-----|-------------|
| `UpsertTunnel` | Register a tunnel to a remote node |
| `DeleteTunnel` | Remove a tunnel entry |

**UpsertTunnelRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `node_ip` | `uint32` | Remote node IP (network byte order) |
| `tunnel_ifindex` | `uint32` | Local tunnel interface index |
| `vni` | `uint32` | Virtual Network Identifier |

#### TC Program Attachment

| RPC | Description |
|-----|-------------|
| `AttachProgram` | Attach eBPF TC program to an interface |
| `DetachProgram` | Detach eBPF TC program from an interface |

**AttachProgramRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `interface_name` | `string` | Network interface name |
| `attach_type` | `AttachType` | `INGRESS` or `EGRESS` |

#### Configuration

| RPC | Description |
|-----|-------------|
| `UpdateConfig` | Push configuration key-value pairs to the CONFIG map |

**UpdateConfigRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `entries` | `map<uint32, uint64>` | Config key-value pairs |

Config keys:

| Key | Value | Description |
|-----|-------|-------------|
| 0 | 0/1 | Mode: 0=overlay, 1=native |
| 1 | 0/1 | Tunnel type: 0=geneve, 1=vxlan |
| 2 | uint32 | Node IP (network byte order) |
| 3 | uint32 | Cluster CIDR IP |
| 4 | uint32 | Cluster CIDR prefix length |
| 5 | 0/1 | Default deny: 0=false, 1=true |
| 6 | 0/1 | Masquerade enable |
| 8 | uint32 | Pod CIDR IP |
| 9 | uint32 | Pod CIDR prefix length |

#### Egress Policy

| RPC | Description |
|-----|-------------|
| `UpsertEgressPolicy` | Add or update an egress rule |
| `DeleteEgressPolicy` | Remove an egress rule |

**UpsertEgressPolicyRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `src_identity` | `uint32` | Source identity |
| `dst_cidr_ip` | `uint32` | Destination CIDR IP |
| `dst_cidr_prefix_len` | `uint32` | Destination CIDR prefix length |
| `protocol` | `uint32` | IP protocol (6=TCP, 17=UDP, 0=any) |
| `dst_port` | `uint32` | Destination port (0 = any) |
| `action` | `EgressAction` | `ALLOW`, `DENY`, or `SNAT` |
| `snat_ip` | `uint32` | SNAT IP (when action=SNAT) |

#### Observability

| RPC | Description |
|-----|-------------|
| `StreamFlows` | Server-streaming RPC for flow events |
| `GetDataplaneStatus` | Dataplane status (endpoints, policies, tunnels, programs) |

**FlowEvent:**

| Field | Type | Description |
|-------|------|-------------|
| `src_ip` | `uint32` | Source IPv4 |
| `dst_ip` | `uint32` | Destination IPv4 |
| `src_identity` | `uint32` | Source security identity |
| `dst_identity` | `uint32` | Destination security identity |
| `protocol` | `uint32` | IP protocol number |
| `src_port` | `uint32` | Source L4 port |
| `dst_port` | `uint32` | Destination L4 port |
| `verdict` | `PolicyAction` | ALLOW or DENY |
| `bytes` | `uint64` | Byte count |
| `packets` | `uint64` | Packet count |
| `timestamp_ns` | `int64` | Kernel timestamp (nanoseconds) |
| `drop_reason` | `DropReason` | Reason for drop (when verdict=DENY) |
| `tcp_flags` | `uint32` | TCP flags (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04) |

---

### AgentControl (Go server, CNI/CLI clients)

**Sockets:** `/run/novanet/cni.sock` (CNI binary), `/run/novanet/novanet.sock` (CLI)

#### CNI Operations

| RPC | Description |
|-----|-------------|
| `AddPod` | Handle CNI ADD: allocate IP, create veth, configure networking |
| `DelPod` | Handle CNI DEL: release IP, clean up networking |

**AddPodRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `pod_name` | `string` | Pod name |
| `pod_namespace` | `string` | Pod namespace |
| `container_id` | `string` | Container ID |
| `netns` | `string` | Network namespace path |
| `if_name` | `string` | Interface name (usually `eth0`) |
| `labels` | `map<string, string>` | Pod labels (for identity) |

**AddPodResponse:**

| Field | Type | Description |
|-------|------|-------------|
| `ip` | `string` | Allocated pod IP |
| `gateway` | `string` | Gateway IP (.1 of pod CIDR) |
| `mac` | `string` | Assigned MAC address |
| `prefix_length` | `int32` | Subnet prefix length |

#### Status and Listing

| RPC | Description |
|-----|-------------|
| `GetAgentStatus` | Node-level status overview |
| `StreamAgentFlows` | Proxy flow events from dataplane |
| `ListPolicies` | Compiled policy rules |

**StreamAgentFlowsRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `drops_only` | `bool` | If true, stream only denied/dropped flow events |

#### Policy and Identity Listing

| RPC | Description |
|-----|-------------|
| `ListIdentities` | Pod-to-identity mappings |
| `ListTunnels` | Active tunnel list |
| `ListEgressPolicies` | Egress rules |

#### Routing (Native Mode)

These RPCs query the integrated routing manager and FRR sidecar for live routing state.

| RPC | Description |
|-----|-------------|
| `GetRoutingPeers` | BGP peer state with BFD status and intent owner info |
| `GetRoutingPrefixes` | Prefix advertisement state from the intent store |
| `GetRoutingBFDSessions` | BFD session state with timers and uptime |
| `GetRoutingOSPFNeighbors` | OSPF neighbor adjacencies |
| `StreamRoutingEvents` | Server-streaming RPC for real-time routing events |

**RoutingPeerInfo:**

| Field | Type | Description |
|-------|------|-------------|
| `neighbor_address` | `string` | Peer IP address |
| `remote_as` | `uint32` | Remote Autonomous System number |
| `state` | `string` | BGP session state (e.g., "Established") |
| `uptime` | `string` | Session uptime |
| `prefixes_received` | `uint32` | Number of prefixes received from peer |
| `prefixes_sent` | `uint32` | Number of prefixes sent to peer |
| `msg_received` | `uint32` | BGP messages received |
| `msg_sent` | `uint32` | BGP messages sent |
| `bfd_status` | `string` | BFD session status ("up", "down", or empty) |
| `owner` | `string` | Intent owner that configured this peer |

**RoutingPrefixInfo:**

| Field | Type | Description |
|-------|------|-------------|
| `prefix` | `string` | Route prefix in CIDR notation |
| `protocol` | `string` | Protocol ("bgp" or "ospf") |
| `state` | `string` | Advertisement state |
| `owner` | `string` | Intent owner |

**RoutingBFDSessionInfo:**

| Field | Type | Description |
|-------|------|-------------|
| `peer_address` | `string` | BFD peer IP address |
| `status` | `string` | Session status ("up", "down") |
| `uptime` | `string` | Session uptime |
| `min_rx_ms` | `uint32` | Minimum receive interval (milliseconds) |
| `min_tx_ms` | `uint32` | Minimum transmit interval (milliseconds) |
| `detect_multiplier` | `uint32` | Detect multiplier |
| `interface_name` | `string` | Network interface |
| `owner` | `string` | Intent owner |

**RoutingOSPFNeighborInfo:**

| Field | Type | Description |
|-------|------|-------------|
| `neighbor_id` | `string` | OSPF neighbor router ID |
| `address` | `string` | Neighbor IP address |
| `interface_name` | `string` | Local interface |
| `state` | `string` | OSPF adjacency state |
| `owner` | `string` | Intent owner |

**StreamRoutingEventsRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `owner_filter` | `string` | Filter events by owner (empty = all) |
| `event_types` | `repeated string` | Filter by event types (empty = all) |

**RoutingEvent:**

| Field | Type | Description |
|-------|------|-------------|
| `timestamp_ns` | `int64` | Event timestamp in nanoseconds |
| `event_type` | `string` | Event type (e.g., "bgp_peer_established", "bfd_session_up") |
| `owner` | `string` | Intent owner |
| `detail` | `string` | Human-readable event detail |
| `metadata` | `map<string, string>` | Additional key-value metadata |

---

### EBPFServices (Go server, external clients)

**Socket:** `/run/novanet/ebpf-services.sock`

The EBPFServices API exposes kernel-level eBPF operations to external consumers such as NovaEdge. It provides SOCKMAP acceleration, mesh traffic redirection via SK_LOOKUP, per-source-IP rate limiting, and passive TCP health monitoring.

**Proto source:** [`api/v1/ebpf_services.proto`](https://github.com/azrtydxb/novanet/blob/main/api/v1/ebpf_services.proto)

#### SOCKMAP Acceleration

SOCKMAP accelerates same-node pod-to-pod TCP traffic by bypassing the kernel
TCP/IP stack. When enabled for a pod, the dataplane's `sock_ops` and `sk_msg`
eBPF programs redirect data directly between sockets using
`bpf_msg_redirect_hash()`.

Callers (typically NovaEdge) identify pods by namespace and name. The server
resolves the pod IP internally using its `EndpointResolver` (backed by the
agent's endpoint store) and forwards the resolved IP to the Rust dataplane.

| RPC | Description |
|-----|-------------|
| `EnableSockmap` | Enable SOCKMAP acceleration for a pod (same-node pod-to-pod bypass) |
| `DisableSockmap` | Disable SOCKMAP acceleration for a pod |
| `GetSockmapStats` | Get SOCKMAP statistics (redirected, fallback, active sockets) |

**EnableSockmapRequest / DisableSockmapRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `pod_namespace` | `string` | Pod namespace (required) |
| `pod_name` | `string` | Pod name (required) |

Both RPCs validate that the fields are non-empty and return `InvalidArgument` if
they are missing. If the pod is not found in the endpoint store, the RPC returns
`NotFound`. If the endpoint resolver or dataplane client is unavailable, the RPC
returns `Unavailable`.

**Implementation flow (EnableSockmap):**

1. Validate `pod_namespace` and `pod_name` are non-empty.
2. Look up the pod IP via `EndpointResolver.LookupEndpoint(namespace, name)`.
3. Call `dataplane.UpsertSockmapEndpoint(ctx, podIP, 0)` to register the IP
   in the `SOCKMAP_ENDPOINTS` eBPF map.
4. Return success. New TCP connections involving this IP are now eligible for
   kernel-level socket redirection.

**Implementation flow (DisableSockmap):**

1. Same validation and IP resolution as `EnableSockmap`.
2. Call `dataplane.DeleteSockmapEndpoint(ctx, podIP, 0)` to remove the IP from
   the `SOCKMAP_ENDPOINTS` eBPF map.
3. Existing accelerated connections are unaffected; only new connections fall
   back to the normal TCP/IP path.

**GetSockmapStatsResponse:**

| Field | Type | Description |
|-------|------|-------------|
| `redirected` | `uint64` | Number of packets redirected via SOCKMAP |
| `fallback` | `uint64` | Number of packets that fell back to normal path |
| `active_sockets` | `uint32` | Number of sockets currently tracked |

#### SK_LOOKUP Mesh Redirection

| RPC | Description |
|-----|-------------|
| `AddMeshRedirect` | Add a mesh traffic redirect entry |
| `RemoveMeshRedirect` | Remove a mesh traffic redirect entry |
| `ListMeshRedirects` | List all active mesh redirect entries |

**AddMeshRedirectRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `ip` | `string` | Target IP address |
| `port` | `uint32` | Original destination port |
| `redirect_port` | `uint32` | Port to redirect traffic to |

**RemoveMeshRedirectRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `ip` | `string` | Target IP address |
| `port` | `uint32` | Original destination port |

**MeshRedirectEntry** (returned by `ListMeshRedirects`):

| Field | Type | Description |
|-------|------|-------------|
| `ip` | `string` | Target IP address |
| `port` | `uint32` | Original destination port |
| `redirect_port` | `uint32` | Port traffic is redirected to |

#### Rate Limiting

| RPC | Description |
|-----|-------------|
| `ConfigureRateLimit` | Configure kernel-level per-source-IP rate limiting |
| `RemoveRateLimit` | Remove a rate limit configuration |
| `GetRateLimitStats` | Get rate limit statistics for a CIDR |

**ConfigureRateLimitRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `cidr` | `string` | Source CIDR to rate limit |
| `rate` | `uint32` | Allowed packets per second |
| `burst` | `uint32` | Burst allowance |

**RemoveRateLimitRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `cidr` | `string` | Source CIDR to remove rate limit for |

**GetRateLimitStatsRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `cidr` | `string` | Source CIDR to query stats for |

**GetRateLimitStatsResponse:**

| Field | Type | Description |
|-------|------|-------------|
| `allowed` | `uint64` | Number of packets allowed |
| `denied` | `uint64` | Number of packets denied (rate limited) |

#### Backend Health Monitoring

| RPC | Description |
|-----|-------------|
| `GetBackendHealth` | Get passive TCP health counters for backends |
| `StreamBackendHealth` | Server-streaming RPC for real-time backend health events |

**GetBackendHealthRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `ip` | `string` | Backend IP to filter (empty = all) |
| `port` | `uint32` | Backend port to filter (0 = all) |

**BackendHealthInfo** (returned by `GetBackendHealth` and `StreamBackendHealth`):

| Field | Type | Description |
|-------|------|-------------|
| `ip` | `string` | Backend IP address |
| `port` | `uint32` | Backend port |
| `total_conns` | `uint64` | Total connections observed |
| `failed_conns` | `uint64` | Failed connections |
| `timeout_conns` | `uint64` | Timed-out connections |
| `success_conns` | `uint64` | Successful connections |
| `avg_rtt_ns` | `uint64` | Average round-trip time in nanoseconds |
| `failure_rate` | `double` | Failure rate (0.0 to 1.0) |

**StreamBackendHealthRequest:**

| Field | Type | Description |
|-------|------|-------------|
| `poll_interval_ms` | `uint32` | Polling interval in milliseconds |

**BackendHealthEvent** (streamed by `StreamBackendHealth`):

| Field | Type | Description |
|-------|------|-------------|
| `backend` | `BackendHealthInfo` | Backend health data |
| `timestamp_ns` | `uint64` | Event timestamp in nanoseconds |

---

## Enums

### PolicyAction

| Value | Number | Description |
|-------|--------|-------------|
| `POLICY_ACTION_DENY` | 0 | Drop the packet |
| `POLICY_ACTION_ALLOW` | 1 | Permit the packet |

### EgressAction

| Value | Number | Description |
|-------|--------|-------------|
| `EGRESS_ACTION_DENY` | 0 | Drop egress |
| `EGRESS_ACTION_ALLOW` | 1 | Permit egress |
| `EGRESS_ACTION_SNAT` | 2 | Permit with source NAT |

### DropReason

| Value | Number | Description |
|-------|--------|-------------|
| `DROP_REASON_NONE` | 0 | No drop |
| `DROP_REASON_POLICY_DENIED` | 1 | Denied by policy |
| `DROP_REASON_NO_IDENTITY` | 2 | Source has no identity |
| `DROP_REASON_NO_ROUTE` | 3 | No route to destination |
| `DROP_REASON_NO_TUNNEL` | 4 | No tunnel for remote node |
| `DROP_REASON_TTL_EXCEEDED` | 5 | TTL reached zero |

### AttachType

| Value | Number | Description |
|-------|--------|-------------|
| `ATTACH_TC_INGRESS` | 0 | TC ingress hook |
| `ATTACH_TC_EGRESS` | 1 | TC egress hook |

---

## Protobuf Source

The full protobuf definition is at [`api/v1/novanet.proto`](https://github.com/azrtydxb/novanet/blob/main/api/v1/novanet.proto).

---

## Next Steps

- [Architecture](architecture.md) -- eBPF program details and data paths
- [CLI Reference](cli-reference.md) -- Using novanetctl
- [Development Guide](development.md) -- Building and contributing
