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
| `ListIdentities` | Pod-to-identity mappings |
| `ListTunnels` | Active tunnel list |
| `ListEgressPolicies` | Egress rules |

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

The full protobuf definition is at [`api/v1/novanet.proto`](../api/v1/novanet.proto).

---

## Next Steps

- [Architecture](architecture.md) -- eBPF program details and data paths
- [CLI Reference](cli-reference.md) -- Using novanetctl
- [Development Guide](development.md) -- Building and contributing
