# Socket-LB Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace broken TC-based ClusterIP DNAT with cgroup socket hooks (connect4/sendmsg4/recvmsg4/getpeername4) that intercept at the socket layer, like Cilium's socket-LB.

**Architecture:** Attach 4 `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` programs to the root cgroup. They share existing SERVICES/BACKENDS/MAGLEV maps. A new `SOCK_LB_ORIGINS` LRU map tracks original destinations per socket cookie. TC hooks retain NodePort/ExternalIP DNAT (north-south). ClusterIP DNAT is removed from TC hooks.

**Tech Stack:** Rust, aya-ebpf 0.1 (kernel), aya 0.13 (userspace), eBPF cgroup_sock_addr

**Design doc:** `docs/plans/2026-03-07-socket-lb-design.md`

---

### Task 1: Add SockLbOrigin to novanet-common

**Files:**
- Modify: `dataplane/novanet-common/src/lib.rs`

**Step 1: Add `SockLbOrigin` struct after `CtValue` (after line 230)**

```rust
// ---------------------------------------------------------------------------
// Socket-LB origin map: socket cookie → original service destination
// ---------------------------------------------------------------------------

/// Stores the original ClusterIP destination before socket-LB rewrites it.
/// Used by recvmsg4/getpeername4 to reverse-translate back to the VIP.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockLbOrigin {
    /// Original service ClusterIP in network byte order.
    pub original_ip: u32,
    /// Original service port in host byte order.
    pub original_port: u16,
    /// IP protocol (6=TCP, 17=UDP).
    pub protocol: u8,
    /// Padding for alignment.
    pub _pad: u8,
}
```

**Step 2: Add map size constant after `MAGLEV_TABLE_SIZE` (after line 459)**

```rust
/// Maximum entries in the socket-LB origin tracking map.
pub const MAX_SOCK_LB_ORIGINS: u32 = 131072;
```

**Step 3: Add `SockLbOrigin` to the `impl_pod!` macro (line 466-480)**

Add `SockLbOrigin,` after the `CtValue,` line in the `impl_pod!` invocation.

**Step 4: Add size and alignment tests in the `mod tests` block**

```rust
#[test]
fn sock_lb_origin_size() {
    // original_ip(4) + original_port(2) + protocol(1) + pad(1) = 8
    assert_eq!(mem::size_of::<SockLbOrigin>(), 8);
}

#[test]
fn sock_lb_origin_alignment() {
    assert_eq!(mem::align_of::<SockLbOrigin>(), 4);
}
```

**Step 5: Run tests**

Run: `cd dataplane/novanet-common && cargo test --features userspace`
Expected: All tests pass including new size/alignment tests.

**Step 6: Commit**

```bash
git add dataplane/novanet-common/src/lib.rs
git commit -m "feat(common): add SockLbOrigin type for socket-LB origin tracking"
```

---

### Task 2: Add cgroup_sock_addr eBPF programs

**Files:**
- Modify: `dataplane/novanet-ebpf/src/main.rs`

This is the largest task. We add the `SOCK_LB_ORIGINS` map, a `sock_service_lookup` helper, and 4 cgroup programs.

**Step 1: Add new imports**

At the top of main.rs, update the `aya_ebpf` use block (lines 15-23). Add `cgroup_sock_addr` to the `macros` import and `SockAddrContext` to the `programs` import:

```rust
use aya_ebpf::{
    bindings::TC_ACT_OK as BPF_TC_ACT_OK,
    bindings::TC_ACT_SHOT as BPF_TC_ACT_SHOT,
    bindings::{bpf_tunnel_key, BPF_F_ZERO_CSUM_TX},
    helpers::{bpf_get_socket_cookie, bpf_redirect, bpf_skb_set_tunnel_key},
    macros::{cgroup_sock_addr, classifier, map},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{SockAddrContext, TcContext},
};
```

**Step 2: Add SOCK_LB_ORIGINS map after RR_COUNTERS (after line 71)**

```rust
#[map]
static SOCK_LB_ORIGINS: LruHashMap<u64, SockLbOrigin> =
    LruHashMap::with_max_entries(MAX_SOCK_LB_ORIGINS, 0);
```

**Step 3: Add `sock_service_lookup` helper**

Add this after the existing `service_lookup` function (after line 413). This is a simplified version that doesn't use conntrack (socket-LB doesn't need it) and handles the case where `src_port` is unknown at connect time:

```rust
// ---------------------------------------------------------------------------
// Helper: socket-LB service lookup + backend selection
// Returns (backend_ip, backend_port) if dst is a ClusterIP service.
// Unlike TC service_lookup, this doesn't create conntrack entries.
// ---------------------------------------------------------------------------

#[inline(always)]
fn sock_service_lookup(
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
) -> Option<(u32, u16)> {
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
            if let Some(c) = unsafe { RR_COUNTERS.get_ptr_mut(offset as u32) } {
                let val = unsafe { *c };
                unsafe { *c = val.wrapping_add(1) };
                val % (count as u32)
            } else {
                0
            }
        }
        LB_ALG_MAGLEV => {
            // Use 3-tuple hash since src_port is unavailable.
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
            if let Some(backend_idx) = unsafe { MAGLEV.get(maglev_idx) } {
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
    let backend = unsafe { BACKENDS.get(backend_array_idx) }?;

    Some((backend.ip, backend.port))
}
```

**Step 4: Add the 4 cgroup_sock_addr programs**

Add these at the end of the file, before the panic handler (before line 1449):

```rust
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
        let _ = unsafe { SOCK_LB_ORIGINS.insert(&cookie, &origin, 0) };

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
        let _ = unsafe { SOCK_LB_ORIGINS.insert(&cookie, &origin, 0) };

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
```

**Step 5: Update the module doc comment at the top of main.rs**

Replace lines 1-10 with:

```rust
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
```

**Step 6: Commit**

```bash
git add dataplane/novanet-ebpf/src/main.rs
git commit -m "feat(ebpf): add cgroup socket-LB programs for ClusterIP DNAT

Add 4 cgroup_sock_addr programs (connect4, sendmsg4, recvmsg4,
getpeername4) that intercept socket syscalls and rewrite ClusterIP
destinations to backend pods. Uses SOCK_LB_ORIGINS LRU map keyed
by socket cookie to track original destinations for reverse translation."
```

---

### Task 3: Remove ClusterIP DNAT from TC hooks

**Files:**
- Modify: `dataplane/novanet-ebpf/src/main.rs`

Now that socket-LB handles ClusterIP, remove the TC-based ClusterIP DNAT path.

**Step 1: Remove ClusterIP DNAT from `try_tc_egress`**

Remove lines 812-825 (the `// --- L4 LB: Service DNAT ---` block):

```rust
    // --- L4 LB: Service DNAT ---
    if let Some((backend_ip, backend_port, _origin_ip, _origin_port)) =
        service_lookup(dst_ip, dst_port, protocol, src_ip, src_port, SVC_SCOPE_CLUSTER_IP)
    {
        if perform_dnat(ctx, l4_offset, protocol, dst_ip, backend_ip, dst_port, backend_port)
            .is_err()
        {
            inc_drop_counter(DROP_REASON_NO_ROUTE);
            return Ok(BPF_TC_ACT_SHOT as i32);
        }
        // Update locals so subsequent endpoint lookup uses real backend IP.
        dst_ip = backend_ip;
        dst_port = backend_port;
    }
```

After removal, `dst_ip` and `dst_port` no longer need to be `mut`. Change their declarations:

```rust
    let dst_ip = u32::to_be(ipv4.dst_addr);   // was: let mut dst_ip
    ...
    let (src_port, dst_port, tcp_flags) = ...;  // was: let (src_port, mut dst_port, ...)
```

**Step 2: Remove ClusterIP reverse SNAT from `try_tc_ingress`**

Remove lines 653-671 (the `// --- L4 LB: Reverse SNAT on return traffic ---` block):

```rust
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
                let _ = perform_snat(ctx, l4_offset, protocol, src_ip, origin_ip, src_port, origin_port);
            }
        }
    }
```

**Note:** Do NOT remove `service_lookup`, `perform_dnat`, `perform_snat`, or the `CONNTRACK` map — they're still used by `tc_host_ingress` for NodePort/ExternalIP.

**Step 3: Verify build**

Run: `cd dataplane/novanet-ebpf && cargo check --target bpfel-unknown-none -Z build-std=core`

If cross-compilation isn't available on macOS, verify there are no syntax errors by inspecting the code.

**Step 4: Commit**

```bash
git add dataplane/novanet-ebpf/src/main.rs
git commit -m "refactor(ebpf): remove ClusterIP DNAT from TC hooks

ClusterIP DNAT is now handled by socket-LB (cgroup hooks).
TC hooks retain NodePort/ExternalIP DNAT via tc_host_ingress.
service_lookup, perform_dnat, perform_snat, and CONNTRACK map
remain for the north-south path."
```

---

### Task 4: Load and attach cgroup programs in userspace

**Files:**
- Modify: `dataplane/novanet-dataplane/src/loader.rs`
- Modify: `dataplane/novanet-dataplane/src/maps.rs`

**Step 1: Update loader.rs to load cgroup programs**

After the TC program loading loop (after line 54), add a loop for cgroup programs:

```rust
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
```

Also add `use aya::programs::CgroupSockAddr;` to the imports (or use the fully qualified path as shown above).

**Step 2: Add cgroup link storage to RealMaps**

In `maps.rs`, add a field to `RealMaps` (after `_tc_links` at line 1282):

```rust
    /// Holds cgroup program links so they stay attached.
    _cgroup_links: std::sync::Mutex<Vec<aya::programs::cgroup_sock_addr::CgroupSockAddrLink>>,
```

Update `RealMaps::new()` to initialize it:

```rust
    _cgroup_links: std::sync::Mutex::new(Vec::new()),
```

**Step 3: Add `attach_cgroup_programs` and `detach_cgroup_programs` methods to `RealMaps`**

Add these methods inside `impl RealMaps` (before the closing `}`):

```rust
    fn attach_cgroup_programs(&self) -> anyhow::Result<()> {
        use aya::programs::{CgroupSockAddr, CgroupAttachMode};

        let cgroup = std::fs::File::open("/sys/fs/cgroup")
            .context("Failed to open root cgroup for socket-LB")?;

        let mut ebpf = self._ebpf.lock().expect("ebpf lock poisoned");
        let mut links = self._cgroup_links.lock().expect("cgroup_links lock poisoned");

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

    fn detach_cgroup_programs(&self) {
        let mut links = self._cgroup_links.lock().expect("cgroup_links lock poisoned");
        let count = links.len();
        links.clear(); // Dropping links detaches programs.
        info!(count, "detached cgroup socket-LB programs");
    }
```

Note: `use anyhow::Context;` and `use tracing::info;` should already be available in the module.

**Step 4: Add public methods on MapManager for cgroup attachment**

In the `impl MapManager` block, add:

```rust
    pub fn attach_cgroup_programs(&self) -> anyhow::Result<()> {
        match &self.inner {
            MapManagerInner::Mock(_) => {
                info!("mock: skipping cgroup program attachment");
                Ok(())
            }
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.attach_cgroup_programs(),
        }
    }

    pub fn detach_cgroup_programs(&self) {
        match &self.inner {
            MapManagerInner::Mock(_) => {}
            #[cfg(target_os = "linux")]
            MapManagerInner::Real(m) => m.detach_cgroup_programs(),
        }
    }
```

**Step 5: Commit**

```bash
git add dataplane/novanet-dataplane/src/loader.rs dataplane/novanet-dataplane/src/maps.rs
git commit -m "feat(dataplane): load and attach cgroup socket-LB programs

Load 4 CgroupSockAddr programs during eBPF initialization and provide
attach_cgroup_programs() to attach them to the root cgroup v2.
Links are stored in RealMaps so they stay attached until shutdown."
```

---

### Task 5: Wire cgroup attachment into dataplane startup

**Files:**
- Modify: `dataplane/novanet-dataplane/src/main.rs`

**Step 1: Call attach_cgroup_programs after loading eBPF**

In `main()`, after the map manager is created (after line 88 `mgr`), add the cgroup attachment call:

```rust
            // Attach cgroup socket-LB programs to root cgroup.
            if let Err(e) = mgr.attach_cgroup_programs() {
                tracing::warn!("Failed to attach cgroup socket-LB programs: {}", e);
                // Non-fatal — L4 LB just won't work for ClusterIP, but the
                // dataplane can still function for policy enforcement.
            }
```

This goes inside the `#[cfg(target_os = "linux")]` block, right after `mgr` is constructed from `loader::load_ebpf`.

**Step 2: Commit**

```bash
git add dataplane/novanet-dataplane/src/main.rs
git commit -m "feat(dataplane): attach socket-LB programs on startup"
```

---

### Task 6: Build, release, deploy, and test

**Step 1: Cross-compile the eBPF programs (if building locally)**

On a Linux machine (or in CI):

```bash
cd dataplane/novanet-ebpf
cargo build --target bpfel-unknown-none -Z build-std=core --release
```

If this fails with import errors for `cgroup_sock_addr` or `SockAddrContext`, verify aya-ebpf 0.1 supports these types. If not, bump to a newer version that does.

**Step 2: Verify Go agent builds (unchanged)**

```bash
go build ./cmd/novanet-agent/
go build ./cmd/novanet-cni/
go build ./cmd/novanetctl/
```

These should pass without changes since no Go code was modified.

**Step 3: Create a new release**

```bash
git tag v1.7.0
git push origin v1.7.0
```

Wait for CI to build Docker images. Verify both `novanet-agent` and `novanet-dataplane` images are published to GHCR.

**Step 4: Update ArgoCD deployment**

Update `deploy/argocd/application.yaml` to use the new image tag:

```yaml
    helm:
      releaseName: novanet
      valuesObject:
        image:
          agent:
            repository: ghcr.io/azrtydxb/novanet/novanet-agent
            tag: v1.7.0
          dataplane:
            repository: ghcr.io/azrtydxb/novanet/novanet-dataplane
            tag: v1.7.0
        l4lb:
          enabled: true
```

Push and let ArgoCD sync.

**Step 5: Verify cgroup programs are attached**

SSH to a worker node and check:

```bash
# Check that cgroup programs are loaded
bpftool prog list | grep cgroup_sock_addr

# Verify programs are attached to root cgroup
bpftool cgroup show /sys/fs/cgroup/ | grep sock_addr
```

Expected output should show 4 cgroup_sock_addr programs.

**Step 6: Test DNS (UDP ClusterIP)**

```bash
kubectl run test-socket-lb --rm -it --image=busybox -- nslookup kubernetes.default
```

Expected: DNS resolution succeeds (the `sendmsg4` hook rewrites the CoreDNS ClusterIP to a backend pod).

**Step 7: Test TCP ClusterIP**

```bash
# Find a ClusterIP service
kubectl get svc -A

# Test connectivity from a pod
kubectl run test-tcp --rm -it --image=curlimages/curl -- curl -s http://<some-clusterip>:<port>
```

Expected: TCP connection succeeds via `connect4` hook.

**Step 8: Test NodePort still works (TC path)**

```bash
# Get a NodePort service port
kubectl get svc -A -o wide | grep NodePort

# Test from outside the cluster
curl http://<node-ip>:<nodeport>
```

Expected: NodePort still works via `tc_host_ingress` (unchanged).

**Step 9: Check novanetctl services**

```bash
kubectl exec -it <novanet-pod> -c agent -- novanetctl services
```

Expected: Same service list as before (Go agent and map population unchanged).

**Step 10: Commit ArgoCD changes and tag**

```bash
git add deploy/argocd/application.yaml
git commit -m "deploy: update to v1.7.0 with socket-LB"
```

---

## Summary of Changes

| File | Lines Changed | What |
|------|---------------|------|
| `dataplane/novanet-common/src/lib.rs` | ~25 added | SockLbOrigin struct, constant, tests |
| `dataplane/novanet-ebpf/src/main.rs` | ~200 added, ~35 removed | 4 cgroup programs, sock_service_lookup, remove TC ClusterIP DNAT |
| `dataplane/novanet-dataplane/src/loader.rs` | ~15 added | Load CgroupSockAddr programs |
| `dataplane/novanet-dataplane/src/maps.rs` | ~40 added | Cgroup attach/detach, link storage |
| `dataplane/novanet-dataplane/src/main.rs` | ~5 added | Call attach_cgroup_programs on startup |
| `deploy/argocd/application.yaml` | ~2 changed | Bump image tags |

**No changes to:** Go agent, proto definitions, Helm chart values, novanetctl, network policy enforcement.
