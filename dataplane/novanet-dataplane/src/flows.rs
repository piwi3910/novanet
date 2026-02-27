//! Flow event reader and streaming.
//!
//! Reads `FlowEvent` structs from the eBPF ring buffer and distributes them
//! to connected gRPC stream subscribers.

#[cfg(target_os = "linux")]
use novanet_common::FlowEvent as RawFlowEvent;
use tokio::sync::broadcast;

/// Capacity of the broadcast channel for flow events.
const FLOW_CHANNEL_CAPACITY: usize = 4096;

/// Global flow event broadcaster. Subscribers (gRPC StreamFlows clients)
/// receive a clone of the broadcast receiver.
static FLOW_BROADCASTER: std::sync::OnceLock<broadcast::Sender<crate::proto::FlowEvent>> =
    std::sync::OnceLock::new();

/// Get (or initialize) the global flow event broadcaster.
pub fn flow_broadcaster() -> &'static broadcast::Sender<crate::proto::FlowEvent> {
    FLOW_BROADCASTER.get_or_init(|| {
        let (tx, _) = broadcast::channel(FLOW_CHANNEL_CAPACITY);
        tx
    })
}

/// Subscribe to flow events. Returns a broadcast receiver.
pub fn subscribe_flows() -> broadcast::Receiver<crate::proto::FlowEvent> {
    flow_broadcaster().subscribe()
}

/// Convert a raw eBPF FlowEvent to the protobuf FlowEvent.
#[cfg(target_os = "linux")]
fn raw_to_proto(raw: &RawFlowEvent) -> crate::proto::FlowEvent {
    use crate::proto::{DropReason, PolicyAction};

    let verdict = match raw.verdict {
        novanet_common::ACTION_ALLOW => PolicyAction::Allow as i32,
        _ => PolicyAction::Deny as i32,
    };

    let drop_reason = match raw.drop_reason {
        novanet_common::DROP_REASON_NONE => DropReason::None as i32,
        novanet_common::DROP_REASON_POLICY_DENIED => DropReason::PolicyDenied as i32,
        novanet_common::DROP_REASON_NO_IDENTITY => DropReason::NoIdentity as i32,
        novanet_common::DROP_REASON_NO_ROUTE => DropReason::NoRoute as i32,
        novanet_common::DROP_REASON_NO_TUNNEL => DropReason::NoTunnel as i32,
        novanet_common::DROP_REASON_TTL_EXCEEDED => DropReason::TtlExceeded as i32,
        _ => DropReason::None as i32,
    };

    crate::proto::FlowEvent {
        src_ip: raw.src_ip,
        dst_ip: raw.dst_ip,
        src_identity: raw.src_identity,
        dst_identity: raw.dst_identity,
        protocol: raw.protocol as u32,
        src_port: raw.src_port as u32,
        dst_port: raw.dst_port as u32,
        verdict,
        bytes: raw.bytes,
        packets: raw.packets,
        timestamp_ns: raw.timestamp_ns as i64,
        drop_reason,
        tcp_flags: raw.tcp_flags as u32,
    }
}

/// Background task that reads flow events from the eBPF ring buffer.
/// Only runs on Linux with real eBPF maps.
#[cfg(target_os = "linux")]
pub async fn flow_reader_task(mut ring_buf: aya::maps::RingBuf<aya::maps::MapData>) {
    use std::mem;
    use std::os::fd::AsRawFd;
    use tokio::io::unix::AsyncFd;
    use tokio::io::Interest;

    let tx = flow_broadcaster();

    tracing::info!("Flow event reader started (epoll mode)");

    // Wrap the ring buffer's file descriptor in AsyncFd for epoll-based notification.
    let fd = ring_buf.as_raw_fd();
    let async_fd = match AsyncFd::with_interest(
        // Safety: the fd is owned by ring_buf which outlives this task.
        unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) },
        Interest::READABLE,
    ) {
        Ok(afd) => afd,
        Err(e) => {
            tracing::warn!("Failed to create AsyncFd for ring buffer, falling back to polling: {}", e);
            // Fallback to polling mode.
            flow_reader_task_polling(ring_buf).await;
            return;
        }
    };

    loop {
        // Wait until the ring buffer becomes readable.
        let mut guard = match async_fd.readable().await {
            Ok(g) => g,
            Err(e) => {
                tracing::warn!("AsyncFd readable error: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        // Drain all available events.
        let mut count = 0u64;
        while let Some(item) = ring_buf.next() {
            let data = item.as_ref();
            if data.len() < mem::size_of::<RawFlowEvent>() {
                tracing::warn!(
                    len = data.len(),
                    expected = mem::size_of::<RawFlowEvent>(),
                    "Short flow event from ring buffer"
                );
                continue;
            }

            // SAFETY: Length is validated above (data.len() >= size_of::<RawFlowEvent>()).
            // The pointer comes from a ring buffer item provided by aya, which guarantees alignment.
            let raw: &RawFlowEvent = unsafe { &*(data.as_ptr() as *const RawFlowEvent) };
            let proto_event = raw_to_proto(raw);
            if tx.send(proto_event).is_err() {
                // No active subscribers — not an error.
            }
            count += 1;
        }

        if count > 0 {
            tracing::debug!(count, "Processed flow events");
        }

        // Clear readiness so we wait for the next epoll notification.
        guard.clear_ready();
    }
}

/// Fallback polling-based flow reader for when AsyncFd is not available.
#[cfg(target_os = "linux")]
async fn flow_reader_task_polling(mut ring_buf: aya::maps::RingBuf<aya::maps::MapData>) {
    use std::mem;

    let tx = flow_broadcaster();

    tracing::info!("Flow event reader started (polling mode)");

    loop {
        let mut count = 0u64;
        while let Some(item) = ring_buf.next() {
            let data = item.as_ref();
            if data.len() < mem::size_of::<RawFlowEvent>() {
                tracing::warn!(
                    len = data.len(),
                    expected = mem::size_of::<RawFlowEvent>(),
                    "Short flow event from ring buffer (polling)"
                );
                continue;
            }
            // SAFETY: Length is validated above (data.len() >= size_of::<RawFlowEvent>()).
            let raw: &RawFlowEvent = unsafe { &*(data.as_ptr() as *const RawFlowEvent) };
            let proto_event = raw_to_proto(raw);
            if tx.send(proto_event).is_err() {
                // No active subscribers — not an error.
            }
            count += 1;
        }
        if count > 0 {
            tracing::debug!(count, "Processed flow events (polling)");
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
}

/// Stub for non-Linux platforms — the flow reader does nothing.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub async fn flow_reader_task(_ring_buf: ()) {
    tracing::info!("Flow event reader is a no-op on this platform");
    // Just park forever.
    std::future::pending::<()>().await;
}
