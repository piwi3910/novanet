//! NovaNet dataplane daemon.
//!
//! On Linux: loads eBPF programs from a compiled object file, manages BPF maps,
//! and exposes a gRPC server on a Unix domain socket for the Go management agent.
//!
//! On macOS (development): runs with mock map implementations and no eBPF loading.

mod flows;
mod loader;
mod maps;
mod server;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tokio::net::UnixListener;
use tokio::signal;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tracing::info;

pub mod proto {
    tonic::include_proto!("novanet.v1");
}

/// NovaNet eBPF dataplane daemon.
#[derive(Parser, Debug)]
#[command(name = "novanet-dataplane", version, about)]
struct Args {
    /// Path to the compiled eBPF object file.
    #[arg(long, default_value = "/opt/novanet/novanet-ebpf")]
    bpf_object: PathBuf,

    /// Unix socket path for the gRPC server.
    #[arg(long, default_value = "/run/novanet/dataplane.sock")]
    socket: PathBuf,

    /// Run in standalone mode (no eBPF loading, mock maps).
    /// Automatically enabled on non-Linux platforms.
    #[arg(long)]
    standalone: bool,

    /// Log level filter (e.g. "info", "debug", "trace").
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&args.log_level)),
        )
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "NovaNet dataplane starting"
    );

    // Determine if we should use real eBPF or mock mode.
    let use_mock = args.standalone || !cfg!(target_os = "linux");
    if use_mock {
        info!("Running in standalone/mock mode (no eBPF programs loaded)");
    }

    // Create the map manager.
    let map_manager = if use_mock {
        maps::MapManager::new_mock()
    } else {
        #[cfg(target_os = "linux")]
        {
            info!(path = %args.bpf_object.display(), "Loading eBPF programs");
            let (mgr, flow_rx) =
                loader::load_ebpf(&args.bpf_object).context("Failed to load eBPF programs")?;

            // Start the flow event reader in the background.
            if let Some(rx) = flow_rx {
                tokio::spawn(async move {
                    flows::flow_reader_task(rx).await;
                });
            }

            // Attach cgroup socket-LB programs to root cgroup.
            if let Err(e) = mgr.attach_cgroup_programs() {
                tracing::warn!("Failed to attach cgroup socket-LB programs: {}", e);
            }

            mgr
        }
        #[cfg(not(target_os = "linux"))]
        {
            maps::MapManager::new_mock()
        }
    };

    // Create the gRPC service.
    let dataplane_service = server::DataplaneService::new(map_manager);
    let svc = proto::dataplane_control_server::DataplaneControlServer::new(dataplane_service);

    // Ensure the socket directory exists.
    if let Some(parent) = args.socket.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("Failed to create socket directory")?;
    }

    // Remove stale socket file if it exists.
    if args.socket.exists() {
        tokio::fs::remove_file(&args.socket)
            .await
            .context("Failed to remove stale socket")?;
    }

    // Bind the Unix domain socket.
    let uds = UnixListener::bind(&args.socket).context("Failed to bind Unix socket")?;
    let uds_stream = UnixListenerStream::new(uds);

    info!(socket = %args.socket.display(), "gRPC server listening");

    // Run the gRPC server with graceful shutdown on SIGTERM/SIGINT.
    Server::builder()
        .add_service(svc)
        .serve_with_incoming_shutdown(uds_stream, async {
            shutdown_signal().await;
            info!("Shutdown signal received, stopping gRPC server");
        })
        .await
        .context("gRPC server error")?;

    info!("NovaNet dataplane stopped");
    Ok(())
}

/// Wait for SIGTERM or SIGINT.
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
