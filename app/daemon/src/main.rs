//! `fvd` — the fastverk daemon.
//!
//! An unprivileged, user-level gRPC server over a Unix-domain socket
//! that wraps `fvkit` and is the single owner of mutable state. The
//! menu-bar GUI, the `fv` CLI, and the Bazel credential helper are all
//! clients. Runs under a LaunchAgent (P4); for dev, `bazel run
//! //app/daemon:fvd` or `cargo run -p fvd`.

use anyhow::Result;

mod sched;
mod server;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fvd=info,fvkit=info".into()),
        )
        .init();

    // Background maintenance + update checks alongside the gRPC server.
    tokio::spawn(sched::run());

    server::serve().await
}
