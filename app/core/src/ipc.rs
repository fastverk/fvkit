//! Unix-domain-socket transport helpers shared by `fvd` (server) and the
//! gRPC clients (GUI, CLI, cred-helper).
//!
//! P0 provides the server-side bind helper (used by `fvd`). The client
//! connector helper lands in P1, when `fv`/`fastverk` start calling the
//! daemon (it needs the tower/hyper-util `connect_with_connector`
//! boilerplate).

use std::path::Path;

use anyhow::{Context, Result};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;

/// Bind a fresh UDS for `fvd`, removing any stale socket file first and
/// ensuring the parent directory exists. The returned stream is fed to
/// `tonic::transport::Server::serve_with_incoming`.
pub fn bind(path: &Path) -> Result<UnixListenerStream> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create socket dir {}", parent.display()))?;
    }
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("bind socket {}", path.display()))?;
    Ok(UnixListenerStream::new(listener))
}
