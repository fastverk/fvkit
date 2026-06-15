//! Unix-domain-socket transport helpers shared by `fvd` (server) and the
//! gRPC clients (GUI, CLI, cred-helper).
//!
//! P0 provides the server-side bind helper (used by `fvd`). The client
//! connector helper lands in P1, when `fv`/`fastverk` start calling the
//! daemon (it needs the tower/hyper-util `connect_with_connector`
//! boilerplate).

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::{UnixListener, UnixStream};
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Channel, Endpoint, Uri};

use crate::proto::fvd_client::FvdClient;

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

/// Connect an `fvd` gRPC client over its Unix-domain socket. The HTTP
/// authority is a placeholder (ignored for UDS); the connector dials the
/// socket path. Mirrors tonic's canonical UDS-client example.
pub async fn connect(path: &Path) -> Result<FvdClient<Channel>> {
    let path = path.to_path_buf();
    let channel = Endpoint::try_from("http://[::1]:50051")
        .context("endpoint")?
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let path = path.clone();
            async move {
                let stream = UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .with_context(|| "connect to fvd socket")?;
    Ok(FvdClient::new(channel))
}

/// Connect to the default `fvd` socket, autostarting `fvd` if it isn't
/// running yet (waiting up to ~5s for the socket to come up).
pub async fn connect_default() -> Result<FvdClient<Channel>> {
    let sock = crate::paths::socket_path()?;
    if let Ok(client) = connect(&sock).await {
        return Ok(client);
    }
    spawn_fvd()?;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if let Ok(client) = connect(&sock).await {
            return Ok(client);
        }
    }
    connect(&sock)
        .await
        .context("fvd did not come up on its socket")
}

/// Spawn the `fvd` daemon detached.
fn spawn_fvd() -> Result<()> {
    let bin = find_fvd().context("could not locate the `fvd` binary")?;
    std::process::Command::new(&bin)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("spawn {}", bin.display()))?;
    Ok(())
}

/// Find the `fvd` binary: next to the current executable (the app bundle /
/// cargo target dir), else on `PATH`.
pub fn find_fvd() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        // Resolve symlinks: `fv` is typically reached via a ~/.local/bin/fv
        // symlink into the .app bundle, and current_exe() returns the symlink
        // path — canonicalize so the sibling lookup lands in the bundle.
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        if let Some(sibling) = exe.parent().map(|d| d.join("fvd")) {
            if sibling.is_file() {
                return Some(sibling);
            }
        }
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|d| d.join("fvd"))
            .find(|p| p.is_file())
    })
}
