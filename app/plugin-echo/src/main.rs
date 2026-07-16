//! `plugin-echo` — a trivial fastverk plugin sidecar used to prove the plugin
//! spine end to end. It serves only the `Plugin` meta-service (the QueryRPC
//! "IUnknown"): `Describe` returns its manifest + health. Its manifest
//! advertises a `fastverk.echo.v1.Echo` interface (which a later slice will
//! actually serve + route); for P0 the host proves discovery + lifecycle via
//! `Describe`.
//!
//! The host spawns it with `$FASTVERK_PLUGIN_SOCKET` and dials that UDS. It
//! lives in the fvkit workspace, so it shares fvkit's tonic/tokio (no
//! cross-crate runtime mismatch) and can reuse `fvkit::ipc::bind`.

use fvkit::plugin_proto::{
    plugin_server::{Plugin, PluginServer},
    DescribeRequest, DescribeResponse, Lifecycle, PluginManifest, Privilege, Runtime, ServiceRef,
};
use tonic::{Request, Response, Status};

struct EchoPlugin;

#[tonic::async_trait]
impl Plugin for EchoPlugin {
    async fn describe(
        &self,
        _request: Request<DescribeRequest>,
    ) -> Result<Response<DescribeResponse>, Status> {
        Ok(Response::new(DescribeResponse {
            manifest: Some(manifest()),
            healthy: true,
        }))
    }
}

fn manifest() -> PluginManifest {
    PluginManifest {
        id: "echo".to_string(),
        display_name: "Echo".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        services: vec![
            ServiceRef {
                name: "fastverk.plugin.v1.Plugin".to_string(),
            },
            ServiceRef {
                name: "fastverk.echo.v1.Echo".to_string(),
            },
        ],
        runtime: Runtime::Sidecar as i32,
        lifecycle: Lifecycle::OnDemand as i32,
        privilege: Privilege::User as i32,
        sidecar_binary: "plugin-echo".to_string(),
        sidecar_args: vec![],
        panels: vec![],
        server_services: vec![],
        // Echo serves no `POST /mcp` and contributes no web routes. Defaulting
        // the rest keeps this example from breaking every time the manifest
        // gains a field (as `web_routes` did), matching the daemon's pattern.
        ..Default::default()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let socket = std::env::var("FASTVERK_PLUGIN_SOCKET")
        .map_err(|_| anyhow::anyhow!("FASTVERK_PLUGIN_SOCKET is not set"))?;
    // Same tonic/tokio as fvkit (one workspace), so reusing fvkit's UDS bind is
    // safe here — no separate-reactor mismatch.
    let incoming = fvkit::ipc::bind(std::path::Path::new(&socket))?;
    tonic::transport::Server::builder()
        .add_service(PluginServer::new(EchoPlugin))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}
