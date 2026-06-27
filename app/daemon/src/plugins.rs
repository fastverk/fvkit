//! fvd's plugin host.
//!
//! Discovers installed plugins, supervises their sidecars, and registers the
//! gRPC services each advertises so the daemon can route `(service, method)`
//! calls to the implementer ("QueryRPC"). Discovery is the plugin's
//! `Plugin.Describe` (the COM-`IUnknown` liveness + manifest echo); the
//! per-service [`Channel`] held here is what the generic router (a later slice)
//! forwards feature calls over.
//!
//! P0 proves the contract + lifecycle + discovery against the `plugin-echo`
//! sidecar; a service no installed plugin implements is gracefully absent
//! (`channel_for` returns `None` — `E_NOINTERFACE`).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use fvkit::plugin_proto::{plugin_client::PluginClient, DescribeRequest, PluginManifest};
use tonic::codegen::http;
use tonic::service::AxumBody;
use tonic::transport::Channel;
use tonic::Code;

/// A launched plugin: the manifest it reported, the channel to its sidecar, and
/// the child process (held so it stays alive while registered). The router
/// forwards feature calls over `channel`; `_child`/`_socket` keep the sidecar up.
pub struct PluginHandle {
    // Reported manifest, kept for introspection (panels/lifecycle) by later slices.
    #[allow(dead_code)]
    pub manifest: PluginManifest,
    pub channel: Channel,
    _child: tokio::process::Child,
    _socket: PathBuf,
}

/// The host's installed-plugin set + a `service → plugin` routing index.
#[derive(Default)]
pub struct Registry {
    /// fully-qualified service name → plugin id implementing it.
    routes: HashMap<String, String>,
    /// plugin id → handle.
    plugins: HashMap<String, PluginHandle>,
}

impl Registry {
    /// The channel serving `service`, if any installed plugin implements it
    /// (QueryRPC). `None` = no implementer (graceful `E_NOINTERFACE`). This is
    /// the hook the generic router ([`route`]) forwards over.
    #[must_use]
    pub fn channel_for(&self, service: &str) -> Option<Channel> {
        let id = self.routes.get(service)?;
        self.plugins.get(id).map(|h| h.channel.clone())
    }

    /// All registered (routable) service names, sorted.
    #[must_use]
    pub fn services(&self) -> Vec<String> {
        let mut v: Vec<String> = self.routes.keys().cloned().collect();
        v.sort();
        v
    }
}

/// The generic QueryRPC router: forward a feature call to the plugin that
/// implements its service.
///
/// gRPC is HTTP/2 with the path `/package.Service/Method`, so we route purely on
/// the *service* prefix and forward the request **verbatim** — the host never
/// compiles any plugin's stubs (the COM-style decoupling that lets a feature
/// live in its own repo). The body's length-prefixed protobuf frames pass
/// through untouched (proto-in/proto-out); the JSON↔proto path the dashboard
/// needs is a later slice. The owning [`Channel`] overwrites the authority with
/// the sidecar's, so only the path matters for dispatch.
///
/// A service no installed plugin implements yields a gRPC `Unimplemented` (12)
/// trailers-only response — the wire form of `E_NOINTERFACE`.
pub async fn route(reg: Arc<Registry>, req: http::Request<AxumBody>) -> http::Response<AxumBody> {
    // `/package.Service/Method` → service = everything before the final `/`.
    let Some((service, _method)) = req.uri().path().trim_start_matches('/').rsplit_once('/') else {
        return grpc_status(Code::Unimplemented, "malformed gRPC path");
    };
    let Some(channel) = reg.channel_for(service) else {
        return grpc_status(
            Code::Unimplemented,
            &format!("no plugin implements {service} (E_NOINTERFACE)"),
        );
    };
    let (parts, body) = req.into_parts();
    let upstream = http::Request::from_parts(parts, tonic::body::boxed(body));
    match tower::ServiceExt::oneshot(channel, upstream).await {
        Ok(resp) => resp.map(AxumBody::new),
        Err(e) => grpc_status(Code::Unavailable, &format!("plugin call failed: {e}")),
    }
}

/// A trailers-only gRPC response carrying just a status `code` + `message` (HTTP
/// 200, empty body, `grpc-status`/`grpc-message` in the headers) — the form
/// tonic itself uses for its default `unimplemented` fallback.
fn grpc_status(code: Code, message: &str) -> http::Response<AxumBody> {
    use http::header::{HeaderValue, CONTENT_TYPE};
    let mut resp = http::Response::new(AxumBody::empty());
    let headers = resp.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    headers.insert("grpc-status", HeaderValue::from(code as i32));
    if let Ok(v) = HeaderValue::from_str(message) {
        headers.insert("grpc-message", v);
    }
    resp
}

/// Spawn a sidecar plugin, wait for it, call `Plugin.Describe` (liveness + the
/// manifest it claims), and register the services it advertises. Returns the
/// plugin id. The sidecar serves gRPC on the UDS passed via
/// `$FASTVERK_PLUGIN_SOCKET`.
pub async fn launch_sidecar(reg: &mut Registry, binary: &Path, runtime_dir: &Path) -> Result<String> {
    std::fs::create_dir_all(runtime_dir)
        .with_context(|| format!("create plugin runtime dir {}", runtime_dir.display()))?;
    let stem = binary.file_stem().and_then(|s| s.to_str()).unwrap_or("plugin");
    let socket = runtime_dir.join(format!("{stem}.sock"));
    let _ = std::fs::remove_file(&socket);

    let child = tokio::process::Command::new(binary)
        .env("FASTVERK_PLUGIN_SOCKET", &socket)
        .stdin(Stdio::null())
        .spawn()
        .with_context(|| format!("spawn plugin {}", binary.display()))?;

    let channel = connect(&socket).await?;
    let desc = PluginClient::new(channel.clone())
        .describe(DescribeRequest {})
        .await
        .context("plugin Describe")?
        .into_inner();
    let manifest = desc.manifest.context("plugin returned no manifest")?;
    anyhow::ensure!(desc.healthy, "plugin '{}' reported unhealthy", manifest.id);

    let id = manifest.id.clone();
    for svc in &manifest.services {
        reg.routes.insert(svc.name.clone(), id.clone());
    }
    tracing::info!(
        plugin = %id,
        services = ?manifest.services.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
        "plugin registered",
    );
    reg.plugins.insert(
        id.clone(),
        PluginHandle { manifest, channel, _child: child, _socket: socket },
    );
    Ok(id)
}

/// Dial the sidecar's UDS, retrying ~5s while it starts up.
async fn connect(socket: &Path) -> Result<Channel> {
    for _ in 0..50 {
        if socket.exists() {
            if let Ok(ch) = fvkit::ipc::connect_channel(socket).await {
                return Ok(ch);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!("plugin socket {} did not come up", socket.display())
}

/// Install a plugin into the plugins dir as a self-contained directory: write
/// `<plugins_dir>/<id>/manifest.binpb` and copy its sidecar binary in beside it
/// (`<dir>/<sidecar_binary>`, executable). This is the runtime-install primitive
/// behind `fv module install`; `launch_installed` picks the result up on the
/// next fvd start. Returns the install dir.
///
/// `sidecar_src` is the built sidecar binary to stage; `manifest.sidecar_binary`
/// is the bare filename it's stored (and later resolved) as.
// The fvd binary itself never installs plugins — this primitive is consumed by
// the GUI's `fv module install` (a separate crate) + the install test here.
#[allow(dead_code)]
pub fn install(manifest: &PluginManifest, sidecar_src: &Path) -> Result<PathBuf> {
    use prost::Message;
    anyhow::ensure!(!manifest.id.is_empty(), "plugin manifest has no id");
    anyhow::ensure!(
        !manifest.sidecar_binary.is_empty(),
        "plugin '{}' manifest has no sidecar_binary",
        manifest.id,
    );
    let dir = plugins_dir().join(&manifest.id);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create plugin dir {}", dir.display()))?;

    let dest = dir.join(&manifest.sidecar_binary);
    std::fs::copy(sidecar_src, &dest)
        .with_context(|| format!("stage sidecar {} -> {}", sidecar_src.display(), dest.display()))?;
    make_executable(&dest)?;

    let manifest_path = dir.join("manifest.binpb");
    std::fs::write(&manifest_path, manifest.encode_to_vec())
        .with_context(|| format!("write manifest {}", manifest_path.display()))?;
    Ok(dir)
}

/// Ensure a staged sidecar is executable (a plain `fs::copy` preserves source
/// mode on Unix, but be explicit so a non-exec source still yields a runnable
/// install). No-op on non-Unix.
#[allow(clippy::unnecessary_wraps, dead_code)] // reachable only via `install` (see above).
fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(perms.mode() | 0o755);
        std::fs::set_permissions(path, perms)
            .with_context(|| format!("chmod +x {}", path.display()))?;
    }
    Ok(())
}

/// Launch every installed plugin: scan the plugins dir (`<dir>/<id>/manifest.binpb`,
/// each naming a `sidecar_binary` staged beside it). Missing/empty dir =
/// empty registry (graceful). Override the dir with `$FASTVERK_PLUGINS_DIR`.
pub async fn launch_installed() -> Registry {
    let mut reg = Registry::default();
    let dir = plugins_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return reg;
    };
    let rt = runtime_dir();
    for entry in entries.flatten() {
        let manifest_path = entry.path().join("manifest.binpb");
        if !manifest_path.is_file() {
            continue;
        }
        if let Err(e) = launch_from_manifest(&mut reg, &manifest_path, &rt).await {
            tracing::warn!(manifest = %manifest_path.display(), error = %e, "plugin launch failed");
        }
    }
    reg
}

async fn launch_from_manifest(reg: &mut Registry, manifest_path: &Path, runtime_dir: &Path) -> Result<()> {
    use prost::Message;
    let bytes = std::fs::read(manifest_path)
        .with_context(|| format!("read manifest {}", manifest_path.display()))?;
    let manifest = PluginManifest::decode(bytes.as_slice()).context("decode manifest")?;
    // Installed plugins are self-contained: the sidecar is staged beside its
    // manifest. Fall back to next-to-fvd / PATH (dev runs, shared sidecars).
    let beside = manifest_path.parent().map(|d| d.join(&manifest.sidecar_binary));
    let binary = beside
        .filter(|p| p.is_file())
        .or_else(|| resolve_binary(&manifest.sidecar_binary))
        .with_context(|| format!("locate sidecar binary '{}'", manifest.sidecar_binary))?;
    launch_sidecar(reg, &binary, runtime_dir).await?;
    Ok(())
}

/// Resolve a sidecar binary by name: next to fvd (the `.app` bundle / target
/// dir), else on `PATH`.
fn resolve_binary(name: &str) -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        if let Some(sib) = exe.parent().map(|d| d.join(name)) {
            if sib.is_file() {
                return Some(sib);
            }
        }
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path).map(|d| d.join(name)).find(|p| p.is_file())
    })
}

fn plugins_dir() -> PathBuf {
    if let Ok(d) = std::env::var("FASTVERK_PLUGINS_DIR") {
        return PathBuf::from(d);
    }
    fvkit::paths::config_dir()
        .map(|c| c.join("plugins"))
        .unwrap_or_else(|_| PathBuf::from("plugins"))
}

fn runtime_dir() -> PathBuf {
    if let Ok(d) = std::env::var("FASTVERK_RUNTIME_DIR") {
        return PathBuf::from(d);
    }
    fvkit::paths::config_dir()
        .map(|c| c.join("run"))
        .unwrap_or_else(|_| std::env::temp_dir())
}

#[cfg(test)]
mod tests {
    use super::*;

    // End-to-end: spawn the real plugin-echo sidecar (path via the test's
    // ECHO_PLUGIN_BIN env, set from a Bazel `data` dep), Describe it, and assert
    // its advertised service is registered + routable, and an unknown service is
    // gracefully absent. Skips under `cargo test` (no ECHO_PLUGIN_BIN).
    #[tokio::test]
    async fn launches_echo_plugin_and_registers_its_service() {
        let Ok(bin) = std::env::var("ECHO_PLUGIN_BIN") else {
            eprintln!("ECHO_PLUGIN_BIN unset; skipping (run via `bazel test`)");
            return;
        };
        let tmp = std::env::temp_dir().join(format!("fvd-plugin-test-{}", std::process::id()));
        let mut reg = Registry::default();

        let id = launch_sidecar(&mut reg, Path::new(&bin), &tmp)
            .await
            .expect("launch echo plugin");

        assert_eq!(id, "echo");
        assert!(
            reg.services().iter().any(|s| s == "fastverk.echo.v1.Echo"),
            "echo service registered; got {:?}",
            reg.services(),
        );
        assert!(reg.channel_for("fastverk.echo.v1.Echo").is_some());
        assert!(
            reg.channel_for("nonexistent.v1.Service").is_none(),
            "unknown service must be gracefully absent (E_NOINTERFACE)",
        );
    }

    // The production discovery path: `install` the echo plugin as a
    // self-contained dir, then `launch_installed` (the path fvd's main() runs)
    // scans it, decodes the manifest, resolves the staged sidecar, spawns it, and
    // registers its services. Proves install + auto-launch + manifest-decode +
    // resolve-beside-manifest. Skips under `cargo test` (no ECHO_PLUGIN_BIN).
    #[tokio::test]
    async fn installs_and_auto_launches_a_plugin() {
        let Ok(bin) = std::env::var("ECHO_PLUGIN_BIN") else {
            eprintln!("ECHO_PLUGIN_BIN unset; skipping (run via `bazel test`)");
            return;
        };
        let base = std::env::temp_dir().join(format!("fvd-install-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        // Short temp dirs keep the plugin's UDS under macOS's 104-char sun_path
        // limit, and isolate the test from the real config dir.
        std::env::set_var("FASTVERK_PLUGINS_DIR", base.join("plugins"));
        std::env::set_var("FASTVERK_RUNTIME_DIR", base.join("run"));

        let manifest = PluginManifest {
            id: "echo".to_string(),
            sidecar_binary: "plugin-echo".to_string(),
            ..Default::default()
        };
        let dir = install(&manifest, Path::new(&bin)).expect("install echo plugin");
        assert!(dir.join("manifest.binpb").is_file(), "manifest staged");
        assert!(dir.join("plugin-echo").is_file(), "sidecar staged beside manifest");

        let reg = launch_installed().await;

        assert!(
            reg.services().iter().any(|s| s == "fastverk.echo.v1.Echo"),
            "the installed plugin must auto-launch and register; got {:?}",
            reg.services(),
        );

        std::env::remove_var("FASTVERK_PLUGINS_DIR");
        std::env::remove_var("FASTVERK_RUNTIME_DIR");
        let _ = std::fs::remove_dir_all(&base);
    }

    // The router's graceful-absence path, exercised directly (no upstream): a
    // call to a service no plugin implements becomes a gRPC `Unimplemented` (12)
    // trailers-only response — E_NOINTERFACE on the wire. Runs under plain
    // `cargo test` (needs no sidecar).
    #[tokio::test]
    async fn routing_an_unimplemented_service_is_e_nointerface() {
        let reg = Arc::new(Registry::default());
        let req = http::Request::builder()
            .uri("/nope.v1.Missing/DoThing")
            .body(AxumBody::empty())
            .expect("build request");

        let resp = route(reg, req).await;

        assert_eq!(
            resp.headers().get("grpc-status").map(|v| v.as_bytes()),
            Some(b"12".as_ref()),
            "unknown service must answer gRPC Unimplemented (12)",
        );
    }
}
