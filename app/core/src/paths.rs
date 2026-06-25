//! Where fastverk keeps its state, and the well-known paths it owns.
//!
//! Mirrors the `directories::ProjectDirs` convention used elsewhere in
//! the workspace (`repos/rules_runpod/cli/src/config.rs`,
//! `repos/mycelium/.../cache.rs`). Every path is overridable via an
//! env var so the daemon, CLI, tests, and the cred-helper can be
//! pointed at a scratch location.

use std::path::PathBuf;

use crate::Result;
use anyhow::Context;

fn project_dirs() -> Option<directories::ProjectDirs> {
    directories::ProjectDirs::from("", "", "fastverk")
}

/// Root config/state directory. Honors `$FASTVERK_CONFIG_DIR`.
pub fn config_dir() -> Result<PathBuf> {
    if let Ok(v) = std::env::var("FASTVERK_CONFIG_DIR") {
        return Ok(PathBuf::from(v));
    }
    Ok(project_dirs()
        .context("could not resolve a config directory")?
        .config_dir()
        .to_path_buf())
}

/// Create the config directory if missing and return it.
pub fn ensure_config_dir() -> Result<PathBuf> {
    let d = config_dir()?;
    std::fs::create_dir_all(&d).with_context(|| format!("create {}", d.display()))?;
    Ok(d)
}

/// The persisted connection registry (prost-encoded `ConnectionRegistry`).
/// Read by both `fvd` and the standalone cred-helper fallback path.
pub fn registry_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("connections.pb"))
}

/// Unix-domain socket `fvd` listens on. Honors `$FASTVERK_SOCKET`.
pub fn socket_path() -> Result<PathBuf> {
    if let Ok(v) = std::env::var("FASTVERK_SOCKET") {
        return Ok(PathBuf::from(v));
    }
    if let Some(dirs) = project_dirs() {
        if let Some(rt) = dirs.runtime_dir() {
            return Ok(rt.join("fvd.sock"));
        }
    }
    Ok(config_dir()?.join("fvd.sock"))
}

/// The user's `~/.bazelrc`, which fastverk co-owns via a managed region.
pub fn user_bazelrc() -> Result<PathBuf> {
    Ok(directories::BaseDirs::new()
        .context("no home directory")?
        .home_dir()
        .join(".bazelrc"))
}
