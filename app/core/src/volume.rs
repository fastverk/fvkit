//! Managed filesystem volumes: one for git repos + worktrees, one for
//! Bazel caches.
//!
//! On macOS these are APFS volumes in the boot container, created with
//! `diskutil apfs addVolume` behind an on-demand admin elevation prompt
//! (see [`crate::platform`]). [`status`] is read-only and safe to call
//! anywhere; [`create`] mutates and is P1.

use anyhow::Result;

use crate::proto::{VolumeSpec, VolumeState};

/// The volumes fastverk manages by default.
#[must_use]
pub fn default_specs() -> Vec<VolumeSpec> {
    vec![
        VolumeSpec {
            id: "repos".to_string(),
            display_name: "Repos & worktrees".to_string(),
            mount_point: "/Volumes/Workspace".to_string(),
            fs_volume: "Workspace".to_string(),
            quota_bytes: 0,
        },
        VolumeSpec {
            id: "caches".to_string(),
            display_name: "Bazel caches".to_string(),
            mount_point: "/Volumes/Cache".to_string(),
            fs_volume: "Cache".to_string(),
            quota_bytes: 0,
        },
    ]
}

/// Observed state of every managed volume. P0 reports mount presence;
/// P1 fills `used_bytes` / `free_bytes` / `device` from `diskutil`/statfs.
pub fn status() -> Result<Vec<VolumeState>> {
    Ok(default_specs()
        .into_iter()
        .map(|spec| {
            let mounted = std::path::Path::new(&spec.mount_point).is_dir();
            VolumeState {
                spec: Some(spec),
                exists: mounted,
                mounted,
                used_bytes: 0,
                free_bytes: 0,
                device: String::new(),
            }
        })
        .collect())
}

/// Create + mount a managed volume by id (`"repos"`, `"caches"`, `"all"`).
pub fn create(_id: &str) -> Result<Vec<VolumeState>> {
    anyhow::bail!("TODO(P1): APFS addVolume + mount (diskutil, osascript elevation)")
}
