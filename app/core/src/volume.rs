//! Managed filesystem volumes: one for git repos + worktrees, one for
//! Bazel caches.
//!
//! On macOS these are APFS volumes in the boot container, created with
//! `diskutil apfs addVolume` behind an on-demand admin elevation prompt
//! (see [`crate::platform`]). [`status`] is read-only and safe to call
//! anywhere; [`create`] mutates and is P1.

use std::path::Path;
use std::process::Command;

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

/// Observed state of every managed volume, with usage from `df`.
pub fn status() -> Result<Vec<VolumeState>> {
    Ok(default_specs()
        .into_iter()
        .map(|spec| {
            let mounted = Path::new(&spec.mount_point).is_dir();
            let (used_bytes, free_bytes, device) = if mounted {
                df(&spec.mount_point).unwrap_or((0, 0, String::new()))
            } else {
                (0, 0, String::new())
            };
            VolumeState {
                spec: Some(spec),
                exists: mounted,
                mounted,
                used_bytes,
                free_bytes,
                device,
            }
        })
        .collect())
}

/// `(used_bytes, free_bytes, device)` for a mount point via `df -kP`.
fn df(mount: &str) -> Option<(i64, i64, String)> {
    let out = Command::new("df").args(["-kP", mount]).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout);
    let fields: Vec<&str> = s.lines().nth(1)?.split_whitespace().collect();
    if fields.len() < 4 {
        return None;
    }
    let used = fields[2].parse::<i64>().ok()? * 1024;
    let free = fields[3].parse::<i64>().ok()? * 1024;
    let device = fields[0].trim_start_matches("/dev/").to_string();
    Some((used, free, device))
}

/// Create + mount a managed volume by id (`"repos"`, `"caches"`, `"all"`).
pub fn create(_id: &str) -> Result<Vec<VolumeState>> {
    anyhow::bail!("TODO(P1): APFS addVolume + mount (diskutil, osascript elevation)")
}
