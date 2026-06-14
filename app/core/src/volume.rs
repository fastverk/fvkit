//! Managed filesystem volumes: one for git repos + worktrees, one for
//! Bazel caches.
//!
//! On macOS these are APFS volumes in the boot container, created with
//! `diskutil apfs addVolume` behind an on-demand admin elevation prompt
//! (see [`crate::platform`]). [`status`] is read-only and safe to call
//! anywhere; [`create`] mutates and is P1.

use std::path::Path;
use std::process::Command;

#[cfg(target_os = "macos")]
use anyhow::Context;
use anyhow::{bail, Result};

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

/// Volumes selected by `id` ("repos" | "caches" | "all").
fn select(id: &str) -> Result<Vec<VolumeSpec>> {
    let v: Vec<VolumeSpec> = default_specs()
        .into_iter()
        .filter(|s| id == "all" || s.id == id)
        .collect();
    if v.is_empty() {
        bail!("unknown volume id: {id} (use repos|caches|all)");
    }
    Ok(v)
}

/// Create + mount managed APFS volume(s) by id. Idempotent: already-mounted
/// volumes are skipped. Creation runs `diskutil apfs addVolume` once behind
/// a single admin elevation prompt. `dry_run` returns the planned command
/// without elevating. Returns `(post-state, human message)`.
#[cfg(target_os = "macos")]
pub fn create(id: &str, dry_run: bool) -> Result<(Vec<VolumeState>, String)> {
    let targets = select(id)?;
    let mut to_create = Vec::new();
    let mut skipped = Vec::new();
    for spec in targets {
        if Path::new(&spec.mount_point).is_dir() {
            skipped.push(spec.id);
        } else {
            to_create.push(spec);
        }
    }

    let mut msg = String::new();
    if !skipped.is_empty() {
        msg.push_str(&format!("already present: {}. ", skipped.join(", ")));
    }
    if to_create.is_empty() {
        if msg.is_empty() {
            msg.push_str("nothing to do");
        }
        return Ok((status()?, msg.trim().to_string()));
    }

    let container = detect_apfs_container()?;
    let script = to_create
        .iter()
        .map(|s| {
            format!(
                "diskutil apfs addVolume {container} APFS '{}' -mountpoint '{}'",
                s.fs_volume, s.mount_point
            )
        })
        .collect::<Vec<_>>()
        .join(" && ");

    if dry_run {
        msg.push_str(&format!("would run (admin): {script}"));
    } else {
        crate::platform::macos::run_elevated(&script).context("create APFS volume(s)")?;
        let names: Vec<String> = to_create.into_iter().map(|s| s.id).collect();
        msg.push_str(&format!("created: {}", names.join(", ")));
    }
    Ok((status()?, msg.trim().to_string()))
}

#[cfg(not(target_os = "macos"))]
pub fn create(_id: &str, _dry_run: bool) -> Result<(Vec<VolumeState>, String)> {
    let _ = select(_id)?;
    bail!("volume create is macOS-only for now (Linux/Windows backends are P6)")
}

/// The boot disk's synthesized APFS container (e.g. "disk3"), parsed from
/// `diskutil info /`.
#[cfg(target_os = "macos")]
fn detect_apfs_container() -> Result<String> {
    let out = Command::new("diskutil")
        .args(["info", "/"])
        .output()
        .context("diskutil info /")?;
    if !out.status.success() {
        bail!("`diskutil info /` failed");
    }
    let s = String::from_utf8_lossy(&out.stdout);
    // `diskutil info /` reports e.g. "APFS Container:   disk3"; fall back
    // to "Part of Whole:" (same container on a single-disk Mac).
    for key in ["APFS Container:", "Part of Whole:"] {
        for line in s.lines() {
            if let Some(rest) = line.trim().strip_prefix(key) {
                let dev = rest.trim();
                if !dev.is_empty() {
                    return Ok(dev.to_string());
                }
            }
        }
    }
    bail!("could not determine the APFS container from `diskutil info /`")
}
