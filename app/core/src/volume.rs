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

use crate::proto::{VolumeAudit, VolumeDisposition, VolumeSpec, VolumeState};

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

/// One row of the system mount table: where a device is mounted + its fs.
struct MountEntry {
    mountpoint: String,
    fstype: String,
}

/// Parse `mount(8)` into mount-point → filesystem-type rows. Handles both
/// the macOS format (`/dev/disk on /mnt (apfs, local, …)`) and the Linux
/// format (`/dev/sda1 on /mnt type ext4 (rw,…)`). Returns empty when the
/// command is unavailable or unparsable — callers treat that as "unknown".
fn mount_table() -> Vec<MountEntry> {
    let out = match Command::new("mount").output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(parse_mount_line)
        .collect()
}

/// Parse one `mount` line into `(mountpoint, fstype)`.
fn parse_mount_line(line: &str) -> Option<MountEntry> {
    let (_device, rest) = line.split_once(" on ")?;
    if let Some(idx) = rest.find(" type ") {
        // Linux: "<mnt> type <fs> (opts)".
        let mountpoint = rest[..idx].to_string();
        let fstype = rest[idx + 6..].split_whitespace().next()?.to_string();
        Some(MountEntry { mountpoint, fstype })
    } else if let Some(idx) = rest.find(" (") {
        // macOS/BSD: "<mnt> (<fs>, opts)".
        let mountpoint = rest[..idx].to_string();
        let fstype = rest[idx + 2..]
            .trim_end_matches(')')
            .split(',')
            .next()?
            .trim()
            .to_string();
        Some(MountEntry { mountpoint, fstype })
    } else {
        None
    }
}

/// Audit every managed location **without changing anything**. For each
/// location it reports whether fastverk would create a new dedicated
/// volume (absent), adopt the existing one as-is (already a dedicated
/// mount), or augment a plain folder in place (data lives on a shared
/// volume). This is the safety contract: an install inspects first and
/// never mounts over or reformats a location that already holds data.
pub fn audit() -> Result<Vec<VolumeAudit>> {
    let table = mount_table();
    Ok(default_specs()
        .into_iter()
        .map(|spec| audit_one(spec, &table))
        .collect())
}

/// Audit a single location against the mount table (infallible — missing
/// `df`/`mount` data degrades to "absent/unknown", never an error).
fn audit_one(spec: VolumeSpec, table: &[MountEntry]) -> VolumeAudit {
    let mp = spec.mount_point.clone();
    let exists = Path::new(&mp).exists();
    let mount = table.iter().find(|e| e.mountpoint == mp);
    let dedicated = mount.is_some();
    let fs_type = mount.map_or(String::new(), |e| e.fstype.clone());
    let (used_bytes, free_bytes, device) = if exists {
        df(&mp).unwrap_or_default()
    } else {
        (0, 0, String::new())
    };

    let (disposition, detail) = if !exists {
        (
            VolumeDisposition::Create,
            format!(
                "absent — fastverk will create a dedicated APFS volume \"{}\" at {mp}",
                spec.fs_volume
            ),
        )
    } else if dedicated {
        let kind = if fs_type.is_empty() {
            "dedicated".to_string()
        } else {
            format!("dedicated {}", fs_type.to_uppercase())
        };
        (
            VolumeDisposition::Adopt,
            format!("already a {kind} volume at {mp} — adopted as-is and left untouched"),
        )
    } else {
        (
            VolumeDisposition::Migrate,
            format!(
                "{mp} is a folder on a shared volume — used in place and augmented \
                 (never mounted over or overwritten); can later be moved onto a \
                 dedicated volume"
            ),
        )
    };

    VolumeAudit {
        state: Some(VolumeState {
            spec: Some(spec),
            exists,
            mounted: dedicated,
            used_bytes,
            free_bytes,
            device,
        }),
        disposition: disposition as i32,
        fs_type,
        dedicated_volume: dedicated,
        detail,
    }
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

/// Provision managed APFS volume(s) by id. **Audit-driven and
/// non-destructive**: only locations the audit classifies as `Create`
/// (genuinely absent) get a new volume via `diskutil apfs addVolume`;
/// `Adopt`/`Migrate` locations already hold data and are left in place
/// (never mounted over), so an install can never clobber existing volumes.
/// Creation runs once behind a single admin elevation prompt. `dry_run`
/// returns the planned command without elevating. Returns `(post-state,
/// human message)`.
#[cfg(target_os = "macos")]
pub fn create(id: &str, dry_run: bool) -> Result<(Vec<VolumeState>, String)> {
    let targets = select(id)?;
    let want: std::collections::HashSet<String> =
        targets.iter().map(|s| s.id.clone()).collect();
    let audits: Vec<VolumeAudit> = audit()?
        .into_iter()
        .filter(|a| {
            a.state
                .as_ref()
                .and_then(|s| s.spec.as_ref())
                .is_some_and(|sp| want.contains(&sp.id))
        })
        .collect();

    let mut to_create: Vec<VolumeSpec> = Vec::new();
    let mut adopted: Vec<String> = Vec::new();
    for a in &audits {
        let Some(spec) = a.state.as_ref().and_then(|s| s.spec.clone()) else {
            continue;
        };
        if a.disposition == VolumeDisposition::Create as i32 {
            to_create.push(spec);
        } else {
            // Adopt / Migrate / Conflict: data may already be here — never
            // mount over it. Report it as left-in-place.
            adopted.push(format!("{} ({})", spec.id, a.detail));
        }
    }

    let mut msg = String::new();
    if !adopted.is_empty() {
        msg.push_str(&format!("left in place: {}. ", adopted.join("; ")));
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

#[cfg(test)]
mod tests {
    use super::parse_mount_line;

    #[test]
    fn parses_macos_and_linux_mount_lines() {
        // macOS/BSD format.
        let m = parse_mount_line("/dev/disk3s5 on /Volumes/Workspace (apfs, local, journaled)")
            .expect("macos line");
        assert_eq!(m.mountpoint, "/Volumes/Workspace");
        assert_eq!(m.fstype, "apfs");

        // Root volume on macOS (sealed/read-only).
        let r = parse_mount_line("/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)")
            .expect("root line");
        assert_eq!(r.mountpoint, "/");
        assert_eq!(r.fstype, "apfs");

        // Linux format.
        let l = parse_mount_line("/dev/sda1 on /mnt/data type ext4 (rw,relatime)")
            .expect("linux line");
        assert_eq!(l.mountpoint, "/mnt/data");
        assert_eq!(l.fstype, "ext4");

        // Garbage / header lines yield nothing.
        assert!(parse_mount_line("not a mount line").is_none());
    }
}
