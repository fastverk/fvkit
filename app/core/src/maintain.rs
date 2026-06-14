//! Periodic maintenance: disk-cache GC, `git gc`, and worktree pruning
//! across the managed repos. Driven by `fvd`'s scheduler (P4) and
//! invokable on demand (`fv maintain`). Every task honors `validate_only`
//! (report what would happen without changing anything) and the `only`
//! filter.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use anyhow::Result;

use crate::config::Config;
use crate::proto::{MaintenanceReport, MaintenanceTask};

const GIB: u64 = 1024 * 1024 * 1024;

/// Run maintenance. `only` restricts to named tasks (empty = all).
pub fn run(validate_only: bool, only: &[String]) -> Result<MaintenanceReport> {
    let cfg = Config::load()?;
    let started = now_rfc3339();
    let want = |n: &str| only.is_empty() || only.iter().any(|x| x == n);

    let mut tasks = Vec::new();
    if want("disk-cache-gc") {
        tasks.push(disk_cache_gc(&cfg, validate_only));
    }
    if want("git-gc") {
        tasks.push(git_across_repos(
            &cfg,
            validate_only,
            "git-gc",
            &["gc", "--auto", "--quiet"],
        ));
    }
    if want("worktree-prune") {
        tasks.push(git_across_repos(
            &cfg,
            validate_only,
            "worktree-prune",
            &["worktree", "prune"],
        ));
    }

    Ok(MaintenanceReport {
        started_at: started,
        finished_at: now_rfc3339(),
        validate_only,
        tasks,
    })
}

fn task(name: &str, ok: bool, detail: String, bytes: i64) -> MaintenanceTask {
    MaintenanceTask {
        name: name.to_string(),
        ok,
        detail,
        bytes_reclaimed: bytes,
    }
}

/// Prune the disk cache to `disk_cache_max_gib` by deleting oldest files
/// first. No-op when under threshold or GC is disabled.
fn disk_cache_gc(cfg: &Config, validate_only: bool) -> MaintenanceTask {
    let name = "disk-cache-gc";
    if cfg.disk_cache_max_gib == 0 {
        return task(name, true, "disabled (disk_cache_max_gib=0)".to_string(), 0);
    }
    if !cfg.disk_cache.is_dir() {
        return task(name, true, "no disk cache present".to_string(), 0);
    }
    let max = cfg.disk_cache_max_gib * GIB;
    let mut files = Vec::new();
    let mut total = 0u64;
    collect_files(&cfg.disk_cache, &mut files, &mut total);
    if total <= max {
        return task(
            name,
            true,
            format!("under threshold ({}/{} GiB)", total / GIB, cfg.disk_cache_max_gib),
            0,
        );
    }
    files.sort_by_key(|(_, _, mtime)| *mtime);
    let mut reclaimed = 0u64;
    let mut removed = 0u64;
    for (path, len, _) in &files {
        if total - reclaimed <= max {
            break;
        }
        if validate_only || std::fs::remove_file(path).is_ok() {
            reclaimed += len;
            removed += 1;
        }
    }
    let verb = if validate_only { "would reclaim" } else { "reclaimed" };
    task(
        name,
        true,
        format!("{verb} {removed} files ({}/{} GiB)", total / GIB, cfg.disk_cache_max_gib),
        i64::try_from(reclaimed).unwrap_or(i64::MAX),
    )
}

/// Run a `git` subcommand in every managed repo checkout.
fn git_across_repos(cfg: &Config, validate_only: bool, name: &str, args: &[&str]) -> MaintenanceTask {
    let repos = managed_repos(&cfg.repos_dir());
    if !validate_only {
        for repo in &repos {
            let _ = Command::new("git").arg("-C").arg(repo).args(args).status();
        }
    }
    let verb = if validate_only { "would run on" } else { "ran on" };
    task(name, true, format!("{verb} {} repos", repos.len()), 0)
}

fn managed_repos(repos_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(repos_dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.join(".git").exists() {
                out.push(p);
            }
        }
    }
    out
}

fn collect_files(dir: &Path, out: &mut Vec<(PathBuf, u64, SystemTime)>, total: &mut u64) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        let p = e.path();
        if ft.is_dir() {
            collect_files(&p, out, total);
        } else if ft.is_file() {
            if let Ok(md) = e.metadata() {
                *total += md.len();
                out.push((p, md.len(), md.modified().unwrap_or(SystemTime::UNIX_EPOCH)));
            }
        }
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}
