//! Periodic maintenance: disk-cache GC, stale Bazel output-base GC, `git gc`,
//! and worktree pruning across the managed repos. Driven by `fvd`'s scheduler
//! (P4) and invokable on demand (`fv maintain`). Every task honors
//! `validate_only` (report what would happen without changing anything) and the
//! `only` filter.
//!
//! Maintenance is descriptor-driven: each task is a `MaintenanceTaskImpl`
//! exposing a `MaintenanceTaskSpec` (the data the scheduler, CLI, and meridian
//! UI read) and a `run`. The built-ins implement the trait in-process; the fvd
//! `Maintenance` gRPC service (maintenance.proto) exposes the same contract so
//! out-of-tree tasks can ship as plugins, routed by QueryRPC. `MaintainNow` is
//! the "run all" aggregate over the registry.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use fvkit_core::Result;

use fvkit_core::config::Config;
use fvkit_core::proto::{MaintenanceReport, MaintenanceTask, MaintenanceTaskSpec, Schedule};

const GIB: u64 = 1024 * 1024 * 1024;
const HOUR: u32 = 3600;
const DAY: u32 = 86400;

/// One maintenance task: its descriptor (`spec`) and how to `run` it. Built-in
/// tasks implement this in-process; the fvd `Maintenance` service exposes the
/// same contract over gRPC so a maintenance plugin can implement it too. `run`
/// honors `validate_only` (preview — change nothing).
pub trait MaintenanceTaskImpl: Send + Sync {
    fn spec(&self) -> MaintenanceTaskSpec;
    fn run(&self, cfg: &Config, validate_only: bool) -> MaintenanceTask;
}

/// The built-in task registry — the single source of truth for what runs.
/// Adding a task is adding an entry here (or, later, installing a plugin that
/// implements the `Maintenance` service).
fn registry() -> Vec<Box<dyn MaintenanceTaskImpl>> {
    vec![
        Box::new(DiskCacheGc),
        Box::new(OutputBaseGc),
        Box::new(GitGc),
        Box::new(WorktreePrune),
    ]
}

/// The specs of every built-in task — drives `fv maintain list`, the scheduler,
/// and the meridian maintenance panel (the `Maintenance.ListTasks` RPC).
pub fn specs() -> Vec<MaintenanceTaskSpec> {
    registry().iter().map(|t| t.spec()).collect()
}

/// Run maintenance. `only` restricts to named task ids (empty = every task
/// whose spec is `default_enabled`). The "run all" aggregate behind
/// `Fvd.MaintainNow`.
pub fn run(validate_only: bool, only: &[String]) -> Result<MaintenanceReport> {
    let cfg = Config::load()?;
    let started = now_rfc3339();
    let tasks = registry()
        .iter()
        .filter(|t| {
            let s = t.spec();
            if only.is_empty() {
                s.default_enabled
            } else {
                only.iter().any(|x| x == &s.id)
            }
        })
        .map(|t| t.run(&cfg, validate_only))
        .collect();

    Ok(MaintenanceReport {
        started_at: started,
        finished_at: now_rfc3339(),
        validate_only,
        tasks,
    })
}

/// Run a single task by id — the `Maintenance.RunTask` interface. Returns
/// `None` when no task has that id (`E_NOINTERFACE`).
pub fn run_one(id: &str, validate_only: bool) -> Result<Option<MaintenanceTask>> {
    let cfg = Config::load()?;
    Ok(registry()
        .iter()
        .find(|t| t.spec().id == id)
        .map(|t| t.run(&cfg, validate_only)))
}

fn mk_spec(
    id: &str,
    display_name: &str,
    description: &str,
    interval_seconds: u32,
    scope: &str,
) -> MaintenanceTaskSpec {
    MaintenanceTaskSpec {
        id: id.to_string(),
        display_name: display_name.to_string(),
        description: description.to_string(),
        schedule: Some(Schedule { interval_seconds }),
        default_enabled: true,
        scope: scope.to_string(),
        reversible: true,
    }
}

fn task(name: &str, ok: bool, detail: String, bytes: i64) -> MaintenanceTask {
    MaintenanceTask {
        name: name.to_string(),
        ok,
        detail,
        bytes_reclaimed: bytes,
    }
}

// ── tasks ────────────────────────────────────────────────────────────────────

/// Prune the Bazel `--disk_cache` to `disk_cache_max_gib`, deleting oldest
/// files first. No-op when under threshold or GC is disabled.
struct DiskCacheGc;
impl MaintenanceTaskImpl for DiskCacheGc {
    fn spec(&self) -> MaintenanceTaskSpec {
        mk_spec(
            "disk-cache-gc",
            "Disk cache GC",
            "Trim the Bazel --disk_cache to its size cap, evicting oldest entries first.",
            DAY,
            "disk-cache",
        )
    }

    fn run(&self, cfg: &Config, validate_only: bool) -> MaintenanceTask {
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
}

/// Reclaim Bazel output bases under `output_user_root` whose source workspace
/// no longer exists — the "stale work trees" left behind by deleted repos,
/// removed git worktrees, and one-off scratchpad builds. Each output base
/// records its source path in a `DO_NOT_BUILD_HERE` marker; a base is orphaned
/// (pure waste, always safe to remove) iff that path is gone. The shared
/// `install` base and `cache` (repository cache) also live under this root and
/// are NOT output bases — they are skipped explicitly. Bazel marks output trees
/// read-only, so reclaim makes them writable first, then removes.
///
/// Cheap by design (a marker read per base, no `du`), so run it frequently and
/// the cache never fills from worktree churn. Bytes freed are the filesystem
/// free-space delta, not a tree walk.
struct OutputBaseGc;
impl MaintenanceTaskImpl for OutputBaseGc {
    fn spec(&self) -> MaintenanceTaskSpec {
        mk_spec(
            "output-base-gc",
            "Output-base GC",
            "Reclaim Bazel output bases whose source workspace no longer exists (stale work trees).",
            HOUR,
            "bazel-output",
        )
    }

    fn run(&self, cfg: &Config, validate_only: bool) -> MaintenanceTask {
        let name = "output-base-gc";
        let root = &cfg.output_user_root;
        if !root.is_dir() {
            return task(name, true, "no output_user_root present".to_string(), 0);
        }

        let mut orphans: Vec<PathBuf> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(root) {
            for e in rd.flatten() {
                let p = e.path();
                if !p.is_dir() {
                    continue;
                }
                // The shared install base + repository cache are not output bases.
                match p.file_name().and_then(|s| s.to_str()) {
                    Some("install") | Some("cache") => continue,
                    _ => {}
                }
                // Only real output bases carry the marker; its content is the
                // source workspace path. A missing path means it is orphaned.
                let Ok(src) = std::fs::read_to_string(p.join("DO_NOT_BUILD_HERE")) else {
                    continue;
                };
                let src = src.trim();
                if !src.is_empty() && !Path::new(src).exists() {
                    orphans.push(p);
                }
            }
        }

        if orphans.is_empty() {
            return task(name, true, "no orphaned output bases".to_string(), 0);
        }
        if validate_only {
            return task(
                name,
                true,
                format!("would reclaim {} orphaned output base(s)", orphans.len()),
                0,
            );
        }

        let before = avail_bytes(root);
        let mut removed = 0usize;
        for p in &orphans {
            // Output trees are read-only by design; make writable before removing.
            let _ = Command::new("chmod").arg("-R").arg("u+w").arg(p).status();
            if std::fs::remove_dir_all(p).is_ok() {
                removed += 1;
            }
        }
        let freed = avail_bytes(root).saturating_sub(before);
        task(
            name,
            removed == orphans.len(),
            format!("reclaimed {removed}/{} orphaned output base(s)", orphans.len()),
            i64::try_from(freed).unwrap_or(i64::MAX),
        )
    }
}

/// `git gc --auto` across the managed repos.
struct GitGc;
impl MaintenanceTaskImpl for GitGc {
    fn spec(&self) -> MaintenanceTaskSpec {
        mk_spec(
            "git-gc",
            "git gc",
            "Run `git gc --auto` across the managed repos.",
            DAY,
            "repos",
        )
    }

    fn run(&self, cfg: &Config, validate_only: bool) -> MaintenanceTask {
        git_across_repos(cfg, validate_only, "git-gc", &["gc", "--auto", "--quiet"])
    }
}

/// `git worktree prune` across the managed repos.
struct WorktreePrune;
impl MaintenanceTaskImpl for WorktreePrune {
    fn spec(&self) -> MaintenanceTaskSpec {
        mk_spec(
            "worktree-prune",
            "Worktree prune",
            "Run `git worktree prune` across the managed repos.",
            DAY,
            "repos",
        )
    }

    fn run(&self, cfg: &Config, validate_only: bool) -> MaintenanceTask {
        git_across_repos(cfg, validate_only, "worktree-prune", &["worktree", "prune"])
    }
}

// ── shared helpers ───────────────────────────────────────────────────────────

/// Available bytes on the filesystem holding `path`, via `df -k` (fast — no
/// per-file walk). The macOS/BSD + GNU `df -k` data line puts available-KiB at
/// column index 3. Returns 0 when it can't be read.
fn avail_bytes(path: &Path) -> u64 {
    let Ok(out) = Command::new("df").arg("-k").arg(path).output() else {
        return 0;
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .and_then(|line| line.split_whitespace().nth(3).map(str::to_string))
        .and_then(|kib| kib.parse::<u64>().ok())
        .map(|kib| kib * 1024)
        .unwrap_or(0)
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
