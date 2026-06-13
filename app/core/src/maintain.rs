//! Periodic maintenance: disk-cache GC, `bazel clean`/shutdown of idle
//! workspaces, `git gc` + `git worktree prune` across managed repos, and
//! an update check. Driven by `fvd`'s internal scheduler (P4) and
//! invokable on demand.
//!
//! P0 returns a well-formed (empty) report so the wiring — `fvd`
//! `MaintainNow`, the CLI, and the tray status — can be exercised end to
//! end before the real tasks land in P1.

use anyhow::Result;

use crate::proto::{MaintenanceReport, MaintenanceTask};

/// Run maintenance. `only` restricts to named tasks (empty = all).
/// `validate_only` reports what would be done without changing anything.
pub fn run(validate_only: bool, _only: &[String]) -> Result<MaintenanceReport> {
    let now = now_rfc3339();
    Ok(MaintenanceReport {
        started_at: now.clone(),
        finished_at: now,
        validate_only,
        tasks: vec![MaintenanceTask {
            name: "noop".to_string(),
            ok: true,
            detail: "TODO(P1): disk-cache GC, bazel clean, git gc, worktree prune".to_string(),
            bytes_reclaimed: 0,
        }],
    })
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}
