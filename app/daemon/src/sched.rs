//! fvd's internal scheduler: periodic background maintenance + update
//! checks (the "runs cache/bazel cleaning + updates in the background"
//! value prop). Runs as a tokio task alongside the gRPC server.
//!
//! Cadence is `$FASTVERK_MAINTAIN_INTERVAL_SECS` (default 6h); `0`
//! disables it. The first tick is skipped so startup isn't a maintenance
//! storm. Blocking work (git/disk) runs on `spawn_blocking`.

use std::time::Duration;

const DEFAULT_INTERVAL_SECS: u64 = 6 * 60 * 60;

pub async fn run() {
    let secs = std::env::var("FASTVERK_MAINTAIN_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);
    if secs == 0 {
        tracing::info!("scheduler disabled (FASTVERK_MAINTAIN_INTERVAL_SECS=0)");
        return;
    }
    tracing::info!(interval_secs = secs, "scheduler started");

    let mut tick = tokio::time::interval(Duration::from_secs(secs));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    tick.tick().await; // consume the immediate first tick

    // Remember the version we last notified about, so a standing update
    // doesn't re-notify every cycle.
    let mut notified_version: Option<String> = None;
    loop {
        tick.tick().await;
        run_once(&mut notified_version).await;
    }
}

async fn run_once(notified_version: &mut Option<String>) {
    // Keep the configured org/group repos in sync with the repos volume.
    if let Ok(cfg) = fvkit::config::Config::load() {
        let (repos_dir, meta, sources) = (cfg.repos_dir(), cfg.meta_repo_name(), cfg.sources);
        if !sources.is_empty() {
            match tokio::task::spawn_blocking(move || {
                fvkit::repos::sync_sources(&repos_dir, &sources, &meta, true, false)
            })
            .await
            {
                Ok(Ok(reports)) => {
                    let n = |a: &str| {
                        reports
                            .iter()
                            .flat_map(|r| &r.outcomes)
                            .filter(|o| o.action == a)
                            .count()
                    };
                    tracing::info!(cloned = n("cloned"), updated = n("updated"), "scheduler: repo sync");
                }
                Ok(Err(e)) => tracing::warn!(error = %e, "scheduler: repo sync failed"),
                Err(e) => tracing::warn!(error = %e, "scheduler: repo sync panicked"),
            }
        }
    }

    tracing::info!("scheduler: maintenance run");
    match tokio::task::spawn_blocking(|| fvkit::maintain::run(false, &[])).await {
        Ok(Ok(report)) => {
            let ok = report.tasks.iter().filter(|t| t.ok).count();
            tracing::info!(ok, total = report.tasks.len(), "scheduler: maintenance done");
        }
        Ok(Err(e)) => tracing::warn!(error = %e, "scheduler: maintenance failed"),
        Err(e) => tracing::warn!(error = %e, "scheduler: maintenance panicked"),
    }
    if let Ok(Ok(info)) = tokio::task::spawn_blocking(fvkit::update::check).await {
        if info.available {
            tracing::info!(latest = %info.latest, "scheduler: update available");
            // Notify once per new version (not every 6h cycle).
            if notified_version.as_deref() != Some(info.latest.as_str()) {
                fvkit::notify::send("fastverk", &format!("Update available: v{}", info.latest));
                *notified_version = Some(info.latest);
            }
        }
    }
}
