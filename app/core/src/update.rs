//! Self-update: check the GitHub Releases of the app repo for a newer
//! version and (best-effort) download the release `.dmg`.
//!
//! P4 implements the check (real, against the Releases API) and a v1
//! apply that downloads the `.dmg` and opens it for a drag-install. A
//! fully silent swap of the running `.app` (verify notarization via
//! `spctl`, replace in place) is a follow-up once signed releases exist.

use std::time::Duration;

use anyhow::{Context, Result};

/// App release repo (owner/name) the updater watches.
const RELEASE_REPO: &str = "fastverk/fastverk";

/// Result of an update check.
pub struct UpdateInfo {
    pub available: bool,
    pub current: String,
    pub latest: String,
    pub url: String,
    pub notes: String,
}

fn current_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Check the release channel for a newer version. Returns
/// `available = false` (not an error) when there are no releases yet.
pub fn check() -> Result<UpdateInfo> {
    let current = current_version();
    let client = reqwest::blocking::Client::builder()
        .user_agent("fastverk-updater")
        .timeout(Duration::from_secs(15))
        .build()
        .context("build http client")?;
    let resp = client
        .get(format!(
            "https://api.github.com/repos/{RELEASE_REPO}/releases/latest"
        ))
        .header("Accept", "application/vnd.github+json")
        .send()
        .context("query releases")?;

    // No releases published yet → nothing to update to.
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(UpdateInfo {
            available: false,
            latest: current.clone(),
            current,
            url: String::new(),
            notes: String::new(),
        });
    }
    let json: serde_json::Value = resp
        .error_for_status()
        .context("releases request")?
        .json()
        .context("parse releases JSON")?;

    let latest = json["tag_name"]
        .as_str()
        .unwrap_or("")
        .trim_start_matches('v')
        .to_string();
    let url = json["assets"]
        .as_array()
        .and_then(|assets| {
            assets.iter().find_map(|a| {
                let name = a["name"].as_str().unwrap_or("");
                name.ends_with(".dmg")
                    .then(|| a["browser_download_url"].as_str().unwrap_or("").to_string())
            })
        })
        .unwrap_or_default();
    let notes = json["body"].as_str().unwrap_or("").to_string();

    Ok(UpdateInfo {
        available: is_newer(&latest, &current),
        latest: if latest.is_empty() {
            current.clone()
        } else {
            latest
        },
        current,
        url,
        notes,
    })
}

/// Download the latest release `.dmg` and open it (drag-install). Errors
/// when no newer release / no dmg asset is available.
pub fn apply() -> Result<()> {
    let info = check()?;
    if !info.available || info.url.is_empty() {
        anyhow::bail!("no newer release with a downloadable .dmg");
    }
    let client = reqwest::blocking::Client::builder()
        .user_agent("fastverk-updater")
        .timeout(Duration::from_secs(300))
        .build()?;
    let bytes = client
        .get(&info.url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .context("download dmg")?
        .bytes()
        .context("read dmg")?;

    let dest = directories::BaseDirs::new()
        .map(|d| d.home_dir().join("Downloads"))
        .unwrap_or_else(std::env::temp_dir)
        .join(format!("fastverk-{}.dmg", info.latest));
    std::fs::write(&dest, &bytes).with_context(|| format!("write {}", dest.display()))?;

    // v1: hand off to Finder for a drag-install. Silent in-place swap
    // (mount, verify notarization, replace the .app) is a follow-up.
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(&dest).status();
    }
    Ok(())
}

/// Compare dotted numeric versions; non-numeric segments fall back to a
/// string inequality check.
fn is_newer(latest: &str, current: &str) -> bool {
    if latest.is_empty() {
        return false;
    }
    let parse = |v: &str| -> Option<Vec<u64>> {
        v.split('.').map(|p| p.parse::<u64>().ok()).collect()
    };
    match (parse(latest), parse(current)) {
        (Some(l), Some(c)) => l > c,
        _ => latest != current,
    }
}

#[cfg(test)]
mod tests {
    use super::is_newer;

    #[test]
    fn version_compare() {
        assert!(is_newer("0.0.2", "0.0.1"));
        assert!(is_newer("0.1.0", "0.0.9"));
        assert!(!is_newer("0.0.1", "0.0.1"));
        assert!(!is_newer("0.0.1", "0.0.2"));
        assert!(!is_newer("", "0.0.1"));
    }
}
