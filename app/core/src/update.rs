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
    /// The asset's `browser_download_url` (for display; needs auth for a
    /// private repo, so not used for the actual download).
    pub url: String,
    /// The asset's API URL (`…/releases/assets/<id>`). GET with
    /// `Accept: application/octet-stream` + the github token downloads the
    /// bytes even from a private repo — this is what `apply` uses.
    pub asset_api_url: String,
    pub notes: String,
}

fn current_version() -> String {
    crate::version().to_string()
}

/// Attach a GitHub auth header for the release/asset API. Tries
/// `$GITHUB_TOKEN` / `$GH_TOKEN` first (the reliable, prompt-free source in
/// headless/recovery/CI contexts) and falls back to the stored connection
/// token (Keychain) for normal interactive use. The updater is the recovery
/// channel, so it must authenticate from whatever source is available.
fn github_auth(req: reqwest::blocking::RequestBuilder) -> reqwest::blocking::RequestBuilder {
    for key in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Ok(v) = std::env::var(key) {
            if !v.is_empty() {
                return req.header("Authorization", format!("Bearer {v}"));
            }
        }
    }
    if let Ok(Some(cred)) = crate::connections::resolve("https://api.github.com/") {
        return req.header(cred.header, cred.value);
    }
    req
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
    // Use /releases (not /releases/latest): the latter 404s while the repo
    // is private or has only prereleases. Authenticate with the stored
    // github token when available (the repo is private) — falling back to
    // anonymous, which simply yields "no update" rather than an error.
    let mut req = client
        .get(format!(
            "https://api.github.com/repos/{RELEASE_REPO}/releases?per_page=10"
        ))
        .header("Accept", "application/vnd.github+json");
    req = github_auth(req);
    let resp = req.send().context("query releases")?;

    // Private/unauthorized/none → treat as "no update", not an error, so a
    // status snapshot never fails on the update check.
    let no_update = || UpdateInfo {
        available: false,
        latest: current.clone(),
        current: current.clone(),
        url: String::new(),
        asset_api_url: String::new(),
        notes: String::new(),
    };
    if matches!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND
            | reqwest::StatusCode::UNAUTHORIZED
            | reqwest::StatusCode::FORBIDDEN
    ) {
        return Ok(no_update());
    }
    let json: serde_json::Value = resp
        .error_for_status()
        .context("releases request")?
        .json()
        .context("parse releases JSON")?;

    // Newest non-draft release (the array is newest-first).
    let Some(rel) = json
        .as_array()
        .and_then(|rels| rels.iter().find(|r| !r["draft"].as_bool().unwrap_or(false)))
    else {
        return Ok(no_update());
    };

    let latest = rel["tag_name"]
        .as_str()
        .unwrap_or("")
        .trim_start_matches('v')
        .to_string();
    // The .dmg asset: capture both its browser URL (display) and its API
    // URL (the authenticated-download path for the private repo).
    let dmg = rel["assets"].as_array().and_then(|assets| {
        assets
            .iter()
            .find(|a| a["name"].as_str().unwrap_or("").ends_with(".dmg"))
    });
    let url = dmg
        .and_then(|a| a["browser_download_url"].as_str())
        .unwrap_or_default()
        .to_string();
    let asset_api_url = dmg
        .and_then(|a| a["url"].as_str())
        .unwrap_or_default()
        .to_string();
    let notes = rel["body"].as_str().unwrap_or("").to_string();

    Ok(UpdateInfo {
        available: is_newer(&latest, &current),
        latest: if latest.is_empty() {
            current.clone()
        } else {
            latest
        },
        current,
        url,
        asset_api_url,
        notes,
    })
}

/// Download the latest release `.dmg` and install it in place. This is the
/// recovery channel: it must keep working even when the rest of the app is
/// broken, so it's daemon-independent (called directly by `fv update`),
/// authenticates the private-repo download, and `force` re-installs the
/// latest even when it isn't strictly newer (to ship a fix at the same or
/// lower version). On macOS it mounts the dmg, replaces
/// `/Applications/fastverk.app`, and relaunches; elsewhere it downloads and
/// opens the dmg.
pub fn apply(force: bool) -> Result<()> {
    let info = check()?;
    if !force && !info.available {
        anyhow::bail!(
            "already up to date (v{}); use --force to reinstall the latest",
            info.current
        );
    }
    if info.asset_api_url.is_empty() && info.url.is_empty() {
        anyhow::bail!("the latest release ({}) has no .dmg asset", info.latest);
    }
    let bytes = download_dmg(&info).context("download release dmg")?;

    let dest = std::env::temp_dir().join(format!("fastverk-{}.dmg", info.latest));
    std::fs::write(&dest, &bytes).with_context(|| format!("write {}", dest.display()))?;

    #[cfg(target_os = "macos")]
    {
        swap_app_from_dmg(&dest).context("install the new .app from the dmg")?;
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = std::process::Command::new("open").arg(&dest).status();
    }
    crate::notify::send("fastverk", &format!("Updated to v{}", info.latest));
    Ok(())
}

/// Download the `.dmg` bytes, authenticating via the stored github token.
/// Prefers the API asset endpoint (works for a private repo); GitHub
/// redirects it to a signed URL, and reqwest drops the `Authorization`
/// header on that cross-host redirect, so the token never leaks.
fn download_dmg(info: &UpdateInfo) -> Result<Vec<u8>> {
    let client = reqwest::blocking::Client::builder()
        .user_agent("fastverk-updater")
        .timeout(Duration::from_secs(300))
        .build()
        .context("build http client")?;
    let via_api = !info.asset_api_url.is_empty();
    let mut req = client.get(if via_api {
        &info.asset_api_url
    } else {
        &info.url
    });
    if via_api {
        req = req.header("Accept", "application/octet-stream");
    }
    req = github_auth(req);
    let bytes = req
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .context("dmg request")?
        .bytes()
        .context("read dmg body")?;
    Ok(bytes.to_vec())
}

/// Mount the dmg, replace `/Applications/fastverk.app`, and relaunch. The
/// running binaries keep their open file handles, so replacing the bundle
/// underneath them is safe; the relaunch picks up the new version.
#[cfg(target_os = "macos")]
fn swap_app_from_dmg(dmg: &std::path::Path) -> Result<()> {
    use std::process::Command;
    let app = "/Applications/fastverk.app";
    let mnt = std::env::temp_dir().join(format!("fastverk-mnt-{}", std::process::id()));
    std::fs::create_dir_all(&mnt).ok();

    let ok = |c: &mut Command, what: &str| -> Result<()> {
        let s = c.status().with_context(|| format!("run {what}"))?;
        anyhow::ensure!(s.success(), "{what} failed");
        Ok(())
    };
    ok(
        Command::new("hdiutil")
            .args([
                "attach",
                &dmg.to_string_lossy(),
                "-nobrowse",
                "-quiet",
                "-mountpoint",
            ])
            .arg(&mnt),
        "hdiutil attach",
    )?;
    // Always detach, even if the copy fails.
    let copy = (|| -> Result<()> {
        let src = mnt.join("fastverk.app");
        anyhow::ensure!(src.is_dir(), "dmg has no fastverk.app");
        let _ = std::fs::remove_dir_all(app);
        ok(
            Command::new("cp").arg("-R").arg(&src).arg("/Applications/"),
            "cp app",
        )
    })();
    let _ = Command::new("hdiutil")
        .args(["detach", "-quiet"])
        .arg(&mnt)
        .status();
    let _ = std::fs::remove_dir_all(&mnt);
    copy?;

    // Best-effort de-quarantine (API/gh downloads aren't quarantined, so
    // EACCES on read-only bundle files here is harmless — stay quiet).
    let _ = Command::new("xattr")
        .args(["-dr", "com.apple.quarantine", app])
        .stderr(std::process::Stdio::null())
        .status();
    // Relaunch the menu-bar app (and refresh the ~/.local/bin/fv symlink).
    if let Some(home) = directories::BaseDirs::new() {
        let _ = std::os::unix::fs::symlink(
            format!("{app}/Contents/MacOS/fv"),
            home.home_dir().join(".local/bin/fv"),
        );
    }
    let _ = Command::new("pkill")
        .args(["-f", "fastverk.app/Contents/MacOS/fvd"])
        .status();
    let _ = Command::new("open").args(["-a", "fastverk"]).status();
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
