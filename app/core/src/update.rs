//! Self-update: check a GitHub-Releases manifest, download the notarized
//! artifact, verify it (`spctl`/`codesign` on macOS), and swap the app.
//! Driven by `fvd` (the scheduler + the tray's "Check for Updates").
//! P4 implements download/verify/swap.

use anyhow::Result;

/// Result of an update check.
pub struct UpdateInfo {
    pub available: bool,
    pub current: String,
    pub latest: String,
    pub url: String,
    pub notes: String,
}

/// Check the release channel for a newer version.
pub fn check() -> Result<UpdateInfo> {
    let current = env!("CARGO_PKG_VERSION").to_string();
    // TODO(P4): query the GitHub-Releases manifest for the latest tag.
    Ok(UpdateInfo {
        available: false,
        latest: current.clone(),
        current,
        url: String::new(),
        notes: String::new(),
    })
}

/// Download, verify, and apply the latest release.
pub fn apply() -> Result<()> {
    anyhow::bail!("TODO(P4): download + verify (spctl/codesign) + swap .app")
}
