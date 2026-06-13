//! macOS backend: APFS volume creation, Keychain, `osascript` elevation,
//! LaunchAgent management. P1+ fills the bodies; the entry points are
//! declared now so the rest of `fvkit` can target them.

use anyhow::Result;

/// Run a shell command with administrator privileges via
/// `osascript -e 'do shell script "…" with administrator privileges'`.
/// This is the single elevation choke point (APFS volume creation). The
/// user is prompted by the OS; no persistent privileged daemon exists.
pub fn run_elevated(_script: &str) -> Result<String> {
    anyhow::bail!("TODO(P1): osascript do-shell-script with administrator privileges")
}
