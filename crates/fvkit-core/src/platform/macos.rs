//! macOS backend: APFS volume creation, Keychain (via fvkit::credstore),
//! `osascript` elevation, LaunchAgent management. The single elevation
//! choke point is [`run_elevated`] — no persistent privileged daemon
//! exists; the OS prompts the user when an action needs admin rights.

use std::process::Command;

use crate::Result;
use anyhow::Context;

/// Run a shell command with administrator privileges via
/// `osascript -e 'do shell script "…" with administrator privileges'`.
/// The OS shows the standard admin prompt; the command runs as root.
pub fn run_elevated(shell_cmd: &str) -> Result<String> {
    // Escape for an AppleScript string literal.
    let escaped = shell_cmd.replace('\\', "\\\\").replace('"', "\\\"");
    let script = format!("do shell script \"{escaped}\" with administrator privileges");
    let out = Command::new("osascript")
        .arg("-e")
        .arg(&script)
        .output()
        .context("spawn osascript")?;
    if !out.status.success() {
        bail!(
            "elevated command failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
