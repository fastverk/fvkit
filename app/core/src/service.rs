//! Install `fvd` as a user background service so it runs at login and is
//! kept alive — a LaunchAgent on macOS (no root: a user agent, matching
//! the unprivileged-daemon design). Linux (systemd user unit) and Windows
//! are P6.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};

/// LaunchAgent label / unit name.
pub const LABEL: &str = "com.fastverk.fvd";

/// Where the agent definition lives + the resolved `fvd` path that runs.
pub struct Plan {
    pub path: PathBuf,
    pub contents: String,
    pub program: PathBuf,
}

/// Compute the LaunchAgent plist + paths without writing anything.
#[cfg(target_os = "macos")]
pub fn plan() -> Result<Plan> {
    let home = directories::BaseDirs::new()
        .context("no home directory")?
        .home_dir()
        .to_path_buf();
    let path = home
        .join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"));
    let program = crate::ipc::find_fvd().context("could not locate the `fvd` binary to run")?;
    let log_dir = crate::paths::config_dir()?;
    let out_log = log_dir.join("fvd.out.log");
    let err_log = log_dir.join("fvd.err.log");
    let contents = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{program}</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{out}</string>
  <key>StandardErrorPath</key><string>{err}</string>
</dict>
</plist>
"#,
        program = program.display(),
        out = out_log.display(),
        err = err_log.display(),
    );
    Ok(Plan {
        path,
        contents,
        program,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn plan() -> Result<Plan> {
    bail!("the background service is macOS-only for now (Linux/Windows are P6)")
}

/// Write the plist and load it into launchd (RunAtLoad starts fvd now).
#[cfg(target_os = "macos")]
pub fn install() -> Result<PathBuf> {
    use std::process::Command;

    let plan = plan()?;
    if let Some(parent) = plan.path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    crate::paths::ensure_config_dir()?;
    std::fs::write(&plan.path, &plan.contents)
        .with_context(|| format!("write {}", plan.path.display()))?;

    let uid = uid()?;
    // Reload cleanly: bootout (ignore "not loaded"), then bootstrap.
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("gui/{uid}/{LABEL}")])
        .output();
    let out = Command::new("launchctl")
        .args(["bootstrap", &format!("gui/{uid}"), &plan.path.to_string_lossy()])
        .output()
        .context("launchctl bootstrap")?;
    if !out.status.success() {
        bail!(
            "launchctl bootstrap failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(plan.path)
}

/// Unload the agent and remove its plist.
#[cfg(target_os = "macos")]
pub fn uninstall() -> Result<()> {
    use std::process::Command;

    let plan = plan()?;
    let uid = uid()?;
    let _ = Command::new("launchctl")
        .args(["bootout", &format!("gui/{uid}/{LABEL}")])
        .output();
    if plan.path.exists() {
        std::fs::remove_file(&plan.path)
            .with_context(|| format!("remove {}", plan.path.display()))?;
    }
    Ok(())
}

/// Whether launchd currently knows about the agent.
#[cfg(target_os = "macos")]
pub fn is_loaded() -> bool {
    use std::process::Command;
    let Ok(uid) = uid() else { return false };
    Command::new("launchctl")
        .args(["print", &format!("gui/{uid}/{LABEL}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
pub fn install() -> Result<PathBuf> {
    bail!("the background service is macOS-only for now (Linux/Windows are P6)")
}

#[cfg(not(target_os = "macos"))]
pub fn uninstall() -> Result<()> {
    bail!("the background service is macOS-only for now (Linux/Windows are P6)")
}

#[cfg(not(target_os = "macos"))]
#[must_use]
pub fn is_loaded() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn uid() -> Result<String> {
    let out = std::process::Command::new("id")
        .arg("-u")
        .output()
        .context("id -u")?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
