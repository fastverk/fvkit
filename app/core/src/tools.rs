//! Provisioning of the bazelisk + bazel binaries for the user.
//!
//! bazelisk is bundled in the app and installed/symlinked onto PATH;
//! the pinned bazel version is exposed via `USE_BAZEL_VERSION` /
//! `.bazelversion` so bazelisk fetches the matching bazel on demand.
//! P1 implements the install + symlink + pin.
//!
//! This module also installs the fastverk Bazel credential helper binary
//! (`fastverk-cred-helper`) into the location the generated `~/.bazelrc`
//! points its single unscoped `--credential_helper` at, so the helper is
//! resolvable on Bazel's per-host hot path.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::bazelrc;

/// Ensure bazelisk is installed and the pinned bazel version is selected.
pub fn ensure_installed(_version: &str) -> Result<()> {
    anyhow::bail!("TODO(P1): install/symlink bundled bazelisk + pin bazel version")
}

/// Whether bazelisk is currently resolvable on PATH.
#[must_use]
pub fn is_installed() -> bool {
    which("bazelisk").is_some() || which("bazel").is_some()
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|p| p.is_file())
}

/// Default install location for the `fastverk-cred-helper` binary.
///
/// Must agree with where the generated `~/.bazelrc` points its unscoped
/// `--credential_helper`, so we defer to [`bazelrc::cred_helper_path`]
/// (which honors `$FASTVERK_CRED_HELPER`, defaulting to
/// `/usr/local/bin/fastverk-cred-helper`).
#[must_use]
pub fn default_install_path() -> PathBuf {
    bazelrc::cred_helper_path()
}

/// Install the `fastverk-cred-helper` binary by copying `from` to `to`.
///
/// Creates the parent directory if missing and marks the installed file
/// executable (`0o755`) on unix. Returns the install path. This is the
/// mechanism that makes the helper resolvable at the path the managed
/// `~/.bazelrc` block references.
pub fn install_cred_helper(from: &Path, to: &Path) -> Result<PathBuf> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create install dir {}", parent.display()))?;
    }
    std::fs::copy(from, to)
        .with_context(|| format!("copy {} -> {}", from.display(), to.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(to, perms)
            .with_context(|| format!("chmod 0755 {}", to.display()))?;
    }
    Ok(to.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::{default_install_path, install_cred_helper};

    #[test]
    fn default_install_path_honors_env() {
        // Sanity: the default path agrees with bazelrc's cred_helper_path.
        assert_eq!(default_install_path(), crate::bazelrc::cred_helper_path());
    }

    #[test]
    fn install_copies_and_sets_mode() {
        let dir = std::env::temp_dir().join(format!("fvkit-install-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let from = dir.join("src-bin");
        let to = dir.join("nested").join("dst-bin");
        std::fs::write(&from, b"#!/bin/sh\ntrue\n").unwrap();

        let installed = install_cred_helper(&from, &to).unwrap();
        assert_eq!(installed, to);
        assert_eq!(std::fs::read(&to).unwrap(), b"#!/bin/sh\ntrue\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&to).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o755);
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
