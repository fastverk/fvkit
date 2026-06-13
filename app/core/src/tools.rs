//! Provisioning of the bazelisk + bazel binaries for the user.
//!
//! bazelisk is bundled in the app and installed/symlinked onto PATH;
//! the pinned bazel version is exposed via `USE_BAZEL_VERSION` /
//! `.bazelversion` so bazelisk fetches the matching bazel on demand.
//! P1 implements the install + symlink + pin.

use anyhow::Result;

/// Ensure bazelisk is installed and the pinned bazel version is selected.
pub fn ensure_installed(_version: &str) -> Result<()> {
    anyhow::bail!("TODO(P1): install/symlink bundled bazelisk + pin bazel version")
}

/// Whether bazelisk is currently resolvable on PATH.
#[must_use]
pub fn is_installed() -> bool {
    which("bazelisk").is_some() || which("bazel").is_some()
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|p| p.is_file())
}
