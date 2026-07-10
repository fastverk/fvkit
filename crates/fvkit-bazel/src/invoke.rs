//! `invoke` — a small, SYNC surface for running Bazel from the CI/build path.
//!
//! Shared by `tbzl build` (the compiled build-runner that replaces
//! `fastverk-deploy/build-runner/entrypoint.sh`) and by any operator/init that
//! reifies targets or probes config, so the isolate-flags, query parsing, and
//! the "is this --config defined?" probe live in ONE place instead of being
//! copy-pasted shell.
//!
//! Sync by design: `tbzl build` runs on a plain `fn main()` and must not spin a
//! tokio runtime — fvkit's async gRPC/daemon client can't be driven from a
//! consumer's runtime (the cross-module tokio boundary). Everything here is
//! `std::process::Command`.

use std::path::{Path, PathBuf};
use std::process::Command;

use fvkit_core::Result;

/// A Bazel invoker rooted at a workspace and isolated from any per-image bazelrc.
///
/// The build-runner base image bakes `ENV BAZELRC=/etc/fastverk/config/bazelrc`
/// (a mount that a fresh CI clone doesn't have — and bazel treats `$BAZELRC` as
/// an explicit user rc, so a missing file is a HARD error `--nohome_rc` can't
/// skip) plus a managed home/system rc. We drop ALL of it (`env -u BAZELRC`,
/// `--nohome_rc --nosystem_rc`) and use ONLY the target repo's workspace
/// `.bazelrc` — plus any explicitly-passed flags, or a mounted `ConfigSet`
/// supplied via `--bazelrc=<path>` (the seam's "mount, don't bake").
pub struct Bazel {
    workspace: PathBuf,
    /// bazel / bazelisk binary (e.g. from `tools::ensure_installed`).
    bin: PathBuf,
    /// Extra startup rc files to honor (e.g. a mounted ConfigSet bazelrc).
    /// Empty by default — the workspace `.bazelrc` is always auto-read.
    bazelrcs: Vec<PathBuf>,
}

impl Bazel {
    /// A Bazel invoker for `workspace`, using `bin` (bazel/bazelisk).
    pub fn new(workspace: impl Into<PathBuf>, bin: impl Into<PathBuf>) -> Self {
        Self { workspace: workspace.into(), bin: bin.into(), bazelrcs: Vec::new() }
    }

    /// Also honor an explicit startup rc file (e.g. a mounted `ConfigSet`).
    /// Applied as `--bazelrc=<path>` before the subcommand, so its `common:`/
    /// `build:` lines merge with the workspace `.bazelrc`.
    pub fn with_bazelrc(mut self, path: impl AsRef<Path>) -> Self {
        self.bazelrcs.push(path.as_ref().to_path_buf());
        self
    }

    /// A `Command` for `bazel <subcommand>`, isolated + rooted at the workspace.
    fn command(&self, subcommand: &str) -> Command {
        let mut c = Command::new(&self.bin);
        c.current_dir(&self.workspace);
        c.env_remove("BAZELRC"); // drop the baked pointer (missing file = hard error)
        // Startup flags come BEFORE the subcommand.
        for rc in &self.bazelrcs {
            c.arg(format!("--bazelrc={}", rc.display()));
        }
        c.arg("--nohome_rc").arg("--nosystem_rc");
        c.arg(subcommand);
        c
    }

    /// Run a `bazel query` expression, returning the matched labels (one per
    /// line, blanks dropped). Surfaces the query's stderr on failure — a reify
    /// failure is almost always a real, actionable error (an undefined config, a
    /// 401 on a private registry, a broken `MODULE.bazel`), not something to
    /// swallow.
    pub fn query(&self, expr: &str) -> Result<Vec<String>> {
        let out = self
            .command("query")
            .arg(expr)
            .output()
            .map_err(|e| fvkit_core::Error::from(anyhow::anyhow!("spawn bazel query: {e}")))?;
        if !out.status.success() {
            bail!(
                "bazel query {expr:?} failed:\n{}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    /// Is `--config=<name>` defined in the workspace's rc files?
    ///
    /// `bazel canonicalize-flags` does NOT error on an undefined config (it's a
    /// false positive), so probe with a `build --nobuild` and look for bazel's
    /// definitive `is not defined in any .rc file`. This is what lets the runner
    /// switch to explicit-remote mode for repos (e.g. the aion fleet) whose
    /// minimal `.bazelrc` defines no RBE config — instead of fast-failing on
    /// `--config=rbe`.
    pub fn config_defined(&self, config: &str) -> bool {
        match self
            .command("build")
            .arg(format!("--config={config}"))
            .arg("--nobuild")
            .output()
        {
            Ok(o) => !String::from_utf8_lossy(&o.stderr).contains("is not defined in any .rc file"),
            // Couldn't even run bazel → treat as "not usable", caller falls back.
            Err(_) => false,
        }
    }

    /// Run a build-graph subcommand (`test` / `build` / `run`) with `args`,
    /// inheriting the runner's stdio (so output streams to the session log).
    /// Returns an error if bazel exits non-zero.
    pub fn exec(&self, subcommand: &str, args: &[String]) -> Result<()> {
        let ok = self
            .command(subcommand)
            .args(args)
            .status()
            .map_err(|e| fvkit_core::Error::from(anyhow::anyhow!("spawn bazel {subcommand}: {e}")))?
            .success();
        if !ok {
            bail!("bazel {subcommand} failed");
        }
        Ok(())
    }
}
