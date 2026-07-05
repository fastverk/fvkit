//! User-facing fastverk settings, persisted as TOML.
//!
//! These are the knobs that drive the generated `~/.bazelrc` and the
//! managed volumes. Secrets are NOT here — those live in the keychain,
//! referenced from the connection registry (see [`crate::connections`]).

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::Result;
use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::paths;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Bazel `--output_user_root` (per-workspace output bases live here).
    pub output_user_root: PathBuf,
    /// Bazel `--disk_cache`.
    pub disk_cache: PathBuf,
    /// Module registries, in resolution order.
    pub registries: Vec<String>,
    /// Where managed git repos + worktrees live (the repos volume).
    pub repos_root: PathBuf,
    /// The meta repo on the repos volume; its `repos/` holds the org
    /// checkouts and its `worktrees/` holds managed worktrees.
    pub meta_repo: PathBuf,
    /// Default org/group to mirror.
    pub org: String,
    /// Default forge: "github" | "gitlab".
    pub forge: String,
    /// Pinned bazel version (drives `USE_BAZEL_VERSION` / `.bazelversion`).
    pub bazel_version: String,
    /// Disk-cache GC threshold in gibibytes (0 disables GC).
    pub disk_cache_max_gib: u64,
    /// OAuth App client ids per provider ("github" -> "Iv1...."), used by
    /// the device-code connect flow. Not secret.
    pub client_ids: BTreeMap<String, String>,
    /// Forges/orgs/groups mirrored into repos/ by `fv repos sync` + the
    /// daemon scheduler.
    pub sources: Vec<crate::repos::RepoSource>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            output_user_root: PathBuf::from("/Volumes/Cache/Bazel/Workspaces"),
            disk_cache: PathBuf::from("/Volumes/Cache/Bazel/disk-cache"),
            registries: vec![
                "file:///Volumes/Workspace/fastverk/repos/bazel-registry".to_string(),
                "https://bcr.bazel.build/".to_string(),
            ],
            repos_root: PathBuf::from("/Volumes/Workspace"),
            meta_repo: PathBuf::from("/Volumes/Workspace/fastverk"),
            org: "fastverk".to_string(),
            forge: "github".to_string(),
            bazel_version: "9.1.0".to_string(),
            disk_cache_max_gib: 50,
            client_ids: BTreeMap::new(),
            sources: vec![crate::repos::RepoSource {
                forge: "github".to_string(),
                host: "github.com".to_string(),
                group: "fastverk".to_string(),
                include_archived: false,
            }],
        }
    }
}

impl Config {
    /// `<config_dir>/config.toml`.
    pub fn path() -> Result<PathBuf> {
        Ok(paths::config_dir()?.join("config.toml"))
    }

    /// Where the org checkouts live: `<meta_repo>/repos`.
    #[must_use]
    pub fn repos_dir(&self) -> PathBuf {
        self.meta_repo.join("repos")
    }

    /// Where managed worktrees live: `<meta_repo>/worktrees`.
    #[must_use]
    pub fn worktrees_dir(&self) -> PathBuf {
        self.meta_repo.join("worktrees")
    }

    /// The org repo name that is the meta repo itself (never a sub-checkout).
    #[must_use]
    pub fn meta_repo_name(&self) -> String {
        self.meta_repo
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Load the persisted config, or defaults when none exists yet.
    pub fn load() -> Result<Self> {
        let p = Self::path()?;
        if p.exists() {
            let s = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
            Ok(toml::from_str(&s).with_context(|| format!("parse {}", p.display()))?)
        } else {
            Ok(Self::default())
        }
    }

    /// Persist the config to `<config_dir>/config.toml`.
    pub fn save(&self) -> Result<()> {
        paths::ensure_config_dir()?;
        let p = Self::path()?;
        let s = toml::to_string_pretty(self).context("serialize config")?;
        Ok(std::fs::write(&p, s).with_context(|| format!("write {}", p.display()))?)
    }
}
