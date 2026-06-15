//! Repo sync + worktree management — the core of "keep the org/group in
//! sync with the repos volume and manage the worktrees."
//!
//! Shells out to `gh` (enumeration; GitLab via `glab` is a follow-up) and
//! `git` (clone/pull/worktree), matching the workspace's no-libgit2
//! convention. `fv` calls these directly; `fvd` wraps them in RPCs + a
//! scheduler. Returns proto DTOs so the daemon, CLI, and GUI share one
//! shape.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::proto::{RepoSpec, RepoState, RepoSyncOutcome, RepoSyncReport, Worktree};

/// A place to mirror into `repos/`: a GitHub org (github.com or an
/// Enterprise host) or a GitLab group (gitlab.com or self-hosted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoSource {
    /// "github" | "gitlab".
    pub forge: String,
    /// Instance host (empty = the forge default).
    #[serde(default)]
    pub host: String,
    /// Org (GitHub) or group path (GitLab).
    pub group: String,
    #[serde(default)]
    pub include_archived: bool,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Directory under `repos/` for an org repo. `.github` → `dotgithub`.
#[must_use]
pub fn dir_name(repo: &str) -> String {
    if repo == ".github" {
        "dotgithub".to_string()
    } else {
        repo.to_string()
    }
}

#[derive(Deserialize)]
struct GhRepo {
    name: String,
    #[serde(rename = "sshUrl")]
    ssh_url: String,
    #[serde(rename = "isPrivate", default)]
    is_private: bool,
}

/// Enumerate every repo in a forge org/group on a given instance host.
/// github.com or GitHub Enterprise via `gh`; gitlab.com or self-hosted
/// GitLab via its REST API (token from the matching connection).
pub fn enumerate(forge: &str, host: &str, group: &str, include_archived: bool) -> Result<Vec<RepoSpec>> {
    match forge {
        "" | "github" => enumerate_github(host, group, include_archived),
        "gitlab" => enumerate_gitlab(host, group, include_archived),
        other => bail!("unknown forge: {other} (use github|gitlab)"),
    }
}

fn enumerate_github(host: &str, org: &str, include_archived: bool) -> Result<Vec<RepoSpec>> {
    let mut cmd = Command::new("gh");
    cmd.args([
        "repo", "list", org, "--limit", "500", "--json", "name,sshUrl,isPrivate",
    ]);
    if !include_archived {
        cmd.arg("--no-archived");
    }
    // GitHub Enterprise: point gh at the instance.
    if !host.is_empty() && host != "github.com" {
        cmd.env("GH_HOST", host);
    }
    let out = cmd
        .output()
        .context("spawn `gh` (installed + authenticated?)")?;
    if !out.status.success() {
        bail!(
            "`gh repo list {org}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let repos: Vec<GhRepo> =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).context("parse `gh` JSON")?;
    Ok(repos
        .into_iter()
        .map(|r| RepoSpec {
            dir: dir_name(&r.name),
            name: r.name,
            clone_url: r.ssh_url,
            forge: "github".to_string(),
            is_private: r.is_private,
        })
        .collect())
}

#[derive(Deserialize)]
struct GlProject {
    path: String,
    #[serde(rename = "ssh_url_to_repo")]
    ssh_url: String,
    #[serde(default)]
    visibility: String,
}

fn enumerate_gitlab(host: &str, group: &str, include_archived: bool) -> Result<Vec<RepoSpec>> {
    let host = if host.is_empty() { "gitlab.com" } else { host };
    let token = gitlab_token(host)?;
    let client = reqwest::blocking::Client::builder()
        .user_agent("fastverk")
        .timeout(Duration::from_secs(30))
        .build()
        .context("build http client")?;
    let group_enc = group.replace('/', "%2F");
    let archived = if include_archived { "" } else { "&archived=false" };

    let mut out = Vec::new();
    let mut page = 1u32;
    loop {
        let url = format!(
            "https://{host}/api/v4/groups/{group_enc}/projects?include_subgroups=true&per_page=100&page={page}{archived}"
        );
        let resp = client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .with_context(|| format!("GitLab projects for group {group} on {host}"))?;
        let next = resp
            .headers()
            .get("x-next-page")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let projects: Vec<GlProject> = resp.json().context("parse GitLab projects")?;
        for p in projects {
            out.push(RepoSpec {
                dir: dir_name(&p.path),
                name: p.path,
                clone_url: p.ssh_url,
                forge: "gitlab".to_string(),
                is_private: p.visibility != "public",
            });
        }
        match next.parse::<u32>() {
            Ok(n) if n > 0 => page = n,
            _ => break,
        }
    }
    Ok(out)
}

/// The access token for a GitLab host, from its connection's keychain item.
fn gitlab_token(host: &str) -> Result<String> {
    let reg = crate::connections::load()?;
    let conn = crate::connections::match_host(&reg, host)
        .with_context(|| format!("no connection for {host} — run `fv connect gitlab --host {host}`"))?;
    crate::credstore::get(&conn.keychain_service, &conn.keychain_account)?
        .with_context(|| format!("no token in keychain for {host}"))
}

/// Sync every configured source (clone missing, optionally pull existing)
/// into `repos_dir`. Returns one report per source.
pub fn sync_sources(
    repos_dir: &Path,
    sources: &[RepoSource],
    meta_repo_name: &str,
    pull: bool,
    validate_only: bool,
) -> Result<Vec<RepoSyncReport>> {
    let mut reports = Vec::new();
    for s in sources {
        let specs = enumerate(&s.forge, &s.host, &s.group, s.include_archived)?;
        let report = sync(
            repos_dir,
            &specs,
            &s.group,
            &s.forge,
            &SyncOpts {
                pull,
                validate_only,
                meta_repo_name: meta_repo_name.to_string(),
            },
        )?;
        reports.push(report);
    }
    Ok(reports)
}

pub struct SyncOpts {
    /// Also fast-forward existing clean clones (vs. clone-missing only).
    pub pull: bool,
    /// Report what would happen without cloning/pulling.
    pub validate_only: bool,
    /// Org repo name that is the meta repo itself — never sub-checked-out.
    pub meta_repo_name: String,
}

/// Clone missing repos into `repos_dir/<dir_name>` and (optionally) pull
/// existing clean ones, skipping dirty/detached checkouts (incl. pinned
/// submodules, which are detached).
pub fn sync(
    repos_dir: &Path,
    specs: &[RepoSpec],
    org: &str,
    forge: &str,
    opts: &SyncOpts,
) -> Result<RepoSyncReport> {
    std::fs::create_dir_all(repos_dir)
        .with_context(|| format!("create {}", repos_dir.display()))?;
    let started = now();
    let mut outcomes = Vec::new();
    for spec in specs {
        if spec.name == opts.meta_repo_name {
            continue;
        }
        let dest = repos_dir.join(&spec.dir);
        outcomes.push(sync_one(&dest, spec, opts));
    }
    Ok(RepoSyncReport {
        org: org.to_string(),
        forge: forge.to_string(),
        started_at: started,
        finished_at: now(),
        validate_only: opts.validate_only,
        outcomes,
    })
}

fn sync_one(dest: &Path, spec: &RepoSpec, opts: &SyncOpts) -> RepoSyncOutcome {
    let mk = |action: &str, detail: String| RepoSyncOutcome {
        name: spec.name.clone(),
        action: action.to_string(),
        detail,
    };

    if !dest.exists() {
        if opts.validate_only {
            return mk("cloned", "would clone".to_string());
        }
        return match clone(dest, &spec.clone_url) {
            Ok(()) => mk("cloned", String::new()),
            Err(e) => mk("failed", e.to_string()),
        };
    }
    if !dest.join(".git").exists() {
        return mk("skipped-present", "exists but not a git repo".to_string());
    }
    if !opts.pull {
        return mk("skipped-present", String::new());
    }
    if git_branch(dest).is_none() {
        return mk("skipped-detached", "detached HEAD".to_string());
    }
    if is_dirty(dest) {
        return mk("skipped-dirty", "uncommitted changes".to_string());
    }
    if opts.validate_only {
        return mk("updated", "would pull".to_string());
    }
    match pull(dest) {
        Ok(true) => mk("updated", String::new()),
        Ok(false) => mk("up-to-date", String::new()),
        Err(e) => mk("failed", e.to_string()),
    }
}

/// Observed state of every spec's checkout under `repos_dir`.
pub fn status(repos_dir: &Path, specs: &[RepoSpec]) -> Vec<RepoState> {
    specs
        .iter()
        .map(|spec| {
            let dest = repos_dir.join(&spec.dir);
            let present = dest.join(".git").exists();
            let (head, branch, dirty) = if present {
                (
                    short_head(&dest).unwrap_or_default(),
                    git_branch(&dest).unwrap_or_default(),
                    is_dirty(&dest),
                )
            } else {
                (String::new(), String::new(), false)
            };
            RepoState {
                spec: Some(spec.clone()),
                present,
                head,
                branch,
                dirty,
            }
        })
        .collect()
}

// ─── Worktrees ─────────────────────────────────────────────────────

/// List git worktrees across repos under `repos_dir` (optionally one repo).
pub fn worktree_list(repos_dir: &Path, filter_repo: &str) -> Result<Vec<Worktree>> {
    let mut dirs: Vec<(String, PathBuf)> = Vec::new();
    for entry in std::fs::read_dir(repos_dir)
        .with_context(|| format!("read {}", repos_dir.display()))?
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !filter_repo.is_empty() && name != filter_repo {
            continue;
        }
        let p = entry.path();
        if p.join(".git").exists() {
            dirs.push((name, p));
        }
    }
    dirs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = Vec::new();
    for (name, dir) in dirs {
        let Ok(porc) = git(&dir, &["worktree", "list", "--porcelain"]) else {
            continue;
        };
        let mut first = true;
        let mut path: Option<String> = None;
        let mut head = String::new();
        let mut branch = String::new();
        // A trailing empty line flushes the last block.
        for line in porc.lines().chain(std::iter::once("")) {
            if line.is_empty() || line.starts_with("worktree ") {
                if let Some(p) = path.take() {
                    out.push(Worktree {
                        repo: name.clone(),
                        path: p,
                        branch: std::mem::take(&mut branch),
                        head: std::mem::take(&mut head),
                        is_primary: first,
                    });
                    first = false;
                }
                if let Some(p) = line.strip_prefix("worktree ") {
                    path = Some(p.to_string());
                }
            } else if let Some(h) = line.strip_prefix("HEAD ") {
                head = h.chars().take(12).collect();
            } else if let Some(b) = line.strip_prefix("branch ") {
                branch = b.trim_start_matches("refs/heads/").to_string();
            }
        }
    }
    Ok(out)
}

/// Create a worktree for `repo` at `worktrees_dir/<repo>/<branch>`,
/// checking out `branch` (created from current HEAD when it doesn't exist).
pub fn worktree_add(
    repos_dir: &Path,
    worktrees_dir: &Path,
    repo: &str,
    branch: &str,
) -> Result<Worktree> {
    let repo_path = repos_dir.join(repo);
    if !repo_path.join(".git").exists() {
        bail!(
            "{} is not a git repo (run `fv repos sync` first)",
            repo_path.display()
        );
    }
    let wt_path = worktrees_dir.join(repo).join(branch);
    if let Some(parent) = wt_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    let wt = wt_path.to_string_lossy().into_owned();
    // Prefer an existing branch; fall back to creating one.
    if git(&repo_path, &["worktree", "add", &wt, branch]).is_err() {
        git(&repo_path, &["worktree", "add", "-b", branch, &wt])
            .with_context(|| format!("git worktree add for {repo}@{branch}"))?;
    }
    Ok(Worktree {
        repo: repo.to_string(),
        head: short_head(&wt_path).unwrap_or_default(),
        path: wt,
        branch: branch.to_string(),
        is_primary: false,
    })
}

/// Remove the worktree at `path`.
pub fn worktree_remove(path: &Path, force: bool) -> Result<bool> {
    let p = path.to_string_lossy().into_owned();
    let mut args = vec!["worktree", "remove"];
    if force {
        args.push("--force");
    }
    args.push(&p);
    git(path, &args).with_context(|| format!("git worktree remove {p}"))?;
    Ok(true)
}

// ─── git/process helpers ───────────────────────────────────────────

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .context("spawn `git`")?;
    if !out.status.success() {
        bail!(
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn clone(dest: &Path, url: &str) -> Result<()> {
    let out = Command::new("git")
        .args(["clone", "--filter=blob:none", url])
        .arg(dest)
        .output()
        .context("spawn `git clone`")?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn pull(dir: &Path) -> Result<bool> {
    let before = git(dir, &["rev-parse", "HEAD"]).unwrap_or_default();
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["pull", "--ff-only"])
        .output()
        .context("spawn `git pull`")?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let after = git(dir, &["rev-parse", "HEAD"]).unwrap_or_default();
    Ok(before != after)
}

fn git_branch(dir: &Path) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["symbolic-ref", "--quiet", "--short", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let b = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!b.is_empty()).then_some(b)
}

fn short_head(dir: &Path) -> Option<String> {
    let s = git(dir, &["rev-parse", "--short", "HEAD"]).ok()?;
    Some(s.trim().to_string())
}

fn is_dirty(dir: &Path) -> bool {
    Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["status", "--porcelain"])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}
