//! `fvkit` — the fastverk core library.
//!
//! Platform-abstracted machinery the fastverk app is built on: managed
//! filesystem volumes (repos + bazel caches), ownership of the user's
//! `~/.bazelrc`, bazelisk/bazel provisioning, authenticated
//! "connections" (host → keychain-backed token) with OAuth, periodic
//! maintenance, and self-update.
//!
//! `fvkit` is a library: the unprivileged `fvd` daemon wraps it and is
//! the single owner of mutable state; the GUI (`fastverk`) and CLI
//! (`fv`) reach it over gRPC. The generated contract lives in [`proto`].
//!
//! Per-OS work lives behind [`platform`]; macOS is implemented first
//! and other targets are stubs behind the same boundary.

/// Generated gRPC + DTO bindings for `fastverk.v1` (see `build.rs`).
pub mod proto {
    #![allow(clippy::all, clippy::pedantic, clippy::nursery)]
    tonic::include_proto!("fastverk.v1");

    /// FileDescriptorSet for gRPC reflection (wired by `fvd` later).
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("fastverk_descriptor");
}

/// Generated bindings for the `fastverk.plugin.v1` plugin contract (the
/// `PluginManifest` + the `Plugin` meta-service). The fvd host reads manifests
/// to register + route to plugins ("QueryRPC"); see `proto/fastverk/plugin/v1`.
pub mod plugin_proto {
    #![allow(clippy::all, clippy::pedantic, clippy::nursery)]
    tonic::include_proto!("fastverk.plugin.v1");
}

mod error;
pub use error::{Error, Result};

/// Like `anyhow::bail!`, but returns a [`crate::Error`] so it can be used
/// inside fns that return [`crate::Result`]. (`anyhow::bail!` expands to
/// `return Err(anyhow::Error)`, which the blanket `From` can't fix because
/// there's no `?` to trigger the conversion.)
macro_rules! bail {
    ($($arg:tt)*) => {
        return ::core::result::Result::Err($crate::Error::from(::anyhow::anyhow!($($arg)*)))
    };
}

/// Like `anyhow::ensure!`, but returns a [`crate::Error`] (see [`bail!`]).
macro_rules! ensure {
    ($cond:expr $(,)?) => {
        if !($cond) {
            $crate::bail!(::core::concat!("Condition failed: `", ::core::stringify!($cond), "`"));
        }
    };
    ($cond:expr, $($arg:tt)*) => {
        if !($cond) {
            $crate::bail!($($arg)*);
        }
    };
}

pub(crate) use {bail, ensure};

pub mod bazelrc;
pub mod config;
pub mod connections;
pub mod credstore;
pub mod ipc;
pub mod maintain;
pub mod notify;
pub mod oauth;
pub mod paths;
pub mod platform;
pub mod repos;
pub mod secretstore;
pub mod service;
pub mod tools;
pub mod update;
pub mod uri;
pub mod volume;

/// The app version. Prefers the stamped `FASTVERK_VERSION` (the git tag,
/// injected by the Bazel workspace-status stamp — see
/// `tools/workspace_status.sh`), falling back to the crate version for
/// non-stamped / `cargo` builds. A non-stamp Bazel build leaves the literal
/// `{STABLE_FASTVERK_VERSION}`, which the `'{'` check rejects.
#[must_use]
pub fn version() -> &'static str {
    match option_env!("FASTVERK_VERSION") {
        Some(v) if !v.is_empty() && !v.contains('{') => v,
        _ => env!("CARGO_PKG_VERSION"),
    }
}
