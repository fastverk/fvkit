//! `fvkit-core` — the platform-neutral, non-Bazel half of the fastverk core.
//!
//! The shared substrate both `fv` (fastverk product CLI) and `tbzl` (tomato-bazel
//! dev CLI) build on: the generated `fastverk.v1` contract ([`proto`]), the error
//! type, authenticated "connections" (host → keychain-backed token) with OAuth,
//! identity, IPC, notifications, config/paths, repo sync, secret storage, service
//! (LaunchAgent), and self-update. Per-OS work lives behind [`platform`].
//!
//! The Bazel-specific surfaces (`~/.bazelrc`, bazelisk/bazel provisioning, managed
//! volumes, maintenance) live in the sibling `fvkit-bazel`, which depends on this.
//! The `fvkit` facade crate re-exports both for backward-compatible consumers.

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

/// Generated bindings for the `fastverk.identity.v1` Login/Account contract (the
/// `Auth` service). fvd implements it in-process; see [`crate::identity`].
pub mod identity_proto {
    #![allow(clippy::all, clippy::pedantic, clippy::nursery)]
    tonic::include_proto!("fastverk.identity.v1");
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

pub mod config;
pub mod connections;
pub mod credstore;
pub mod identity;
pub mod ipc;
pub mod notify;
pub mod oauth;
pub mod paths;
pub mod platform;
pub mod repos;
pub mod secretstore;
pub mod service;
pub mod update;
pub mod uri;

/// The app version. Prefers the stamped `FASTVERK_VERSION` (the git tag,
/// injected by the Bazel workspace-status stamp), falling back to the crate
/// version for non-stamped / `cargo` builds.
#[must_use]
pub fn version() -> &'static str {
    match option_env!("FASTVERK_VERSION") {
        Some(v) if !v.is_empty() && !v.contains('{') => v,
        _ => env!("CARGO_PKG_VERSION"),
    }
}
