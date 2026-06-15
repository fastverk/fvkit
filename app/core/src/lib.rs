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
