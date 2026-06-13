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
pub mod oauth;
pub mod paths;
pub mod platform;
pub mod tools;
pub mod update;
pub mod uri;
pub mod volume;
