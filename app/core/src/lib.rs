//! `fvkit` — a facade re-exporting `fvkit-core` + `fvkit-bazel`.
//!
//! Backward-compatible: existing consumers keep `use fvkit::{bazelrc, config,
//! connections, proto, …}`, `fvkit::version()`, and `fvkit::{Error, Result}`.
//! The platform-neutral substrate lives in `fvkit-core`; the Bazel-specific
//! surfaces (`~/.bazelrc`, tool provisioning, managed volumes, maintenance) in
//! `fvkit-bazel`. New consumers that want only the substrate — e.g. a slim `fv`
//! product CLI — can depend on `fvkit-core` directly.

pub use fvkit_core::*;
pub use fvkit_bazel::{bazelrc, invoke, maintain, tools, volume};
