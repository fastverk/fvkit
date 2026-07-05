//! `fvkit-bazel` — the Bazel-specific half of the fastverk core.
//!
//! Ownership of the user's `~/.bazelrc` managed region, bazelisk/bazel + the
//! cred-helper provisioning, managed filesystem volumes (repos + bazel caches),
//! and the maintenance runners (disk-cache GC, git gc, worktree prune). Depends
//! on `fvkit-core` for the shared substrate (config, paths, proto, the error
//! type). Consumed by `tbzl` directly, and by `fv` via the `fvkit` facade.

/// `bail!`/`ensure!` returning [`fvkit_core::Error`]. fvkit-core's own macros are
/// crate-local there, so we mirror them here over the shared error type.
macro_rules! bail {
    ($($arg:tt)*) => {
        return ::core::result::Result::Err(
            ::fvkit_core::Error::from(::anyhow::anyhow!($($arg)*)),
        )
    };
}

pub(crate) use bail;

pub mod bazelrc;
pub mod maintain;
pub mod tools;
pub mod volume;
