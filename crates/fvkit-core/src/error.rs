//! The public `fvkit` error type.
//!
//! `fvkit` is consumed cross-module (the meta-repo's `cli/fv`, `fastverk-app`).
//! In a multi-module `crate_universe` each module gets its OWN `anyhow` crate
//! instance, so returning `anyhow::Result` / `anyhow::Error` from the public
//! API makes a consumer's `?` fail ("multiple different versions of crate
//! anyhow"). Instead the public API returns a concrete [`Error`] that
//! implements [`std::error::Error`]: a consumer can `?` it straight into THEIR
//! `anyhow` (which has a blanket `impl From<E: std::error::Error>`).
//!
//! Internally `fvkit` keeps full `anyhow` ergonomics: [`Error`] wraps an
//! `anyhow::Error`, so `.context(..)?`, `anyhow!(..)`, and the crate-local
//! [`crate::bail!`] / [`crate::ensure!`] macros all convert in via
//! `From<anyhow::Error>`. A raw `?` on a std error (io, reqwest, fmt, …) is
//! attached to a `.context(..)` (which yields an `anyhow::Error`) or, at the
//! few context-less sites, `.map_err(Error::from_std)`. We can't add a blanket
//! `impl<E: std::error::Error> From<E>` because `Error` is itself a
//! `std::error::Error`, so it would collide with the reflexive `From<T> for T`
//! (E0119) — the same reason `anyhow::Error` does not implement
//! `std::error::Error`.

/// A `fvkit` error. A concrete type (not `anyhow`) so the public API doesn't
/// leak `anyhow` — see the module docs for why that matters across Bazel
/// modules. It's a real [`std::error::Error`], so a consumer can turn it back
/// into their own error type (e.g. `?` into their `anyhow::Error`), and it
/// keeps the underlying `anyhow` chain so `source()` and the `{:#}` Display
/// still surface the full context internally.
#[derive(Debug)]
pub struct Error(anyhow::Error);

impl Error {
    /// An [`Error`] from any displayable message.
    pub fn msg(m: impl std::fmt::Display) -> Self {
        Self(anyhow::Error::msg(m.to_string()))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `{:#}` includes the full anyhow context chain in one line.
        write!(f, "{:#}", self.0)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

// `Error` wraps `anyhow::Error`, so `.context(..)?`, `anyhow!(..)`, and the
// crate-local `bail!`/`ensure!` all convert in via this single `From`.
//
// We deliberately do NOT add a blanket `impl<E: Into<anyhow::Error>> From<E>`
// (or one bounded on `std::error::Error`): because `Error` itself implements
// `std::error::Error`, any such blanket overlaps the reflexive `From<T> for T`
// and the compiler rejects it (E0119) — the same reason `anyhow::Error` itself
// does NOT implement `std::error::Error`. Instead, a raw `?` on a std error
// (io, reqwest, fmt, …) goes through [`anyhow::Error`] first via [`from_std`],
// usually attached to a `.context(..)`; the few context-less sites call
// `.map_err(Error::from_std)`.
impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Self(e)
    }
}

impl Error {
    /// Wrap any std error into an [`Error`] (routes through `anyhow::Error`).
    /// Use at a context-less `?` site: `x.map_err(Error::from_std)?`.
    pub fn from_std<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self(anyhow::Error::new(e))
    }
}

/// `Result` for the public `fvkit` API.
pub type Result<T, E = Error> = std::result::Result<T, E>;
