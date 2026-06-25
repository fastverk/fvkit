//! Pluggable secret backends.
//!
//! The connection registry names *where* each secret lives via a
//! [`SecretRef`] (a proto `oneof`); this module turns that reference into
//! the secret bytes. Backends are a fixed, compiled-in set behind the
//! [`SecretStore`] trait, selected by the ref's variant — adding one is a
//! contained `impl SecretStore` + a new oneof variant, never runtime-loaded
//! code. That's the right kind of "extensible" for something that reads
//! secrets.
//!
//! The cheap, dependency-free backends — keychain, env, file — resolve
//! inline and are the only ones the Bazel cred-helper hot path needs
//! ([`Resolver::standard`]). Network/SDK backends (HashiCorp Vault, AWS
//! Secrets Manager / SSM Parameter Store) slot in later as more
//! `SecretStore` impls and resolve through `fvd`, which already owns the
//! network stack and token-refresh loop.
//!
//! Resolution is best-effort: a backend error is treated as a miss and the
//! next ref is tried, so a locked/absent keychain in CI degrades to the env
//! var rather than failing the fetch.

use crate::Result;
use anyhow::Context;

use crate::credstore;
use crate::proto::{secret_ref::Store, EnvRef, FileRef, KeychainRef, SecretRef};

/// One secret backend: reads (and, where writable, stores) the secret a
/// [`SecretRef`] points at.
pub trait SecretStore: Send + Sync {
    /// Stable backend name, for diagnostics.
    fn scheme(&self) -> &'static str;
    /// Whether this backend handles `r`'s store variant.
    fn handles(&self, r: &SecretRef) -> bool;
    /// Read the secret `r` points at; `Ok(None)` if absent or empty.
    fn get(&self, r: &SecretRef) -> Result<Option<String>>;
    /// Store a secret. Read-only backends (env) return an error.
    fn set(&self, _r: &SecretRef, _secret: &str) -> Result<()> {
        bail!("{} backend is read-only", self.scheme())
    }
    /// Delete a secret. No-op success for backends with nothing to delete.
    fn delete(&self, _r: &SecretRef) -> Result<()> {
        Ok(())
    }
}

/// OS keychain backend (macOS login Keychain today; Secret Service /
/// Windows Credential Manager slot in behind `credstore` later).
pub struct KeychainStore;
impl SecretStore for KeychainStore {
    fn scheme(&self) -> &'static str {
        "keychain"
    }
    fn handles(&self, r: &SecretRef) -> bool {
        matches!(r.store, Some(Store::Keychain(_)))
    }
    fn get(&self, r: &SecretRef) -> Result<Option<String>> {
        let Some(Store::Keychain(k)) = &r.store else {
            return Ok(None);
        };
        credstore::get(&k.service, &k.account)
    }
    fn set(&self, r: &SecretRef, secret: &str) -> Result<()> {
        let Some(Store::Keychain(k)) = &r.store else {
            bail!("not a keychain ref");
        };
        credstore::set(&k.service, &k.account, secret)
    }
    fn delete(&self, r: &SecretRef) -> Result<()> {
        let Some(Store::Keychain(k)) = &r.store else {
            return Ok(());
        };
        credstore::delete(&k.service, &k.account)
    }
}

/// Environment-variable backend — the CI/automation source where there's
/// no keychain. Read-only. The first non-empty of `var` then each alias
/// wins, so the canonical name is preferred but ecosystem names still work.
pub struct EnvStore;
impl SecretStore for EnvStore {
    fn scheme(&self) -> &'static str {
        "env"
    }
    fn handles(&self, r: &SecretRef) -> bool {
        matches!(r.store, Some(Store::Env(_)))
    }
    fn get(&self, r: &SecretRef) -> Result<Option<String>> {
        let Some(Store::Env(e)) = &r.store else {
            return Ok(None);
        };
        Ok(std::iter::once(&e.name)
            .chain(e.aliases.iter())
            .filter(|n| !n.is_empty())
            .find_map(|n| std::env::var(n).ok().filter(|v| !v.is_empty())))
    }
}

/// File backend — a secret read from disk (mode 0600), for headless Linux
/// or mounted-secret CI. The trimmed file contents are the secret unless
/// `field` selects a key from a `KEY=VALUE` map.
pub struct FileStore;
impl SecretStore for FileStore {
    fn scheme(&self) -> &'static str {
        "file"
    }
    fn handles(&self, r: &SecretRef) -> bool {
        matches!(r.store, Some(Store::File(_)))
    }
    fn get(&self, r: &SecretRef) -> Result<Option<String>> {
        let Some(Store::File(f)) = &r.store else {
            return Ok(None);
        };
        let p = std::path::Path::new(&f.path);
        if !p.exists() {
            return Ok(None);
        }
        let raw = std::fs::read_to_string(p).with_context(|| format!("read {}", f.path))?;
        let val = if f.field.is_empty() {
            raw.trim().to_string()
        } else {
            extract_field(&raw, &f.field).unwrap_or_default()
        };
        Ok((!val.is_empty()).then_some(val))
    }
    fn set(&self, r: &SecretRef, secret: &str) -> Result<()> {
        let Some(Store::File(f)) = &r.store else {
            bail!("not a file ref");
        };
        if !f.field.is_empty() {
            bail!("file backend: writing a single field is unsupported");
        }
        std::fs::write(&f.path, secret).with_context(|| format!("write {}", f.path))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 0600 {}", f.path))?;
        }
        Ok(())
    }
    fn delete(&self, r: &SecretRef) -> Result<()> {
        if let Some(Store::File(f)) = &r.store {
            if std::path::Path::new(&f.path).exists() {
                std::fs::remove_file(&f.path).with_context(|| format!("rm {}", f.path))?;
            }
        }
        Ok(())
    }
}

/// Extract `field` from a `KEY=VALUE` map (one per line; surrounding quotes
/// trimmed). JSON maps can be added here later.
fn extract_field(raw: &str, field: &str) -> Option<String> {
    raw.lines().find_map(|line| {
        let (k, v) = line.trim().split_once('=')?;
        (k.trim() == field).then(|| v.trim().trim_matches('"').to_string())
    })
}

/// An ordered set of backends. [`resolve`](Self::resolve) reads through a
/// connection's `secret_refs`; the first ref a backend resolves to a
/// non-empty secret wins.
pub struct Resolver {
    backends: Vec<Box<dyn SecretStore>>,
}

impl Resolver {
    /// The standard, dependency-free backend set used by both the
    /// cred-helper hot path and `fvd` today: keychain, then env, then file.
    #[must_use]
    pub fn standard() -> Self {
        Self {
            backends: vec![
                Box::new(KeychainStore),
                Box::new(EnvStore),
                Box::new(FileStore),
            ],
        }
    }

    /// Build a resolver from an explicit backend list (tests, or `fvd`'s
    /// later full set including network backends).
    #[must_use]
    pub fn with(backends: Vec<Box<dyn SecretStore>>) -> Self {
        Self { backends }
    }

    /// Read the secret a single ref points at, via its backend. A backend
    /// error becomes `Ok(None)` so resolution degrades rather than aborts.
    #[must_use]
    pub fn get_ref(&self, r: &SecretRef) -> Option<String> {
        self.backends
            .iter()
            .find(|b| b.handles(r))
            .and_then(|b| b.get(r).ok().flatten())
            .filter(|s| !s.is_empty())
    }

    /// The first non-empty secret across `refs`, tried in order.
    #[must_use]
    pub fn resolve(&self, refs: &[SecretRef]) -> Option<String> {
        refs.iter().find_map(|r| self.get_ref(r))
    }

    /// Store `secret` at the first ref handled by a writable backend.
    pub fn store(&self, refs: &[SecretRef], secret: &str) -> Result<()> {
        for r in refs {
            if let Some(b) = self.backends.iter().find(|b| b.handles(r)) {
                if b.set(r, secret).is_ok() {
                    return Ok(());
                }
            }
        }
        bail!("no writable secret backend among the connection's refs")
    }

    /// Delete the secret behind every ref (best-effort).
    pub fn delete(&self, refs: &[SecretRef]) -> Result<()> {
        for r in refs {
            if let Some(b) = self.backends.iter().find(|b| b.handles(r)) {
                let _ = b.delete(r);
            }
        }
        Ok(())
    }
}

// ─── SecretRef constructors (used by connection presets) ────────────

/// A keychain secret ref.
#[must_use]
pub fn keychain_ref(service: impl Into<String>, account: impl Into<String>) -> SecretRef {
    SecretRef {
        store: Some(Store::Keychain(KeychainRef {
            service: service.into(),
            account: account.into(),
        })),
    }
}

/// An env-var secret ref: canonical `name` + accepted `aliases`.
#[must_use]
pub fn env_ref(name: impl Into<String>, aliases: Vec<String>) -> SecretRef {
    SecretRef {
        store: Some(Store::Env(EnvRef {
            name: name.into(),
            aliases,
        })),
    }
}

/// A file secret ref (`field` empty = whole file).
#[must_use]
pub fn file_ref(path: impl Into<String>, field: impl Into<String>) -> SecretRef {
    SecretRef {
        store: Some(Store::File(FileRef {
            path: path.into(),
            field: field.into(),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::{env_ref, extract_field, EnvStore, FileStore, Resolver, SecretStore};
    use crate::secretstore::file_ref;

    /// EnvStore prefers the canonical var, falls back through aliases, and
    /// returns the first non-empty. Serialized via unique var names so the
    /// ambient CI env can't interfere; values are placeholders.
    #[test]
    fn env_prefers_canonical_then_aliases() {
        let canon = "FASTVERK_TEST_CANON";
        let alias = "FASTVERK_TEST_ALIAS";
        for k in [canon, alias] {
            std::env::remove_var(k);
        }
        let store = EnvStore;
        let r = env_ref(canon, vec![alias.to_string()]);
        // neither set -> miss
        assert_eq!(store.get(&r).unwrap(), None);
        // only the alias set -> alias wins
        std::env::set_var(alias, "from-alias");
        assert_eq!(store.get(&r).unwrap().as_deref(), Some("from-alias"));
        // canonical set -> canonical wins over the alias
        std::env::set_var(canon, "from-canon");
        assert_eq!(store.get(&r).unwrap().as_deref(), Some("from-canon"));
        // empty canonical is skipped, alias still wins
        std::env::set_var(canon, "");
        assert_eq!(store.get(&r).unwrap().as_deref(), Some("from-alias"));
        for k in [canon, alias] {
            std::env::remove_var(k);
        }
    }

    /// The Resolver tries refs in order; a read-only backend that can't
    /// store is skipped so `store` lands on the writable (file) ref.
    #[test]
    fn resolver_order_and_file_round_trip() {
        let dir = std::env::temp_dir().join("fvkit-secretstore-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("token");
        let _ = std::fs::remove_file(&path);
        let refs = vec![
            env_ref("FASTVERK_TEST_UNSET_XYZ", vec![]),
            file_ref(path.to_string_lossy().to_string(), ""),
        ];
        // env + file backends only (no keychain touch in tests).
        let r = Resolver::with(vec![Box::new(EnvStore), Box::new(FileStore)]);
        assert_eq!(r.resolve(&refs), None);
        // store -> the env ref is read-only, so it lands in the file ref.
        r.store(&refs, "s3cr3t").unwrap();
        assert_eq!(r.resolve(&refs).as_deref(), Some("s3cr3t"));
        r.delete(&refs).unwrap();
        assert_eq!(r.resolve(&refs), None);
    }

    #[test]
    fn file_field_extraction() {
        assert_eq!(
            extract_field("A=1\nTOKEN=\"abc\"\nB=2", "TOKEN").as_deref(),
            Some("abc")
        );
        assert_eq!(extract_field("A=1", "MISSING"), None);
    }
}
