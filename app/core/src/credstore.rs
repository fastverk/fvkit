//! OS keychain wrapper for connection secrets.
//!
//! Secrets (OAuth access tokens, API keys) live in the OS keychain,
//! referenced from the connection registry by `(service, account)`. macOS
//! uses the login Keychain via the `keyring` crate's apple-native backend.
//! Linux (Secret Service) / Windows (Credential Manager) are P6 — there,
//! these stub out (`get` -> `None`), so callers (e.g. the cred-helper)
//! fall through to their env-var path and `fvkit` still builds.

#[cfg(target_os = "macos")]
mod backend {
    use anyhow::{Context, Result};

    fn entry(service: &str, account: &str) -> Result<keyring::Entry> {
        keyring::Entry::new(service, account)
            .with_context(|| format!("open keychain entry {service}/{account}"))
    }

    pub fn get(service: &str, account: &str) -> Result<Option<String>> {
        match entry(service, account)?.get_password() {
            Ok(s) => Ok(Some(s)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(e).context("read keychain"),
        }
    }

    pub fn set(service: &str, account: &str, secret: &str) -> Result<()> {
        entry(service, account)?
            .set_password(secret)
            .context("write keychain")
    }

    pub fn delete(service: &str, account: &str) -> Result<()> {
        match entry(service, account)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e).context("delete keychain"),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod backend {
    use anyhow::{bail, Result};

    pub fn get(_service: &str, _account: &str) -> Result<Option<String>> {
        Ok(None)
    }

    pub fn set(_service: &str, _account: &str, _secret: &str) -> Result<()> {
        bail!("OS keychain is not available on this platform yet (P6)")
    }

    pub fn delete(_service: &str, _account: &str) -> Result<()> {
        Ok(())
    }
}

/// Read the current secret for a keychain item, or `None` if absent.
pub fn get(service: &str, account: &str) -> anyhow::Result<Option<String>> {
    backend::get(service, account)
}

/// Store (or replace) the secret for a keychain item.
pub fn set(service: &str, account: &str, secret: &str) -> anyhow::Result<()> {
    backend::set(service, account, secret)
}

/// Delete a keychain item; succeeds even if it was already absent.
pub fn delete(service: &str, account: &str) -> anyhow::Result<()> {
    backend::delete(service, account)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{delete, get, set};

    // Touches the real login keychain, so it's opt-in: run with
    // `cargo test -p fvkit -- --ignored keychain_round_trip`.
    #[test]
    #[ignore]
    fn keychain_round_trip() {
        let (svc, acct) = ("fastverk-test", "round-trip");
        set(svc, acct, "s3cr3t").unwrap();
        assert_eq!(get(svc, acct).unwrap().as_deref(), Some("s3cr3t"));
        delete(svc, acct).unwrap();
        assert_eq!(get(svc, acct).unwrap(), None);
    }
}
