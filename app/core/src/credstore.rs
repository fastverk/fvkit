//! OS keychain wrapper for connection secrets.
//!
//! Secrets (OAuth access tokens, API keys) live in the OS keychain,
//! referenced from the connection registry by `(service, account)`. On
//! macOS this is the login Keychain via the `keyring` crate's
//! apple-native backend; Linux (Secret Service) / Windows (Credential
//! Manager) backends are enabled per-OS in a later phase.

use anyhow::{Context, Result};

fn entry(service: &str, account: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(service, account)
        .with_context(|| format!("open keychain entry {service}/{account}"))
}

/// Read the current secret for a keychain item, or `None` if absent.
pub fn get(service: &str, account: &str) -> Result<Option<String>> {
    match entry(service, account)?.get_password() {
        Ok(s) => Ok(Some(s)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(e).context("read keychain"),
    }
}

/// Store (or replace) the secret for a keychain item.
pub fn set(service: &str, account: &str, secret: &str) -> Result<()> {
    entry(service, account)?
        .set_password(secret)
        .context("write keychain")
}

/// Delete a keychain item; succeeds even if it was already absent.
pub fn delete(service: &str, account: &str) -> Result<()> {
    match entry(service, account)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e).context("delete keychain"),
    }
}

#[cfg(test)]
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
