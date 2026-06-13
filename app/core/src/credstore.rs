//! OS keychain wrapper for connection secrets.
//!
//! Secrets (OAuth access tokens, API keys) live in the OS keychain,
//! referenced from the connection registry by `(service, account)`.
//!
//! P1 wires the real backend (macOS Keychain via the `keyring` crate /
//! Security-framework). The signatures are stable now so [`crate::connections::resolve`],
//! `fvd`, and the cred-helper can all be written against them.

use anyhow::Result;

/// Read the current secret for a keychain item, or `None` if absent.
pub fn get(_service: &str, _account: &str) -> Result<Option<String>> {
    // TODO(P1): keyring::Entry::new(service, account).get_password().
    Ok(None)
}

/// Store (or replace) the secret for a keychain item.
pub fn set(_service: &str, _account: &str, _secret: &str) -> Result<()> {
    anyhow::bail!("TODO(P1): keychain write (keyring crate / Security-framework)")
}

/// Delete a keychain item; succeeds even if it was already absent.
pub fn delete(_service: &str, _account: &str) -> Result<()> {
    // TODO(P1): keyring delete, treating NoEntry as success.
    Ok(())
}
