//! OAuth flows for connecting providers (GitHub, GitLab, generic OIDC).
//!
//! P1 implements RFC 8628 device-code (preferred for a menu-bar app —
//! no loopback server) and PKCE loopback, via `reqwest`, plus refresh.
//! `web/src/auth.rs` (Cognito OIDC/JWKS) is the in-repo reference for
//! the OIDC shapes. The result is `(secret, expires_at)` which `fvd`
//! writes to the keychain and records in the connection registry.

use anyhow::Result;

use crate::proto::Connection;

/// Outcome of an OAuth flow: the access token plus its optional RFC 3339
/// expiry (empty when it does not expire).
pub struct Token {
    pub secret: String,
    pub expires_at: Option<String>,
}

/// Run the provider's OAuth flow to completion and return a token.
pub fn run_flow(_conn: &Connection) -> Result<Token> {
    anyhow::bail!("TODO(P1): OAuth device-code / PKCE flow")
}

/// Exchange a refresh token for a fresh access token.
pub fn refresh(_conn: &Connection) -> Result<Token> {
    anyhow::bail!("TODO(P1): OAuth token refresh")
}
