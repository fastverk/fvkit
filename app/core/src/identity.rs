//! fastverk identity — login / logout / whoami over the Cognito hosted-UI PKCE
//! flow.
//!
//! A thin layer over [`crate::connections`] (the `fastverk` preset) and
//! [`crate::oauth::pkce_flow`]. The **access token** is stored as the
//! connection's bearer secret (the API credential); the **id_token** is kept
//! alongside it so [`whoami`] can report the account (email/sub) offline,
//! without a network round-trip. fvd exposes this as the
//! `fastverk.identity.v1.Auth` service (see the daemon's `auth` module).
//!
//! The id_token's claims are decoded but **not** signature-verified here: the
//! token was just obtained directly from Cognito over TLS in our own PKCE
//! exchange, so it's locally trusted for display. (Server-side consumers — e.g.
//! `web/` — still verify it against the Cognito JWKS, like
//! `repos/botnoc/web/src/auth.rs`.)

use anyhow::Context;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::Deserialize;

use crate::identity_proto::Identity;
use crate::proto::SecretRef;
use crate::{connections, oauth, secretstore};
use crate::Result;

/// The connection id for the fastverk identity (matches the `fastverk` preset).
const FASTVERK_ID: &str = "fastverk";

/// Run the interactive PKCE login and persist the tokens. `open(authorize_url)`
/// opens the system browser. Returns the signed-in identity. Blocks until the
/// user authorizes (the loopback redirect arrives).
pub fn login(open: impl FnOnce(&str)) -> Result<Identity> {
    let conn = connections::preset(FASTVERK_ID, "", "")?;
    let oauth_cfg = conn
        .oauth
        .as_ref()
        .context("fastverk preset is missing its OAuth config")?;
    let issuer = oauth_cfg.issuer.clone();
    let audience = oauth_cfg.client_id.clone();
    let token = oauth::pkce_flow(oauth_cfg, open)?;

    // The access token is the connection's bearer secret (API credential).
    connections::persist(conn, &token.secret)?;

    // The id_token carries the identity claims; keep it for offline `whoami`.
    let id_token = token
        .id_token
        .context("Cognito returned no id_token (the `openid` scope is required)")?;
    // Establish trust at login: verify the RS256 signature + iss/aud/exp against
    // the IdP's JWKS (the network is up — we just exchanged the code). whoami
    // later trusts the stored, already-verified token (offline). A preset with
    // no issuer falls back to decode-only (trusting the direct TLS exchange).
    let claims = if issuer.is_empty() {
        decode_claims(&id_token)?
    } else {
        verify_id_token(&id_token, &issuer, &audience)?
    };
    secretstore::Resolver::standard().store(&[id_token_ref()], &id_token)?;

    Ok(identity_from_claims(&claims))
}

/// The current signed-in identity, decoded from the stored id_token, or an
/// unauthenticated `Identity` when not logged in.
pub fn whoami() -> Result<Identity> {
    match secretstore::Resolver::standard().resolve(&[id_token_ref()]) {
        // Offline: the stored token was signature-verified at login; read its
        // claims. An undecodable token still proves a login happened.
        Some(id_token) => Ok(identity_from_claims(
            &decode_claims(&id_token).unwrap_or_default(),
        )),
        None => Ok(Identity::default()),
    }
}

/// Forget the stored identity: delete the id_token and disconnect the
/// `fastverk` connection (which also clears its access token). Returns whether a
/// connection was present.
pub fn logout() -> Result<bool> {
    // Best-effort id_token cleanup; the connection removal is the source of truth.
    let _ = secretstore::Resolver::standard().delete(&[id_token_ref()]);
    connections::disconnect(FASTVERK_ID)
}

/// Where the id_token is stored: alongside the connection's access token in the
/// keychain, under a distinct account.
fn id_token_ref() -> SecretRef {
    secretstore::keychain_ref(format!("fastverk.{FASTVERK_ID}"), "id_token")
}

/// Build an `Identity` from decoded id_token claims. `authenticated` is true
/// whenever we hold a token (even one whose optional claims are absent).
fn identity_from_claims(claims: &Claims) -> Identity {
    Identity {
        authenticated: true,
        subject: claims.sub.clone(),
        email: claims.email.clone(),
        name: claims.name.clone(),
        expires_at: claims
            .exp
            .and_then(|e| chrono::DateTime::from_timestamp(e, 0))
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_default(),
    }
}

/// Verify an OIDC id_token: RS256 signature against the issuer's JWKS, plus the
/// iss / aud / exp claims. Returns the verified claims. Fetches the JWKS over
/// the network (`{issuer}/.well-known/jwks.json`).
fn verify_id_token(id_token: &str, issuer: &str, audience: &str) -> Result<Claims> {
    use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};

    let kid = decode_header(id_token)
        .context("read id_token header")?
        .kid
        .context("id_token has no `kid`")?;
    let jwks_url = format!("{}/.well-known/jwks.json", issuer.trim_end_matches('/'));
    let jwks: JwkSet = reqwest::blocking::get(&jwks_url)
        .and_then(reqwest::blocking::Response::error_for_status)
        .context("fetch JWKS")?
        .json()
        .context("parse JWKS")?;
    let jwk = jwks
        .find(&kid)
        .context("id_token signing key not in JWKS (key rotated?)")?;
    let key = DecodingKey::from_jwk(jwk).context("build decoding key from JWK")?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    Ok(decode::<Claims>(id_token, &key, &validation)
        .context("verify id_token signature/claims")?
        .claims)
}

/// The subset of OIDC id_token claims we surface.
#[derive(Deserialize, Default)]
struct Claims {
    #[serde(default)]
    sub: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    exp: Option<i64>,
}

/// Decode (without verifying) a JWT's claims: the middle `payload` segment is
/// base64url-no-pad JSON.
fn decode_claims(jwt: &str) -> Result<Claims> {
    let payload = jwt
        .split('.')
        .nth(1)
        .context("id_token is not a JWT (no payload segment)")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .context("base64url-decode id_token payload")?;
    Ok(serde_json::from_slice(&bytes).context("parse id_token claims")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build an unsigned JWT (`header.payload.`) with the given claims object —
    /// enough to exercise the claims decoder (which doesn't verify signatures).
    fn unsigned_jwt(claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        format!("{header}.{payload}.")
    }

    #[test]
    fn decodes_identity_from_id_token() {
        let jwt = unsigned_jwt(json!({
            "sub": "abc-123",
            "email": "marsh@example.com",
            "name": "Marsh",
            "exp": 1_700_000_000_i64,
        }));
        let id = identity_from_claims(&decode_claims(&jwt).unwrap());
        assert!(id.authenticated);
        assert_eq!(id.subject, "abc-123");
        assert_eq!(id.email, "marsh@example.com");
        assert_eq!(id.name, "Marsh");
        // 1_700_000_000 = 2023-11-14T22:13:20Z
        assert!(id.expires_at.starts_with("2023-11-14T22:13:20"));
    }

    #[test]
    fn identity_survives_missing_claims() {
        // Only `sub` — email/name absent, exp absent: still authenticated.
        let jwt = unsigned_jwt(json!({ "sub": "only-sub" }));
        let id = identity_from_claims(&decode_claims(&jwt).unwrap());
        assert!(id.authenticated);
        assert_eq!(id.subject, "only-sub");
        assert!(id.email.is_empty());
        assert!(id.expires_at.is_empty());
    }

    #[test]
    fn holding_a_token_reads_as_authenticated() {
        // whoami builds identity even from empty claims (an undecodable but
        // present token still proves a login happened).
        let id = identity_from_claims(&Claims::default());
        assert!(id.authenticated);
        assert!(id.subject.is_empty());
    }

    #[test]
    fn decode_claims_rejects_non_jwt() {
        assert!(decode_claims("nodots").is_err());
    }

    #[test]
    fn verify_id_token_rejects_malformed_token() {
        // Fails at header parse — before any network — so it's hermetic.
        assert!(verify_id_token("not-a-jwt", "https://issuer.example", "aud").is_err());
    }
}
