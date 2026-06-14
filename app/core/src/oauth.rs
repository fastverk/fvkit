//! OAuth2 device-code flow (RFC 8628) for connecting providers.
//!
//! Device flow is the right fit for a menu-bar app: no loopback server,
//! the user authorizes in a browser with a short code. Needs a registered
//! OAuth App `client_id` per provider (device flow enabled). Blocking
//! HTTP via `reqwest::blocking`; `fv` calls it directly, `fvd` wraps it in
//! `spawn_blocking`.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::proto::OAuthConfig;

/// An access token plus its optional RFC 3339 expiry.
pub struct Token {
    pub secret: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Deserialize)]
struct DeviceAuth {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default = "default_interval")]
    interval: u64,
}

const fn default_interval() -> u64 {
    5
}

#[derive(Deserialize)]
struct TokenResp {
    access_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    error: Option<String>,
}

fn expiry(expires_in: Option<i64>) -> Option<String> {
    expires_in.map(|s| (chrono::Utc::now() + chrono::Duration::seconds(s)).to_rfc3339())
}

/// Run the device-code flow to completion. `prompt(user_code,
/// verification_uri)` is invoked once so the caller can display + open it;
/// then this polls the token endpoint until the user authorizes.
pub fn device_flow(oauth: &OAuthConfig, prompt: impl FnOnce(&str, &str)) -> Result<Token> {
    if oauth.client_id.is_empty() {
        bail!("missing OAuth client_id (register an OAuth App with device flow enabled)");
    }
    if oauth.device_auth_url.is_empty() {
        bail!("provider has no device_auth_url (device flow unsupported)");
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build http client")?;
    let scope = oauth.scopes.join(" ");

    let da: DeviceAuth = client
        .post(&oauth.device_auth_url)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", oauth.client_id.as_str()),
            ("scope", scope.as_str()),
        ])
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .context("device authorization request")?
        .json()
        .context("parse device authorization response")?;

    prompt(&da.user_code, &da.verification_uri);

    let mut interval = da.interval.max(1);
    loop {
        std::thread::sleep(Duration::from_secs(interval));
        let resp: TokenResp = client
            .post(&oauth.token_url)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", oauth.client_id.as_str()),
                ("device_code", da.device_code.as_str()),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .context("token poll")?
            .json()
            .context("parse token response")?;

        if let Some(secret) = resp.access_token {
            return Ok(Token {
                secret,
                refresh_token: resp.refresh_token,
                expires_at: expiry(resp.expires_in),
            });
        }
        match resp.error.as_deref() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            Some("expired_token") => bail!("device code expired; start over"),
            Some("access_denied") => bail!("authorization denied"),
            Some(other) => bail!("oauth error: {other}"),
            None => bail!("token endpoint returned neither access_token nor error"),
        }
    }
}

/// Exchange a refresh token for a fresh access token.
pub fn refresh(oauth: &OAuthConfig, refresh_token: &str) -> Result<Token> {
    let client = reqwest::blocking::Client::new();
    let resp: TokenResp = client
        .post(&oauth.token_url)
        .header("Accept", "application/json")
        .form(&[
            ("client_id", oauth.client_id.as_str()),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ])
        .send()
        .context("refresh request")?
        .json()
        .context("parse refresh response")?;
    match resp.access_token {
        Some(secret) => Ok(Token {
            secret,
            refresh_token: resp.refresh_token,
            expires_at: expiry(resp.expires_in),
        }),
        None => bail!(
            "refresh failed: {}",
            resp.error.unwrap_or_else(|| "no access_token".to_string())
        ),
    }
}
