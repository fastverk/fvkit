//! OAuth2 device-code flow (RFC 8628) for connecting providers.
//!
//! Device flow is the right fit for a menu-bar app: no loopback server,
//! the user authorizes in a browser with a short code. Needs a registered
//! OAuth App `client_id` per provider (device flow enabled). Blocking
//! HTTP via `reqwest::blocking`; `fv` calls it directly, `fvd` wraps it in
//! `spawn_blocking`.

use std::time::Duration;

use crate::Result;
use anyhow::Context;
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

// ─── PKCE authorization-code loopback flow (RFC 7636 + RFC 8252) ─────────────
//
// The device flow above suits forge logins (GitHub/GitLab) but not every IdP
// exposes a device endpoint. App login against Cognito (shared with the VPN)
// uses the authorization-code flow with PKCE over a localhost redirect: no
// client secret, no public server. The VPN's `wg-client` already does this; this
// is the shared fvkit implementation both consume.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

/// Run the OAuth2 authorization-code flow with PKCE over a loopback redirect.
/// `open(authorize_url)` is invoked so the caller can open the browser; this
/// then binds a localhost listener, waits for the redirect, validates `state`,
/// and exchanges the code (+ verifier) for a token. Blocking (like
/// [`device_flow`]); `fvd` wraps it in `spawn_blocking`.
///
/// Binds an ephemeral loopback port (RFC 8252 §7.3). IdPs that require an exact
/// pre-registered redirect URI (Cognito) need a fixed port — that's wired in the
/// Login slice via an `OAuthConfig` redirect field; for now the bound port is
/// used, which suits IdPs that allow dynamic loopback ports.
pub fn pkce_flow(oauth: &OAuthConfig, open: impl FnOnce(&str)) -> Result<Token> {
    if oauth.client_id.is_empty() {
        bail!("missing OAuth client_id");
    }
    if oauth.auth_url.is_empty() || oauth.token_url.is_empty() {
        bail!("provider has no auth_url/token_url (authorization-code flow unsupported)");
    }
    let verifier = code_verifier();
    let challenge = code_challenge(&verifier);
    let state = random_token(16);

    let (listener, redirect_uri) = bind_redirect(&oauth.redirect_uri)?;

    let url = authorize_url(oauth, &redirect_uri, &challenge, &state)?;
    open(&url);

    let code = receive_code(&listener, &state)?;
    exchange_code(oauth, &code, &redirect_uri, &verifier)
}

/// Bind the loopback listener for the PKCE redirect and return it with the
/// redirect URI to advertise. A `configured` redirect (an IdP that requires an
/// exact pre-registered URI — e.g. Cognito) is bound on its exact port and used
/// verbatim; otherwise we take an ephemeral 127.0.0.1 port (RFC 8252 §7.3),
/// which suits IdPs that allow dynamic loopback ports. We always bind 127.0.0.1
/// (a `localhost` URI resolves to it), so the browser's redirect reaches us.
fn bind_redirect(configured: &str) -> Result<(TcpListener, String)> {
    if configured.is_empty() {
        let listener =
            TcpListener::bind("127.0.0.1:0").context("bind loopback redirect listener")?;
        let port = listener.local_addr().context("loopback addr")?.port();
        return Ok((listener, format!("http://127.0.0.1:{port}/callback")));
    }
    let port = reqwest::Url::parse(configured)
        .context("parse redirect_uri")?
        .port()
        .context("redirect_uri has no explicit port")?;
    let listener = TcpListener::bind(("127.0.0.1", port))
        .with_context(|| format!("bind loopback redirect port {port} (already in use?)"))?;
    Ok((listener, configured.to_string()))
}

/// A high-entropy PKCE code verifier: base64url of 32 bytes of OS randomness
/// (43 chars from RFC 7636's unreserved set).
fn code_verifier() -> String {
    random_token(32)
}

/// base64url-no-pad of `nbytes` of OS randomness (PKCE verifier / CSRF `state`).
fn random_token(nbytes: usize) -> String {
    let mut buf = vec![0u8; nbytes];
    getrandom::getrandom(&mut buf).expect("OS RNG unavailable");
    URL_SAFE_NO_PAD.encode(buf)
}

/// The PKCE `S256` challenge for a verifier: base64url(SHA-256(verifier)).
fn code_challenge(verifier: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.as_ref())
}

/// Build the authorization-endpoint URL for the PKCE flow.
fn authorize_url(
    oauth: &OAuthConfig,
    redirect_uri: &str,
    challenge: &str,
    state: &str,
) -> Result<String> {
    // reqwest re-exports the `url` crate, so percent-encoding is handled for us.
    let url = reqwest::Url::parse_with_params(
        &oauth.auth_url,
        &[
            ("response_type", "code"),
            ("client_id", oauth.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("scope", oauth.scopes.join(" ").as_str()),
            ("state", state),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ],
    )
    .context("build authorize url")?;
    Ok(url.into())
}

/// Block on the loopback listener for the OAuth redirect, validate `state`
/// (CSRF), send the browser a friendly page, and return the authorization code.
fn receive_code(listener: &TcpListener, expected_state: &str) -> Result<String> {
    let (mut stream, _) = listener.accept().context("accept loopback redirect")?;
    // "GET /callback?code=...&state=... HTTP/1.1" — we only need the target.
    let request_line = {
        let mut reader = BufReader::new(&stream);
        let mut line = String::new();
        reader.read_line(&mut line).context("read redirect request")?;
        line
    };
    let target = request_line
        .split_whitespace()
        .nth(1)
        .context("malformed redirect request line")?;
    let (code, state) = parse_callback(target)?;
    ensure!(
        state.as_deref() == Some(expected_state),
        "OAuth state mismatch (possible CSRF); ignoring redirect"
    );
    let code = code.context("redirect carried no authorization code")?;

    let body = "<!doctype html><title>fastverk</title><body style=\"font-family:system-ui;text-align:center;padding-top:3rem\"><h2>fastverk</h2><p>You're signed in. You can close this window.</p></body>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let _ = stream.write_all(response.as_bytes());
    Ok(code)
}

/// Parse a redirect target (`/callback?code=A&state=B`) into `(code, state)`,
/// failing if the IdP returned an `error`.
fn parse_callback(target: &str) -> Result<(Option<String>, Option<String>)> {
    let url = reqwest::Url::parse(&format!("http://localhost{target}"))
        .context("parse redirect target")?;
    let mut code = None;
    let mut state = None;
    for (k, v) in url.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => bail!("authorization failed: {v}"),
            _ => {}
        }
    }
    Ok((code, state))
}

/// Exchange an authorization `code` (+ PKCE `verifier`) for a token.
fn exchange_code(
    oauth: &OAuthConfig,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<Token> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build http client")?;
    let resp: TokenResp = client
        .post(&oauth.token_url)
        .header("Accept", "application/json")
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", oauth.client_id.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ])
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)
        .context("token exchange")?
        .json()
        .context("parse token response")?;
    match resp.access_token {
        Some(secret) => Ok(Token {
            secret,
            refresh_token: resp.refresh_token,
            expires_at: expiry(resp.expires_in),
        }),
        None => bail!(
            "token exchange failed: {}",
            resp.error.unwrap_or_else(|| "no access_token".to_string())
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpStream;

    // RFC 7636 Appendix B test vector pins the S256 challenge derivation
    // (SHA-256 + base64url-no-pad) — the security-critical bit of PKCE.
    #[test]
    fn s256_challenge_matches_rfc7636_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            code_challenge(verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        );
    }

    #[test]
    fn verifier_is_high_entropy_and_url_safe() {
        let v = code_verifier();
        assert_eq!(v.len(), 43, "base64url of 32 bytes is 43 chars");
        assert!(
            v.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')),
            "verifier must be url-safe: {v}",
        );
        assert_ne!(code_verifier(), code_verifier(), "verifiers must differ");
    }

    #[test]
    fn authorize_url_carries_pkce_params() {
        let oauth = OAuthConfig {
            client_id: "cid".to_string(),
            auth_url: "https://idp.example.com/authorize".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
            ..Default::default()
        };
        let url = authorize_url(&oauth, "http://127.0.0.1:9/callback", "CHAL", "STATE").unwrap();
        let parsed = reqwest::Url::parse(&url).unwrap();
        let params: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(parsed.path(), "/authorize");
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["client_id"], "cid");
        assert_eq!(params["code_challenge"], "CHAL");
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["state"], "STATE");
        assert_eq!(params["redirect_uri"], "http://127.0.0.1:9/callback");
        assert_eq!(params["scope"], "openid email");
    }

    #[test]
    fn parse_callback_extracts_code_and_surfaces_errors() {
        let (code, state) = parse_callback("/callback?code=abc123&state=xyz").unwrap();
        assert_eq!(code.as_deref(), Some("abc123"));
        assert_eq!(state.as_deref(), Some("xyz"));
        assert!(parse_callback("/callback?error=access_denied").is_err());
    }

    // The loopback half end-to-end (no browser/IdP): a real client connects to
    // the listener and "redirects" with code+state; receive_code parses it,
    // validates state, and answers the browser HTTP 200.
    #[test]
    fn receive_code_round_trips_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let client = std::thread::spawn(move || {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            s.write_all(b"GET /callback?code=THE_CODE&state=THE_STATE HTTP/1.1\r\nHost: x\r\n\r\n")
                .unwrap();
            let mut resp = String::new();
            s.read_to_string(&mut resp).unwrap();
            resp
        });

        let code = receive_code(&listener, "THE_STATE").expect("receive code");
        assert_eq!(code, "THE_CODE");
        let browser_response = client.join().unwrap();
        assert!(browser_response.starts_with("HTTP/1.1 200 OK"));
        assert!(browser_response.contains("signed in"));
    }

    #[test]
    fn bind_redirect_uses_configured_port_verbatim() {
        // An IdP-registered redirect must be bound on its exact port and used
        // verbatim (Cognito matches the redirect_uri string exactly).
        let configured = "http://localhost:8765/callback";
        let (listener, uri) = match bind_redirect(configured) {
            Ok(pair) => pair,
            // 8765 already in use on this host — don't flake.
            Err(_) => return,
        };
        assert_eq!(uri, configured);
        assert_eq!(listener.local_addr().unwrap().port(), 8765);
    }

    #[test]
    fn bind_redirect_falls_back_to_ephemeral_loopback() {
        let (listener, uri) = bind_redirect("").expect("ephemeral bind");
        let port = listener.local_addr().unwrap().port();
        assert_ne!(port, 0);
        assert_eq!(uri, format!("http://127.0.0.1:{port}/callback"));
    }

    #[test]
    fn receive_code_rejects_state_mismatch() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let _client = std::thread::spawn(move || {
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
                let _ = s.write_all(b"GET /callback?code=C&state=WRONG HTTP/1.1\r\n\r\n");
                let mut buf = Vec::new();
                let _ = s.read_to_end(&mut buf);
            }
        });
        assert!(
            receive_code(&listener, "EXPECTED").is_err(),
            "a mismatched state must be rejected (CSRF defense)",
        );
    }
}
