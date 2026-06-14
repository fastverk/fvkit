//! The connection registry: the host → auth mapping the credential
//! helper consults and the GUI manages.
//!
//! Persisted as a prost-encoded [`ConnectionRegistry`] at
//! [`crate::paths::registry_path`]. Secrets are never stored here — only
//! a keychain reference. [`resolve`] is the read path the cred-helper
//! (and `fvd`'s `GetCredentials`) use to turn a request URI into a
//! header + value.

use anyhow::{bail, Context, Result};
use prost::Message;

use crate::proto::{AuthKind, Connection, ConnectionRegistry, OAuthConfig};
use crate::{credstore, oauth, paths, uri};

/// Load the persisted registry, or an empty one when none exists.
pub fn load() -> Result<ConnectionRegistry> {
    let p = paths::registry_path()?;
    if !p.exists() {
        return Ok(ConnectionRegistry::default());
    }
    let bytes = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
    ConnectionRegistry::decode(bytes.as_slice()).context("decode connection registry")
}

/// Persist the registry.
pub fn save(reg: &ConnectionRegistry) -> Result<()> {
    paths::ensure_config_dir()?;
    let p = paths::registry_path()?;
    std::fs::write(&p, reg.encode_to_vec()).with_context(|| format!("write {}", p.display()))
}

/// Remove a connection by id; returns whether one was removed. The
/// caller is responsible for deleting any associated keychain item.
pub fn remove(reg: &mut ConnectionRegistry, id: &str) -> bool {
    let before = reg.connections.len();
    reg.connections.retain(|c| c.id != id);
    reg.connections.len() != before
}

/// The first connection whose host patterns match `host`.
#[must_use]
pub fn match_host<'a>(reg: &'a ConnectionRegistry, host: &str) -> Option<&'a Connection> {
    reg.connections
        .iter()
        .find(|c| c.host_patterns.iter().any(|p| host_matches(p, host)))
}

/// `*.suffix` matches `suffix` and any `*.suffix`; otherwise exact.
#[must_use]
pub fn host_matches(pattern: &str, host: &str) -> bool {
    pattern.strip_prefix("*.").map_or_else(
        || pattern == host,
        |suffix| host == suffix || host.ends_with(&format!(".{suffix}")),
    )
}

/// A resolved credential ready to emit as a Bazel cred-helper header.
pub struct ResolvedCred {
    pub header: String,
    pub value: String,
}

/// Resolve the auth header for a request URI from the persisted registry
/// + keychain. `None` => anonymous fetch. Does NOT refresh expired
/// tokens — `fvd` wraps this with refresh; the cred-helper fallback path
/// reads whatever token is currently stored.
pub fn resolve(req_uri: &str) -> Result<Option<ResolvedCred>> {
    let host = uri::host_of(req_uri);
    if host.is_empty() {
        return Ok(None);
    }
    let reg = load()?;
    let Some(conn) = match_host(&reg, host) else {
        return Ok(None);
    };
    let Some(secret) = credstore::get(&conn.keychain_service, &conn.keychain_account)? else {
        return Ok(None);
    };
    if secret.is_empty() {
        return Ok(None);
    }
    Ok(Some(ResolvedCred {
        header: conn.header.clone(),
        value: format!("{}{secret}", conn.value_prefix),
    }))
}

// ─── Provider presets + connect ────────────────────────────────────

/// Built-in (public) OAuth App client ids shipped with the app, so users
/// can connect with one click — no per-machine configuration. Device-code
/// client ids carry NO secret, so bundling them is safe. An explicit
/// `--client-id` or `config.client_ids[provider]` overrides these.
///
/// Empty until the org's OAuth Apps (with Device Flow enabled) are
/// registered; fill in the Client ID values then.
const GITHUB_CLIENT_ID: &str = "";
const GITLAB_CLIENT_ID: &str = "";

/// `given` if non-empty, else the bundled `default`.
fn pick(given: &str, default: &str) -> String {
    if given.is_empty() { default } else { given }.to_string()
}

/// Build a connection from a provider preset, leaving the secret to be
/// filled by [`connect`]. For OAuth providers, falls back to the built-in
/// [`GITHUB_CLIENT_ID`]/[`GITLAB_CLIENT_ID`] when `client_id` is empty.
pub fn preset(provider: &str, client_id: &str) -> Result<Connection> {
    let mut c = Connection::default();
    match provider {
        "github" => {
            c.id = "github".to_string();
            c.display_name = "GitHub".to_string();
            c.provider = "github".to_string();
            c.host_patterns = vec![
                "github.com".to_string(),
                "*.github.com".to_string(),
                "raw.githubusercontent.com".to_string(),
                "codeload.github.com".to_string(),
            ];
            c.header = "Authorization".to_string();
            c.value_prefix = "Bearer ".to_string();
            c.auth_kind = AuthKind::Oauth as i32;
            c.oauth = Some(OAuthConfig {
                client_id: pick(client_id, GITHUB_CLIENT_ID),
                auth_url: "https://github.com/login/oauth/authorize".to_string(),
                token_url: "https://github.com/login/oauth/access_token".to_string(),
                device_auth_url: "https://github.com/login/device/code".to_string(),
                scopes: vec!["repo".to_string(), "read:org".to_string()],
                ..Default::default()
            });
            c.keychain_service = "fastverk.github".to_string();
            c.keychain_account = "oauth".to_string();
        }
        "gitlab" => {
            c.id = "gitlab".to_string();
            c.display_name = "GitLab".to_string();
            c.provider = "gitlab".to_string();
            c.host_patterns = vec!["gitlab.com".to_string(), "*.gitlab.com".to_string()];
            c.header = "Authorization".to_string();
            c.value_prefix = "Bearer ".to_string();
            c.auth_kind = AuthKind::Oauth as i32;
            c.oauth = Some(OAuthConfig {
                client_id: pick(client_id, GITLAB_CLIENT_ID),
                auth_url: "https://gitlab.com/oauth/authorize".to_string(),
                token_url: "https://gitlab.com/oauth/token".to_string(),
                device_auth_url: "https://gitlab.com/oauth/authorize_device".to_string(),
                scopes: vec!["api".to_string(), "read_repository".to_string()],
                ..Default::default()
            });
            c.keychain_service = "fastverk.gitlab".to_string();
            c.keychain_account = "oauth".to_string();
        }
        "buildbuddy" => {
            // BuildBuddy authenticates with a static API key (no OAuth).
            c.id = "buildbuddy".to_string();
            c.display_name = "BuildBuddy".to_string();
            c.provider = "buildbuddy".to_string();
            c.host_patterns = vec!["remote.buildbuddy.io".to_string()];
            c.header = "x-buildbuddy-api-key".to_string();
            c.auth_kind = AuthKind::ApiKey as i32;
            c.keychain_service = "fastverk.buildbuddy".to_string();
            c.keychain_account = "api-key".to_string();
        }
        other => bail!("unknown provider preset: {other} (use github|gitlab|buildbuddy)"),
    }
    Ok(c)
}

/// Inputs for [`connect`].
pub struct ConnectParams {
    pub provider: String,
    /// OAuth App client id (required for OAuth providers).
    pub client_id: String,
    /// API key (required for AUTH_KIND_API_KEY providers, e.g. BuildBuddy).
    pub api_key: String,
}

/// Establish a connection: run the provider's auth (OAuth device flow or
/// API key), store the secret in the keychain, and upsert the registry.
/// `prompt(user_code, verification_uri)` is shown during OAuth. Returns
/// the persisted connection (which never carries the secret).
pub fn connect(params: &ConnectParams, prompt: impl FnOnce(&str, &str)) -> Result<Connection> {
    let mut conn = preset(&params.provider, &params.client_id)?;
    let secret = match conn.auth_kind() {
        AuthKind::Oauth => {
            let oauth_cfg = conn
                .oauth
                .as_ref()
                .context("OAuth preset is missing its config")?;
            oauth::device_flow(oauth_cfg, prompt)?.secret
        }
        AuthKind::ApiKey => {
            if params.api_key.is_empty() {
                bail!("provider {} needs an API key", params.provider);
            }
            params.api_key.clone()
        }
        AuthKind::Unspecified => bail!("connection has no auth kind"),
    };

    conn.connected_at = chrono::Utc::now().to_rfc3339();
    credstore::set(&conn.keychain_service, &conn.keychain_account, &secret)?;

    let mut reg = load()?;
    reg.connections.retain(|c| c.id != conn.id);
    reg.connections.push(conn.clone());
    save(&reg)?;
    Ok(conn)
}

/// Remove a connection and delete its keychain secret.
pub fn disconnect(id: &str) -> Result<bool> {
    let mut reg = load()?;
    if let Some(c) = reg.connections.iter().find(|c| c.id == id) {
        let _ = credstore::delete(&c.keychain_service, &c.keychain_account);
    }
    let removed = remove(&mut reg, id);
    if removed {
        save(&reg)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::{host_matches, preset};
    use crate::proto::AuthKind;

    #[test]
    fn wildcard_and_exact() {
        assert!(host_matches("github.com", "github.com"));
        assert!(!host_matches("github.com", "api.github.com"));
        assert!(host_matches("*.github.com", "api.github.com"));
        assert!(host_matches("*.github.com", "github.com"));
        assert!(!host_matches("*.github.com", "notgithub.com"));
    }

    #[test]
    fn presets_have_expected_shape() {
        let gh = preset("github", "cid123").unwrap();
        assert_eq!(gh.auth_kind(), AuthKind::Oauth);
        assert_eq!(gh.header, "Authorization");
        assert_eq!(gh.oauth.as_ref().unwrap().client_id, "cid123");
        assert!(gh.host_patterns.iter().any(|h| h == "github.com"));

        let bb = preset("buildbuddy", "").unwrap();
        assert_eq!(bb.auth_kind(), AuthKind::ApiKey);
        assert_eq!(bb.header, "x-buildbuddy-api-key");

        assert!(preset("nope", "").is_err());
    }
}
