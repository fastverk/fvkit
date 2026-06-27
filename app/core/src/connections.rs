//! The connection registry: the host → auth mapping the credential
//! helper consults and the GUI manages.
//!
//! Persisted as a prost-encoded [`ConnectionRegistry`] at
//! [`crate::paths::registry_path`]. Secrets are never stored here — only
//! a keychain reference. [`resolve`] is the read path the cred-helper
//! (and `fvd`'s `GetCredentials`) use to turn a request URI into a
//! header + value.

use crate::Result;
use anyhow::Context;
use prost::Message;

use crate::proto::{secret_ref::Store, AuthKind, Connection, ConnectionRegistry, OAuthConfig};
use crate::{oauth, paths, secretstore, uri};

/// Load the persisted registry, or an empty one when none exists.
pub fn load() -> Result<ConnectionRegistry> {
    let p = paths::registry_path()?;
    if !p.exists() {
        return Ok(ConnectionRegistry::default());
    }
    let bytes = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
    let mut reg =
        ConnectionRegistry::decode(bytes.as_slice()).context("decode connection registry")?;
    migrate(&mut reg);
    Ok(reg)
}

/// Migrate registries written before secret backends were pluggable: a
/// connection with no `secret_refs` but a legacy `keychain_service` gets a
/// single keychain ref synthesized so its stored token keeps resolving.
fn migrate(reg: &mut ConnectionRegistry) {
    for c in &mut reg.connections {
        if c.secret_refs.is_empty() && !c.keychain_service.is_empty() {
            let account = if c.keychain_account.is_empty() {
                "oauth".to_string()
            } else {
                c.keychain_account.clone()
            };
            c.secret_refs = vec![secretstore::keychain_ref(c.keychain_service.clone(), account)];
        }
    }
}

/// Persist the registry.
pub fn save(reg: &ConnectionRegistry) -> Result<()> {
    paths::ensure_config_dir()?;
    let p = paths::registry_path()?;
    Ok(std::fs::write(&p, reg.encode_to_vec()).with_context(|| format!("write {}", p.display()))?)
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

/// Resolve the auth header for a request URI. `None` => anonymous fetch.
///
/// Matches the request host against the user's registry first, then the
/// built-in [`default_registry`], so CI (env backend) and a fresh machine
/// resolve through the same path. The connection's `secret_refs` are then
/// tried in order (keychain locally, the canonical env var in CI) via the
/// [`secretstore::Resolver`]. Best-effort: a corrupt registry or a
/// keychain error degrades to the next ref / anonymous rather than failing
/// the build. Does NOT refresh expired tokens — `fvd` wraps this with
/// refresh; this path reads whatever token is currently stored.
pub fn resolve(req_uri: &str) -> Result<Option<ResolvedCred>> {
    let host = uri::host_of(req_uri);
    if host.is_empty() {
        return Ok(None);
    }
    // User registry wins; the built-in defaults fill in on a miss (or when
    // there's no registry file at all, e.g. CI).
    let reg = load().unwrap_or_default();
    let conn = match match_host(&reg, host) {
        Some(c) => c.clone(),
        None => {
            let def = default_registry();
            let Some(c) = match_host(&def, host) else {
                return Ok(None);
            };
            c.clone()
        }
    };
    let Some(secret) = secretstore::Resolver::standard().resolve(&conn.secret_refs) else {
        return Ok(None);
    };
    Ok(Some(ResolvedCred {
        header: conn.header.clone(),
        value: format!("{}{secret}", conn.value_prefix),
    }))
}

// ─── diagnose: explain how a request URI resolves (no secret values) ────

/// One `secret_ref`'s resolution attempt, for `diagnose`. Carries no secret —
/// only where it reads from and whether that source is present.
pub struct RefTrace {
    /// Backend scheme: `keychain` / `env` / `file` / `unknown`.
    pub backend: String,
    /// Where it reads from: env var names (canonical + aliases), keychain
    /// `service/account`, or file path.
    pub target: String,
    /// The concrete source that produced a value (e.g. the env var name that
    /// was set), or `None` if this ref yielded nothing.
    pub yielded_from: Option<String>,
}

/// The connection a host matched, and from which registry.
pub struct MatchedConn {
    pub id: String,
    pub host_patterns: Vec<String>,
    /// `true` = matched the user's persisted registry; `false` = the built-in
    /// default registry (the CI / fresh-machine path).
    pub from_user_registry: bool,
}

/// A full, secret-free resolution trace for a request URI — what `cred-helper
/// diagnose <uri>` renders. Mirrors [`resolve`]'s logic so it explains exactly
/// what the hot path would do.
pub struct ResolveExplain {
    pub host: String,
    pub path: String,
    pub matched: Option<MatchedConn>,
    pub refs: Vec<RefTrace>,
    /// The header that would be emitted (e.g. `Authorization`), or `None` for
    /// an anonymous fetch.
    pub chosen_header: Option<String>,
    /// Length of the emitted header value (prefix + secret) — never the value.
    pub chosen_value_len: usize,
    /// `backend:source` of the ref that won (e.g. `env:FASTVERK_TOKEN_…`).
    pub chosen_source: Option<String>,
}

/// First non-empty of an env ref's `name` then `aliases` — the var the env
/// backend would actually read (mirrors `secretstore::EnvStore::get`).
fn env_source(name: &str, aliases: &[String]) -> Option<String> {
    std::iter::once(name)
        .chain(aliases.iter().map(String::as_str))
        .filter(|n| !n.is_empty())
        .find(|n| std::env::var(n).is_ok_and(|v| !v.is_empty()))
        .map(String::from)
}

/// Describe a single ref: `(backend, target, concrete-source-if-present)`.
fn trace_ref(resolver: &secretstore::Resolver, r: &crate::proto::SecretRef) -> RefTrace {
    let yields = resolver.get_ref(r).is_some();
    match &r.store {
        Some(Store::Env(e)) => {
            let names: Vec<&str> = std::iter::once(e.name.as_str())
                .chain(e.aliases.iter().map(String::as_str))
                .filter(|n| !n.is_empty())
                .collect();
            RefTrace {
                backend: "env".to_string(),
                target: names.join(" → "),
                yielded_from: env_source(&e.name, &e.aliases),
            }
        }
        Some(Store::Keychain(k)) => RefTrace {
            backend: "keychain".to_string(),
            target: format!("{}/{}", k.service, k.account),
            yielded_from: yields.then(|| format!("{}/{}", k.service, k.account)),
        },
        Some(Store::File(f)) => RefTrace {
            backend: "file".to_string(),
            target: f.path.clone(),
            yielded_from: yields.then(|| f.path.clone()),
        },
        None => RefTrace {
            backend: "unknown".to_string(),
            target: String::new(),
            yielded_from: None,
        },
    }
}

/// Explain how `req_uri` resolves: the matched connection, every `secret_ref`
/// tried (with which source is present), and the header that would be sent.
/// Reads no secret values — safe to print in CI logs.
#[must_use]
pub fn explain(req_uri: &str) -> ResolveExplain {
    let host = uri::host_of(req_uri).to_string();
    let path = uri::path_of(req_uri).to_string();
    let mut out = ResolveExplain {
        host: host.clone(),
        path,
        matched: None,
        refs: Vec::new(),
        chosen_header: None,
        chosen_value_len: 0,
        chosen_source: None,
    };
    if host.is_empty() {
        return out;
    }
    let reg = load().unwrap_or_default();
    let (conn, from_user) = match match_host(&reg, &host) {
        Some(c) => (c.clone(), true),
        None => match match_host(&default_registry(), &host) {
            Some(c) => (c.clone(), false),
            None => return out,
        },
    };
    out.matched = Some(MatchedConn {
        id: conn.id.clone(),
        host_patterns: conn.host_patterns.clone(),
        from_user_registry: from_user,
    });

    let resolver = secretstore::Resolver::standard();
    for r in &conn.secret_refs {
        let trace = trace_ref(&resolver, r);
        // The first ref that yields wins — record what the header would be.
        if out.chosen_header.is_none() && trace.yielded_from.is_some() {
            if let Some(secret) = resolver.get_ref(r) {
                out.chosen_header = Some(conn.header.clone());
                out.chosen_value_len = conn.value_prefix.len() + secret.len();
                out.chosen_source = trace
                    .yielded_from
                    .as_ref()
                    .map(|s| format!("{}:{s}", trace.backend));
            }
        }
        out.refs.push(trace);
    }
    out
}

impl std::fmt::Display for ResolveExplain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "cred-helper diagnose")?;
        writeln!(f, "  host: {}", self.host)?;
        writeln!(f, "  path: {}", self.path)?;
        match &self.matched {
            None => {
                writeln!(f, "  matched connection: <none> → anonymous fetch")?;
                return Ok(());
            }
            Some(m) => {
                writeln!(
                    f,
                    "  matched connection: {} ({} registry)",
                    m.id,
                    if m.from_user_registry { "user" } else { "default" },
                )?;
                writeln!(f, "  host patterns: {}", m.host_patterns.join(", "))?;
            }
        }
        writeln!(f, "  secret refs (in order):")?;
        for (i, r) in self.refs.iter().enumerate() {
            let status = match &r.yielded_from {
                Some(s) => format!("PRESENT (from {s})"),
                None => "absent".to_string(),
            };
            writeln!(f, "    {}. [{}] {} — {status}", i + 1, r.backend, r.target)?;
        }
        match (&self.chosen_header, &self.chosen_source) {
            (Some(h), Some(src)) => writeln!(
                f,
                "  → sends: {h}: <redacted, len={}> via {src}",
                self.chosen_value_len,
            )?,
            _ => writeln!(f, "  → sends: nothing (anonymous — no ref yielded a secret)")?,
        }
        Ok(())
    }
}

/// The built-in connections — GitHub, GitLab, BuildBuddy — each carrying a
/// keychain ref and the canonical/alias env refs. Used as the fallback when
/// a host isn't in the user's registry (notably CI, which has no registry
/// file and resolves the env backend). This replaces the old hand-rolled
/// host→env table that lived in the cred-helper.
#[must_use]
pub fn default_registry() -> ConnectionRegistry {
    let mut reg = ConnectionRegistry::default();
    for provider in ["github", "gitlab", "buildbuddy"] {
        if let Ok(c) = preset(provider, "", "") {
            reg.connections.push(c);
        }
    }
    reg
}

// ─── Provider presets + connect ────────────────────────────────────

/// Built-in (public) OAuth App client ids shipped with the app, so users
/// can connect with one click — no per-machine configuration. Device-code
/// client ids carry NO secret, so bundling them is safe. An explicit
/// `--client-id` or `config.client_ids[provider]` overrides these.
///
/// These are the fastverk org's OAuth Apps (Device Flow enabled). Public
/// client ids — no secret — so shipping them is safe.
const GITHUB_CLIENT_ID: &str = "Ov23lioy3u3aCHYDK8IJ";
const GITLAB_CLIENT_ID: &str =
    "ef3e11b3ac17b8df79facfcf4bcc94152b2343c1f221e1f3884ca1b62330eb35";

/// The org's self-hosted GitLab instance — the default `gitlab` host (so
/// `fv connect gitlab` is one-click for the org). Override with any host.
const GITLAB_HOST: &str = "gitlab.savvifi.com";

/// fastverk identity (the `fastverk` provider): the shared Cognito user pool —
/// region + hosted-UI domain label — and the bundled `fastverk-desktop` public
/// app client (PKCE, no secret, so it ships safely). This is the login other
/// plugins consume; Cognito has no device endpoint, so it uses the PKCE flow.
const COGNITO_REGION: &str = "us-east-1";
const FASTVERK_COGNITO_DOMAIN: &str = "botnoc-msoftware";
const FASTVERK_DESKTOP_CLIENT_ID: &str = "3c20pofajki4i5cjki97sidhv5";
/// The authenticated fastverk API/web host the identity token is sent to.
const FASTVERK_API_HOST: &str = "botnoc.msoftware.co";
/// The desktop login's pre-registered loopback redirect (Cognito needs an exact
/// match; `localhost` is its only allowed non-HTTPS callback). 8766/8787 are
/// also registered as spares.
const FASTVERK_REDIRECT_URI: &str = "http://localhost:8765/callback";

/// `given` if non-empty, else the bundled `default`.
fn pick(given: &str, default: &str) -> String {
    if given.is_empty() { default } else { given }.to_string()
}

/// The default instance host for a provider when none is given.
fn default_host(provider: &str) -> &'static str {
    match provider {
        "github" => "github.com",
        "gitlab" => GITLAB_HOST,
        "buildbuddy" => "remote.buildbuddy.io",
        "fastverk" => FASTVERK_COGNITO_DOMAIN,
        _ => "",
    }
}

/// Bundled (public) OAuth client id for a specific (provider, host), or ""
/// for instances we don't ship one for (the user supplies `--client-id`).
fn default_client_id(provider: &str, host: &str) -> &'static str {
    if provider == "github" && host == "github.com" {
        GITHUB_CLIENT_ID
    } else if provider == "gitlab" && host == GITLAB_HOST {
        GITLAB_CLIENT_ID
    } else if provider == "fastverk" && host == FASTVERK_COGNITO_DOMAIN {
        FASTVERK_DESKTOP_CLIENT_ID
    } else {
        ""
    }
}

/// Stable connection id: the short provider name for its default host, the
/// instance host otherwise (so multiple instances of one provider coexist
/// — github.com vs github.acme.com vs gitlab.savvifi.com).
fn connection_id(provider: &str, host: &str) -> String {
    if host == default_host(provider) {
        provider.to_string()
    } else {
        host.to_string()
    }
}

/// Build a connection from a provider preset for a given instance `host`
/// (empty = the provider default). OAuth `client_id` falls back to the
/// bundled id for known (provider, host) pairs. The same provider can be
/// connected one-by-one across hosted / enterprise / self-hosted hosts.
pub fn preset(provider: &str, host: &str, client_id: &str) -> Result<Connection> {
    let host = if host.is_empty() {
        default_host(provider)
    } else {
        host
    };
    let id = connection_id(provider, host);
    let mut c = Connection::default();
    match provider {
        "github" => {
            let canonical = host == "github.com";
            c.display_name = if canonical {
                "GitHub".to_string()
            } else {
                format!("GitHub ({host})")
            };
            c.provider = "github".to_string();
            // github.com has dedicated raw/codeload hosts; GHE serves all
            // from the instance host.
            c.host_patterns = if canonical {
                vec![
                    "github.com".to_string(),
                    "*.github.com".to_string(),
                    "raw.githubusercontent.com".to_string(),
                    "codeload.github.com".to_string(),
                ]
            } else {
                vec![host.to_string(), format!("*.{host}")]
            };
            c.header = "Authorization".to_string();
            c.value_prefix = "Bearer ".to_string();
            c.auth_kind = AuthKind::Oauth as i32;
            c.oauth = Some(OAuthConfig {
                client_id: pick(client_id, default_client_id("github", host)),
                auth_url: format!("https://{host}/login/oauth/authorize"),
                token_url: format!("https://{host}/login/oauth/access_token"),
                device_auth_url: format!("https://{host}/login/device/code"),
                scopes: vec!["repo".to_string(), "read:org".to_string()],
                ..Default::default()
            });
        }
        "gitlab" => {
            c.display_name = format!("GitLab ({host})");
            c.provider = "gitlab".to_string();
            c.host_patterns = vec![host.to_string(), format!("*.{host}")];
            c.header = "Authorization".to_string();
            c.value_prefix = "Bearer ".to_string();
            c.auth_kind = AuthKind::Oauth as i32;
            c.oauth = Some(OAuthConfig {
                client_id: pick(client_id, default_client_id("gitlab", host)),
                auth_url: format!("https://{host}/oauth/authorize"),
                token_url: format!("https://{host}/oauth/token"),
                device_auth_url: format!("https://{host}/oauth/authorize_device"),
                scopes: vec!["api".to_string(), "read_repository".to_string()],
                ..Default::default()
            });
        }
        "buildbuddy" => {
            // BuildBuddy authenticates with a static API key (no OAuth).
            c.display_name = "BuildBuddy".to_string();
            c.provider = "buildbuddy".to_string();
            c.host_patterns = vec![host.to_string()];
            c.header = "x-buildbuddy-api-key".to_string();
            c.auth_kind = AuthKind::ApiKey as i32;
        }
        "fastverk" => {
            // fastverk identity: Cognito hosted-UI OIDC against the shared user
            // pool. Authorization-code + PKCE (no device endpoint → empty
            // device_auth_url forces the PKCE flow). The bearer token is the
            // identity other plugins consume. `host` is the hosted-UI domain
            // label (defaulted above to the bundled pool's domain).
            let domain = host;
            c.display_name = "fastverk".to_string();
            c.provider = "fastverk".to_string();
            c.host_patterns = vec![FASTVERK_API_HOST.to_string()];
            c.header = "Authorization".to_string();
            c.value_prefix = "Bearer ".to_string();
            c.auth_kind = AuthKind::Oauth as i32;
            c.oauth = Some(OAuthConfig {
                client_id: pick(client_id, default_client_id("fastverk", domain)),
                auth_url: format!(
                    "https://{domain}.auth.{COGNITO_REGION}.amazoncognito.com/oauth2/authorize"
                ),
                token_url: format!(
                    "https://{domain}.auth.{COGNITO_REGION}.amazoncognito.com/oauth2/token"
                ),
                scopes: vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
                redirect_uri: FASTVERK_REDIRECT_URI.to_string(),
                ..Default::default()
            });
        }
        other => {
            bail!("unknown provider preset: {other} (use github|gitlab|buildbuddy|fastverk)")
        }
    }
    // Where this connection's secret lives, in precedence order: the
    // keychain locally, then the canonical env var (+ provider/host alias
    // names) for CI/automation. Secrets never live in the registry itself.
    let account = if provider == "buildbuddy" { "api-key" } else { "oauth" };
    c.secret_refs = vec![
        secretstore::keychain_ref(format!("fastverk.{id}"), account),
        secretstore::env_ref(canonical_env_var(&id), env_aliases(provider, host)),
    ];
    c.id = id;
    Ok(c)
}

/// Canonical env var for a connection id: id "github" ->
/// "FASTVERK_TOKEN_GITHUB", "gitlab.example.com" ->
/// "FASTVERK_TOKEN_GITLAB_EXAMPLE_COM" (non-alphanumerics become `_`).
fn canonical_env_var(id: &str) -> String {
    let suffix: String = id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("FASTVERK_TOKEN_{suffix}")
}

/// Ecosystem/compat env var aliases for a (provider, host), tried after the
/// canonical var (first non-empty wins).
fn env_aliases(provider: &str, host: &str) -> Vec<String> {
    // Self-hosted savvi GitLab: the org's CI vars, in the precedence studio
    // CI expects (AION_NPM_TOKEN highest), ahead of the generic name.
    if host == "gitlab.savvifi.com" {
        // FASTVERK_TOKEN_GITLAB_SAVVIFI_COM first: the org's CI + the infra/images
        // bazelrc set this name explicitly. (The DEFAULT connection's id is
        // `gitlab`, so its *canonical* var is FASTVERK_TOKEN_GITLAB — without this
        // alias, the host-specific name silently does nothing and resolution falls
        // through to AION_NPM_TOKEN; the cause of a real CI 401 hunt.) Then the
        // ecosystem names, AION_NPM_TOKEN highest per studio CI precedence.
        return [
            "FASTVERK_TOKEN_GITLAB_SAVVIFI_COM",
            "AION_NPM_TOKEN",
            "GITLAB_SAVVIFI_TOKEN",
            "GITLAB_TOKEN",
        ]
        .into_iter()
        .map(String::from)
        .collect();
    }
    match provider {
        "github" => vec!["GITHUB_TOKEN", "GH_TOKEN"],
        "gitlab" => vec!["GITLAB_TOKEN"],
        "buildbuddy" => vec!["BUILDBUDDY_API_KEY"],
        _ => vec![],
    }
    .into_iter()
    .map(String::from)
    .collect()
}

/// Inputs for [`connect`].
pub struct ConnectParams {
    pub provider: String,
    /// Instance host (empty = the provider default). Lets the same
    /// provider be connected across hosted / enterprise / self-hosted.
    pub host: String,
    /// OAuth App client id (empty = bundled default for known hosts).
    pub client_id: String,
    /// API key (required for AUTH_KIND_API_KEY providers, e.g. BuildBuddy).
    pub api_key: String,
}

/// Establish a connection: run the provider's auth (OAuth device flow or
/// API key), store the secret in the keychain, and upsert the registry.
/// `prompt(user_code, verification_uri)` is shown during OAuth. Returns
/// the persisted connection (which never carries the secret).
pub fn connect(params: &ConnectParams, prompt: impl FnOnce(&str, &str)) -> Result<Connection> {
    let mut conn = preset(&params.provider, &params.host, &params.client_id)?;
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

    persist(conn, &secret)
}

/// Establish a connection via the OAuth2 authorization-code + PKCE flow — for
/// OAuth providers without a device endpoint (e.g. `fastverk`/Cognito).
/// `open(authorize_url)` opens the system browser; this binds the loopback
/// redirect, waits for the callback, exchanges the code, stores the token, and
/// upserts the registry. Returns the persisted connection (no secret in it).
pub fn connect_pkce(params: &ConnectParams, open: impl FnOnce(&str)) -> Result<Connection> {
    let conn = preset(&params.provider, &params.host, &params.client_id)?;
    if conn.auth_kind() != AuthKind::Oauth {
        bail!("provider {} is not an OAuth provider", params.provider);
    }
    let oauth_cfg = conn
        .oauth
        .as_ref()
        .context("OAuth preset is missing its config")?;
    let secret = oauth::pkce_flow(oauth_cfg, open)?.secret;
    persist(conn, &secret)
}

/// Stamp `connected_at`, store the secret out-of-band (keychain/env), and upsert
/// the connection into the registry (which never carries the secret). Shared by
/// the device-code and PKCE connect paths.
fn persist(mut conn: Connection, secret: &str) -> Result<Connection> {
    conn.connected_at = chrono::Utc::now().to_rfc3339();
    secretstore::Resolver::standard().store(&conn.secret_refs, secret)?;

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
        let _ = secretstore::Resolver::standard().delete(&c.secret_refs);
    }
    let removed = remove(&mut reg, id);
    if removed {
        save(&reg)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_env_var, default_registry, env_aliases, host_matches, match_host, preset,
    };
    use crate::proto::{secret_ref::Store, AuthKind};

    /// The keychain item a preset pins its secret to (first keychain ref).
    fn keychain_of(c: &crate::proto::Connection) -> (&str, &str) {
        c.secret_refs
            .iter()
            .find_map(|r| match &r.store {
                Some(Store::Keychain(k)) => Some((k.service.as_str(), k.account.as_str())),
                _ => None,
            })
            .expect("a keychain secret ref")
    }

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
        // Default GitHub host.
        let gh = preset("github", "", "cid123").unwrap();
        assert_eq!(gh.id, "github");
        assert_eq!(gh.auth_kind(), AuthKind::Oauth);
        assert_eq!(gh.header, "Authorization");
        assert_eq!(gh.oauth.as_ref().unwrap().client_id, "cid123");
        assert!(gh.host_patterns.iter().any(|h| h == "github.com"));

        // GitHub Enterprise instance: distinct id, host-derived endpoints.
        let ghe = preset("github", "github.acme.com", "ent").unwrap();
        assert_eq!(ghe.id, "github.acme.com");
        assert_eq!(keychain_of(&ghe), ("fastverk.github.acme.com", "oauth"));
        assert!(ghe.host_patterns.iter().any(|h| h == "github.acme.com"));
        assert_eq!(
            ghe.oauth.as_ref().unwrap().device_auth_url,
            "https://github.acme.com/login/device/code"
        );

        // Self-hosted GitLab default + an arbitrary instance.
        let gl = preset("gitlab", "", "").unwrap();
        assert_eq!(gl.id, "gitlab");
        assert!(gl.host_patterns.iter().any(|h| h == "gitlab.savvifi.com"));
        let gl2 = preset("gitlab", "gitlab.example.com", "x").unwrap();
        assert_eq!(gl2.id, "gitlab.example.com");

        let bb = preset("buildbuddy", "", "").unwrap();
        assert_eq!(bb.auth_kind(), AuthKind::ApiKey);
        assert_eq!(bb.header, "x-buildbuddy-api-key");
        assert_eq!(keychain_of(&bb), ("fastverk.buildbuddy", "api-key"));

        assert!(preset("nope", "", "").is_err());
    }

    #[test]
    fn fastverk_preset_is_cognito_pkce() {
        let fv = preset("fastverk", "", "").unwrap();
        assert_eq!(fv.id, "fastverk");
        assert_eq!(fv.auth_kind(), AuthKind::Oauth);
        assert_eq!(fv.header, "Authorization");
        assert_eq!(fv.value_prefix, "Bearer ");
        assert_eq!(keychain_of(&fv), ("fastverk.fastverk", "oauth"));

        let o = fv.oauth.as_ref().unwrap();
        // Bundled public desktop client; Cognito hosted-UI endpoints.
        assert_eq!(o.client_id, "3c20pofajki4i5cjki97sidhv5");
        assert!(o.client_secret.is_empty(), "public client carries no secret");
        assert_eq!(
            o.auth_url,
            "https://botnoc-msoftware.auth.us-east-1.amazoncognito.com/oauth2/authorize"
        );
        assert_eq!(
            o.token_url,
            "https://botnoc-msoftware.auth.us-east-1.amazoncognito.com/oauth2/token"
        );
        // No device endpoint → forces the PKCE flow; loopback redirect must match
        // the pre-registered callback.
        assert!(o.device_auth_url.is_empty(), "Cognito has no device endpoint");
        assert_eq!(o.redirect_uri, "http://localhost:8765/callback");
        assert_eq!(o.scopes, ["openid", "email", "profile"]);

        // An explicit client_id / hosted-UI domain override the bundled defaults.
        let custom = preset("fastverk", "acme-pool", "my-client").unwrap();
        assert_eq!(custom.id, "acme-pool");
        let co = custom.oauth.as_ref().unwrap();
        assert_eq!(co.client_id, "my-client");
        assert!(co.auth_url.contains("acme-pool.auth.us-east-1.amazoncognito.com"));
    }

    /// Canonical env naming + the alias table + the default registry. This
    /// hermetically guards the property the old cred-helper env_fallback
    /// test covered (savvi GitLab uses `Authorization: Bearer`, NOT
    /// `Private-Token`, and accepts the org's `AION_NPM_TOKEN`) — without
    /// reading any secret.
    #[test]
    fn env_refs_and_default_registry() {
        assert_eq!(canonical_env_var("github"), "FASTVERK_TOKEN_GITHUB");
        assert_eq!(
            canonical_env_var("gitlab.example.com"),
            "FASTVERK_TOKEN_GITLAB_EXAMPLE_COM"
        );

        // GitHub preset carries the canonical var + ecosystem aliases.
        let gh = preset("github", "", "").unwrap();
        let env = gh
            .secret_refs
            .iter()
            .find_map(|r| match &r.store {
                Some(Store::Env(e)) => Some(e),
                _ => None,
            })
            .expect("an env secret ref");
        assert_eq!(env.name, "FASTVERK_TOKEN_GITHUB");
        assert!(env.aliases.iter().any(|a| a == "GITHUB_TOKEN"));
        assert!(env.aliases.iter().any(|a| a == "GH_TOKEN"));

        // savvi GitLab: Bearer, and AION_NPM_TOKEN / GITLAB_TOKEN accepted.
        let gl = preset("gitlab", "", "").unwrap();
        assert_eq!(gl.header, "Authorization");
        assert_eq!(gl.value_prefix, "Bearer ");
        let aliases = env_aliases("gitlab", "gitlab.savvifi.com");
        assert!(aliases.iter().any(|a| a == "AION_NPM_TOKEN"));
        assert!(aliases.iter().any(|a| a == "GITLAB_TOKEN"));

        // The default registry covers the savvi host (the CI fallback path).
        let def = default_registry();
        let c = match_host(&def, "gitlab.savvifi.com").expect("savvi host in defaults");
        assert_eq!(c.value_prefix, "Bearer ");
        assert!(match_host(&def, "github.com").is_some());
    }
}
