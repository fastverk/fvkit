//! Request-URI host extraction, shared by `fvd`'s `GetCredentials` and
//! the standalone cred-helper. Lifted from the aion universal credential
//! helper (`infra/ci/cred_helper/cred_helper.rs`): a dependency-free,
//! robust parse that handles `https://` / `grpcs://` / bare `host/path`,
//! userinfo, ports, and IPv6 literals.

/// Extract the host/authority (no port, no userinfo) from a request URI.
/// Returns `""` when no host can be found.
#[must_use]
pub fn host_of(uri: &str) -> &str {
    let after_scheme = match uri.find("://") {
        Some(i) => &uri[i + 3..],
        None => uri,
    };
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    // Strip optional userinfo (`user:pass@host`).
    let host_port = match authority.rfind('@') {
        Some(i) => &authority[i + 1..],
        None => authority,
    };
    // Strip the port. Guard IPv6 literals (`[::1]:443`): only cut on the
    // last ':' when there's no ']' after it.
    match host_port.rfind(':') {
        Some(i) if !host_port[i..].contains(']') => &host_port[..i],
        _ => host_port,
    }
}

/// Extract the path component (`/...`, no query/fragment) from a request URI.
/// Returns `"/"` when there's no explicit path. Used by `diagnose` output and
/// by path-aware connection routing.
#[must_use]
pub fn path_of(uri: &str) -> &str {
    let after_scheme = match uri.find("://") {
        Some(i) => &uri[i + 3..],
        None => uri,
    };
    let path_start = match after_scheme.find('/') {
        Some(i) => i,
        None => return "/",
    };
    let rest = &after_scheme[path_start..];
    let end = rest.find(['?', '#']).unwrap_or(rest.len());
    &rest[..end]
}

/// Extract the `"uri"` field from a Bazel credential-helper request body
/// (`{"uri":"https://…"}`). Dependency-free scanner that honors backslash
/// escapes — the request shape is trivial, so this avoids a JSON dep in
/// the hot-path helper. Returns `None` when there's no well-formed `uri`.
#[must_use]
pub fn parse_request_uri(body: &str) -> Option<String> {
    let key = body.find("\"uri\"")?;
    let colon = body[key + 5..].find(':')? + key + 5;
    let rest = &body[colon + 1..];
    let open = rest.find('"')? + 1;
    let mut out = String::new();
    let mut chars = rest[open..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('r') => out.push('\r'),
                Some('u') => {
                    let hex: String = (&mut chars).take(4).collect();
                    let cp = u32::from_str_radix(&hex, 16).ok();
                    out.push(cp.and_then(char::from_u32).unwrap_or('\u{FFFD}'));
                }
                Some(other) => out.push(other),
                None => return Some(out),
            },
            _ => out.push(c),
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::{host_of, parse_request_uri};

    #[test]
    fn parses_common_shapes() {
        assert_eq!(host_of("https://github.com/o/r"), "github.com");
        assert_eq!(host_of("grpcs://remote.buildbuddy.io"), "remote.buildbuddy.io");
        assert_eq!(host_of("https://remote.buildbuddy.io:443/y"), "remote.buildbuddy.io");
        assert_eq!(host_of("https://user:pw@github.com/a/b"), "github.com");
        assert_eq!(host_of("https://[::1]:8080/p"), "[::1]");
        assert_eq!(host_of("github.com/foo"), "github.com");
        assert_eq!(host_of("https://example.com?q=1"), "example.com");
    }

    #[test]
    fn extracts_path() {
        use super::path_of;
        assert_eq!(path_of("https://gitlab.savvifi.com/api/v4/projects/137/x"), "/api/v4/projects/137/x");
        assert_eq!(path_of("https://gitlab.savvifi.com"), "/");
        assert_eq!(path_of("https://gitlab.savvifi.com/"), "/");
        assert_eq!(path_of("https://host:443/a/b?q=1#f"), "/a/b");
        assert_eq!(path_of("host/p/q"), "/p/q");
    }

    #[test]
    fn parses_request_uri_field() {
        assert_eq!(
            parse_request_uri(r#"{"uri":"https://github.com/a"}"#).as_deref(),
            Some("https://github.com/a")
        );
        assert_eq!(
            parse_request_uri(r#"{ "uri" : "grpcs://remote.buildbuddy.io" , "x": 1 }"#).as_deref(),
            Some("grpcs://remote.buildbuddy.io")
        );
        assert_eq!(parse_request_uri("{}"), None);
        assert_eq!(parse_request_uri("not json"), None);
    }
}
