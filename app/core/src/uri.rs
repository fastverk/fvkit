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

#[cfg(test)]
mod tests {
    use super::host_of;

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
}
