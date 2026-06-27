//! The `fastverk.identity.v1.Auth` service — fvd's in-process Login/Account
//! implementation, delegating to `fvkit::identity`.
//!
//! Identity is the keystone: the token minted here is what every other plugin
//! consumes. fvd implements it in-process and registers it through the gateway
//! like any plugin, dogfooding the plugin contract. Login runs the blocking
//! PKCE loopback flow off the async reactor and opens the system browser.

use tonic::{Request, Response, Status};

use fvkit::identity_proto::auth_server::Auth;
use fvkit::identity_proto::{
    Identity, LoginRequest, LoginResponse, LogoutRequest, LogoutResponse, WhoAmIRequest,
};

#[derive(Default)]
pub struct AuthService;

fn internal<E: std::fmt::Display>(e: E) -> Status {
    Status::internal(e.to_string())
}

#[tonic::async_trait]
impl Auth for AuthService {
    async fn login(
        &self,
        _request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        // pkce_flow blocks on the browser + loopback redirect; keep it off the
        // reactor (it also builds its own blocking HTTP client).
        let identity = tokio::task::spawn_blocking(|| fvkit::identity::login(open_browser))
            .await
            .map_err(internal)?
            .map_err(internal)?;
        Ok(Response::new(LoginResponse {
            identity: Some(identity),
        }))
    }

    async fn logout(
        &self,
        _request: Request<LogoutRequest>,
    ) -> Result<Response<LogoutResponse>, Status> {
        let removed = fvkit::identity::logout().map_err(internal)?;
        Ok(Response::new(LogoutResponse { removed }))
    }

    async fn who_am_i(
        &self,
        _request: Request<WhoAmIRequest>,
    ) -> Result<Response<Identity>, Status> {
        let identity = fvkit::identity::whoami().map_err(internal)?;
        Ok(Response::new(identity))
    }
}

/// Open the authorization URL in the user's default browser.
fn open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let opener = Some("open");
    #[cfg(target_os = "linux")]
    let opener = Some("xdg-open");
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let opener: Option<&str> = None;

    tracing::info!(%url, "opening browser for fastverk login");
    if let Some(opener) = opener {
        if let Err(e) = std::process::Command::new(opener).arg(url).spawn() {
            tracing::warn!(error = %e, "could not open browser; visit the URL manually");
        }
    }
}
