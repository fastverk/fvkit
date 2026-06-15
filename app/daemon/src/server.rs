//! The `Fvd` gRPC service implementation, delegating to `fvkit`.
//!
//! P0 implements the read-only + safe RPCs end to end (credentials,
//! connection listing, volume status, bazelrc preview, maintenance,
//! status, update check) so every wire path can be exercised. The
//! mutating-with-side-effects RPCs that need the keychain, OAuth, or
//! admin elevation (Connect, VolumeCreate, BazelrcApply, ApplyUpdate)
//! return `unimplemented` until P1/P4. State serialization (single
//! writer) also lands in P1.

use anyhow::Result;
use tonic::{Request, Response, Status};

use fvkit::proto::fvd_server::{Fvd, FvdServer};
use fvkit::proto::{
    ApplyUpdateRequest, ApplyUpdateResponse, BazelrcApplyRequest, BazelrcApplyResponse,
    BazelrcPreviewRequest, BazelrcPreviewResponse, CheckUpdateRequest, CheckUpdateResponse,
    ConnectProviderRequest, ConnectProviderResponse, DisconnectRequest, DisconnectResponse,
    GetCredentialsRequest, GetCredentialsResponse, GetStatusRequest, ListConnectionsRequest,
    ListConnectionsResponse, MaintainNowRequest, MaintenanceReport, RepoSyncReport,
    ReposStatusRequest, ReposStatusResponse, ReposSyncRequest, StatusResponse, VolumeCreateRequest,
    VolumeCreateResponse, VolumeStatusRequest, VolumeStatusResponse, Worktree, WorktreeAddRequest,
    WorktreeListRequest, WorktreeListResponse, WorktreeRemoveRequest, WorktreeRemoveResponse,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Default)]
pub struct FvdService;

fn internal<E: std::fmt::Display>(e: E) -> Status {
    Status::internal(e.to_string())
}

#[tonic::async_trait]
impl Fvd for FvdService {
    async fn get_credentials(
        &self,
        request: Request<GetCredentialsRequest>,
    ) -> Result<Response<GetCredentialsResponse>, Status> {
        let uri = request.into_inner().uri;
        // P1 wraps this with token refresh; P0 reads the stored token.
        let resolved = fvkit::connections::resolve(&uri).map_err(internal)?;
        Ok(Response::new(match resolved {
            Some(c) => GetCredentialsResponse {
                found: true,
                header: c.header,
                value: c.value,
            },
            None => GetCredentialsResponse {
                found: false,
                header: String::new(),
                value: String::new(),
            },
        }))
    }

    async fn list_connections(
        &self,
        _request: Request<ListConnectionsRequest>,
    ) -> Result<Response<ListConnectionsResponse>, Status> {
        let reg = fvkit::connections::load().map_err(internal)?;
        Ok(Response::new(ListConnectionsResponse {
            connections: reg.connections,
        }))
    }

    async fn connect_provider(
        &self,
        request: Request<ConnectProviderRequest>,
    ) -> Result<Response<ConnectProviderResponse>, Status> {
        let req = request.into_inner();
        let cfg = fvkit::config::Config::load().map_err(internal)?;
        // client_id: explicit oauth override wins, else the configured one.
        let client_id = req
            .oauth
            .map(|o| o.client_id)
            .filter(|s| !s.is_empty())
            .or_else(|| cfg.client_ids.get(&req.provider).cloned())
            .unwrap_or_default();
        let params = fvkit::connections::ConnectParams {
            provider: req.provider,
            host: req.host,
            client_id,
            api_key: req.api_key,
        };
        // The device flow blocks on the user authorizing; keep it off the
        // async reactor. (Streaming the user-code to the client is a P3
        // follow-up; for now fvd logs it.)
        let conn = tokio::task::spawn_blocking(move || {
            fvkit::connections::connect(&params, |code, uri| {
                tracing::info!(user_code = %code, verification_uri = %uri, "authorize device");
            })
        })
        .await
        .map_err(internal)?
        .map_err(internal)?;
        Ok(Response::new(ConnectProviderResponse {
            connection: Some(conn),
            message: String::new(),
        }))
    }

    async fn disconnect(
        &self,
        request: Request<DisconnectRequest>,
    ) -> Result<Response<DisconnectResponse>, Status> {
        let removed =
            fvkit::connections::disconnect(&request.into_inner().id).map_err(internal)?;
        Ok(Response::new(DisconnectResponse { removed }))
    }

    async fn volume_status(
        &self,
        _request: Request<VolumeStatusRequest>,
    ) -> Result<Response<VolumeStatusResponse>, Status> {
        let volumes = fvkit::volume::status().map_err(internal)?;
        Ok(Response::new(VolumeStatusResponse { volumes }))
    }

    async fn volume_create(
        &self,
        request: Request<VolumeCreateRequest>,
    ) -> Result<Response<VolumeCreateResponse>, Status> {
        let id = request.into_inner().id;
        // Elevation prompt + diskutil are blocking; keep them off the reactor.
        let (volumes, message) =
            tokio::task::spawn_blocking(move || fvkit::volume::create(&id, false))
                .await
                .map_err(internal)?
                .map_err(internal)?;
        Ok(Response::new(VolumeCreateResponse { volumes, message }))
    }

    async fn bazelrc_preview(
        &self,
        _request: Request<BazelrcPreviewRequest>,
    ) -> Result<Response<BazelrcPreviewResponse>, Status> {
        let cfg = fvkit::config::Config::load().map_err(internal)?;
        let ch = fvkit::bazelrc::cred_helper_path();
        let block = fvkit::bazelrc::managed_block(&cfg, &ch);
        let path = fvkit::paths::user_bazelrc().map_err(internal)?;
        Ok(Response::new(BazelrcPreviewResponse {
            managed_block: block,
            path: path.display().to_string(),
        }))
    }

    async fn bazelrc_apply(
        &self,
        request: Request<BazelrcApplyRequest>,
    ) -> Result<Response<BazelrcApplyResponse>, Status> {
        let validate_only = request.into_inner().validate_only;
        let cfg = fvkit::config::Config::load().map_err(internal)?;
        let ch = fvkit::bazelrc::cred_helper_path();
        let (changed, diff) =
            fvkit::bazelrc::apply(&cfg, &ch, validate_only).map_err(internal)?;
        Ok(Response::new(BazelrcApplyResponse { changed, diff }))
    }

    async fn repos_sync(
        &self,
        request: Request<ReposSyncRequest>,
    ) -> Result<Response<RepoSyncReport>, Status> {
        let req = request.into_inner();
        let cfg = fvkit::config::Config::load().map_err(internal)?;
        let org = if req.org.is_empty() { cfg.org.clone() } else { req.org };
        let forge = if req.forge.is_empty() {
            cfg.forge.clone()
        } else {
            req.forge
        };
        let specs =
            fvkit::repos::enumerate(&forge, &org, req.include_archived).map_err(internal)?;
        let report = fvkit::repos::sync(
            &cfg.repos_dir(),
            &specs,
            &org,
            &forge,
            &fvkit::repos::SyncOpts {
                pull: req.pull,
                validate_only: req.validate_only,
                meta_repo_name: cfg.meta_repo_name(),
            },
        )
        .map_err(internal)?;
        Ok(Response::new(report))
    }

    async fn repos_status(
        &self,
        request: Request<ReposStatusRequest>,
    ) -> Result<Response<ReposStatusResponse>, Status> {
        let req = request.into_inner();
        let cfg = fvkit::config::Config::load().map_err(internal)?;
        let org = if req.org.is_empty() { cfg.org.clone() } else { req.org };
        let forge = if req.forge.is_empty() {
            cfg.forge.clone()
        } else {
            req.forge
        };
        let specs = fvkit::repos::enumerate(&forge, &org, true).map_err(internal)?;
        let repos = fvkit::repos::status(&cfg.repos_dir(), &specs);
        Ok(Response::new(ReposStatusResponse { repos }))
    }

    async fn worktree_list(
        &self,
        request: Request<WorktreeListRequest>,
    ) -> Result<Response<WorktreeListResponse>, Status> {
        let cfg = fvkit::config::Config::load().map_err(internal)?;
        let worktrees =
            fvkit::repos::worktree_list(&cfg.repos_dir(), &request.into_inner().repo)
                .map_err(internal)?;
        Ok(Response::new(WorktreeListResponse { worktrees }))
    }

    async fn worktree_add(
        &self,
        request: Request<WorktreeAddRequest>,
    ) -> Result<Response<Worktree>, Status> {
        let req = request.into_inner();
        let cfg = fvkit::config::Config::load().map_err(internal)?;
        let wt = fvkit::repos::worktree_add(
            &cfg.repos_dir(),
            &cfg.worktrees_dir(),
            &req.repo,
            &req.branch,
        )
        .map_err(internal)?;
        Ok(Response::new(wt))
    }

    async fn worktree_remove(
        &self,
        request: Request<WorktreeRemoveRequest>,
    ) -> Result<Response<WorktreeRemoveResponse>, Status> {
        let req = request.into_inner();
        let removed =
            fvkit::repos::worktree_remove(std::path::Path::new(&req.path), req.force)
                .map_err(internal)?;
        Ok(Response::new(WorktreeRemoveResponse { removed }))
    }

    async fn maintain_now(
        &self,
        request: Request<MaintainNowRequest>,
    ) -> Result<Response<MaintenanceReport>, Status> {
        let req = request.into_inner();
        let report = fvkit::maintain::run(req.validate_only, &req.only).map_err(internal)?;
        Ok(Response::new(report))
    }

    async fn get_status(
        &self,
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<StatusResponse>, Status> {
        let volumes = fvkit::volume::status().unwrap_or_default();
        let reg = fvkit::connections::load().unwrap_or_default();
        let update = fvkit::update::check().map_err(internal)?;
        Ok(Response::new(StatusResponse {
            version: VERSION.to_string(),
            volumes,
            connection_count: i32::try_from(reg.connections.len()).unwrap_or(i32::MAX),
            last_maintenance: None,
            update_available: update.available,
            latest_version: update.latest,
        }))
    }

    async fn check_update(
        &self,
        _request: Request<CheckUpdateRequest>,
    ) -> Result<Response<CheckUpdateResponse>, Status> {
        let info = fvkit::update::check().map_err(internal)?;
        Ok(Response::new(CheckUpdateResponse {
            update_available: info.available,
            current_version: info.current,
            latest_version: info.latest,
            download_url: info.url,
            notes: info.notes,
        }))
    }

    async fn apply_update(
        &self,
        _request: Request<ApplyUpdateRequest>,
    ) -> Result<Response<ApplyUpdateResponse>, Status> {
        match tokio::task::spawn_blocking(fvkit::update::apply)
            .await
            .map_err(internal)?
        {
            Ok(()) => Ok(Response::new(ApplyUpdateResponse {
                started: true,
                message: "downloading the latest release".to_string(),
            })),
            Err(e) => Ok(Response::new(ApplyUpdateResponse {
                started: false,
                message: e.to_string(),
            })),
        }
    }
}

/// Bind the UDS and serve the `Fvd` service until shutdown.
pub async fn serve() -> Result<()> {
    let sock = fvkit::paths::socket_path()?;
    let incoming = fvkit::ipc::bind(&sock)?;
    tracing::info!(socket = %sock.display(), version = VERSION, "fvd listening");

    tonic::transport::Server::builder()
        .add_service(FvdServer::new(FvdService::default()))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}
