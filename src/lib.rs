mod admin;
mod bindings;
mod certificates;
mod clock;
mod cloudflare;
mod crypto;
mod model;
pub mod operations;
mod provider;
mod proxy;
mod store;

use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use tokio::{net::TcpListener, sync::watch, task::JoinHandle};

use crate::{
    admin::AdminState, bindings::BindingManager, certificates::CertificateResolver,
    cloudflare::Cloudflare, proxy::ProxyState, store::Store,
};

pub use crate::certificates::{AcmeConfig, CertificateMode};
pub use crate::clock::Clock;
pub use crate::cloudflare::CloudflareEndpoints;
pub use crate::operations::FileConfig;

#[derive(Clone, Debug)]
pub struct Config {
    pub state_dir: PathBuf,
    pub admin_listen: SocketAddr,
    pub secure_admin_cookies: bool,
    pub admin_public_url: Option<url::Url>,
    pub cloudflare_endpoints: CloudflareEndpoints,
    pub http_listen: SocketAddr,
    pub https_listen: SocketAddr,
    pub public_ips: Vec<IpAddr>,
    pub drain_duration: std::time::Duration,
    pub certificate_mode: CertificateMode,
    pub admin_tls: bool,
    pub clock: Clock,
    pub renewal_check_interval: std::time::Duration,
}

impl Config {
    pub fn for_test(state_dir: impl AsRef<Path>, admin_listen: SocketAddr) -> Self {
        Self {
            state_dir: state_dir.as_ref().to_path_buf(),
            admin_listen,
            secure_admin_cookies: false,
            admin_public_url: None,
            cloudflare_endpoints: CloudflareEndpoints::default(),
            http_listen: "127.0.0.1:0".parse().expect("valid test address"),
            https_listen: "127.0.0.1:0".parse().expect("valid test address"),
            public_ips: vec!["203.0.113.1".parse().expect("valid documentation IP")],
            drain_duration: std::time::Duration::from_secs(5 * 60),
            certificate_mode: CertificateMode::Local,
            admin_tls: false,
            clock: Clock::system(),
            renewal_check_interval: std::time::Duration::from_secs(15 * 60),
        }
    }

    pub fn with_cloudflare_endpoints(mut self, endpoints: CloudflareEndpoints) -> Self {
        self.cloudflare_endpoints = endpoints;
        self
    }

    pub fn with_proxy_listeners(
        mut self,
        http_listen: SocketAddr,
        https_listen: SocketAddr,
    ) -> Self {
        self.http_listen = http_listen;
        self.https_listen = https_listen;
        self
    }

    pub fn with_public_ips(mut self, public_ips: Vec<IpAddr>) -> Self {
        self.public_ips = public_ips;
        self
    }

    pub fn with_drain_duration(mut self, drain_duration: std::time::Duration) -> Self {
        self.drain_duration = drain_duration;
        self
    }

    pub fn with_certificate_mode(mut self, certificate_mode: CertificateMode) -> Self {
        self.certificate_mode = certificate_mode;
        self
    }

    pub fn with_admin_tls(mut self, admin_tls: bool) -> Self {
        self.admin_tls = admin_tls;
        self
    }

    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_renewal_check_interval(mut self, interval: std::time::Duration) -> Self {
        self.renewal_check_interval = interval;
        self
    }
}

pub struct HostKnot;

#[doc(hidden)]
#[deprecated(note = "renamed to HostKnot")]
pub type Hostknot = HostKnot;

impl HostKnot {
    pub async fn start(config: Config) -> Result<RunningHostKnot> {
        let store = Store::open_with_clock(&config.state_dir, config.clock.clone())
            .context("open HostKnot state")?;
        let bootstrap_token = store
            .issue_bootstrap_if_unconfigured()
            .context("issue bootstrap token")?;
        let listener = TcpListener::bind(config.admin_listen)
            .await
            .with_context(|| format!("bind administration listener at {}", config.admin_listen))?;
        let admin_addr = listener.local_addr()?;
        let http_listener = TcpListener::bind(config.http_listen)
            .await
            .with_context(|| format!("bind HTTP listener at {}", config.http_listen))?;
        let http_addr = http_listener.local_addr()?;
        let https_listener = TcpListener::bind(config.https_listen)
            .await
            .with_context(|| format!("bind HTTPS listener at {}", config.https_listen))?;
        let https_addr = https_listener.local_addr()?;
        let public_url = config.admin_public_url.unwrap_or_else(|| {
            let scheme = if config.secure_admin_cookies {
                "https"
            } else {
                "http"
            };
            url::Url::parse(&format!("{scheme}://{admin_addr}/"))
                .expect("socket address forms a valid URL")
        });
        let certificates = CertificateResolver::new(store.clone(), config.certificate_mode)?;
        let cloudflare = Arc::new(Cloudflare::new(
            store.clone(),
            config.cloudflare_endpoints.clone(),
            public_url.join("oauth/cloudflare/callback")?,
        )?);
        let binding_manager = BindingManager::new(
            store.clone(),
            cloudflare.clone(),
            certificates.clone(),
            config.public_ips.clone(),
            [admin_addr.port(), http_addr.port(), https_addr.port()],
            config.drain_duration,
        );
        let reconciliation_manager = binding_manager.clone();
        let state = Arc::new(AdminState::new(
            store.clone(),
            config.secure_admin_cookies,
            public_url,
            config.cloudflare_endpoints,
            binding_manager,
            certificates.clone(),
        )?);
        let router = admin::router(state);
        let proxy_state = Arc::new(ProxyState::new(store.clone(), certificates.clone()));
        let http_router = proxy::http_router(proxy_state.clone());
        let https_router = proxy::https_router(proxy_state);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut http_shutdown = shutdown_rx.clone();
        let http_task = tokio::spawn(async move {
            if let Err(error) = axum::serve(
                http_listener,
                http_router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                let _ = http_shutdown.changed().await;
            })
            .await
            {
                tracing::error!(%error, "HTTP listener stopped");
            }
        });
        let admin_ip = if config.admin_tls {
            let admin_ip = config
                .public_ips
                .first()
                .copied()
                .context("admin TLS requires a configured public IP address")?;
            // A failed issuance must not lock the operator out of the only
            // recovery UI: fall back to the self-signed certificate and keep
            // retrying from the renewal loop.
            if let Err(error) = certificates.ensure_ip(admin_ip).await {
                tracing::error!(
                    %error, %admin_ip,
                    "failed to obtain the trusted admin IP certificate; serving the admin UI \
                     with the self-signed fallback until issuance succeeds. Verify the public \
                     IP is reachable and port 80 is open."
                );
                let _ = store.record_event(
                    "certificate",
                    &format!("Admin IP certificate issuance failed: {error:#}"),
                );
            }
            Some(admin_ip)
        } else {
            None
        };
        let admin_task = if config.admin_tls {
            tokio::spawn(serve_tls(
                listener,
                router,
                certificates.clone(),
                shutdown_rx.clone(),
            ))
        } else {
            let mut admin_shutdown = shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(error) = axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .with_graceful_shutdown(async move {
                    let _ = admin_shutdown.changed().await;
                })
                .await
                {
                    tracing::error!(%error, "administration listener stopped");
                }
            })
        };
        let tls_task = tokio::spawn(serve_tls(
            https_listener,
            https_router,
            certificates.clone(),
            shutdown_rx,
        ));
        let renewal_certificates = certificates.clone();
        let mut renewal_shutdown = shutdown_tx.subscribe();
        let renewal_check_interval = config.renewal_check_interval;
        let renewal_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(renewal_check_interval);
            loop {
                tokio::select! {
                    _ = renewal_shutdown.changed() => break,
                    _ = interval.tick() => {
                        if let Some(address) = admin_ip
                            && let Err(error) = renewal_certificates.ensure_ip(address).await
                        {
                            tracing::warn!(%error, "admin IP certificate issuance retry failed");
                        }
                        renewal_certificates.renew_due().await;
                    }
                }
            }
        });
        let mut reconciliation_shutdown = shutdown_tx.subscribe();
        let reconciliation_task = tokio::spawn(async move {
            let mut retry = std::time::Duration::from_secs(1);
            loop {
                let pending = match reconciliation_manager.reconcile_once().await {
                    Ok(pending) => pending,
                    Err(error) => {
                        tracing::warn!(%error, "binding reconciliation pass failed");
                        true
                    }
                };
                let jitter = std::time::Duration::from_millis(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_millis() as u64
                        % 250,
                );
                let delay = if pending {
                    let current = retry + jitter;
                    retry = (retry * 2).min(std::time::Duration::from_secs(5 * 60));
                    current
                } else {
                    retry = std::time::Duration::from_secs(1);
                    std::time::Duration::from_secs(30)
                };
                tokio::select! {
                    _ = reconciliation_shutdown.changed() => break,
                    _ = tokio::time::sleep(delay) => {}
                    _ = reconciliation_manager.reconcile_nudged() => {
                        retry = std::time::Duration::from_secs(1);
                    }
                }
            }
        });

        Ok(RunningHostKnot {
            admin_addr,
            http_addr,
            https_addr,
            bootstrap_token,
            shutdown_tx: Some(shutdown_tx),
            tasks: vec![
                admin_task,
                http_task,
                tls_task,
                renewal_task,
                reconciliation_task,
            ],
        })
    }

    pub fn reset_admin(state_dir: impl AsRef<Path>) -> Result<String> {
        let store = Store::open(state_dir.as_ref())?;
        store.reset_administrator()?;
        store
            .issue_bootstrap_if_unconfigured()?
            .context("failed to issue administrator reset token")
    }
}

pub struct RunningHostKnot {
    admin_addr: SocketAddr,
    http_addr: SocketAddr,
    https_addr: SocketAddr,
    bootstrap_token: Option<String>,
    shutdown_tx: Option<watch::Sender<bool>>,
    tasks: Vec<JoinHandle<()>>,
}

#[doc(hidden)]
#[deprecated(note = "renamed to RunningHostKnot")]
pub type RunningHostknot = RunningHostKnot;

impl RunningHostKnot {
    pub fn admin_addr(&self) -> SocketAddr {
        self.admin_addr
    }

    pub fn bootstrap_token(&self) -> Option<String> {
        self.bootstrap_token.clone()
    }

    pub fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }

    pub fn https_addr(&self) -> SocketAddr {
        self.https_addr
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(true);
        }
        for task in self.tasks {
            let _ = task.await;
        }
    }
}

async fn serve_tls(
    listener: TcpListener,
    router: axum::Router,
    certificates: Arc<CertificateResolver>,
    mut shutdown: watch::Receiver<bool>,
) {
    use axum::extract::Extension;
    use hyper_util::{
        rt::{TokioExecutor, TokioIo},
        server::conn::auto::Builder,
        service::TowerToHyperService,
    };
    use rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;

    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(certificates);
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let (socket, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        // Persistent accept errors (EMFILE under fd
                        // exhaustion) must not busy-spin the loop.
                        tracing::warn!(%error, "TLS listener accept failed");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let service = router.clone().layer(Extension(peer));
                tokio::spawn(async move {
                    // Bound the handshake so a client that never sends a
                    // ClientHello cannot pin a task and an fd forever.
                    let Ok(Ok(stream)) = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        acceptor.accept(socket),
                    )
                    .await
                    else {
                        return;
                    };
                    let io = TokioIo::new(stream);
                    let service = TowerToHyperService::new(service);
                    let builder = Builder::new(TokioExecutor::new());
                    if let Err(error) = builder
                        .serve_connection_with_upgrades(io, service)
                        .await
                    {
                        tracing::debug!(%error, "TLS connection ended");
                    }
                });
            }
        }
    }
}
