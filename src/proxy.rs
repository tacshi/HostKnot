use std::{net::SocketAddr, sync::Arc};

use axum::{
    Router,
    body::Body,
    extract::{Extension, State},
    http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode, Uri, header},
    response::{IntoResponse, Redirect, Response},
};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{
        Client,
        connect::{HttpConnector, dns::Name},
    },
    rt::TokioExecutor,
};
use rustls::{
    DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};

use crate::{certificates::CertificateResolver, store::Store};

/// Upstream URIs carry the binding hostname (so TLS verification and SNI run
/// against a name a real certificate can match), while this resolver pins the
/// actual connection to loopback — the only place upstreams may live.
#[derive(Clone)]
struct LoopbackResolver;

impl tower::Service<Name> for LoopbackResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _name: Name) -> Self::Future {
        std::future::ready(Ok(vec![
            SocketAddr::from(([127, 0, 0, 1], 0)),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 0)),
        ]
        .into_iter()))
    }
}

#[derive(Clone)]
pub struct ProxyState {
    store: Store,
    client: Client<HttpsConnector<HttpConnector<LoopbackResolver>>, Body>,
    insecure_client: Client<HttpsConnector<HttpConnector<LoopbackResolver>>, Body>,
    certificates: Arc<CertificateResolver>,
}

impl ProxyState {
    pub fn new(store: Store, certificates: Arc<CertificateResolver>) -> Self {
        let loopback_connector = || {
            let mut connector = HttpConnector::new_with_resolver(LoopbackResolver);
            connector.enforce_http(false);
            connector
        };
        let verified = HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("load native TLS roots")
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(loopback_connector());
        let insecure_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureCertificateVerifier))
            .with_no_client_auth();
        let insecure = HttpsConnectorBuilder::new()
            .with_tls_config(insecure_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(loopback_connector());
        Self {
            store,
            client: Client::builder(TokioExecutor::new()).build(verified),
            insecure_client: Client::builder(TokioExecutor::new()).build(insecure),
            certificates,
        }
    }
}

pub fn http_router(state: Arc<ProxyState>) -> Router {
    Router::new().fallback(http_entry).with_state(state)
}

pub fn https_router(state: Arc<ProxyState>) -> Router {
    Router::new().fallback(proxy_entry).with_state(state)
}

async fn http_entry(State(state): State<Arc<ProxyState>>, request: Request<Body>) -> Response {
    if let Some(token) = request
        .uri()
        .path()
        .strip_prefix("/.well-known/acme-challenge/")
    {
        return state.certificates.challenge(token).map_or_else(
            || StatusCode::NOT_FOUND.into_response(),
            IntoResponse::into_response,
        );
    }
    let Some(hostname) = request_hostname(&request) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !state.store.hostname_is_routable(&hostname).unwrap_or(false) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let location = format!("https://{hostname}{path}");
    permanent_redirect(&location)
}

async fn proxy_entry(
    State(state): State<Arc<ProxyState>>,
    Extension(peer): Extension<SocketAddr>,
    mut request: Request<Body>,
) -> Response {
    let Some(hostname) = request_hostname(&request) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(binding) = state.store.active_binding(&hostname).ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // h2 requests carry no Host header; materialize one from :authority so the
    // HTTP/1.1 upstream hop sees the original host instead of the loopback URI.
    if !request.headers().contains_key(header::HOST)
        && let Some(authority) = request.uri().authority()
        && let Ok(value) = HeaderValue::from_str(authority.as_str())
    {
        request.headers_mut().insert(header::HOST, value);
    }
    let websocket = is_websocket_upgrade(request.headers());
    let downstream_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
    prepare_forward_headers(request.headers_mut(), peer, &hostname, "https", websocket);
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let upstream_uri: Uri = match format!(
        "{}://{}:{}{}",
        binding.upstream_scheme, hostname, binding.upstream_port, path
    )
    .parse()
    {
        Ok(uri) => uri,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    *request.uri_mut() = upstream_uri;
    // Downstream h2 requests must not force h2 on the loopback connection.
    *request.version_mut() = axum::http::Version::HTTP_11;
    let client = if binding.upstream_scheme == "https" && binding.insecure_tls {
        &state.insecure_client
    } else {
        &state.client
    };
    match client.request(request).await {
        Ok(mut response) => {
            // Persist health only on transitions — a WAL commit per proxied
            // request would serialize all traffic on the store mutex.
            if binding.health != "healthy"
                && let Err(error) = state.store.update_binding_health(&binding.id, true, None)
            {
                tracing::debug!(%error, "failed to persist upstream health");
            }
            if websocket && response.status() == StatusCode::SWITCHING_PROTOCOLS {
                let upstream_upgrade = hyper::upgrade::on(&mut response);
                tokio::spawn(async move {
                    let (Some(downstream_upgrade), Ok(upstream)) =
                        (downstream_upgrade, upstream_upgrade.await)
                    else {
                        return;
                    };
                    let Ok(downstream) = downstream_upgrade.await else {
                        return;
                    };
                    let mut downstream = hyper_util::rt::TokioIo::new(downstream);
                    let mut upstream = hyper_util::rt::TokioIo::new(upstream);
                    if let Err(error) =
                        tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await
                    {
                        tracing::debug!(%error, "WebSocket tunnel ended");
                    }
                });
            }
            let (mut parts, body) = response.into_parts();
            let upgraded = websocket && parts.status == StatusCode::SWITCHING_PROTOCOLS;
            strip_hop_by_hop(&mut parts.headers, upgraded);
            Response::from_parts(parts, Body::new(body))
        }
        Err(error) => {
            tracing::warn!(hostname, %error, "upstream request failed");
            if binding.health != "unavailable"
                && let Err(store_error) = state.store.update_binding_health(
                    &binding.id,
                    false,
                    Some("loopback upstream is unavailable"),
                )
            {
                tracing::debug!(%store_error, "failed to persist upstream failure");
            }
            (StatusCode::BAD_GATEWAY, "Upstream unavailable").into_response()
        }
    }
}

#[derive(Debug)]
struct InsecureCertificateVerifier;

impl ServerCertVerifier for InsecureCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}

fn request_hostname(request: &Request<Body>) -> Option<String> {
    // HTTP/2 requests carry the host in the :authority pseudo-header (surfaced
    // through the request URI), not in a Host header.
    let raw = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.as_str().to_owned())
        })?;
    let host = if raw.starts_with('[') {
        raw.split(']').next()?.trim_start_matches('[')
    } else {
        raw.split(':').next()?
    };
    Some(host.trim_end_matches('.').to_ascii_lowercase())
}

fn prepare_forward_headers(
    headers: &mut HeaderMap,
    peer: SocketAddr,
    hostname: &str,
    scheme: &str,
    preserve_upgrade: bool,
) {
    strip_hop_by_hop(headers, preserve_upgrade);
    headers.remove("forwarded");
    headers.remove("x-real-ip");
    headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&peer.ip().to_string()).expect("IP is a valid header value"),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-host"),
        HeaderValue::from_str(hostname).expect("hostname is a valid header value"),
    );
    let forwarded = format!("for=\"{}\";proto={scheme};host=\"{hostname}\"", peer.ip());
    headers.insert(
        HeaderName::from_static("forwarded"),
        HeaderValue::from_str(&forwarded).expect("Forwarded value is valid"),
    );
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && headers
            .get(header::CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
}

fn strip_hop_by_hop(headers: &mut HeaderMap, preserve_upgrade: bool) {
    let connection_headers = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect::<Vec<_>>();
    for name in connection_headers {
        if !(preserve_upgrade && name == header::UPGRADE) {
            headers.remove(name);
        }
    }
    for name in [
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
    ] {
        headers.remove(name);
    }
    if !preserve_upgrade {
        headers.remove(header::CONNECTION);
        headers.remove(header::UPGRADE);
    } else {
        headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
    }
}

fn permanent_redirect(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(location) => {
            let mut response = Redirect::permanent("/").into_response();
            response.headers_mut().insert(header::LOCATION, location);
            response
        }
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}
