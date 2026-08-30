use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

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

use crate::{certificates::CertificateResolver, model::BindingHealth, store::Store};

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
    let request_path = request.uri().path().to_owned();
    let Some(route) = state
        .store
        .active_proxy_route(&hostname, &request_path)
        .ok()
        .flatten()
    else {
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
    // For Cloudflare-proxied bindings the TCP peer is a Cloudflare edge, and
    // the real visitor is in CF-Connecting-IP. Trust that header ONLY when
    // the peer verifiably belongs to Cloudflare's published ranges; from any
    // other peer the header is an untrusted spoof and must not reach the app.
    let trusted_cloudflare_hop = route.proxied && is_cloudflare_ip(peer.ip());
    if !trusted_cloudflare_hop {
        request.headers_mut().remove("cf-connecting-ip");
        request.headers_mut().remove("true-client-ip");
    }
    let client_ip = resolve_client_ip(peer.ip(), request.headers(), trusted_cloudflare_hop);
    prepare_forward_headers(
        request.headers_mut(),
        client_ip,
        &hostname,
        "https",
        websocket,
    );
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let upstream_uri: Uri = match format!(
        "{}://{}:{}{}",
        route.upstream_scheme, route.hostname, route.upstream_port, path
    )
    .parse()
    {
        Ok(uri) => uri,
        Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    *request.uri_mut() = upstream_uri;
    // Downstream h2 requests must not force h2 on the loopback connection.
    *request.version_mut() = axum::http::Version::HTTP_11;
    // HTTPS upstreams are pinned to loopback by the connector. HostKnot owns
    // the public certificate, so a private/self-signed certificate on this
    // local-only hop must not require operator configuration.
    let client = if route.upstream_scheme == "https" {
        &state.insecure_client
    } else {
        &state.client
    };
    match client.request(request).await {
        Ok(mut response) => {
            // Persist health only on transitions — a WAL commit per proxied
            // request would serialize all traffic on the store mutex.
            if route.health != BindingHealth::Healthy {
                let result = if let Some(route_id) = route.path_route_id.as_deref() {
                    state.store.update_path_route_health(route_id, true, None)
                } else {
                    state
                        .store
                        .update_binding_health(&route.binding_id, true, None)
                };
                if let Err(error) = result {
                    tracing::debug!(%error, "failed to persist upstream health");
                }
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
            let health_error = if route.upstream_scheme == "https" {
                "HTTPS upstream failed. Verify the local service actually uses HTTPS on this \
                 port; HostKnot already accepts its private/self-signed certificate."
            } else {
                "HTTP upstream failed. Verify the local service is running on this port."
            };
            if route.health != BindingHealth::Unavailable
                || route.last_error.as_deref() != Some(health_error)
            {
                let result = if let Some(route_id) = route.path_route_id.as_deref() {
                    state
                        .store
                        .update_path_route_health(route_id, false, Some(health_error))
                } else {
                    state
                        .store
                        .update_binding_health(&route.binding_id, false, Some(health_error))
                };
                if let Err(store_error) = result {
                    tracing::debug!(%store_error, "failed to persist upstream failure");
                }
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
    client_ip: IpAddr,
    hostname: &str,
    scheme: &str,
    preserve_upgrade: bool,
) {
    strip_hop_by_hop(headers, preserve_upgrade);
    headers.remove("forwarded");
    headers.remove("x-real-ip");
    headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&client_ip.to_string()).expect("IP is a valid header value"),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("https"),
    );
    headers.insert(
        HeaderName::from_static("x-forwarded-host"),
        HeaderValue::from_str(hostname).expect("hostname is a valid header value"),
    );
    let forwarded = format!("for=\"{client_ip}\";proto={scheme};host=\"{hostname}\"");
    headers.insert(
        HeaderName::from_static("forwarded"),
        HeaderValue::from_str(&forwarded).expect("Forwarded value is valid"),
    );
}

/// Cloudflare's published egress ranges (https://www.cloudflare.com/ips/).
/// These change very rarely; refresh alongside dependency bumps.
const CLOUDFLARE_RANGES: &[&str] = &[
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
];

fn is_cloudflare_ip(ip: IpAddr) -> bool {
    CLOUDFLARE_RANGES.iter().any(|range| {
        let Some((network, prefix)) = range.split_once('/') else {
            return false;
        };
        let Ok(prefix): Result<u32, _> = prefix.parse() else {
            return false;
        };
        match (ip, network.parse::<IpAddr>()) {
            (IpAddr::V4(ip), Ok(IpAddr::V4(network))) => {
                prefix == 0 || (u32::from(ip) ^ u32::from(network)) >> (32 - prefix) == 0
            }
            (IpAddr::V6(ip), Ok(IpAddr::V6(network))) => {
                prefix == 0 || (u128::from(ip) ^ u128::from(network)) >> (128 - prefix) == 0
            }
            _ => false,
        }
    })
}

/// The visitor address to report to the app: CF-Connecting-IP when the hop is
/// a verified Cloudflare edge, otherwise the TCP peer.
fn resolve_client_ip(peer: IpAddr, headers: &HeaderMap, trusted_cloudflare_hop: bool) -> IpAddr {
    if trusted_cloudflare_hop
        && let Some(client) = headers
            .get("cf-connecting-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<IpAddr>().ok())
    {
        return client;
    }
    peer
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_ranges_match_edges_and_reject_others() {
        // Addresses inside published Cloudflare ranges (v4 and v6).
        assert!(is_cloudflare_ip("104.23.198.120".parse().unwrap()));
        assert!(is_cloudflare_ip("172.71.0.1".parse().unwrap()));
        assert!(is_cloudflare_ip("2606:4700::1".parse().unwrap()));
        // Loopback, RFC1918, documentation, and arbitrary public space.
        assert!(!is_cloudflare_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_cloudflare_ip("192.168.1.10".parse().unwrap()));
        assert!(!is_cloudflare_ip("203.0.113.7".parse().unwrap()));
        assert!(!is_cloudflare_ip("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn client_ip_uses_cf_header_only_over_a_trusted_hop() {
        let peer: IpAddr = "104.23.198.120".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "198.51.100.7".parse().unwrap());
        // Trusted Cloudflare hop: the header wins.
        assert_eq!(
            resolve_client_ip(peer, &headers, true),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        // Untrusted hop: same header is ignored.
        assert_eq!(resolve_client_ip(peer, &headers, false), peer);
        // Garbage header falls back to the peer even when trusted.
        let mut junk = HeaderMap::new();
        junk.insert("cf-connecting-ip", "not-an-ip".parse().unwrap());
        assert_eq!(resolve_client_ip(peer, &junk, true), peer);
    }
}
