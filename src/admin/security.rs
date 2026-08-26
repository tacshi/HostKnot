use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};

use super::{AdminState, views::error_page};
use crate::store::Store;

/// The TLS accept loop attaches the peer as `Extension<SocketAddr>`, while the
/// plain-HTTP admin listener provides `ConnectInfo`; handlers consume this
/// normalized extension in either case.
#[derive(Clone, Copy)]
pub(super) struct PeerIp(pub(super) IpAddr);

pub(super) async fn attach_peer_ip(mut request: Request, next: Next) -> Response {
    let peer_ip = request
        .extensions()
        .get::<SocketAddr>()
        .copied()
        .or_else(|| {
            request
                .extensions()
                .get::<ConnectInfo<SocketAddr>>()
                .map(|ConnectInfo(peer)| *peer)
        })
        .map(|peer| peer.ip())
        .unwrap_or(IpAddr::from([0, 0, 0, 0]));
    request.extensions_mut().insert(PeerIp(peer_ip));
    // HTTP/2 requests carry the host in :authority, not a Host header;
    // materialize it so header-based checks see it uniformly.
    if !request.headers().contains_key(header::HOST)
        && let Some(authority) = request.uri().authority()
        && let Ok(value) = HeaderValue::from_str(authority.as_str())
    {
        request.headers_mut().insert(header::HOST, value);
    }
    next.run(request).await
}

pub(super) fn authenticated_csrf(store: &Store, headers: &HeaderMap) -> Option<String> {
    let session = cookie(headers, "hostknot_session")?;
    store.session_csrf(session).ok().flatten()
}

/// Guards a mutating request. Returns the failure response to send, or `None`
/// when the request may proceed. A missing or expired session is not a CSRF
/// problem — it redirects to the login page instead of a dead-end 403.
pub(super) fn require_csrf(
    state: &AdminState,
    headers: &HeaderMap,
    supplied: &str,
) -> Option<Response> {
    use subtle::ConstantTimeEq;
    let Some(expected) = authenticated_csrf(&state.store, headers) else {
        return Some(Redirect::to("/login").into_response());
    };
    let origin_is_valid = match headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    {
        // Without an Origin header, fall back to Sec-Fetch-Site when the
        // browser sent one ("none" = user-initiated navigation).
        None => headers
            .get("sec-fetch-site")
            .and_then(|value| value.to_str().ok())
            .is_none_or(|site| matches!(site, "same-origin" | "none")),
        Some(origin) if origin == state.expected_origin => true,
        // A browser pins Origin to the source page, so matching it to the
        // request Host remains valid even when the operator used a different
        // local address than the configured public URL.
        Some(origin)
            if origin_host(origin).is_some()
                && origin_host(origin)
                    == headers
                        .get(header::HOST)
                        .and_then(|value| value.to_str().ok())
                        .map(|host| host.trim().to_ascii_lowercase()) =>
        {
            true
        }
        // "null" is ambiguous under restrictive referrer policies. The
        // per-session CSRF token remains the actual authorization check.
        Some("null") => headers
            .get("sec-fetch-site")
            .and_then(|value| value.to_str().ok())
            .is_none_or(|site| matches!(site, "same-origin" | "none")),
        Some(_) => false,
    };
    if !origin_is_valid {
        return Some(error_page(
            StatusCode::FORBIDDEN,
            "Request blocked",
            "This submission did not come from the HostKnot admin pages, so it was rejected for safety.",
        ));
    }
    if !bool::from(expected.as_bytes().ct_eq(supplied.as_bytes())) {
        return Some(error_page(
            StatusCode::FORBIDDEN,
            "This page went stale",
            "It was loaded under a previous session. Go back to the bindings page and try again from there.",
        ));
    }
    None
}

pub(super) fn login_is_throttled(state: &AdminState, peer_ip: IpAddr) -> bool {
    let mut failed_logins = state.failed_logins.lock().unwrap();
    let cutoff = state.clock.now() - 5 * 60;
    failed_logins.retain(|_, attempts| {
        while attempts.front().is_some_and(|attempt| *attempt < cutoff) {
            attempts.pop_front();
        }
        !attempts.is_empty()
    });
    failed_logins
        .get(&peer_ip)
        .is_some_and(|attempts| attempts.len() >= 5)
}

pub(super) fn record_login_failure(state: &AdminState, peer_ip: IpAddr) {
    let now = state.clock.now();
    state
        .failed_logins
        .lock()
        .unwrap()
        .entry(peer_ip)
        .or_default()
        .push_back(now);
}

pub(super) fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .filter_map(|part| part.trim().split_once('='))
        .find_map(|(key, value)| (key == name).then_some(value))
}

// SameSite=Lax (not Strict): the OAuth callback arrives as a cross-site
// top-level navigation from Cloudflare, and Strict would withhold the session
// cookie there. Mutating routes remain POST + CSRF-token protected.
pub(super) fn session_redirect(session: &str, secure: bool, location: &'static str) -> Response {
    let secure = if secure { "; Secure" } else { "" };
    let mut response = Redirect::to(location).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "hostknot_session={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200{secure}"
        ))
        .expect("valid session cookie"),
    );
    response
}

pub(super) async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000"),
    );
    response
}

fn origin_host(origin: &str) -> Option<String> {
    origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .map(str::to_ascii_lowercase)
}
