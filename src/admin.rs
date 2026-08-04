use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};

use axum::{
    Form, Router,
    extract::{ConnectInfo, Extension, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use serde::Deserialize;

use crate::{
    bindings::{BindingManager, CreateBinding, UpdateBinding},
    certificates::CertificateResolver,
    cloudflare::{Cloudflare, CloudflareEndpoints},
    store::Store,
};

pub struct AdminState {
    store: Store,
    secure_cookies: bool,
    cloudflare: Cloudflare,
    bindings: BindingManager,
    expected_origin: String,
    failed_logins: Mutex<HashMap<IpAddr, VecDeque<i64>>>,
    certificates: Arc<CertificateResolver>,
    clock: crate::Clock,
}

impl AdminState {
    pub fn new(
        store: Store,
        secure_cookies: bool,
        public_url: url::Url,
        cloudflare_endpoints: CloudflareEndpoints,
        bindings: BindingManager,
        certificates: Arc<CertificateResolver>,
    ) -> anyhow::Result<Self> {
        let callback_url = public_url.join("oauth/cloudflare/callback")?;
        let expected_origin = public_url.origin().ascii_serialization();
        let cloudflare = Cloudflare::new(store.clone(), cloudflare_endpoints, callback_url)?;
        let clock = store.clock();
        Ok(Self {
            store,
            secure_cookies,
            cloudflare,
            bindings,
            expected_origin,
            failed_logins: Mutex::new(HashMap::new()),
            certificates,
            clock,
        })
    }
}

pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/setup", get(setup_page).post(setup))
        .route("/login", get(login_page).post(login))
        .route("/logout", axum::routing::post(logout))
        .route("/bindings/new", get(new_binding_page))
        .route("/bindings", axum::routing::post(create_binding))
        .route("/bindings/{id}/edit", get(edit_binding_page))
        .route("/bindings/{id}", axum::routing::post(update_binding))
        .route("/bindings/{id}/remove", axum::routing::post(remove_binding))
        .route("/providers/cloudflare", get(cloudflare_page))
        .route(
            "/providers/cloudflare/configure",
            axum::routing::post(configure_cloudflare),
        )
        .route(
            "/providers/cloudflare/connect/start",
            get(start_cloudflare_connect),
        )
        .route("/providers/cloudflare/connect", get(connect_cloudflare))
        .route(
            "/providers/cloudflare/disconnect",
            axum::routing::post(disconnect_cloudflare),
        )
        .route("/oauth/cloudflare/callback", get(cloudflare_callback))
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn(attach_peer_ip))
        .with_state(state)
}

/// The TLS accept loop attaches the peer as `Extension<SocketAddr>`, while the
/// plain-HTTP admin listener provides `ConnectInfo`; normalize both so
/// handlers can rely on a `PeerIp` extension always being present.
#[derive(Clone, Copy)]
struct PeerIp(IpAddr);

async fn attach_peer_ip(mut request: axum::extract::Request, next: Next) -> Response {
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

async fn index(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    if !state.store.is_configured().unwrap_or(false) {
        return Redirect::to("/setup").into_response();
    }
    let Some(csrf) = authenticated_csrf(&state.store, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let bindings = state.bindings.list().unwrap_or_default();
    let refresh_after = bindings
        .iter()
        .any(|binding| binding.status == "draining")
        .then(|| state.store.draining_bindings().unwrap_or_default())
        .and_then(|draining| draining.into_iter().map(|(_, _, deadline)| deadline).min())
        .map(|deadline| {
            deadline
                .saturating_sub(state.clock.now())
                .max(0)
                .saturating_add(1)
        });
    let refresh = refresh_after
        .map(|seconds| format!(r#"<meta http-equiv="refresh" content="{seconds}">"#))
        .unwrap_or_default();
    let content = if bindings.is_empty() {
        r#"<section class="empty"><h2>No bindings yet</h2><p>Connect a DNS provider, then bind a hostname to a local port.</p></section>"#.to_owned()
    } else {
        let rows = bindings
            .iter()
            .map(|binding| {
                let draining = binding.status == "draining";
                let health = if draining {
                    "Cached traffic is still served briefly".to_owned()
                } else {
                    title_status(&binding.health)
                };
                let health_error = if binding.status == "degraded" {
                    binding
                        .last_error
                        .as_deref()
                        .map(|error| {
                            format!(
                                r#"<small class="health-error">{}</small>"#,
                                escape_html(error)
                            )
                        })
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                let certificate = if draining {
                    "Retained during drain".to_owned()
                } else {
                    let error = if binding.status == "degraded" {
                        String::new()
                    } else {
                        binding
                            .last_error
                            .as_deref()
                            .map(escape_html)
                            .unwrap_or_default()
                    };
                    format!(
                        "{}<small>{}</small>",
                        title_status(&binding.certificate_status),
                        error
                    )
                };
                let dns = if draining {
                    "Released".to_owned()
                } else if binding.proxied {
                    "Cloudflare proxied".to_owned()
                } else {
                    "DNS only".to_owned()
                };
                let actions = if draining {
                    r#"<span class="muted">Removal in progress</span>"#.to_owned()
                } else {
                    format!(
                        r#"<div class="row-actions"><a class="button secondary" href="/bindings/{}/edit">Edit</a><form class="inline" method="post" action="/bindings/{}/remove"><input type="hidden" name="csrf" value="{}"><button class="danger" type="submit">Unbind</button></form></div>"#,
                        binding.id,
                        binding.id,
                        escape_html(&csrf)
                    )
                };
                format!(
                    r#"<tr data-binding-id="{}"><td data-label="Hostname"><strong>{}</strong></td><td data-label="Upstream"><code class="upstream">{}://127.0.0.1:{}</code></td><td data-label="Status / health"><span class="pill {}">{}</span><small>{}</small>{}</td><td data-label="Certificate">{}</td><td data-label="DNS">{}</td><td class="actions" data-label="Actions">{}</td></tr>"#,
                    binding.id,
                    escape_html(&binding.hostname),
                    binding.upstream_scheme,
                    binding.upstream_port,
                    binding.status,
                    title_status(&binding.status),
                    health,
                    health_error,
                    certificate,
                    dns,
                    actions
                )
            })
            .collect::<String>();
        format!(
            r#"<section class="table"><table><thead><tr><th>Hostname</th><th>Upstream</th><th>Status / health</th><th>Certificate</th><th>DNS</th><th>Actions</th></tr></thead><tbody>{rows}</tbody></table></section>"#
        )
    };
    let mut grouped: Vec<(crate::store::Event, u32)> = Vec::new();
    for event in state.store.recent_events(50).unwrap_or_default() {
        if let Some((last, count)) = grouped.last_mut()
            && last.kind == event.kind
            && last.message == event.message
        {
            *count += 1;
        } else {
            grouped.push((event, 1));
        }
    }
    let events = grouped
        .into_iter()
        .take(15)
        .map(|(event, count)| {
            let repeat = if count > 1 {
                format!(r#" <span class="repeat">×{count}</span>"#)
            } else {
                String::new()
            };
            format!(
                r#"<li><span class="tag">{}</span><span class="event-message">{}{repeat}</span><time>{}</time></li>"#,
                escape_html(&event.kind),
                escape_html(&event.message),
                format_timestamp(event.created_at)
            )
        })
        .collect::<String>();
    let history =
        format!("<section class=\"events\"><h2>Event history</h2><ol>{events}</ol></section>");
    Html(page_with_head(
        "Hostknot",
        &refresh,
        &format!(r#"<main><header><div><span class="eyebrow">HOSTKNOT</span><h1>Domain bindings</h1></div><nav><a href="/providers/cloudflare">Cloudflare</a><a class="button" href="/bindings/new">New binding</a><form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="{}"><button type="submit">Sign out</button></form></nav></header>{content}{history}</main>"#, escape_html(&csrf)),
    ))
    .into_response()
}

async fn setup_page(
    State(state): State<Arc<AdminState>>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if state.store.is_configured().unwrap_or(false) {
        return Redirect::to("/").into_response();
    }
    let token = query.get("token").cloned().unwrap_or_default();
    if !state.store.bootstrap_valid(&token).unwrap_or(false) {
        return (StatusCode::FORBIDDEN, "Invalid setup token").into_response();
    }
    Html(page(
        "Create administrator",
        &format!(
            r#"<main class="narrow"><span class="eyebrow">FIRST RUN</span><h1>Create administrator</h1><p>Use this account to manage providers and domain bindings.</p><form method="post" action="/setup"><input type="hidden" name="token" value="{}"><label>Password<input name="password" type="password" minlength="12" autocomplete="new-password" required></label><label>ACME contact email<input name="acme_email" type="email" autocomplete="email" required></label><button type="submit">Finish setup</button></form></main>"#,
            escape_html(&token)
        ),
    ))
    .into_response()
}

#[derive(Deserialize)]
struct SetupForm {
    token: String,
    password: String,
    acme_email: String,
}

async fn setup(State(state): State<Arc<AdminState>>, Form(form): Form<SetupForm>) -> Response {
    match state
        .store
        .complete_setup(&form.token, &form.password, &form.acme_email)
    {
        Ok(session) => {
            if let Err(error) = state.certificates.update_contact(&form.acme_email).await {
                tracing::warn!(%error, "failed to update ACME contact; renewal will retry without blocking setup");
            }
            session_redirect(&session, state.secure_cookies, "/")
        }
        Err(_) => (StatusCode::FORBIDDEN, "Setup failed").into_response(),
    }
}

async fn login_page(State(state): State<Arc<AdminState>>) -> Response {
    if !state.store.is_configured().unwrap_or(false) {
        return Redirect::to("/setup").into_response();
    }
    Html(page(
        "Sign in",
        r#"<main class="narrow"><span class="eyebrow">HOSTKNOT</span><h1>Sign in</h1><form method="post" action="/login"><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button type="submit">Sign in</button></form></main>"#,
    ))
    .into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
}

async fn login(
    State(state): State<Arc<AdminState>>,
    Extension(PeerIp(peer_ip)): Extension<PeerIp>,
    Form(form): Form<LoginForm>,
) -> Response {
    // Throttling is keyed per client IP so an attacker cannot lock the real
    // operator out of the only management surface.
    if login_is_throttled(&state, peer_ip) {
        let mut response =
            (StatusCode::TOO_MANY_REQUESTS, "Too many login attempts").into_response();
        response
            .headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("300"));
        return response;
    }
    if !state.store.verify_password(&form.password).unwrap_or(false) {
        record_login_failure(&state, peer_ip);
        let _ = state.store.record_event(
            "security",
            &format!("Failed administrator login from {peer_ip}"),
        );
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }
    state.failed_logins.lock().unwrap().remove(&peer_ip);
    match state.store.create_session() {
        Ok(session) => session_redirect(&session, state.secure_cookies, "/"),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn logout(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    if let Some(rejection) = require_csrf(&state, &headers, &form.csrf) {
        return rejection;
    }
    if let Some(session) = cookie(&headers, "hostknot_session") {
        let _ = state.store.destroy_session(session);
    }
    let mut response = Redirect::to("/login").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static("hostknot_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"),
    );
    response
}

async fn cloudflare_page(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some(csrf) = authenticated_csrf(&state.store, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let configured = state.cloudflare.configured();
    let connected = state.cloudflare.connected();
    let status = if connected {
        format!(
            r#"<div class="status good"><strong>Connected</strong><span>Cloudflare can manage DNS records.</span></div><form class="inline" method="post" action="/providers/cloudflare/disconnect"><input type="hidden" name="csrf" value="{}"><button class="danger" type="submit">Disconnect</button></form>"#,
            escape_html(&csrf)
        )
    } else if configured {
        r#"<div class="status"><strong>OAuth client saved</strong><span>Authorize Cloudflare to finish connecting.</span></div>"#.to_owned()
    } else {
        r#"<div class="status"><strong>Not configured</strong><span>Create a private Cloudflare OAuth client first.</span></div>"#.to_owned()
    };
    let callback = escape_html(state.cloudflare.callback_url().as_str());
    let flow = if connected {
        String::new()
    } else if configured {
        format!(
            r#"<section class="instructions next-step"><span class="step-label">STEP 3 · CLOUDFLARE</span><h2>Authorize Cloudflare</h2><p>Open Cloudflare, review the requested DNS permissions, and approve access.</p><a class="button" href="/providers/cloudflare/connect">Authorize with Cloudflare</a></section><details class="reconfigure"><summary>Change OAuth client credentials</summary><form method="post" action="/providers/cloudflare/configure"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="scopes" value="zone.read dns.write offline_access"><h2>Replace saved credentials</h2><label>Client ID<input name="client_id" required></label><label>Client secret<input name="client_secret" type="password" autocomplete="off" required></label><button type="submit">Save OAuth client</button></form></details>"#,
            escape_html(&csrf)
        )
    } else {
        format!(
            r#"<p class="provider-actions"><a class="button" href="https://dash.cloudflare.com/?to=%2F%3Aaccount%2Foauth-clients" target="_blank" rel="noopener noreferrer">Create OAuth client in Cloudflare ↗</a></p><section class="instructions"><span class="step-label">STEP 1 · CLOUDFLARE</span><h2>Use these OAuth settings</h2><p>Enter these values on Cloudflare's <strong>Configure OAuth client</strong> screen.</p><dl class="oauth-settings"><div><dt>Client name</dt><dd>Hostknot</dd></div><div><dt>Response type</dt><dd>Code</dd></div><div><dt>Grant types</dt><dd>Authorization Code + Refresh Token</dd></div><div><dt>Token authentication</dt><dd>Client Secret Basic</dd></div><div class="wide"><dt>Redirect (Callback) URL</dt><dd><code>{callback}</code></dd></div></dl><p><strong>After Continue:</strong> select <strong>Zone · Read</strong> and <strong>DNS · Edit</strong>. Keep the client <strong>Private</strong> and leave Client URL blank. Cloudflare's “Client URL required” badge only matters if you later make the client public.</p></section><form method="post" action="/providers/cloudflare/configure"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="scopes" value="zone.read dns.write offline_access"><span class="step-label">STEP 2 · HOSTKNOT</span><h2>Paste the generated credentials</h2><p>Cloudflare shows the client secret once. Copy both values before leaving the page.</p><label>Client ID<input name="client_id" required></label><label>Client secret<input name="client_secret" type="password" autocomplete="off" required></label><button type="submit">Save OAuth client</button></form>"#,
            escape_html(&csrf)
        )
    };
    Html(page(
        "Cloudflare",
        &format!(r#"<main class="narrow"><a href="/">← Bindings</a><span class="eyebrow block">DNS PROVIDER</span><h1>Cloudflare</h1>{status}{flow}</main>"#),
    ))
    .into_response()
}

async fn disconnect_cloudflare(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    if let Some(rejection) = require_csrf(&state, &headers, &form.csrf) {
        return rejection;
    }
    // Bindings that never obtained records (dns_pending) or already gave them
    // up (draining) do not depend on the provider and must not block
    // disconnecting.
    let blocking = state
        .bindings
        .list()
        .unwrap_or_default()
        .into_iter()
        .any(|binding| !matches!(binding.status.as_str(), "dns_pending" | "draining"));
    if blocking {
        return error_page(
            StatusCode::CONFLICT,
            "Bindings still depend on Cloudflare",
            "Remove all active bindings before disconnecting Cloudflare, so their DNS records can be reverted safely.",
        );
    }
    match state.cloudflare.disconnect().await {
        Ok(()) => Redirect::to("/providers/cloudflare").into_response(),
        Err(error) => error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Disconnect failed",
            &error.to_string(),
        ),
    }
}

#[derive(Deserialize)]
struct ConfigureCloudflareForm {
    csrf: String,
    client_id: String,
    client_secret: String,
    scopes: String,
}

async fn configure_cloudflare(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Form(form): Form<ConfigureCloudflareForm>,
) -> Response {
    if let Some(rejection) = require_csrf(&state, &headers, &form.csrf) {
        return rejection;
    }
    match state
        .cloudflare
        .configure(&form.client_id, &form.client_secret, &form.scopes)
    {
        Ok(()) => Redirect::to("/providers/cloudflare").into_response(),
        Err(error) => error_page(
            StatusCode::BAD_REQUEST,
            "Couldn't save the OAuth client",
            &error.to_string(),
        ),
    }
}

async fn connect_cloudflare(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some(session) = cookie(&headers, "hostknot_session") else {
        return Redirect::to("/login").into_response();
    };
    if !state.store.session_valid(session).unwrap_or(false) {
        return Redirect::to("/login").into_response();
    }
    match state.cloudflare.authorization_url(session) {
        Ok(url) => Redirect::to(url.as_str()).into_response(),
        Err(error) => error_page(
            StatusCode::BAD_REQUEST,
            "Couldn't start Cloudflare authorization",
            &error.to_string(),
        ),
    }
}

async fn start_cloudflare_connect(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = cookie(&headers, "hostknot_session") else {
        return Redirect::to("/login").into_response();
    };
    if !state.store.session_valid(session).unwrap_or(false) {
        return Redirect::to("/login").into_response();
    }
    Html(page_with_head(
        "Continue to Cloudflare",
        r#"<meta http-equiv="refresh" content="0;url=/providers/cloudflare/connect">"#,
        r#"<main class="narrow"><span class="eyebrow">DNS PROVIDER</span><h1>Opening Cloudflare</h1><p>If authorization does not open automatically, continue below.</p><p><a class="button" href="/providers/cloudflare/connect">Authorize with Cloudflare</a></p></main>"#,
    ))
    .into_response()
}

#[derive(Deserialize)]
struct OAuthCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn cloudflare_callback(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(query): Query<OAuthCallback>,
) -> Response {
    // The stored OAuth attempt is bound to the admin session that started the
    // flow; a leaked state value alone is useless to anyone else.
    let Some(session) = cookie(&headers, "hostknot_session") else {
        return Redirect::to("/login").into_response();
    };
    if !state.store.session_valid(session).unwrap_or(false) {
        return Redirect::to("/login").into_response();
    }
    if let Some(error) = query.error {
        let Some(oauth_state) = query.state else {
            return (StatusCode::BAD_REQUEST, "Incomplete OAuth cancellation").into_response();
        };
        if state
            .cloudflare
            .cancel_authorization(&oauth_state, session)
            .is_err()
        {
            return (StatusCode::BAD_REQUEST, "Invalid OAuth cancellation state").into_response();
        }
        return (
            StatusCode::BAD_REQUEST,
            format!("Cloudflare authorization failed: {}", escape_html(&error)),
        )
            .into_response();
    }
    let (Some(code), Some(oauth_state)) = (query.code, query.state) else {
        return (StatusCode::BAD_REQUEST, "Incomplete OAuth callback").into_response();
    };
    match state
        .cloudflare
        .complete_authorization(&code, &oauth_state, session)
        .await
    {
        Ok(()) => {
            state.bindings.nudge_reconciliation();
            Redirect::to("/providers/cloudflare").into_response()
        }
        Err(_) => (
            StatusCode::BAD_REQUEST,
            "Cloudflare authorization could not be completed",
        )
            .into_response(),
    }
}

async fn new_binding_page(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some(csrf) = authenticated_csrf(&state.store, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let ports = discover_listening_ports()
        .into_iter()
        .filter(|port| state.bindings.port_is_bindable(*port))
        .map(|port| format!(r#"<option value="{port}"></option>"#))
        .collect::<String>();
    Html(page(
        "New binding",
        &format!(
            r#"<main class="narrow"><a href="/">← Bindings</a><span class="eyebrow block">NEW ROUTE</span><h1>Bind a domain</h1><form method="post" action="/bindings"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="replace_existing" value="false"><div class="managed-tls"><strong>Public HTTPS included</strong><span>Hostknot obtains and renews the domain certificate automatically.</span></div><label>Hostname<input name="hostname" placeholder="app.example.com" required><small class="form-help">The exact domain visitors will use. Its zone must be in your connected Cloudflare account.</small></label><label>Local port<input name="upstream_port" type="number" min="1" max="65535" list="ports" required><datalist id="ports">{ports}</datalist><small class="form-help">The loopback port your service listens on — detected listeners are suggested as you type.</small></label><details class="local-options"><summary>Local connection options</summary><label>Local service protocol<select name="upstream_scheme"><option value="http" selected>HTTP</option><option value="https">HTTPS</option></select><small class="form-help">Use HTTPS only when the local service itself requires it. Private and self-signed loopback certificates are accepted automatically.</small></label></details><label class="check"><input name="proxied" type="checkbox" value="true" checked> Enable Cloudflare proxy</label><small class="form-help check-help">Serves traffic through Cloudflare’s network and hides this server’s IP; your app still sees the real visitor address. Uncheck for direct DNS records.</small><button type="submit">Bind domain</button></form></main>"#,
            escape_html(&csrf)
        ),
    ))
    .into_response()
}

#[derive(Deserialize)]
struct BindingForm {
    csrf: String,
    hostname: String,
    upstream_scheme: String,
    upstream_port: u16,
    #[serde(default)]
    proxied: bool,
    #[serde(default)]
    insecure_tls: bool,
    #[serde(default)]
    replace_existing: bool,
}

async fn create_binding(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Form(form): Form<BindingForm>,
) -> Response {
    if let Some(rejection) = require_csrf(&state, &headers, &form.csrf) {
        return rejection;
    }
    let input = CreateBinding {
        hostname: form.hostname,
        upstream_scheme: form.upstream_scheme,
        upstream_port: form.upstream_port,
        proxied: form.proxied,
        insecure_tls: form.insecure_tls,
        replace_existing: form.replace_existing,
    };
    match state.bindings.create(input.clone()).await {
        Ok(_) => Redirect::to("/").into_response(),
        Err(error) if crate::provider::is_authorization_required(&error) => {
            if !state.cloudflare.configured() {
                return Redirect::to("/providers/cloudflare").into_response();
            }
            Redirect::to("/providers/cloudflare/connect/start").into_response()
        }
        Err(error) if crate::provider::is_conflict(&error) => Html(page(
            "Confirm DNS replacement",
            &format!(
                r#"<main class="narrow"><span class="eyebrow">DNS CONFLICT</span><h1>Replace existing records?</h1><p>Replace existing records only if they should point to this VPS. Hostknot will save them and restore them on unbind.</p><form method="post" action="/bindings"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="hostname" value="{}"><input type="hidden" name="upstream_scheme" value="{}"><input type="hidden" name="upstream_port" value="{}"><input type="hidden" name="proxied" value="{}"><input type="hidden" name="insecure_tls" value="{}"><input type="hidden" name="replace_existing" value="true"><button class="danger" type="submit">Replace existing records</button></form></main>"#,
                escape_html(&form.csrf),
                escape_html(&input.hostname),
                escape_html(&input.upstream_scheme),
                input.upstream_port,
                input.proxied,
                input.insecure_tls
            ),
        )).into_response_with_status(StatusCode::CONFLICT),
        Err(error) => error_page(
            StatusCode::BAD_REQUEST,
            "Couldn't bind that domain",
            &error.to_string(),
        ),
    }
}

async fn edit_binding_page(
    State(state): State<Arc<AdminState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let Some(csrf) = authenticated_csrf(&state.store, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let Some(binding) = state.store.binding(&id).ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let http_selected = if binding.upstream_scheme == "http" {
        " selected"
    } else {
        ""
    };
    let https_selected = if binding.upstream_scheme == "https" {
        " selected"
    } else {
        ""
    };
    let proxied = if binding.proxied { " checked" } else { "" };
    Html(page(
        "Edit binding",
        &format!(
            r#"<main class="narrow"><a href="/">← Bindings</a><span class="eyebrow block">EDIT ROUTE</span><h1>{}</h1><p>Hostnames are immutable. Create a replacement binding to use a different hostname.</p><form method="post" action="/bindings/{}"><input type="hidden" name="csrf" value="{}"><div class="managed-tls"><strong>Public HTTPS is automatic</strong><span>These settings only control the connection to the local service.</span></div><label>Local service protocol<select name="upstream_scheme"><option value="http"{http_selected}>HTTP</option><option value="https"{https_selected}>HTTPS</option></select><small class="form-help">Private and self-signed loopback certificates are accepted automatically.</small></label><label>Local port<input name="upstream_port" type="number" min="1" max="65535" value="{}" required></label><label class="check"><input name="proxied" type="checkbox" value="true"{proxied}> Enable Cloudflare proxy</label><button type="submit">Save changes</button></form></main>"#,
            escape_html(&binding.hostname),
            binding.id,
            escape_html(&csrf),
            binding.upstream_port,
        ),
    ))
    .into_response()
}

#[derive(Deserialize)]
struct UpdateBindingForm {
    csrf: String,
    upstream_scheme: String,
    upstream_port: u16,
    #[serde(default)]
    proxied: bool,
    #[serde(default)]
    insecure_tls: bool,
}

async fn update_binding(
    State(state): State<Arc<AdminState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<UpdateBindingForm>,
) -> Response {
    if let Some(rejection) = require_csrf(&state, &headers, &form.csrf) {
        return rejection;
    }
    match state
        .bindings
        .update(
            &id,
            UpdateBinding {
                upstream_scheme: form.upstream_scheme,
                upstream_port: form.upstream_port,
                proxied: form.proxied,
                insecure_tls: form.insecure_tls,
            },
        )
        .await
    {
        Ok(()) => Redirect::to("/").into_response(),
        Err(error) if crate::provider::is_drift(&error) => error_page(
            StatusCode::CONFLICT,
            "DNS records changed outside Hostknot",
            "A managed record was modified by something else, so Hostknot left everything untouched. \
             Fix or restore the records in Cloudflare; Hostknot re-checks automatically and will finish this operation.",
        ),
        Err(error) => error_page(
            StatusCode::BAD_REQUEST,
            "Couldn't apply that change",
            &error.to_string(),
        ),
    }
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

async fn remove_binding(
    State(state): State<Arc<AdminState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    if let Some(rejection) = require_csrf(&state, &headers, &form.csrf) {
        return rejection;
    }
    match state.bindings.remove(&id).await {
        Ok(()) => Redirect::to("/").into_response(),
        Err(error) if crate::provider::is_drift(&error) => error_page(
            StatusCode::CONFLICT,
            "DNS records changed outside Hostknot",
            "A managed record was modified by something else, so Hostknot left everything untouched. \
             Fix or restore the records in Cloudflare; Hostknot re-checks automatically and will finish this operation.",
        ),
        Err(error) => error_page(
            StatusCode::BAD_REQUEST,
            "Couldn't apply that change",
            &error.to_string(),
        ),
    }
}

trait HtmlStatus {
    fn into_response_with_status(self, status: StatusCode) -> Response;
}

impl HtmlStatus for Html<String> {
    fn into_response_with_status(self, status: StatusCode) -> Response {
        let mut response = self.into_response();
        *response.status_mut() = status;
        response
    }
}

fn origin_host(origin: &str) -> Option<String> {
    origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .map(str::to_ascii_lowercase)
}

fn authenticated_csrf(store: &Store, headers: &HeaderMap) -> Option<String> {
    let session = cookie(headers, "hostknot_session")?;
    store.session_csrf(session).ok().flatten()
}

/// Guards a mutating request. Returns the failure response to send, or `None`
/// when the request may proceed. A missing or expired session is not a CSRF
/// problem — it redirects to the login page instead of a dead-end 403.
fn require_csrf(state: &AdminState, headers: &HeaderMap, supplied: &str) -> Option<Response> {
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
        // Self-consistency, independent of any configured URL: a same-origin
        // submission always has an Origin whose host equals the request's own
        // Host, no matter which address the operator browses the VPS by. A
        // forged cross-site POST cannot fake this — the browser pins Origin
        // to the attacker's page.
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
        // "null" is ambiguous, not proof of cross-origin: restrictive
        // referrer policies make browsers send it even for same-origin form
        // POSTs, and Safari may omit Sec-Fetch-* entirely. Only treat it as
        // cross-origin when Sec-Fetch-Site positively says so; the
        // per-session CSRF token below remains the real gate.
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
            "This submission did not come from the Hostknot admin pages, so it was rejected for safety.",
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

fn login_is_throttled(state: &AdminState, peer_ip: IpAddr) -> bool {
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

fn record_login_failure(state: &AdminState, peer_ip: IpAddr) {
    let now = state.clock.now();
    state
        .failed_logins
        .lock()
        .unwrap()
        .entry(peer_ip)
        .or_default()
        .push_back(now);
}

fn cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
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
// cookie there — breaking the session binding of the OAuth flow. All mutating
// routes are POST + CSRF-token protected, which Lax still covers.
fn session_redirect(session: &str, secure: bool, location: &'static str) -> Response {
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

async fn security_headers(request: axum::extract::Request, next: Next) -> Response {
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
    // same-origin, not no-referrer: a no-referrer policy makes browsers send
    // "Origin: null" on same-origin form POSTs (Fetch spec), which broke the
    // origin check for browsers that omit Sec-Fetch-* (Safari). same-origin
    // still sends nothing cross-origin.
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        header::HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    // Admin pages embed per-session CSRF tokens and event history; they must
    // never land in a shared or forensic browser cache.
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000"),
    );
    response
}

fn page(title: &str, body: &str) -> String {
    page_with_head(title, "", body)
}

/// Every failure the operator can hit renders as a styled page with a way
/// back — never a bare text response.
fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    Html(page(
        title,
        &format!(
            r#"<main class="narrow"><span class="eyebrow">SOMETHING NEEDS ATTENTION</span><h1>{}</h1><p class="error-detail">{}</p><p><a class="button" href="/">Back to bindings</a></p></main>"#,
            escape_html(title),
            escape_html(message)
        ),
    ))
    .into_response_with_status(status)
}

fn page_with_head(title: &str, head: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">{head}<title>{title} · Hostknot</title><style>{CSS}</style></head><body>{body}</body></html>"#
    )
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn format_timestamp(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|moment| {
            let format = time::format_description::parse_borrowed::<2>(
                "[year]-[month]-[day] [hour]:[minute] UTC",
            )
            .ok()?;
            moment.format(&format).ok()
        })
        .unwrap_or_else(|| unix.to_string())
}

fn title_status(status: &str) -> String {
    status
        .split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(target_os = "linux")]
fn discover_listening_ports() -> Vec<u16> {
    let mut ports = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in contents.lines().skip(1) {
            let columns: Vec<_> = line.split_whitespace().collect();
            if columns.len() > 3
                && columns[3] == "0A"
                && let Some((address, port)) = columns[1].split_once(':')
            {
                // Only offer sockets the proxy can actually reach: it
                // connects to 127.0.0.1, so a listener bound solely to a
                // public interface would always 502.
                let reachable_via_loopback = matches!(
                    address,
                    "0100007F"                                  // 127.0.0.1
                        | "00000000"                            // 0.0.0.0
                        | "00000000000000000000000001000000"    // ::1
                        | "00000000000000000000000000000000" // ::
                );
                if !reachable_via_loopback {
                    continue;
                }
                if let Ok(port) = u16::from_str_radix(port, 16) {
                    ports.push(port);
                }
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[cfg(not(target_os = "linux"))]
fn discover_listening_ports() -> Vec<u16> {
    Vec::new()
}

const CSS: &str = r#"
:root{color-scheme:dark;--bg:#101311;--panel:#181d1a;--line:#303a33;--ink:#f4f7f4;--muted:#9ba89f;--accent:#a7f3c3}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(circle at top right,#20352a 0,transparent 32rem),var(--bg);color:var(--ink);font:16px/1.5 ui-sans-serif,system-ui,sans-serif;min-height:100vh}
main{max-width:1050px;margin:0 auto;padding:64px 28px}
.narrow{max-width:620px}
.eyebrow{color:var(--accent);font-size:.75rem;font-weight:800;letter-spacing:.18em}
.block{display:block;margin-top:2rem}
header{display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:24px}
header>div{min-width:0}
nav{display:flex;align-items:center;flex-wrap:wrap;gap:18px}
h1{font-size:clamp(2.2rem,6vw,4rem);line-height:1;margin:.25rem 0 1rem;letter-spacing:-.05em;overflow-wrap:anywhere}
h2{margin-top:0}
p{color:var(--muted)}
a{color:var(--accent)}
form,.empty,.instructions,.status,.table,.events{margin-top:2rem;padding:28px;border:1px solid var(--line);border-radius:18px;background:color-mix(in srgb,var(--panel) 94%,transparent);box-shadow:0 24px 80px #0005}
.inline{margin:0;padding:0;border:0;background:none;box-shadow:none}
.status{display:flex;justify-content:space-between;gap:18px}
.status span,small,.muted{display:block;color:var(--muted)}
.form-help{margin-top:7px}
.health-error{margin-top:5px;color:#ffb4a9}
.managed-tls{display:flex;flex-direction:column;gap:3px;margin-bottom:22px;padding:14px 16px;border:1px solid #65d68b66;border-radius:12px;background:#112219}
.managed-tls span{color:var(--muted);font-size:.875rem}
.local-options{margin:-2px 0 20px;color:var(--muted)}
.local-options summary{width:max-content;max-width:100%;cursor:pointer;color:var(--accent)}
.local-options label{margin:16px 0 0}
.provider-actions{margin:1rem 0 0}
.next-step .button{margin-top:6px}
.reconfigure{margin-top:18px;color:var(--muted)}
.reconfigure summary{width:max-content;max-width:100%;cursor:pointer;color:var(--accent)}
.reconfigure form{margin-top:14px}
.step-label{display:block;margin-bottom:8px;color:var(--accent);font-size:.7rem;font-weight:800;letter-spacing:.14em}
.oauth-settings{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;margin:20px 0;border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--line)}
.oauth-settings>div{min-width:0;padding:14px 16px;background:#0d100e}
.oauth-settings .wide{grid-column:1/-1}
.oauth-settings dt{color:var(--muted);font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em}
.oauth-settings dd{margin:5px 0 0;color:var(--ink);font-weight:700}
.oauth-settings code{display:block;overflow-x:auto;overflow-wrap:normal;white-space:nowrap;padding:0;background:none;font-size:.875rem;font-weight:500}
label{display:block;color:var(--muted);font-size:.875rem;margin-bottom:20px}
input,select{width:100%;margin-top:7px;border:1px solid var(--line);border-radius:10px;background:#0d100e;color:var(--ink);font:inherit;padding:12px 14px;outline:none}
.check{display:flex;align-items:center;gap:10px}
.check input{width:auto;margin:0}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px #a7f3c322}
button,.button{display:inline-block;border:0;border-radius:999px;background:var(--accent);color:#102117;font:inherit;font-weight:800;padding:12px 20px;cursor:pointer;text-decoration:none;white-space:nowrap}
.secondary{border:1px solid var(--line);background:transparent;color:var(--accent)}
.danger{background:#ffb4a9;color:#3b0a06}
code{overflow-wrap:anywhere;background:#0b0e0c;padding:6px 9px;border-radius:8px;color:#d6ffe5}
code.upstream{display:inline-block;max-width:100%;overflow-x:auto;overflow-wrap:normal;white-space:nowrap}
.instructions code{display:block;padding:12px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:14px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.1em}
.actions{white-space:nowrap}
.actions .inline{margin:0}
.row-actions{display:flex;align-items:center;gap:10px;flex-wrap:nowrap}
.row-actions button,.row-actions .button{padding:10px 16px}
.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:3px 10px}
.pill.active{border-color:#65d68b;color:var(--accent)}
.pill.degraded{border-color:#f2c94c88;color:#f2d98a}
.pill.drifted{border-color:#ffb4a988;color:#ffb4a9}
.pill.draining,.pill.dns_pending,.pill.certificate_pending{color:var(--muted)}
.check-help{margin:-12px 0 20px 30px}
.error-detail{overflow-wrap:anywhere}
.events ol{list-style:none;margin:0;padding:0}
.events li{display:flex;align-items:baseline;gap:12px;padding:10px 0;border-bottom:1px solid var(--line)}
.events li:last-child{border-bottom:0}
.events .tag{flex-shrink:0;border:1px solid var(--line);border-radius:6px;padding:1px 8px;color:var(--muted);font-size:.7rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.events .event-message{min-width:0;overflow-wrap:anywhere}
.events .repeat{color:var(--muted);font-size:.8rem}
.events time{margin-left:auto;flex-shrink:0;color:var(--muted);font-size:.8rem;white-space:nowrap}
@media(max-width:600px){.events time{display:none}}
@media(max-width:1100px){
  .table table,.table tbody{display:block}
  .table thead{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
  .table tr{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px;padding:22px 0;border-bottom:1px solid var(--line)}
  .table tr:first-child{padding-top:0}
  .table tr:last-child{padding-bottom:0;border-bottom:0}
  .table td{display:block;min-width:0;padding:0;border:0}
  .table td::before{content:attr(data-label);display:block;margin-bottom:7px;color:var(--muted);font-size:.75rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase}
  .table .actions{grid-column:1/-1;white-space:normal}
  .table .actions .inline{margin:0}
}
@media(max-width:900px){
  header{align-items:flex-start;flex-direction:column}
}
@media(max-width:500px){
  main{padding:40px 18px}
  form,.empty,.instructions,.status,.table,.events{padding:20px}
  .oauth-settings{grid-template-columns:1fr}
  .oauth-settings .wide{grid-column:auto}
  .table tr{grid-template-columns:1fr}
  .table .actions{grid-column:auto}
}
"#;
