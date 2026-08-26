mod security;
mod views;

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::{Arc, Mutex},
};

use axum::{
    Form, Router,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use serde::Deserialize;

use self::security::{
    PeerIp, attach_peer_ip, authenticated_csrf, cookie, login_is_throttled, record_login_failure,
    require_csrf, security_headers, session_redirect,
};
use self::views::{
    HtmlStatus, discover_listening_ports, error_page, escape_html, format_timestamp, page,
    page_with_head, title_status,
};

use crate::{
    bindings::{BindingManager, CreateBinding, UpdateBinding},
    certificates::CertificateResolver,
    cloudflare::{Cloudflare, CloudflareEndpoints},
    model::BindingStatus,
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
        .any(|binding| binding.status == BindingStatus::Draining)
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
                let draining = binding.status == BindingStatus::Draining;
                let health = if draining {
                    "Cached traffic is still served briefly".to_owned()
                } else {
                    title_status(binding.health.as_str())
                };
                let health_error = if binding.status == BindingStatus::Degraded {
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
                    let error = if binding.status == BindingStatus::Degraded {
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
                        title_status(binding.certificate_status.as_str()),
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
                let actions = if matches!(
                    binding.status,
                    BindingStatus::Removing | BindingStatus::Draining
                ) {
                    r#"<span class="muted">Removal in progress</span>"#.to_owned()
                } else if binding.status == BindingStatus::Updating {
                    r#"<span class="muted">Update in progress</span>"#.to_owned()
                } else if !binding.status.is_editable() {
                    format!(
                        r#"<form class="inline" method="post" action="/bindings/{}/remove"><input type="hidden" name="csrf" value="{}"><button class="danger" type="submit">Unbind</button></form>"#,
                        binding.id,
                        escape_html(&csrf)
                    )
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
                    binding.status.as_str(),
                    title_status(binding.status.as_str()),
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
        "HostKnot",
        &refresh,
        &format!(r#"<main><header><div><span class="eyebrow">HostKnot</span><h1>Domain bindings</h1></div><nav><a href="/providers/cloudflare">Cloudflare</a><a class="button" href="/bindings/new">New binding</a><form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="{}"><button type="submit">Sign out</button></form></nav></header>{content}{history}</main>"#, escape_html(&csrf)),
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
        r#"<main class="narrow"><span class="eyebrow">HostKnot</span><h1>Sign in</h1><form method="post" action="/login"><label>Password<input name="password" type="password" autocomplete="current-password" required></label><button type="submit">Sign in</button></form></main>"#,
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
            r#"<p class="provider-actions"><a class="button" href="https://dash.cloudflare.com/?to=%2F%3Aaccount%2Foauth-clients" target="_blank" rel="noopener noreferrer">Create OAuth client in Cloudflare ↗</a></p><section class="instructions"><span class="step-label">STEP 1 · CLOUDFLARE</span><h2>Use these OAuth settings</h2><p>Enter these values on Cloudflare's <strong>Configure OAuth client</strong> screen.</p><dl class="oauth-settings"><div><dt>Client name</dt><dd>HostKnot</dd></div><div><dt>Response type</dt><dd>Code</dd></div><div><dt>Grant types</dt><dd>Authorization Code + Refresh Token</dd></div><div><dt>Token authentication</dt><dd>Client Secret Basic</dd></div><div class="wide"><dt>Redirect (Callback) URL</dt><dd><code>{callback}</code></dd></div></dl><p><strong>After Continue:</strong> select <strong>Zone · Read</strong> and <strong>DNS · Edit</strong>. Keep the client <strong>Private</strong> and leave Client URL blank. Cloudflare's “Client URL required” badge only matters if you later make the client public.</p></section><form method="post" action="/providers/cloudflare/configure"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="scopes" value="zone.read dns.write offline_access"><span class="step-label">STEP 2 · HostKnot</span><h2>Paste the generated credentials</h2><p>Cloudflare shows the client secret once. Copy both values before leaving the page.</p><label>Client ID<input name="client_id" required></label><label>Client secret<input name="client_secret" type="password" autocomplete="off" required></label><button type="submit">Save OAuth client</button></form>"#,
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
    // Only a binding that completed DNS removal no longer depends on the
    // provider. Pending creates may already have a durable or in-flight plan.
    let blocking = state
        .bindings
        .list()
        .unwrap_or_default()
        .into_iter()
        .any(|binding| binding.status.depends_on_provider());
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
            r#"<main class="narrow"><a href="/">← Bindings</a><span class="eyebrow block">NEW ROUTE</span><h1>Bind a domain</h1><form method="post" action="/bindings"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="replace_existing" value="false"><div class="managed-tls"><strong>Public HTTPS included</strong><span>HostKnot obtains and renews the domain certificate automatically.</span></div><label>Hostname<input name="hostname" placeholder="app.example.com" required><small class="form-help">The exact domain visitors will use. Its zone must be in your connected Cloudflare account.</small></label><label>Local port<input name="upstream_port" type="number" min="1" max="65535" list="ports" required><datalist id="ports">{ports}</datalist><small class="form-help">The loopback port your service listens on — detected listeners are suggested as you type.</small></label><details class="local-options"><summary>Local connection options</summary><label>Local service protocol<select name="upstream_scheme"><option value="http" selected>HTTP</option><option value="https">HTTPS</option></select><small class="form-help">Use HTTPS only when the local service itself requires it. Private and self-signed loopback certificates are accepted automatically.</small></label></details><label class="check"><input name="proxied" type="checkbox" value="true" checked> Enable Cloudflare proxy</label><small class="form-help check-help">Serves traffic through Cloudflare’s network and hides this server’s IP; your app still sees the real visitor address. Uncheck for direct DNS records.</small><button type="submit">Bind domain</button></form></main>"#,
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
                r#"<main class="narrow"><span class="eyebrow">DNS CONFLICT</span><h1>Replace existing records?</h1><p>Replace existing records only if they should point to this VPS. HostKnot will save them and restore them on unbind.</p><form method="post" action="/bindings"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="hostname" value="{}"><input type="hidden" name="upstream_scheme" value="{}"><input type="hidden" name="upstream_port" value="{}"><input type="hidden" name="proxied" value="{}"><input type="hidden" name="replace_existing" value="true"><button class="danger" type="submit">Replace existing records</button></form></main>"#,
                escape_html(&form.csrf),
                escape_html(&input.hostname),
                escape_html(&input.upstream_scheme),
                input.upstream_port,
                input.proxied
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
            },
        )
        .await
    {
        Ok(()) => Redirect::to("/").into_response(),
        Err(error) if crate::provider::is_drift(&error) => error_page(
            StatusCode::CONFLICT,
            "DNS records changed outside HostKnot",
            "A managed record was modified by something else, so HostKnot left everything untouched. \
             Fix or restore the records in Cloudflare; HostKnot re-checks automatically and will finish this operation.",
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
            "DNS records changed outside HostKnot",
            "A managed record was modified by something else, so HostKnot left everything untouched. \
             Fix or restore the records in Cloudflare; HostKnot re-checks automatically and will finish this operation.",
        ),
        Err(error) => error_page(
            StatusCode::BAD_REQUEST,
            "Couldn't apply that change",
            &error.to_string(),
        ),
    }
}
