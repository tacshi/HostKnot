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
    LoginAttempt, PeerIp, attach_peer_ip, authenticated_csrf, begin_login_attempt,
    clear_login_attempts, cookie, require_csrf, security_headers, session_cookie,
    session_cookie_name, session_redirect,
};
use self::views::{
    FAVICON_SVG, HtmlStatus, ICON_ALERT, ICON_CHECK, ICON_LOCK, Nav, app_page, auth_page,
    back_link, binding_edit_page, dashboard_page, discover_listening_ports, error_page,
    escape_html, notice, page, page_with_head, protocol_select,
};

use crate::{
    bindings::{BindingManager, CreateBinding, CreatePathRoute, UpdateBinding, UpdatePathRoute},
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
    session_cookie: &'static str,
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
            session_cookie: session_cookie_name(secure_cookies),
            certificates,
            clock,
        })
    }
}

pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/favicon.svg", get(favicon))
        .route("/setup", get(setup_page).post(setup))
        .route("/login", get(login_page).post(login))
        .route("/logout", axum::routing::post(logout))
        .route("/bindings/new", get(new_binding_page))
        .route("/bindings", axum::routing::post(create_binding))
        .route("/bindings/{id}/edit", get(edit_binding_page))
        .route("/bindings/{id}", axum::routing::post(update_binding))
        .route("/bindings/{id}/remove", axum::routing::post(remove_binding))
        .route(
            "/bindings/{id}/routes",
            axum::routing::post(create_path_route),
        )
        .route(
            "/bindings/{binding_id}/routes/{route_id}/edit",
            get(edit_path_route_page),
        )
        .route(
            "/bindings/{binding_id}/routes/{route_id}",
            axum::routing::post(update_path_route),
        )
        .route(
            "/bindings/{binding_id}/routes/{route_id}/remove",
            axum::routing::post(remove_path_route),
        )
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
    let Some(csrf) = authenticated_csrf(&state, &headers) else {
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
    grouped.truncate(15);
    Html(dashboard_page(
        &bindings,
        &grouped,
        state.cloudflare.connected(),
        &csrf,
        &refresh,
    ))
    .into_response()
}

async fn favicon() -> Response {
    ([(header::CONTENT_TYPE, "image/svg+xml")], FAVICON_SVG).into_response()
}

/// Setup links are single-use and short-lived, so a dead one points the
/// operator at the CLI that mints a fresh link.
fn expired_setup_link() -> Response {
    Html(page(
        "Setup link expired",
        &notice(
            "warn",
            "First run",
            "This setup link no longer works",
            "Setup links work once and expire after an hour. On the server, run <code>hostknot admin url</code> to get a fresh one.",
            "",
        ),
    ))
    .into_response_with_status(StatusCode::FORBIDDEN)
}

fn setup_form(token: &str, error: Option<&str>) -> String {
    let error = error
        .map(|error| {
            format!(
                r#"<div class="form-error" role="alert">{ICON_ALERT}<span>{}</span></div>"#,
                escape_html(error)
            )
        })
        .unwrap_or_default();
    auth_page(
        "Create administrator",
        &format!(
            r#"<form class="card" method="post" action="/setup"><span class="eyebrow">First run</span><h1>Create administrator</h1><p>This account manages DNS providers and domain bindings on this server.</p>{error}<input type="hidden" name="token" value="{}"><label>Password<input name="password" type="password" minlength="12" autocomplete="new-password" required autofocus><small class="form-help">At least 12 characters.</small></label><label>ACME contact email<input name="acme_email" type="email" autocomplete="email" required><small class="form-help">Let’s Encrypt sends certificate notices here.</small></label><button type="submit">Finish setup</button></form>"#,
            escape_html(token)
        ),
    )
}

fn login_form(error: Option<&str>) -> String {
    let error = error
        .map(|error| {
            format!(
                r#"<div class="form-error" role="alert">{ICON_ALERT}<span>{}</span></div>"#,
                escape_html(error)
            )
        })
        .unwrap_or_default();
    auth_page(
        "Sign in",
        &format!(
            r#"<form class="card" method="post" action="/login"><h1>Sign in</h1><p>Enter the administrator password for this server.</p>{error}<label>Password<input name="password" type="password" autocomplete="current-password" required autofocus></label><button type="submit">Sign in</button></form><p class="auth-foot">Forgot it? Run <code>hostknot admin reset</code> on the server.</p>"#
        ),
    )
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
        return expired_setup_link();
    }
    Html(setup_form(&token, None)).into_response()
}

#[derive(Deserialize)]
struct SetupForm {
    token: String,
    password: String,
    acme_email: String,
}

async fn setup(State(state): State<Arc<AdminState>>, Form(form): Form<SetupForm>) -> Response {
    // Argon2 hashing is deliberately slow; keep it off the async workers
    // that also serve proxy traffic.
    let store = state.store.clone();
    let (token, password, acme_email) = (
        form.token.clone(),
        form.password.clone(),
        form.acme_email.clone(),
    );
    let completed =
        tokio::task::spawn_blocking(move || store.complete_setup(&token, &password, &acme_email))
            .await
            .unwrap_or_else(|error| Err(anyhow::anyhow!("setup task failed: {error}")));
    match completed {
        Ok(session) => {
            if let Err(error) = state.certificates.update_contact(&form.acme_email).await {
                tracing::warn!(%error, "failed to update ACME contact; renewal will retry without blocking setup");
            }
            session_redirect(&state, &session, "/")
        }
        // With a still-valid token the input itself was rejected; show why
        // and let the operator correct it.
        Err(error) if state.store.bootstrap_valid(&form.token).unwrap_or(false) => {
            Html(setup_form(&form.token, Some(&error.to_string())))
                .into_response_with_status(StatusCode::BAD_REQUEST)
        }
        Err(_) => expired_setup_link(),
    }
}

async fn login_page(State(state): State<Arc<AdminState>>) -> Response {
    if !state.store.is_configured().unwrap_or(false) {
        return Redirect::to("/setup").into_response();
    }
    Html(login_form(None)).into_response()
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
    // Throttling is keyed per client address so an attacker cannot lock the
    // real operator out of the only management surface.
    let first_attempt = match begin_login_attempt(&state, peer_ip) {
        LoginAttempt::Throttled => {
            let mut response = Html(login_form(Some(
                "Too many failed attempts from this address. Wait five minutes and try again.",
            )))
            .into_response_with_status(StatusCode::TOO_MANY_REQUESTS);
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("300"));
            return response;
        }
        LoginAttempt::Allowed { first } => first,
    };
    // Argon2 verification is deliberately slow; keep it off the async
    // workers that also serve proxy traffic.
    let store = state.store.clone();
    let password = form.password;
    let verified = tokio::task::spawn_blocking(move || store.verify_password(&password))
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false);
    if !verified {
        if first_attempt {
            let _ = state.store.record_event(
                "security",
                &format!("Failed administrator login from {peer_ip}"),
            );
        }
        return Html(login_form(Some("That password is incorrect.")))
            .into_response_with_status(StatusCode::UNAUTHORIZED);
    }
    clear_login_attempts(&state, peer_ip);
    match state.store.create_session() {
        Ok(session) => session_redirect(&state, &session, "/"),
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
    if let Some(session) = cookie(&headers, state.session_cookie) {
        let _ = state.store.destroy_session(session);
    }
    let mut response = Redirect::to("/login").into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, session_cookie(&state, "", 0));
    response
}

async fn cloudflare_page(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some(csrf) = authenticated_csrf(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let configured = state.cloudflare.configured();
    let connected = state.cloudflare.connected();
    let status = if connected {
        format!(
            r#"<section class="card status-card good"><div class="status-icon">{ICON_CHECK}</div><div class="status-text"><strong>Connected</strong><span>Cloudflare can manage DNS records.</span></div><form class="inline" method="post" action="/providers/cloudflare/disconnect"><input type="hidden" name="csrf" value="{}"><button class="danger small" type="submit">Disconnect</button></form></section>"#,
            escape_html(&csrf)
        )
    } else if configured {
        format!(
            r#"<section class="card status-card pending"><div class="status-icon">{ICON_LOCK}</div><div class="status-text"><strong>OAuth client saved</strong><span>Authorize Cloudflare to finish connecting.</span></div></section>"#
        )
    } else {
        format!(
            r#"<section class="card status-card"><div class="status-icon">{ICON_LOCK}</div><div class="status-text"><strong>Not configured</strong><span>Create a private Cloudflare OAuth client first.</span></div></section>"#
        )
    };
    let callback = escape_html(state.cloudflare.callback_url().as_str());
    let credentials_fields = r#"<input type="hidden" name="scopes" value="zone.read dns.write offline_access"><label>Client ID<input name="client_id" autocomplete="off" spellcheck="false" required></label><label>Client secret<input name="client_secret" type="password" autocomplete="off" required></label>"#;
    let flow = if connected {
        String::new()
    } else if configured {
        format!(
            r#"<section class="card step"><div class="step-head"><span class="step-num">3</span><div><span class="step-label">In Cloudflare</span><h2>Authorize Cloudflare</h2></div></div><p>Open Cloudflare, review the requested DNS permissions, and approve access.</p><div class="step-actions"><a class="button" href="/providers/cloudflare/connect?csrf={csrf}">Authorize with Cloudflare</a></div></section><details class="reconfigure"><summary>Change OAuth client credentials</summary><form class="card" method="post" action="/providers/cloudflare/configure"><input type="hidden" name="csrf" value="{csrf}"><div class="form-title"><h2>Replace saved credentials</h2></div>{credentials_fields}<div class="form-actions"><button type="submit">Save OAuth client</button></div></form></details>"#,
            csrf = escape_html(&csrf)
        )
    } else {
        format!(
            r#"<section class="card step"><div class="step-head"><span class="step-num">1</span><div><span class="step-label">In Cloudflare</span><h2>Use these OAuth settings</h2></div></div><p>Create an OAuth client, then enter these values on Cloudflare's <strong>Configure OAuth client</strong> screen.</p><p class="step-actions"><a class="button secondary" href="https://dash.cloudflare.com/?to=%2F%3Aaccount%2Foauth-clients" target="_blank" rel="noopener noreferrer">Create OAuth client in Cloudflare ↗</a></p><dl class="oauth-settings"><div><dt>Client name</dt><dd>HostKnot</dd></div><div><dt>Response type</dt><dd>Code</dd></div><div><dt>Grant types</dt><dd>Authorization Code + Refresh Token</dd></div><div><dt>Token authentication</dt><dd>Client Secret Basic</dd></div><div class="wide"><dt>Redirect (Callback) URL</dt><dd><code>{callback}</code></dd></div></dl><p><strong>After Continue:</strong> select <strong>Zone · Read</strong> and <strong>DNS · Edit</strong>. Keep the client <strong>Private</strong> and leave Client URL blank. Cloudflare's “Client URL required” badge only matters if you later make the client public.</p></section><form class="card step" method="post" action="/providers/cloudflare/configure"><input type="hidden" name="csrf" value="{}"><div class="step-head"><span class="step-num">2</span><div><span class="step-label">In HostKnot</span><h2>Paste the generated credentials</h2></div></div><p>Cloudflare shows the client secret once. Copy both values before leaving the page.</p>{credentials_fields}<div class="form-actions"><button type="submit">Save OAuth client</button></div></form>"#,
            escape_html(&csrf)
        )
    };
    Html(app_page(
        "Cloudflare",
        "",
        Nav::Cloudflare,
        &csrf,
        &format!(
            r#"<main class="narrow">{back}<div class="page-head"><div><span class="eyebrow">DNS provider</span><h1>Cloudflare</h1><p>HostKnot manages A and AAAA records in your Cloudflare zones through a private OAuth client.</p></div></div>{status}{flow}</main>"#,
            back = back_link("/", "Bindings"),
        ),
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

#[derive(Deserialize)]
struct ConnectQuery {
    #[serde(default)]
    csrf: String,
}

async fn connect_cloudflare(
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
    Query(query): Query<ConnectQuery>,
) -> Response {
    // Starting authorization can end with a different Cloudflare account's
    // tokens stored, so a cross-site link must not be able to trigger it.
    if let Some(rejection) = require_csrf(&state, &headers, &query.csrf) {
        return rejection;
    }
    let Some(session) = cookie(&headers, state.session_cookie) else {
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
    let Some(csrf) = authenticated_csrf(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let connect = format!("/providers/cloudflare/connect?csrf={}", escape_html(&csrf));
    Html(page_with_head(
        "Continue to Cloudflare",
        &format!(r#"<meta http-equiv="refresh" content="0;url={connect}">"#),
        &views::bare(&notice(
            "info",
            "DNS provider",
            "Opening Cloudflare",
            "If authorization does not open automatically, continue below.",
            &format!(
                r#"<div class="notice-actions"><a class="button" href="{connect}">Authorize with Cloudflare</a></div>"#
            ),
        )),
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
    let Some(session) = cookie(&headers, state.session_cookie) else {
        return Redirect::to("/login").into_response();
    };
    if !state.store.session_valid(session).unwrap_or(false) {
        return Redirect::to("/login").into_response();
    }
    if let Some(error) = query.error {
        let Some(oauth_state) = query.state else {
            return error_page(
                StatusCode::BAD_REQUEST,
                "Cloudflare authorization was cancelled",
                "The response from Cloudflare was incomplete. Start the connection again from the Cloudflare page.",
            );
        };
        if state
            .cloudflare
            .cancel_authorization(&oauth_state, session)
            .is_err()
        {
            return error_page(
                StatusCode::BAD_REQUEST,
                "Cloudflare authorization was cancelled",
                "This authorization attempt is no longer valid. Start the connection again from the Cloudflare page.",
            );
        }
        return error_page(
            StatusCode::BAD_REQUEST,
            "Cloudflare authorization failed",
            &format!("Cloudflare returned: {error}"),
        );
    }
    let (Some(code), Some(oauth_state)) = (query.code, query.state) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Cloudflare authorization failed",
            "The response from Cloudflare was incomplete. Start the connection again from the Cloudflare page.",
        );
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
        Err(_) => error_page(
            StatusCode::BAD_REQUEST,
            "Cloudflare authorization could not be completed",
            "Cloudflare did not accept the authorization. Check the OAuth client settings and try again.",
        ),
    }
}

async fn new_binding_page(State(state): State<Arc<AdminState>>, headers: HeaderMap) -> Response {
    let Some(csrf) = authenticated_csrf(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let ports = discover_listening_ports()
        .into_iter()
        .filter(|port| state.bindings.port_is_bindable(*port))
        .map(|port| format!(r#"<option value="{port}"></option>"#))
        .collect::<String>();
    Html(app_page(
        "New binding",
        "",
        Nav::Bindings,
        &csrf,
        &format!(
            r#"<main class="narrow">{back}<div class="page-head"><div><h1>Bind a domain</h1><p>Route a hostname to a service listening on this server.</p></div></div><form class="card" method="post" action="/bindings"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="replace_existing" value="false"><div class="callout">{ICON_LOCK}<div><strong>Public HTTPS included</strong><span>HostKnot obtains and renews the domain certificate automatically.</span></div></div><label>Hostname<input name="hostname" placeholder="app.example.com" autocomplete="off" autocapitalize="off" spellcheck="false" required autofocus><small class="form-help">The exact domain visitors will use. Its zone must be in your connected Cloudflare account.</small></label><label>Local port<input name="upstream_port" type="number" min="1" max="65535" list="ports" placeholder="3000" required><datalist id="ports">{ports}</datalist><small class="form-help">The loopback port your service listens on — detected listeners are suggested as you type.</small></label><details class="local-options"><summary>Local connection options</summary><label>Local service protocol{protocol}<small class="form-help">Use HTTPS only when the local service itself requires it. Private and self-signed loopback certificates are accepted automatically.</small></label></details><label class="check"><input name="proxied" type="checkbox" value="true" checked> Enable Cloudflare proxy</label><small class="form-help check-help">Serves traffic through Cloudflare’s network and hides this server’s IP; your app still sees the real visitor address. Turn off for direct DNS records.</small><div class="form-actions"><a class="button ghost" href="/">Cancel</a><button type="submit">Bind domain</button></div></form></main>"#,
            back = back_link("/", "Bindings"),
            csrf = escape_html(&csrf),
            protocol = protocol_select("http"),
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
        Err(error) if crate::provider::is_conflict(&error) => {
            let hostname = escape_html(&input.hostname);
            Html(app_page(
                "Confirm DNS replacement",
                "",
                Nav::Bindings,
                &form.csrf,
                &notice(
                    "warn",
                    "DNS conflict",
                    "Replace existing records?",
                    &format!("<strong>{hostname}</strong> already has DNS records. Replace them only if they should point to this server. HostKnot saves them and restores them on unbind."),
                    &format!(
                        r#"<form method="post" action="/bindings"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="hostname" value="{hostname}"><input type="hidden" name="upstream_scheme" value="{}"><input type="hidden" name="upstream_port" value="{}"><input type="hidden" name="proxied" value="{}"><input type="hidden" name="replace_existing" value="true"><a class="button ghost" href="/bindings/new">Cancel</a><button class="danger solid" type="submit">Replace existing records</button></form>"#,
                        escape_html(&form.csrf),
                        escape_html(&input.upstream_scheme),
                        input.upstream_port,
                        input.proxied
                    ),
                ),
            ))
            .into_response_with_status(StatusCode::CONFLICT)
        }
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
    let Some(csrf) = authenticated_csrf(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let Some(binding) = state.store.binding(&id).ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let routes = match state.bindings.list_path_routes(&binding.id) {
        Ok(routes) => routes,
        Err(error) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Couldn't load path routes",
                &error.to_string(),
            );
        }
    };
    Html(binding_edit_page(&binding, &routes, &csrf)).into_response()
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
struct PathRouteForm {
    csrf: String,
    path_prefix: String,
    upstream_scheme: String,
    upstream_port: u16,
}

async fn create_path_route(
    State(state): State<Arc<AdminState>>,
    Path(binding_id): Path<String>,
    headers: HeaderMap,
    Form(form): Form<PathRouteForm>,
) -> Response {
    if let Some(rejection) = require_csrf(&state, &headers, &form.csrf) {
        return rejection;
    }
    match state.bindings.create_path_route(
        &binding_id,
        CreatePathRoute {
            path_prefix: form.path_prefix,
            upstream_scheme: form.upstream_scheme,
            upstream_port: form.upstream_port,
        },
    ) {
        Ok(_) => Redirect::to(&format!("/bindings/{binding_id}/edit")).into_response(),
        Err(error) => error_page(
            StatusCode::BAD_REQUEST,
            "Couldn't add that path route",
            &error.to_string(),
        ),
    }
}

async fn edit_path_route_page(
    State(state): State<Arc<AdminState>>,
    Path((binding_id, route_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let Some(csrf) = authenticated_csrf(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    let Some(binding) = state.store.binding(&binding_id).ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(route) = state.store.path_route(&route_id).ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if route.binding_id != binding.id {
        return StatusCode::NOT_FOUND.into_response();
    }
    Html(app_page(
        "Edit path route",
        "",
        Nav::Bindings,
        &csrf,
        &format!(
            r#"<main class="narrow">{back}<div class="page-head"><div><span class="eyebrow">Path route</span><h1>{path}</h1><p>Requests to <strong>{hostname}</strong> under this prefix go to the service below.</p></div></div><form class="card" method="post" action="/bindings/{binding_id}/routes/{route_id}"><input type="hidden" name="csrf" value="{csrf}"><label>Path prefix<input name="path_prefix" value="{path}" autocomplete="off" spellcheck="false" required><small class="form-help">The complete request path is preserved. Trailing slashes are normalized.</small></label><div class="field-row"><label>Local service protocol{protocol}</label><label>Local port<input name="upstream_port" type="number" min="1" max="65535" value="{port}" required></label></div><div class="form-actions"><a class="button ghost" href="/bindings/{binding_id}/edit">Cancel</a><button type="submit">Save path route</button></div></form></main>"#,
            back = back_link(&format!("/bindings/{}/edit", binding.id), &escape_html(&binding.hostname)),
            hostname = escape_html(&binding.hostname),
            path = escape_html(&route.path_prefix),
            binding_id = binding.id,
            route_id = route.id,
            csrf = escape_html(&csrf),
            protocol = protocol_select(&route.upstream_scheme),
            port = route.upstream_port,
        ),
    ))
    .into_response()
}

async fn update_path_route(
    State(state): State<Arc<AdminState>>,
    Path((binding_id, route_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<PathRouteForm>,
) -> Response {
    if let Some(rejection) = require_csrf(&state, &headers, &form.csrf) {
        return rejection;
    }
    match state.bindings.update_path_route(
        &binding_id,
        &route_id,
        UpdatePathRoute {
            path_prefix: form.path_prefix,
            upstream_scheme: form.upstream_scheme,
            upstream_port: form.upstream_port,
        },
    ) {
        Ok(()) => Redirect::to(&format!("/bindings/{binding_id}/edit")).into_response(),
        Err(error) => error_page(
            StatusCode::BAD_REQUEST,
            "Couldn't update that path route",
            &error.to_string(),
        ),
    }
}

async fn remove_path_route(
    State(state): State<Arc<AdminState>>,
    Path((binding_id, route_id)): Path<(String, String)>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    if let Some(rejection) = require_csrf(&state, &headers, &form.csrf) {
        return rejection;
    }
    match state.bindings.delete_path_route(&binding_id, &route_id) {
        Ok(()) => Redirect::to(&format!("/bindings/{binding_id}/edit")).into_response(),
        Err(error) => error_page(
            StatusCode::BAD_REQUEST,
            "Couldn't remove that path route",
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
