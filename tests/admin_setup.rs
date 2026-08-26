use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use hostknot::{Clock, Config, HostKnot, RunningHostKnot};
use reqwest::{Client, StatusCode, redirect::Policy};
use tempfile::TempDir;

#[tokio::test]
async fn bootstrap_token_creates_the_administrator_once() {
    let state = TempDir::new().expect("temporary state directory");
    let running = HostKnot::start(Config::for_test(
        state.path(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    ))
    .await
    .expect("start HostKnot");
    let token = running
        .bootstrap_token()
        .expect("fresh installations have a bootstrap token");
    let base = format!("http://{}", running.admin_addr());
    let client = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .expect("HTTP client");

    let setup_page = client
        .get(format!("{base}/setup?token={token}"))
        .send()
        .await
        .expect("setup page");
    assert_eq!(setup_page.status(), StatusCode::OK);
    assert!(
        setup_page
            .text()
            .await
            .unwrap()
            .contains("Create administrator")
    );

    let setup = client
        .post(format!("{base}/setup"))
        .form(&[
            ("token", token.as_str()),
            ("password", "correct horse battery staple"),
            ("acme_email", "operator@example.com"),
        ])
        .send()
        .await
        .expect("submit setup");
    assert_eq!(setup.status(), StatusCode::SEE_OTHER);
    assert_eq!(setup.headers()["location"], "/");

    let dashboard = client.get(&base).send().await.expect("dashboard");
    assert_eq!(dashboard.status(), StatusCode::OK);
    assert!(dashboard.text().await.unwrap().contains("Domain bindings"));

    let reused = Client::new()
        .post(format!("{base}/setup"))
        .form(&[
            ("token", token.as_str()),
            ("password", "another sufficiently long password"),
            ("acme_email", "attacker@example.com"),
        ])
        .send()
        .await
        .expect("reuse setup token");
    assert_eq!(reused.status(), StatusCode::FORBIDDEN);

    running.shutdown().await;
}

#[tokio::test]
async fn csrf_origin_policy_accepts_local_navigation_and_rejects_cross_site_posts() {
    let (_state, running, base, client) = configured_admin(Clock::system()).await;
    let provider_page = client
        .get(format!("{base}/providers/cloudflare"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = hidden_value(&provider_page, "csrf");
    let cross_origin = client
        .post(format!("{base}/providers/cloudflare/configure"))
        .header("origin", "https://attacker.invalid")
        .form(&[
            ("csrf", csrf.as_str()),
            ("client_id", "client"),
            ("client_secret", "secret"),
            ("scopes", "zone.read dns.write offline_access"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(cross_origin.status(), StatusCode::FORBIDDEN);

    // Safari with a restrictive referrer policy: same-origin form POSTs carry
    // "Origin: null" and no Sec-Fetch-Site header. The CSRF token is the
    // gate; a null origin alone must not reject the request.
    let null_origin = client
        .post(format!("{base}/providers/cloudflare/configure"))
        .header("origin", "null")
        .form(&[
            ("csrf", csrf.as_str()),
            ("client_id", "client"),
            ("client_secret", "secret"),
            ("scopes", "zone.read dns.write offline_access"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(null_origin.status(), StatusCode::SEE_OTHER);

    // Browsing the admin UI by an address that differs from the configured
    // admin_public_url (NAT, alias, stale config) must still work: the
    // origin check is self-consistent against the request's own Host.
    let alias_origin = client
        .post(format!("{base}/providers/cloudflare/configure"))
        .header("origin", "http://vps-alias.example:9443")
        .header("host", "vps-alias.example:9443")
        .form(&[
            ("csrf", csrf.as_str()),
            ("client_id", "client"),
            ("client_secret", "secret"),
            ("scopes", "zone.read dns.write offline_access"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(alias_origin.status(), StatusCode::SEE_OTHER);

    // But a null origin that Sec-Fetch-Site positively marks as cross-site
    // is still rejected.
    let null_cross_site = client
        .post(format!("{base}/providers/cloudflare/configure"))
        .header("origin", "null")
        .header("sec-fetch-site", "cross-site")
        .form(&[
            ("csrf", csrf.as_str()),
            ("client_id", "client"),
            ("client_secret", "secret"),
            ("scopes", "zone.read dns.write offline_access"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(null_cross_site.status(), StatusCode::FORBIDDEN);

    running.shutdown().await;
}

#[tokio::test]
async fn logout_invalidates_the_session_and_failed_logins_are_throttled() {
    let (_state, running, base, client) = configured_admin(Clock::system()).await;
    let provider_page = client
        .get(format!("{base}/providers/cloudflare"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = hidden_value(&provider_page, "csrf");
    let logout = client
        .post(format!("{base}/logout"))
        .form(&[("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::SEE_OTHER);
    assert_eq!(logout.headers()["location"], "/login");
    let logged_out = client.get(&base).send().await.unwrap();
    assert_eq!(logged_out.status(), StatusCode::SEE_OTHER);
    assert_eq!(logged_out.headers()["location"], "/login");

    let unauthenticated = Client::new();
    for _ in 0..5 {
        let response = unauthenticated
            .post(format!("{base}/login"))
            .form(&[("password", "wrong password")])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let throttled = unauthenticated
        .post(format!("{base}/login"))
        .form(&[("password", "wrong password")])
        .send()
        .await
        .unwrap();
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(throttled.headers().contains_key("retry-after"));

    running.shutdown().await;
}

#[tokio::test]
async fn admin_reset_invalidates_sessions_and_issues_a_new_setup_token() {
    let state = TempDir::new().unwrap();
    let config = Config::for_test(
        state.path(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    );
    let running = HostKnot::start(config).await.unwrap();
    let token = running.bootstrap_token().unwrap();
    let base = format!("http://{}", running.admin_addr());
    let client = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let setup = client
        .post(format!("{base}/setup"))
        .form(&[
            ("token", token.as_str()),
            ("password", "correct horse battery staple"),
            ("acme_email", "operator@example.com"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(setup.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        client.get(&base).send().await.unwrap().status(),
        StatusCode::OK
    );

    // `hostknot admin reset` runs against the live service's state directory,
    // exactly like the CLI on a VPS.
    let reset_token = HostKnot::reset_admin(state.path()).expect("reset administrator");
    assert_ne!(reset_token, token);

    // The pre-reset session cookie must no longer authenticate.
    let stale_session = client.get(&base).send().await.unwrap();
    assert_eq!(stale_session.status(), StatusCode::SEE_OTHER);
    assert_eq!(stale_session.headers()["location"], "/setup");

    // The reset token completes a fresh setup with a new password.
    let fresh = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let redo_setup = fresh
        .post(format!("{base}/setup"))
        .form(&[
            ("token", reset_token.as_str()),
            ("password", "a brand new admin password"),
            ("acme_email", "operator@example.com"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(redo_setup.status(), StatusCode::SEE_OTHER);
    let dashboard = fresh.get(&base).send().await.unwrap();
    assert_eq!(dashboard.status(), StatusCode::OK);
    assert!(dashboard.text().await.unwrap().contains("Domain bindings"));
    running.shutdown().await;
}

#[tokio::test]
async fn bootstrap_tokens_expire_and_restart_issues_a_fresh_one() {
    let clock = Clock::system();
    let state = TempDir::new().unwrap();
    let config = Config::for_test(
        state.path(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .with_clock(clock.clone());
    let running = HostKnot::start(config.clone()).await.unwrap();
    let stale_token = running.bootstrap_token().unwrap();
    let base = format!("http://{}", running.admin_addr());
    let client = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();

    // Bootstrap tokens printed to the journal expire after one hour.
    clock.advance(60 * 60 + 1);
    let expired_setup = client
        .post(format!("{base}/setup"))
        .form(&[
            ("token", stale_token.as_str()),
            ("password", "correct horse battery staple"),
            ("acme_email", "operator@example.com"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(expired_setup.status(), StatusCode::FORBIDDEN);

    // A restart issues a fresh token, which works.
    running.shutdown().await;
    let running = HostKnot::start(config).await.unwrap();
    let base = format!("http://{}", running.admin_addr());
    let token = running.bootstrap_token().unwrap();
    let setup = client
        .post(format!("{base}/setup"))
        .form(&[
            ("token", token.as_str()),
            ("password", "correct horse battery staple"),
            ("acme_email", "operator@example.com"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(setup.status(), StatusCode::SEE_OTHER);

    running.shutdown().await;
}

#[tokio::test]
async fn login_throttling_releases_after_its_window() {
    let clock = Clock::system();
    let (_state, running, base, _client) = configured_admin(clock.clone()).await;
    let attacker = Client::new();
    for _ in 0..5 {
        attacker
            .post(format!("{base}/login"))
            .form(&[("password", "wrong password")])
            .send()
            .await
            .unwrap();
    }
    let throttled = attacker
        .post(format!("{base}/login"))
        .form(&[("password", "wrong password")])
        .send()
        .await
        .unwrap();
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    clock.advance(5 * 60 + 1);
    let released = attacker
        .post(format!("{base}/login"))
        .form(&[("password", "wrong password")])
        .send()
        .await
        .unwrap();
    assert_eq!(released.status(), StatusCode::UNAUTHORIZED);

    running.shutdown().await;
}

#[tokio::test]
async fn hostknot_listener_ports_cannot_be_bound_as_upstreams() {
    let (_state, running, base, client) = configured_admin(Clock::system()).await;
    let bindings_page = client
        .get(format!("{base}/bindings/new"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let admin_port = base.rsplit(':').next().unwrap().to_owned();
    let own_port = client
        .post(format!("{base}/bindings"))
        .form(&[
            ("csrf", hidden_value(&bindings_page, "csrf").as_str()),
            ("hostname", "admin.example.com"),
            ("upstream_scheme", "http"),
            ("upstream_port", &admin_port),
            ("proxied", "true"),
            ("replace_existing", "false"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(own_port.status(), StatusCode::BAD_REQUEST);
    let body = own_port.text().await.unwrap();
    assert!(body.contains("own listeners"));
    assert!(body.contains("admin UI"));

    running.shutdown().await;
}

#[tokio::test]
async fn expired_sessions_redirect_reads_and_mutations_to_login() {
    let clock = Clock::system();
    let (_state, running, base, client) = configured_admin(clock.clone()).await;
    let bindings_page = client
        .get(format!("{base}/bindings/new"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        client.get(&base).send().await.unwrap().status(),
        StatusCode::OK
    );
    clock.advance(12 * 60 * 60 + 1);
    let expired_session = client.get(&base).send().await.unwrap();
    assert_eq!(expired_session.status(), StatusCode::SEE_OTHER);
    assert_eq!(expired_session.headers()["location"], "/login");

    // A mutating POST with an expired session redirects to login instead of
    // dead-ending on a CSRF error.
    let expired_post = client
        .post(format!("{base}/bindings"))
        .form(&[
            ("csrf", hidden_value(&bindings_page, "csrf").as_str()),
            ("hostname", "app.example.com"),
            ("upstream_scheme", "http"),
            ("upstream_port", "8080"),
            ("proxied", "true"),
            ("replace_existing", "false"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(expired_post.status(), StatusCode::SEE_OTHER);
    assert_eq!(expired_post.headers()["location"], "/login");

    running.shutdown().await;
}

async fn configured_admin(clock: Clock) -> (TempDir, RunningHostKnot, String, Client) {
    let state = TempDir::new().unwrap();
    let config = Config::for_test(
        state.path(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .with_clock(clock);
    let running = HostKnot::start(config).await.unwrap();
    let base = format!("http://{}", running.admin_addr());
    let client = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let token = running.bootstrap_token().unwrap();
    let setup = client
        .post(format!("{base}/setup"))
        .form(&[
            ("token", token.as_str()),
            ("password", "correct horse battery staple"),
            ("acme_email", "operator@example.com"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(setup.status(), StatusCode::SEE_OTHER);
    (state, running, base, client)
}

fn hidden_value(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    html.split_once(&marker)
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0
        .to_owned()
}
