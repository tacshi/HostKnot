use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
};

use axum::{
    Form, Json, Router,
    extract::{Path, State},
    routing::{get, post},
};
use hostknot::{CloudflareEndpoints, Config, Hostknot};
use reqwest::{Client, StatusCode, redirect::Policy};
use serde_json::json;
use tempfile::TempDir;
use tokio::net::TcpListener;
use url::Url;

#[tokio::test]
async fn cloudflare_oauth_uses_pkce_and_rejects_callback_replay() {
    let token_grants = Arc::new(Mutex::new(Vec::new()));
    let rate_limited = Arc::new(AtomicBool::new(false));
    let fake_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fake_addr = fake_listener.local_addr().unwrap();
    let fake = Router::new()
        .route(
            "/oauth2/token",
            post(|State(grants): State<Arc<Mutex<Vec<String>>>>, Form(form): Form<HashMap<String, String>>| async move {
                let grant = form["grant_type"].clone();
                grants.lock().unwrap().push(grant.clone());
                if grant == "authorization_code" {
                    assert_eq!(form["code"], "valid-code");
                    assert!(form["code_verifier"].len() >= 43);
                    Json(json!({
                        "access_token": "expired-access-token",
                        "refresh_token": "cf-refresh-token",
                        "expires_in": 0,
                        "token_type": "bearer",
                        "scope": "zone.read dns.write offline_access"
                    }))
                } else {
                    assert_eq!(form["refresh_token"], "cf-refresh-token");
                    Json(json!({
                        "access_token": "fresh-access-token",
                        "refresh_token": "rotated-refresh-token",
                        "expires_in": 3600,
                        "token_type": "bearer",
                        "scope": "zone.read dns.write offline_access"
                    }))
                }
            }),
        )
        .route(
            "/client/v4/zones",
            get({
                let rate_limited = rate_limited.clone();
                move |headers: axum::http::HeaderMap| {
                    let rate_limited = rate_limited.clone();
                    async move {
                        use axum::response::IntoResponse;
                        assert_eq!(headers["authorization"], "Bearer fresh-access-token");
                        if !rate_limited.swap(true, Ordering::SeqCst) {
                            return (
                                StatusCode::TOO_MANY_REQUESTS,
                                [("retry-after", "0")],
                                Json(json!({"success": false, "errors": [{"code": 1015, "message": "rate limited"}], "result": []})),
                            ).into_response();
                        }
                        Json(json!({"success": true, "errors": [], "result": [
                            {"id": "zone-1", "name": "example.com"}
                        ]})).into_response()
                    }
                }
            }),
        )
        .route(
            "/client/v4/zones/{zone}/dns_records",
            get(|| async { Json(json!({"success": true, "errors": [], "result": []})) })
                .post(|Path(_zone): Path<String>, Json(record): Json<serde_json::Value>| async move {
                    Json(json!({"success": true, "errors": [], "result": {
                        "id": "record-1", "type": record["type"], "name": record["name"],
                        "content": record["content"], "proxied": record["proxied"],
                        "ttl": 1, "comment": record["comment"]
                    }}))
                }),
        )
        .with_state(token_grants.clone());
    let fake_task = tokio::spawn(async move {
        axum::serve(fake_listener, fake).await.unwrap();
    });

    let state = TempDir::new().unwrap();
    let config = Config::for_test(
        state.path(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
    )
    .with_cloudflare_endpoints(CloudflareEndpoints {
        authorization: Url::parse(&format!("http://{fake_addr}/oauth2/auth")).unwrap(),
        token: Url::parse(&format!("http://{fake_addr}/oauth2/token")).unwrap(),
        api: Url::parse(&format!("http://{fake_addr}/client/v4/")).unwrap(),
    });
    let running = Hostknot::start(config).await.unwrap();
    let base = format!("http://{}", running.admin_addr());
    let client = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let bootstrap = running.bootstrap_token().unwrap();
    client
        .post(format!("{base}/setup"))
        .form(&[
            ("token", bootstrap.as_str()),
            ("password", "correct horse battery staple"),
            ("acme_email", "operator@example.com"),
        ])
        .send()
        .await
        .unwrap();

    let provider_page = client
        .get(format!("{base}/providers/cloudflare"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = hidden_value(&provider_page, "csrf");
    assert!(provider_page.contains("/oauth/cloudflare/callback"));

    let configured = client
        .post(format!("{base}/providers/cloudflare/configure"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("client_id", "private-client-id"),
            ("client_secret", "private-client-secret"),
            ("scopes", "zone.read dns.write offline_access"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(configured.status(), StatusCode::SEE_OTHER);

    let cancelled_connect = client
        .get(format!("{base}/providers/cloudflare/connect"))
        .send()
        .await
        .unwrap();
    let cancelled_authorization =
        Url::parse(cancelled_connect.headers()["location"].to_str().unwrap()).unwrap();
    let cancelled_query: HashMap<_, _> =
        cancelled_authorization.query_pairs().into_owned().collect();
    let cancelled_state = cancelled_query["state"].clone();
    let cancelled = client
        .get(format!(
            "{base}/oauth/cloudflare/callback?error=access_denied&state={cancelled_state}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(cancelled.status(), StatusCode::BAD_REQUEST);
    let cancelled_replay = client
        .get(format!(
            "{base}/oauth/cloudflare/callback?code=valid-code&state={cancelled_state}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(cancelled_replay.status(), StatusCode::BAD_REQUEST);

    let connect = client
        .get(format!("{base}/providers/cloudflare/connect"))
        .send()
        .await
        .unwrap();
    assert_eq!(connect.status(), StatusCode::SEE_OTHER);
    let authorization = Url::parse(connect.headers()["location"].to_str().unwrap()).unwrap();
    let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
    assert_eq!(query["client_id"], "private-client-id");
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["code_challenge_method"], "S256");
    assert!(!query["code_challenge"].is_empty());
    let state_param = query["state"].clone();

    let callback = client
        .get(format!(
            "{base}/oauth/cloudflare/callback?code=valid-code&state={state_param}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(callback.status(), StatusCode::SEE_OTHER);

    let connected = client
        .get(format!("{base}/providers/cloudflare"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(connected.contains("Connected"));

    let replay = client
        .get(format!(
            "{base}/oauth/cloudflare/callback?code=valid-code&state={state_param}"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

    let forged = client
        .get(format!(
            "{base}/oauth/cloudflare/callback?code=valid-code&state=forged-state-value"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), StatusCode::BAD_REQUEST);

    let binding_page = client
        .get(format!("{base}/bindings/new"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let binding_csrf = hidden_value(&binding_page, "csrf");
    let binding = client
        .post(format!("{base}/bindings"))
        .form(&[
            ("csrf", binding_csrf.as_str()),
            ("hostname", "refresh.example.com"),
            ("upstream_scheme", "http"),
            ("upstream_port", "8080"),
            ("proxied", "true"),
            ("insecure_tls", "false"),
            ("replace_existing", "false"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(binding.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        token_grants.lock().unwrap().as_slice(),
        ["authorization_code", "refresh_token"]
    );

    let provider_page = client
        .get(format!("{base}/providers/cloudflare"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let disconnect = client
        .post(format!("{base}/providers/cloudflare/disconnect"))
        .form(&[("csrf", hidden_value(&provider_page, "csrf"))])
        .send()
        .await
        .unwrap();
    assert_eq!(disconnect.status(), StatusCode::CONFLICT);
    assert!(disconnect.text().await.unwrap().contains("active bindings"));

    running.shutdown().await;
    fake_task.abort();
}

fn hidden_value(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let remainder = html.split_once(&marker).expect("hidden input").1;
    remainder.split_once('"').unwrap().0.to_owned()
}
