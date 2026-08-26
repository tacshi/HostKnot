use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::State,
    http::HeaderMap,
    routing::{any, get, post},
};
use hostknot::{CloudflareEndpoints, Config, HostKnot};
use reqwest::{Client, StatusCode, redirect::Policy};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use url::Url;

/// Browsers negotiate HTTP/2 over TLS and carry the host in :authority instead
/// of a Host header; routing must work for them, and the upstream hop must be
/// downgraded to HTTP/1.1.
#[tokio::test]
async fn http2_requests_route_by_authority_and_reach_http1_upstreams() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream_listener.local_addr().unwrap().port();
    let upstream = Router::new().route(
        "/hello",
        any(|headers: HeaderMap| async move {
            format!(
                "host={};upgrade={}",
                headers["host"].to_str().unwrap(),
                headers
                    .get("upgrade")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("absent"),
            )
        }),
    );
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream).await.unwrap();
    });

    let (provider_addr, provider_task) = fake_cloudflare().await;
    let state = TempDir::new().unwrap();
    let config = Config::for_test(state.path(), "127.0.0.1:0".parse().unwrap())
        .with_proxy_listeners(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .with_public_ips(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))])
        .with_cloudflare_endpoints(CloudflareEndpoints {
            authorization: Url::parse(&format!("http://{provider_addr}/oauth2/auth")).unwrap(),
            token: Url::parse(&format!("http://{provider_addr}/oauth2/token")).unwrap(),
            api: Url::parse(&format!("http://{provider_addr}/client/v4/")).unwrap(),
        });
    let running = HostKnot::start(config).await.unwrap();
    let base = format!("http://{}", running.admin_addr());
    let browser = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    initialize_and_connect(&browser, &base, running.bootstrap_token().unwrap()).await;
    create_binding(&browser, &base, "app.example.com", upstream_port).await;

    // resolve() pins the hostname to the local proxy listener, so the request
    // carries app.example.com in :authority (h2) with no Host header.
    let https_addr = running.https_addr();
    let h2_client = Client::builder()
        .danger_accept_invalid_certs(true)
        .resolve("app.example.com", https_addr)
        .build()
        .unwrap();
    let response = h2_client
        .get(format!(
            "https://app.example.com:{}/hello",
            https_addr.port()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .contains("host=app.example.com")
    );

    // A websocket-style request that the upstream answers with a plain 200 must
    // not come back with hop-by-hop upgrade headers re-attached.
    let h1_client = Client::builder()
        .danger_accept_invalid_certs(true)
        .http1_only()
        .build()
        .unwrap();
    let not_upgraded = h1_client
        .get(format!("https://{https_addr}/hello"))
        .header("host", "app.example.com")
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .send()
        .await
        .unwrap();
    assert_eq!(not_upgraded.status(), StatusCode::OK);
    assert!(not_upgraded.headers().get("upgrade").is_none());
    assert!(
        not_upgraded
            .headers()
            .get("connection")
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| !value.to_ascii_lowercase().contains("upgrade"))
    );

    running.shutdown().await;
    provider_task.abort();
    upstream_task.abort();
}

async fn fake_cloudflare() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let records = Arc::new(Mutex::new(Vec::<Value>::new()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new()
        .route(
            "/oauth2/token",
            post(|| async {
                Json(json!({
                    "access_token": "access",
                    "refresh_token": "refresh",
                    "expires_in": 3600,
                    "scope": "zone.read dns.write offline_access"
                }))
            }),
        )
        .route(
            "/client/v4/zones",
            get(|| async {
                Json(json!({
                    "success": true,
                    "errors": [],
                    "result": [{"id": "zone-1", "name": "example.com", "status": "active"}],
                    "result_info": {"total_pages": 1}
                }))
            }),
        )
        .route(
            "/client/v4/zones/{zone}/dns_records",
            get(
                |State(records): State<Arc<Mutex<Vec<Value>>>>| async move {
                    Json(
                        json!({"success": true, "errors": [], "result": records.lock().unwrap().clone()}),
                    )
                },
            )
            .post(
                |State(records): State<Arc<Mutex<Vec<Value>>>>, Json(mut record): Json<Value>| async move {
                    let mut records = records.lock().unwrap();
                    record["id"] = json!(format!("record-{}", records.len() + 1));
                    records.push(record.clone());
                    Json(json!({"success": true, "errors": [], "result": record}))
                },
            ),
        )
        .with_state(records);
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (addr, task)
}

async fn create_binding(browser: &Client, base: &str, hostname: &str, port: u16) {
    let page = browser
        .get(format!("{base}/bindings/new"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let response = browser
        .post(format!("{base}/bindings"))
        .form(&[
            ("csrf", hidden_value(&page, "csrf")),
            ("hostname", hostname.to_owned()),
            ("upstream_scheme", "http".to_owned()),
            ("upstream_port", port.to_string()),
            ("proxied", "true".to_owned()),
            ("replace_existing", "false".to_owned()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

async fn initialize_and_connect(client: &Client, base: &str, bootstrap: String) {
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
    let provider = client
        .get(format!("{base}/providers/cloudflare"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = hidden_value(&provider, "csrf");
    client
        .post(format!("{base}/providers/cloudflare/configure"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("client_id", "client"),
            ("client_secret", "secret"),
            ("scopes", "zone.read dns.write offline_access"),
        ])
        .send()
        .await
        .unwrap();
    let connect = client
        .get(format!("{base}/providers/cloudflare/connect"))
        .send()
        .await
        .unwrap();
    let authorization = Url::parse(connect.headers()["location"].to_str().unwrap()).unwrap();
    let query: HashMap<_, _> = authorization.query_pairs().into_owned().collect();
    client
        .get(format!(
            "{base}/oauth/cloudflare/callback?code=code&state={}",
            query["state"]
        ))
        .send()
        .await
        .unwrap();
}

fn hidden_value(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    html.split_once(&marker)
        .expect("hidden input")
        .1
        .split_once('"')
        .unwrap()
        .0
        .to_owned()
}
