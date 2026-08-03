use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode as AxumStatus,
    routing::{delete, get, post},
};
use hostknot::{CloudflareEndpoints, Config, Hostknot};
use reqwest::{Client, StatusCode, redirect::Policy};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use url::Url;

#[derive(Clone)]
struct FakeDns {
    records: Arc<Mutex<Vec<Value>>>,
}

#[tokio::test]
async fn conflicting_dns_requires_confirmation_and_is_restored_on_unbind() {
    let prior = json!({
        "id": "prior-cname",
        "type": "CNAME",
        "name": "app.example.com",
        "content": "old.example.net",
        "proxied": false,
        "ttl": 300,
        "comment": "owned elsewhere"
    });
    let dns = FakeDns {
        records: Arc::new(Mutex::new(vec![prior.clone()])),
    };
    let provider_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_addr = provider_listener.local_addr().unwrap();
    let provider = fake_provider_router(dns.clone());
    let provider_task = tokio::spawn(async move {
        axum::serve(provider_listener, provider).await.unwrap();
    });

    let state = TempDir::new().unwrap();
    let config = Config::for_test(state.path(), "127.0.0.1:0".parse().unwrap())
        .with_public_ips(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))])
        .with_drain_duration(Duration::from_millis(200))
        .with_cloudflare_endpoints(CloudflareEndpoints {
            authorization: Url::parse(&format!("http://{provider_addr}/oauth2/auth")).unwrap(),
            token: Url::parse(&format!("http://{provider_addr}/oauth2/token")).unwrap(),
            api: Url::parse(&format!("http://{provider_addr}/client/v4/")).unwrap(),
        });
    let running = Hostknot::start(config.clone()).await.unwrap();
    let base = format!("http://{}", running.admin_addr());
    let browser = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    initialize_and_connect(&browser, &base, running.bootstrap_token().unwrap()).await;
    let csrf = binding_csrf(&browser, &base).await;

    let conflict = create_binding(&browser, &base, &csrf, false).await;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let conflict_page = conflict.text().await.unwrap();
    assert!(conflict_page.contains("Replace existing records"));
    assert_eq!(
        dns.records.lock().unwrap().as_slice(),
        std::slice::from_ref(&prior)
    );

    let replaced = create_binding(&browser, &base, &csrf, true).await;
    assert_eq!(replaced.status(), StatusCode::SEE_OTHER);
    let active = dns.records.lock().unwrap().clone();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0]["type"], "A");

    let dashboard = browser
        .get(&base)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let binding_id = data_value(&dashboard, "binding-id");
    let remove_csrf = hidden_value(&dashboard, "csrf");
    let remove = browser
        .post(format!("{base}/bindings/{binding_id}/remove"))
        .form(&[("csrf", remove_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(remove.status(), StatusCode::SEE_OTHER);
    assert_eq!(dns.records.lock().unwrap().len(), 1);
    assert_eq!(dns.records.lock().unwrap()[0]["type"], "CNAME");
    assert_eq!(dns.records.lock().unwrap()[0]["content"], "old.example.net");

    running.shutdown().await;
    let restarted = Hostknot::start(config).await.unwrap();
    let base = format!("http://{}", restarted.admin_addr());
    let mut dashboard = String::new();
    for _ in 0..40 {
        let response = browser.get(&base).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        dashboard = response.text().await.unwrap();
        if !dashboard.contains("data-binding-id") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The drained binding is gone from an authenticated dashboard — not from
    // a login redirect or error page.
    assert!(dashboard.contains("Domain bindings"));
    assert!(!dashboard.contains("data-binding-id"));

    restarted.shutdown().await;
    provider_task.abort();
}

fn fake_provider_router(dns: FakeDns) -> Router {
    Router::new()
        .route(
            "/oauth2/token",
            post(|| async {
                Json(json!({
                    "access_token":"access", "refresh_token":"refresh",
                    "expires_in":3600, "scope":"zone.read dns.write offline_access"
                }))
            }),
        )
        .route(
            "/client/v4/zones",
            get(|| async {
                Json(json!({
                    "success":true,"errors":[],
                    "result":[{"id":"zone-1","name":"example.com","status":"active"}],
                    "result_info":{"total_pages":1}
                }))
            }),
        )
        .route(
            "/client/v4/zones/{zone}/dns_records",
            get(|State(dns): State<FakeDns>| async move {
                Json(json!({"success":true,"errors":[],"result":dns.records.lock().unwrap().clone()}))
            })
            .post(
                |State(dns): State<FakeDns>, Json(mut record): Json<Value>| async move {
                    let id = format!("created-{}", dns.records.lock().unwrap().len() + 1);
                    record["id"] = json!(id);
                    dns.records.lock().unwrap().push(record.clone());
                    Json(json!({"success":true,"errors":[],"result":record}))
                },
            ),
        )
        .route(
            "/client/v4/zones/{zone}/dns_records/{record}",
            delete(
                |State(dns): State<FakeDns>, Path((_zone, record)): Path<(String, String)>| async move {
                    let mut records = dns.records.lock().unwrap();
                    let before = records.len();
                    records.retain(|item| item["id"] != record);
                    if records.len() == before {
                        return (AxumStatus::NOT_FOUND, Json(json!({"success":false})));
                    }
                    (AxumStatus::OK, Json(json!({"success":true,"result":{"id":record}})))
                },
            ),
        )
        .with_state(dns)
}

#[tokio::test]
async fn external_drift_blocks_unbind_and_recovers_when_restored() {
    let dns = FakeDns {
        records: Arc::new(Mutex::new(Vec::new())),
    };
    let provider_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_addr = provider_listener.local_addr().unwrap();
    let provider = fake_provider_router(dns.clone());
    let provider_task = tokio::spawn(async move {
        axum::serve(provider_listener, provider).await.unwrap();
    });

    let state = TempDir::new().unwrap();
    let config = Config::for_test(state.path(), "127.0.0.1:0".parse().unwrap())
        .with_public_ips(vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))])
        .with_drain_duration(Duration::from_millis(100))
        .with_cloudflare_endpoints(CloudflareEndpoints {
            authorization: Url::parse(&format!("http://{provider_addr}/oauth2/auth")).unwrap(),
            token: Url::parse(&format!("http://{provider_addr}/oauth2/token")).unwrap(),
            api: Url::parse(&format!("http://{provider_addr}/client/v4/")).unwrap(),
        });
    let running = Hostknot::start(config).await.unwrap();
    let base = format!("http://{}", running.admin_addr());
    let browser = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    initialize_and_connect(&browser, &base, running.bootstrap_token().unwrap()).await;
    let csrf = binding_csrf(&browser, &base).await;
    let created = create_binding(&browser, &base, &csrf, false).await;
    assert_eq!(created.status(), StatusCode::SEE_OTHER);

    // Simulate external tampering: the managed A record changes outside
    // Hostknot's control.
    let managed_id = {
        let mut records = dns.records.lock().unwrap();
        let record = records
            .iter_mut()
            .find(|record| record["type"] == "A")
            .expect("managed A record");
        record["content"] = json!("198.51.100.99");
        record["id"].as_str().unwrap().to_owned()
    };

    let dashboard = browser
        .get(&base)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let binding_id = data_value(&dashboard, "binding-id");
    let remove_csrf = hidden_value(&dashboard, "csrf");
    let drifted = browser
        .post(format!("{base}/bindings/{binding_id}/remove"))
        .form(&[("csrf", remove_csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(drifted.status(), StatusCode::CONFLICT);
    assert!(drifted.text().await.unwrap().contains("drift"));
    // The tampered external record must not have been touched.
    assert_eq!(
        dns.records
            .lock()
            .unwrap()
            .iter()
            .find(|record| record["id"] == managed_id.as_str())
            .unwrap()["content"],
        "198.51.100.99"
    );
    let status_page = browser
        .get(&base)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(status_page.contains("Drifted"));

    // Restore the record externally: reconciliation retries the revert and
    // finishes the removal on its own.
    dns.records
        .lock()
        .unwrap()
        .iter_mut()
        .find(|record| record["id"] == managed_id.as_str())
        .unwrap()["content"] = json!("203.0.113.10");
    let mut dashboard = String::new();
    for _ in 0..100 {
        let response = browser.get(&base).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        dashboard = response.text().await.unwrap();
        if !dashboard.contains("data-binding-id") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(dashboard.contains("Domain bindings"));
    assert!(!dashboard.contains("data-binding-id"));
    assert!(
        dns.records
            .lock()
            .unwrap()
            .iter()
            .all(|record| record["type"] != "A"),
        "the managed record is removed once drift is resolved"
    );

    running.shutdown().await;
    provider_task.abort();
}

async fn create_binding(
    client: &Client,
    base: &str,
    csrf: &str,
    replace: bool,
) -> reqwest::Response {
    client
        .post(format!("{base}/bindings"))
        .form(&[
            ("csrf", csrf),
            ("hostname", "app.example.com"),
            ("upstream_scheme", "http"),
            ("upstream_port", "8080"),
            ("proxied", "true"),
            ("insecure_tls", "false"),
            ("replace_existing", if replace { "true" } else { "false" }),
        ])
        .send()
        .await
        .unwrap()
}

async fn binding_csrf(client: &Client, base: &str) -> String {
    let page = client
        .get(format!("{base}/bindings/new"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    hidden_value(&page, "csrf")
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
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0
        .to_owned()
}

fn data_value(html: &str, name: &str) -> String {
    let marker = format!("data-{name}=\"");
    html.split_once(&marker)
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0
        .to_owned()
}
