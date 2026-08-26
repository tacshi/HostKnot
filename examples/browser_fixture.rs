//! Runs a real HostKnot process for the Playwright suite, plus a
//! protocol-level fake Cloudflare (OAuth + DNS API) and a live loopback
//! upstream so the browser can exercise the full connect/bind/unbind flow.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Result;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::Redirect,
    routing::{get, post},
};
use hostknot::{CloudflareEndpoints, Config, HostKnot};
use serde_json::{Value, json};
use url::Url;

#[tokio::main]
async fn main() -> Result<()> {
    let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let state = std::env::var_os("HOSTKNOT_BROWSER_STATE")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join(format!("hostknot-browser-{suffix}")));
    let address = std::env::var("HOSTKNOT_BROWSER_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:19443".to_owned())
        .parse()?;

    let upstream_port = spawn_upstream().await?;
    let provider_addr = spawn_fake_cloudflare().await?;

    let config = Config::for_test(&state, address)
        .with_proxy_listeners("127.0.0.1:0".parse()?, "127.0.0.1:0".parse()?)
        .with_public_ips(vec!["203.0.113.10".parse()?])
        .with_drain_duration(Duration::from_secs(2))
        .with_cloudflare_endpoints(CloudflareEndpoints {
            authorization: Url::parse(&format!("http://{provider_addr}/oauth2/auth"))?,
            token: Url::parse(&format!("http://{provider_addr}/oauth2/token"))?,
            api: Url::parse(&format!("http://{provider_addr}/client/v4/"))?,
        });
    let running = HostKnot::start(config).await?;
    if let Some(token) = running.bootstrap_token() {
        println!("http://{}/setup?token={token}", running.admin_addr());
    }
    println!("upstream-port: {upstream_port}");
    tokio::signal::ctrl_c().await?;
    running.shutdown().await;
    Ok(())
}

async fn spawn_upstream() -> Result<u16> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let router = Router::new().route("/", get(|| async { "hello from upstream" }));
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(port)
}

async fn spawn_fake_cloudflare() -> Result<SocketAddr> {
    // Pre-seed a conflicting CNAME so the browser flow can exercise the
    // replacement confirmation interstitial.
    let records = Arc::new(Mutex::new(vec![json!({
        "id": "prior-cname",
        "type": "CNAME",
        "name": "conflict.example.com",
        "content": "old.example.net",
        "proxied": false,
        "ttl": 300,
        "comment": "owned elsewhere"
    })]));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let router = Router::new()
        .route(
            "/oauth2/auth",
            get(
                |Query(query): Query<std::collections::HashMap<String, String>>| async move {
                    // A real Cloudflare consent screen would sit here; the fake
                    // approves immediately and redirects back.
                    Redirect::to(&format!(
                        "{}?code=fixture-code&state={}",
                        query["redirect_uri"], query["state"]
                    ))
                },
            ),
        )
        .route(
            "/oauth2/token",
            post(|| async {
                Json(json!({
                    "access_token": "fixture-access",
                    "refresh_token": "fixture-refresh",
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
                |State(records): State<Arc<Mutex<Vec<Value>>>>,
                 Query(query): Query<std::collections::HashMap<String, String>>| async move {
                    let records = records
                        .lock()
                        .unwrap()
                        .iter()
                        .filter(|record| {
                            query
                                .get("name")
                                .is_none_or(|name| record["name"].as_str() == Some(name))
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    Json(json!({"success": true, "errors": [], "result": records}))
                },
            )
            .post(
                |State(records): State<Arc<Mutex<Vec<Value>>>>,
                 Json(mut record): Json<Value>| async move {
                    let mut records = records.lock().unwrap();
                    record["id"] = json!(format!("record-{}", records.len() + 1));
                    records.push(record.clone());
                    Json(json!({"success": true, "errors": [], "result": record}))
                },
            ),
        )
        .route(
            "/client/v4/zones/{zone}/dns_records/{record}",
            axum::routing::delete(
                |State(records): State<Arc<Mutex<Vec<Value>>>>,
                 Path((_zone, record)): Path<(String, String)>| async move {
                    records.lock().unwrap().retain(|item| item["id"] != record);
                    Json(json!({"success": true, "errors": [], "result": {"id": record}}))
                },
            ),
        )
        .with_state(records);
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Ok(addr)
}
