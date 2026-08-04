use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
    routing::{any, get, post},
};
use futures_util::{SinkExt, StreamExt};
use hostknot::{CloudflareEndpoints, Config, Hostknot};
use reqwest::{Client, StatusCode, redirect::Policy};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use url::Url;

#[tokio::test]
async fn browser_binding_creates_dns_and_routes_exact_host_over_tls() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = upstream_listener.local_addr().unwrap().port();
    let upstream = Router::new()
        .route(
            "/hello",
            any(|headers: HeaderMap| async move {
                format!(
                    "host={};proto={};for={};secret={}",
                    headers["host"].to_str().unwrap(),
                    headers["x-forwarded-proto"].to_str().unwrap(),
                    headers["x-forwarded-for"].to_str().unwrap(),
                    headers
                        .get("x-secret-hop")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("absent")
                )
            }),
        )
        .route(
            "/ws",
            get(|upgrade: axum::extract::WebSocketUpgrade| async move {
                upgrade.on_upgrade(|mut socket| async move {
                    if let Some(Ok(message)) = socket.recv().await {
                        let _ = socket.send(message).await;
                    }
                })
            }),
        )
        .route(
            "/events",
            get(|| async {
                let stream = futures_util::stream::unfold(0_u8, |state| async move {
                    match state {
                        0 => Some((
                            Ok::<_, std::convert::Infallible>(bytes::Bytes::from_static(
                                b"data: first\n\n",
                            )),
                            1,
                        )),
                        1 => {
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            Some((Ok(bytes::Bytes::from_static(b"data: second\n\n")), 2))
                        }
                        _ => None,
                    }
                });
                Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(Body::from_stream(stream))
                    .unwrap()
            }),
        );
    let upstream_task = tokio::spawn(async move {
        axum::serve(upstream_listener, upstream).await.unwrap();
    });
    let updated_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let updated_port = updated_listener.local_addr().unwrap().port();
    let updated_task = tokio::spawn(async move {
        axum::serve(
            updated_listener,
            Router::new()
                .route("/hello", get(|| async { "updated upstream" }))
                .route(
                    "/ws",
                    get(|upgrade: axum::extract::WebSocketUpgrade| async move {
                        upgrade.on_upgrade(|mut socket| async move {
                            if let Some(Ok(message)) = socket.recv().await {
                                let _ = socket.send(message).await;
                            }
                        })
                    }),
                ),
        )
        .await
        .unwrap();
    });
    let (https_upstream_port, https_upstream_task) = tls_upstream().await;

    let created_records = Arc::new(Mutex::new(Vec::<Value>::new()));
    let provider_state = created_records.clone();
    let provider_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_addr = provider_listener.local_addr().unwrap();
    let provider = Router::new()
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
                    "result_info": {"page": 1, "per_page": 50, "count": 1, "total_count": 1, "total_pages": 1}
                }))
            }),
        )
        .route(
            "/client/v4/zones/{zone}/dns_records",
            get(|State(records): State<Arc<Mutex<Vec<Value>>>>, Path(zone): Path<String>, Query(query): Query<HashMap<String, String>>| async move {
                assert_eq!(zone, "zone-1");
                let records = records.lock().unwrap().iter()
                    .filter(|record| query.get("name").is_none_or(|name| record["name"].as_str() == Some(name.as_str())))
                    .cloned().collect::<Vec<_>>();
                Json(json!({"success": true, "errors": [], "result": records}))
            })
            .post(
                |State(records): State<Arc<Mutex<Vec<Value>>>>,
                 Path(zone): Path<String>,
                 Json(record): Json<Value>| async move {
                    assert_eq!(zone, "zone-1");
                    let mut records = records.lock().unwrap();
                    let id = format!("record-{}", records.len() + 1);
                    let mut record = record;
                    record["id"] = json!(id);
                    records.push(record.clone());
                    Json(json!({
                        "success": true,
                        "errors": [],
                        "result": {
                            "id": record["id"],
                            "type": record["type"],
                            "name": record["name"],
                            "content": record["content"],
                            "proxied": record["proxied"],
                            "ttl": 1,
                            "comment": record["comment"]
                        }
                    }))
                },
            ),
        )
        .route(
            "/client/v4/zones/{zone}/dns_records/{record_id}",
            axum::routing::patch(|State(records): State<Arc<Mutex<Vec<Value>>>>, Path((_zone, record_id)): Path<(String, String)>, Json(update): Json<Value>| async move {
                let mut records = records.lock().unwrap();
                let record = records.iter_mut().find(|record| record["id"] == record_id).unwrap();
                record["proxied"] = update["proxied"].clone();
                Json(json!({"success": true, "errors": [], "result": record.clone()}))
            }),
        )
        .with_state(provider_state);
    let provider_task = tokio::spawn(async move {
        axum::serve(provider_listener, provider).await.unwrap();
    });

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
    let running = Hostknot::start(config.clone()).await.unwrap();
    let base = format!("http://{}", running.admin_addr());
    let browser = Client::builder()
        .redirect(Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    initialize_and_connect(&browser, &base, running.bootstrap_token().unwrap()).await;

    let new_page = browser
        .get(format!("{base}/bindings/new"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    let csrf = hidden_value(&new_page, "csrf");
    let create = browser
        .post(format!("{base}/bindings"))
        .form(&[
            ("csrf", csrf.as_str()),
            ("hostname", "app.example.com"),
            ("upstream_scheme", "http"),
            ("upstream_port", &upstream_port.to_string()),
            ("proxied", "true"),
            ("insecure_tls", "false"),
            ("replace_existing", "false"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::SEE_OTHER);

    let dashboard = browser
        .get(&base)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(dashboard.contains("app.example.com"));
    assert!(dashboard.contains("Active"));
    let app_binding_id = data_value(&dashboard, "binding-id");

    {
        let records = created_records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["type"], "A");
        assert_eq!(records[0]["name"], "app.example.com");
        assert_eq!(records[0]["content"], "203.0.113.10");
        assert_eq!(records[0]["proxied"], true);
    }

    let proxy = Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(Policy::none())
        .build()
        .unwrap();
    let proxied = proxy
        .get(format!("https://{}/hello", running.https_addr()))
        .header("host", "app.example.com")
        .header("x-forwarded-for", "spoofed")
        .header("connection", "keep-alive, x-secret-hop")
        .header("x-secret-hop", "hidden")
        .send()
        .await
        .unwrap();
    assert_eq!(proxied.status(), StatusCode::OK);
    let body = proxied.text().await.unwrap();
    assert!(body.contains("host=app.example.com"));
    assert!(body.contains("proto=https"));
    assert!(!body.contains("spoofed"));
    assert!(body.contains("secret=absent"));

    let streaming = proxy
        .get(format!("https://{}/events", running.https_addr()))
        .header("host", "app.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(streaming.headers()["content-type"], "text/event-stream");
    let mut events = streaming.bytes_stream();
    // Generous timeout for loaded CI runners; buffering is still caught
    // because a buffered response would deliver both events in one chunk and
    // fail the equality assertion below.
    let first = tokio::time::timeout(std::time::Duration::from_secs(2), events.next())
        .await
        .expect("first SSE event is streamed without waiting")
        .unwrap()
        .unwrap();
    assert_eq!(first, "data: first\n\n");
    let second = tokio::time::timeout(std::time::Duration::from_secs(5), events.next())
        .await
        .expect("second SSE event is streamed")
        .unwrap()
        .unwrap();
    assert_eq!(second, "data: second\n\n");

    let edit_page = browser
        .get(format!("{base}/bindings/{app_binding_id}/edit"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(edit_page.contains("app.example.com"));
    assert!(!edit_page.contains("name=\"hostname\""));
    let edited = browser
        .post(format!("{base}/bindings/{app_binding_id}"))
        .form(&[
            ("csrf", hidden_value(&edit_page, "csrf")),
            ("upstream_scheme", "http".to_owned()),
            ("upstream_port", updated_port.to_string()),
            ("proxied", "false".to_owned()),
            ("insecure_tls", "false".to_owned()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(edited.status(), StatusCode::SEE_OTHER);
    let updated = proxy
        .get(format!("https://{}/hello", running.https_addr()))
        .header("host", "app.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(updated.text().await.unwrap(), "updated upstream");
    assert_eq!(
        created_records
            .lock()
            .unwrap()
            .iter()
            .find(|record| record["name"] == "app.example.com")
            .unwrap()["proxied"],
        false
    );

    create_binding(
        &browser,
        &base,
        "secure.example.com",
        "https",
        https_upstream_port,
        false,
    )
    .await;
    let secure = proxy
        .get(format!("https://{}/secure", running.https_addr()))
        .header("host", "secure.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(secure.status(), StatusCode::OK);
    assert_eq!(secure.text().await.unwrap(), "secure upstream");

    let unavailable = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unavailable_port = unavailable.local_addr().unwrap().port();
    drop(unavailable);
    create_binding(
        &browser,
        &base,
        "down.example.com",
        "http",
        unavailable_port,
        false,
    )
    .await;
    let failed = proxy
        .get(format!("https://{}/", running.https_addr()))
        .header("host", "down.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(failed.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(failed.text().await.unwrap(), "Upstream unavailable");
    let status_page = browser
        .get(&base)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(status_page.contains("Healthy"));
    assert!(status_page.contains("Degraded"));
    assert!(status_page.contains("HTTP upstream failed"));
    assert!(status_page.contains("Binding activated"));

    let request = format!("wss://{}/ws", running.https_addr())
        .into_client_request()
        .unwrap();
    let (mut websocket, _) = tokio_tungstenite::connect_async_tls_with_config(
        with_host(request, "app.example.com"),
        None,
        false,
        Some(tokio_tungstenite::Connector::Rustls(insecure_tls_client())),
    )
    .await
    .expect("WebSocket upgrade through Hostknot");
    websocket
        .send(tokio_tungstenite::tungstenite::Message::Text("ping".into()))
        .await
        .unwrap();
    assert_eq!(
        websocket
            .next()
            .await
            .unwrap()
            .unwrap()
            .into_text()
            .unwrap(),
        "ping"
    );

    let redirect = proxy
        .get(format!("http://{}/hello", running.http_addr()))
        .header("host", "app.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(redirect.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(
        redirect.headers()["location"],
        "https://app.example.com/hello"
    );

    let unknown = proxy
        .get(format!("https://{}/", running.https_addr()))
        .header("host", "unknown.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    let certificate_before_restart =
        peer_certificate(running.https_addr(), "app.example.com").await;
    running.shutdown().await;
    let restarted = Hostknot::start(config).await.unwrap();
    assert!(restarted.bootstrap_token().is_none());
    let certificate_after_restart =
        peer_certificate(restarted.https_addr(), "app.example.com").await;
    assert_eq!(certificate_after_restart, certificate_before_restart);
    let after_restart = proxy
        .get(format!("https://{}/hello", restarted.https_addr()))
        .header("host", "app.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(after_restart.status(), StatusCode::OK);
    restarted.shutdown().await;
    provider_task.abort();
    upstream_task.abort();
    updated_task.abort();
    https_upstream_task.abort();
}

async fn peer_certificate(address: std::net::SocketAddr, server_name: &str) -> Vec<u8> {
    let connector = tokio_rustls::TlsConnector::from(insecure_tls_client());
    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from(server_name.to_owned()).unwrap();
    let stream = connector.connect(name, socket).await.unwrap();
    stream
        .get_ref()
        .1
        .peer_certificates()
        .unwrap()
        .first()
        .unwrap()
        .as_ref()
        .to_vec()
}

async fn create_binding(
    browser: &Client,
    base: &str,
    hostname: &str,
    scheme: &str,
    port: u16,
    insecure_tls: bool,
) {
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
            ("upstream_scheme", scheme.to_owned()),
            ("upstream_port", port.to_string()),
            ("proxied", "true".to_owned()),
            ("insecure_tls", insecure_tls.to_string()),
            ("replace_existing", "false".to_owned()),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
}

async fn tls_upstream() -> (u16, tokio::task::JoinHandle<()>) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(["127.0.0.1".to_owned()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
        signing_key.serialize_der(),
    ));
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let router = Router::new().route("/secure", get(|| async { "secure upstream" }));
    let task = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let service = router.clone();
            tokio::spawn(async move {
                use hyper_util::{
                    rt::{TokioExecutor, TokioIo},
                    server::conn::auto::Builder,
                    service::TowerToHyperService,
                };
                let stream = acceptor.accept(socket).await.unwrap();
                let builder = Builder::new(TokioExecutor::new());
                builder
                    .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service))
                    .await
                    .unwrap();
            });
        }
    });
    (port, task)
}

use tokio_tungstenite::tungstenite::client::IntoClientRequest;

fn with_host(
    mut request: tokio_tungstenite::tungstenite::http::Request<()>,
    host: &str,
) -> tokio_tungstenite::tungstenite::http::Request<()> {
    request.headers_mut().insert("host", host.parse().unwrap());
    request
}

fn insecure_tls_client() -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth(),
    )
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
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
