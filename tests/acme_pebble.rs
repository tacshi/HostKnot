use std::{
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use hostknot::{AcmeConfig, CertificateMode, Clock, Config, Hostknot};
use reqwest::{Certificate, Client, StatusCode, redirect::Policy};
use tempfile::TempDir;

/// Run with a Pebble directory whose HTTP-01 validation port matches
/// `HOSTKNOT_PEBBLE_HTTP_LISTEN`, for example `127.0.0.1:5002`.
#[tokio::test]
#[ignore = "requires a running Pebble ACME server"]
async fn pebble_issues_persists_and_renews_the_admin_ip_certificate() {
    let directory =
        std::env::var("HOSTKNOT_PEBBLE_DIRECTORY").expect("set HOSTKNOT_PEBBLE_DIRECTORY");
    let root =
        PathBuf::from(std::env::var("HOSTKNOT_PEBBLE_ROOT").expect("set HOSTKNOT_PEBBLE_ROOT"));
    let http_listen = std::env::var("HOSTKNOT_PEBBLE_HTTP_LISTEN")
        .expect("set HOSTKNOT_PEBBLE_HTTP_LISTEN")
        .parse()
        .unwrap();
    let clock = Clock::system();
    let state = TempDir::new().unwrap();
    let mut config = Config::for_test(state.path(), "127.0.0.1:0".parse().unwrap())
        .with_proxy_listeners(http_listen, "127.0.0.1:0".parse().unwrap())
        .with_public_ips(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
        .with_certificate_mode(CertificateMode::Acme(AcmeConfig {
            directory_url: directory,
            root_certificate: Some(root.clone()),
        }))
        .with_admin_tls(true)
        .with_clock(clock.clone())
        .with_renewal_check_interval(std::time::Duration::from_millis(500));
    config.secure_admin_cookies = true;

    let running = Hostknot::start(config.clone()).await.unwrap();
    let root_pem = std::fs::read(&root).unwrap();
    let management = std::env::var("HOSTKNOT_PEBBLE_MANAGEMENT")
        .unwrap_or_else(|_| "https://localhost:15000".to_owned());
    let issuer_root = Client::builder()
        .add_root_certificate(Certificate::from_pem(&root_pem).unwrap())
        .build()
        .unwrap()
        .get(format!("{management}/roots/0"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let client = Client::builder()
        .add_root_certificate(Certificate::from_pem(&issuer_root).unwrap())
        .redirect(Policy::none())
        .build()
        .unwrap();
    let response = client
        .get(format!("https://{}/", running.admin_addr()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let certificate_before_restart = peer_certificate(running.admin_addr()).await;
    running.shutdown().await;

    let restarted = Hostknot::start(config).await.unwrap();
    assert!(restarted.bootstrap_token().is_some());
    // The certificate must be restored from the store, not silently re-issued.
    assert_eq!(
        peer_certificate(restarted.admin_addr()).await,
        certificate_before_restart
    );

    // Renewal: jump past renew_at (and not_after — Pebble certs are short) and
    // wait for the renewal loop to obtain a fresh certificate automatically.
    clock.advance(30 * 24 * 60 * 60);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let renewed = loop {
        let current = peer_certificate(restarted.admin_addr()).await;
        if current != certificate_before_restart {
            break current;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "certificate was never renewed after its renewal time passed"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    };
    assert_ne!(renewed, certificate_before_restart);
    // The renewed certificate chain still verifies against the ACME issuer.
    let after_renewal = client
        .get(format!("https://{}/", restarted.admin_addr()))
        .send()
        .await
        .unwrap();
    assert_eq!(after_renewal.status(), StatusCode::SEE_OTHER);
    restarted.shutdown().await;
}

async fn peer_certificate(address: std::net::SocketAddr) -> Vec<u8> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(TrustAnyCertificate))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
    let socket = tokio::net::TcpStream::connect(address).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from(address.ip().to_string()).unwrap();
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

#[derive(Debug)]
struct TrustAnyCertificate;

impl rustls::client::danger::ServerCertVerifier for TrustAnyCertificate {
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
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }
}
