use std::{
    collections::HashMap,
    fmt,
    io::{BufReader, Cursor},
    net::IpAddr,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use anyhow::{Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, CertificateIdentifier, ChallengeType,
    Identifier, NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rand::Rng;
use rcgen::generate_simple_self_signed;
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use sha2::{Digest, Sha256};

use crate::{clock::Clock, store::Store};

pub struct CertificateResolver {
    certificates: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    fallback: RwLock<Arc<CertifiedKey>>,
    store: Store,
    mode: CertificateMode,
    challenges: RwLock<HashMap<String, String>>,
    account: tokio::sync::Mutex<Option<Account>>,
    issuance_lock: tokio::sync::Mutex<()>,
    clock: Clock,
    /// Per-identifier renewal failure backoff: (consecutive failures, unix
    /// time before which no retry runs). Prevents a single misconfigured
    /// hostname from burning ACME failed-validation rate limits every pass
    /// and throttling the shared account.
    renewal_backoff: RwLock<HashMap<String, (u32, i64)>>,
    /// Last ARI poll per identifier, so shortened renewal windows (e.g. after
    /// a mass revocation) are noticed without hammering the ACME server.
    ari_checked: RwLock<HashMap<String, i64>>,
}

#[derive(Clone, Debug)]
pub enum CertificateMode {
    Local,
    Acme(AcmeConfig),
}

#[derive(Clone, Debug)]
pub struct AcmeConfig {
    pub directory_url: String,
    pub root_certificate: Option<PathBuf>,
}

impl fmt::Debug for CertificateResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateResolver")
            .field(
                "certificate_count",
                &self.certificates.read().map(|map| map.len()).unwrap_or(0),
            )
            .finish_non_exhaustive()
    }
}

impl CertificateResolver {
    pub fn new(store: Store, mode: CertificateMode) -> Result<Arc<Self>> {
        install_crypto_provider();
        let fallback = self_signed(&["localhost", "127.0.0.1", "::1"])?;
        let clock = store.clock();
        let resolver = Arc::new(Self {
            certificates: RwLock::new(HashMap::new()),
            fallback: RwLock::new(fallback),
            store,
            mode,
            challenges: RwLock::new(HashMap::new()),
            account: tokio::sync::Mutex::new(None),
            issuance_lock: tokio::sync::Mutex::new(()),
            clock,
            renewal_backoff: RwLock::new(HashMap::new()),
            ari_checked: RwLock::new(HashMap::new()),
        });
        for certificate in resolver.store.certificates()? {
            resolver.install_pem(
                &certificate.identifier,
                &certificate.certificate_pem,
                &certificate.private_key_pem,
            )?;
        }
        Ok(resolver)
    }

    pub async fn ensure_dns(&self, hostname: &str) -> Result<()> {
        self.ensure_identifier(hostname, Identifier::Dns(hostname.to_owned()), false)
            .await
    }

    pub async fn ensure_ip(&self, address: IpAddr) -> Result<()> {
        let identifier = address.to_string();
        self.ensure_identifier(&identifier, Identifier::Ip(address), true)
            .await
    }

    async fn ensure_identifier(
        &self,
        identifier: &str,
        acme_identifier: Identifier,
        make_fallback: bool,
    ) -> Result<()> {
        if !self.store.certificate_due(identifier)? {
            if make_fallback {
                self.use_as_fallback(identifier)?;
            }
            return Ok(());
        }
        match &self.mode {
            CertificateMode::Local => self.ensure_local(identifier)?,
            CertificateMode::Acme(_) => self.issue(identifier, acme_identifier).await?,
        }
        if make_fallback {
            self.use_as_fallback(identifier)?;
        }
        Ok(())
    }

    /// Callers gate on `certificate_due`, so reaching this always means a new
    /// certificate is needed — an in-memory hit must NOT short-circuit here,
    /// or an expired local certificate would be served forever.
    pub fn ensure_local(&self, hostname: &str) -> Result<()> {
        let rcgen::CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![hostname.to_owned()])
                .context("generate local TLS certificate")?;
        let certificate_pem = cert.pem();
        let private_key_pem = signing_key.serialize_pem();
        let now = self.clock.now();
        self.store.save_certificate(
            hostname,
            &certificate_pem,
            &private_key_pem,
            now + 365 * 24 * 60 * 60,
            now + 300 * 24 * 60 * 60,
        )?;
        let certificate = certified_key(&certificate_pem, &private_key_pem)?;
        self.certificates
            .write()
            .map_err(|_| anyhow::anyhow!("certificate map is poisoned"))?
            .insert(hostname.to_owned(), certificate);
        Ok(())
    }

    pub fn remove(&self, hostname: &str) {
        if let Ok(mut certificates) = self.certificates.write() {
            certificates.remove(hostname);
        }
        if let Err(error) = self.store.remove_certificate(hostname) {
            tracing::error!(%error, hostname, "failed to remove persisted certificate");
        }
    }

    pub fn challenge(&self, token: &str) -> Option<String> {
        self.challenges
            .read()
            .ok()
            .and_then(|challenges| challenges.get(token).cloned())
    }

    pub async fn renew_due(&self) {
        if !matches!(self.mode, CertificateMode::Acme(_)) {
            return;
        }
        let Ok(certificates) = self.store.certificates() else {
            return;
        };
        for certificate in certificates {
            if certificate.renew_at > self.clock.now() {
                self.refresh_ari(&certificate).await;
                continue;
            }
            let backoff_active = self
                .renewal_backoff
                .read()
                .ok()
                .and_then(|backoff| backoff.get(&certificate.identifier).copied())
                .is_some_and(|(_, next_retry)| next_retry > self.clock.now());
            if backoff_active {
                continue;
            }
            if certificate.not_after <= self.clock.now() {
                tracing::warn!(
                    identifier = certificate.identifier,
                    "certificate is expired; attempting immediate renewal"
                );
            }
            let result = if let Ok(address) = certificate.identifier.parse::<IpAddr>() {
                self.ensure_identifier(&certificate.identifier, Identifier::Ip(address), true)
                    .await
            } else {
                self.ensure_dns(&certificate.identifier).await
            };
            match result {
                Ok(()) => {
                    if let Ok(mut backoff) = self.renewal_backoff.write() {
                        backoff.remove(&certificate.identifier);
                    }
                }
                Err(error) => {
                    let attempts = self
                        .renewal_backoff
                        .read()
                        .ok()
                        .and_then(|backoff| backoff.get(&certificate.identifier).copied())
                        .map(|(attempts, _)| attempts + 1)
                        .unwrap_or(1);
                    let delay = (15 * 60 * i64::from(2_u32.pow(attempts.min(6)))).min(24 * 60 * 60);
                    let jitter = rand::rng().random_range(0..300_i64);
                    if let Ok(mut backoff) = self.renewal_backoff.write() {
                        backoff.insert(
                            certificate.identifier.clone(),
                            (attempts, self.clock.now() + delay + jitter),
                        );
                    }
                    tracing::warn!(
                        %error,
                        identifier = certificate.identifier,
                        retry_in_seconds = delay + jitter,
                        "certificate renewal failed"
                    );
                    let _ = self.store.record_event(
                        "certificate",
                        &format!(
                            "Certificate renewal for {} failed (attempt {attempts}, retrying in {}m): {error:#}",
                            certificate.identifier,
                            (delay + jitter) / 60
                        ),
                    );
                }
            }
        }
    }

    /// Re-poll ARI for certificates that are not yet due: Let's Encrypt can
    /// shorten the suggested window after issuance (mass revocation), and a
    /// renew_at frozen at issuance time would never notice.
    async fn refresh_ari(&self, certificate: &crate::store::StoredCertificate) {
        const ARI_POLL_INTERVAL: i64 = 6 * 60 * 60;
        let CertificateMode::Acme(config) = &self.mode else {
            return;
        };
        let recently_checked = self
            .ari_checked
            .read()
            .ok()
            .and_then(|checked| checked.get(&certificate.identifier).copied())
            .is_some_and(|checked_at| checked_at + ARI_POLL_INTERVAL > self.clock.now());
        if recently_checked {
            return;
        }
        if let Ok(mut checked) = self.ari_checked.write() {
            checked.insert(certificate.identifier.clone(), self.clock.now());
        }
        let result: Result<()> = async {
            let (_, _, first_der) = certificate_validity(&certificate.certificate_pem)?;
            let certificate_id = CertificateIdentifier::try_from(&first_der)
                .map_err(|error| anyhow::anyhow!("compute ARI certificate id: {error}"))?;
            let account = self.account(config).await?;
            let (info, _) = account.renewal_info(&certificate_id).await?;
            let start = info.suggested_window.start.unix_timestamp();
            let end = info.suggested_window.end.unix_timestamp();
            let suggested = start + (end - start) / 2;
            if suggested < certificate.renew_at {
                self.store
                    .update_certificate_renew_at(&certificate.identifier, suggested)?;
                self.store.record_event(
                    "certificate",
                    &format!(
                        "ACME shortened the renewal window for {}; renewal moved earlier",
                        certificate.identifier
                    ),
                )?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::debug!(%error, identifier = certificate.identifier, "ARI poll failed");
        }
    }

    pub async fn update_contact(&self, email: &str) -> Result<()> {
        let CertificateMode::Acme(config) = &self.mode else {
            return Ok(());
        };
        let account = self.account(config).await?;
        let contact = format!("mailto:{email}");
        account.update_contacts(&[contact.as_str()]).await?;
        Ok(())
    }

    pub fn install_pem(
        &self,
        identifier: &str,
        certificate_pem: &str,
        private_key_pem: &str,
    ) -> Result<()> {
        let certificate = certified_key(certificate_pem, private_key_pem)?;
        self.certificates
            .write()
            .map_err(|_| anyhow::anyhow!("certificate map is poisoned"))?
            .insert(identifier.to_ascii_lowercase(), certificate);
        Ok(())
    }

    fn use_as_fallback(&self, identifier: &str) -> Result<()> {
        let certificate = self
            .certificates
            .read()
            .map_err(|_| anyhow::anyhow!("certificate map is poisoned"))?
            .get(&identifier.to_ascii_lowercase())
            .cloned()
            .context("admin certificate is not loaded")?;
        *self
            .fallback
            .write()
            .map_err(|_| anyhow::anyhow!("fallback certificate lock is poisoned"))? = certificate;
        Ok(())
    }

    async fn account(&self, config: &AcmeConfig) -> Result<Account> {
        let mut account = self.account.lock().await;
        if let Some(account) = account.as_ref() {
            return Ok(account.clone());
        }
        let builder = if let Some(root) = &config.root_certificate {
            Account::builder_with_root(root)?
        } else {
            Account::builder()?
        };
        let account_key = format!(
            "acme_account:{}",
            hex::encode(Sha256::digest(config.directory_url.as_bytes()))
        );
        let restored = self.store.secret(&account_key)?;
        let created = if let Some(credentials) = restored {
            let credentials: AccountCredentials =
                serde_json::from_str(&credentials).context("decode ACME account credentials")?;
            builder.from_credentials(credentials).await?
        } else {
            let contact = self
                .store
                .acme_email()?
                .map(|email| format!("mailto:{email}"))
                .into_iter()
                .collect::<Vec<_>>();
            let contact_refs = contact.iter().map(String::as_str).collect::<Vec<_>>();
            let (created, credentials) = builder
                .create(
                    &NewAccount {
                        contact: &contact_refs,
                        terms_of_service_agreed: true,
                        only_return_existing: false,
                    },
                    config.directory_url.clone(),
                    None,
                )
                .await?;
            self.store
                .save_secret(&account_key, &serde_json::to_string(&credentials)?)?;
            created
        };
        *account = Some(created.clone());
        Ok(created)
    }

    async fn issue(&self, identifier_key: &str, identifier: Identifier) -> Result<()> {
        let _guard = self.issuance_lock.lock().await;
        if !self.store.certificate_due(identifier_key)? {
            return Ok(());
        }
        let CertificateMode::Acme(config) = &self.mode else {
            return self.ensure_local(identifier_key);
        };
        let account = self.account(config).await?;
        let identifiers = vec![identifier.clone()];
        let mut request = NewOrder::new(&identifiers);
        if matches!(identifier, Identifier::Ip(_)) {
            request = request.profile("shortlived");
        }
        let mut order = account
            .new_order(&request)
            .await
            .with_context(|| format!("create ACME order for {identifier_key}"))?;
        let mut provisioned = Vec::new();
        let result = async {
            let mut authorizations = order.authorizations();
            while let Some(authorization) = authorizations.next().await {
                let mut authorization = authorization?;
                match authorization.status {
                    AuthorizationStatus::Valid => continue,
                    AuthorizationStatus::Pending => {}
                    status => anyhow::bail!("ACME authorization entered {status:?}"),
                }
                let mut challenge = authorization
                    .challenge(ChallengeType::Http01)
                    .context("ACME server did not offer HTTP-01")?;
                let token = challenge.token.clone();
                let key_authorization = challenge.key_authorization().as_str().to_owned();
                self.challenges
                    .write()
                    .map_err(|_| anyhow::anyhow!("ACME challenge lock is poisoned"))?
                    .insert(token.clone(), key_authorization);
                provisioned.push(token);
                challenge.set_ready().await?;
            }
            if order.poll_ready(&RetryPolicy::default()).await? != OrderStatus::Ready {
                anyhow::bail!("ACME order did not become ready");
            }
            let private_key_pem = order.finalize().await?;
            let certificate_pem = order.poll_certificate(&RetryPolicy::default()).await?;
            let (not_before, not_after, first_der) = certificate_validity(&certificate_pem)?;
            let fallback_renew_at = not_before + ((not_after - not_before) * 2 / 3);
            let renew_at = match CertificateIdentifier::try_from(&first_der) {
                Ok(certificate_id) => account
                    .renewal_info(&certificate_id)
                    .await
                    .ok()
                    .map(|(info, _)| {
                        let start = info.suggested_window.start.unix_timestamp();
                        let end = info.suggested_window.end.unix_timestamp();
                        start + (end - start) / 2
                    })
                    .unwrap_or(fallback_renew_at),
                Err(_) => fallback_renew_at,
            };
            self.store.save_certificate(
                identifier_key,
                &certificate_pem,
                &private_key_pem,
                not_after,
                renew_at,
            )?;
            self.install_pem(identifier_key, &certificate_pem, &private_key_pem)?;
            Result::<()>::Ok(())
        }
        .await;
        if let Ok(mut challenges) = self.challenges.write() {
            for token in provisioned {
                challenges.remove(&token);
            }
        }
        result
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        client_hello
            .server_name()
            .and_then(|name| {
                self.certificates
                    .read()
                    .ok()
                    .and_then(|certificates| certificates.get(&name.to_ascii_lowercase()).cloned())
            })
            .or_else(|| {
                self.fallback
                    .read()
                    .ok()
                    .map(|certificate| certificate.clone())
            })
    }
}

fn self_signed(names: &[&str]) -> Result<Arc<CertifiedKey>> {
    let rcgen::CertifiedKey { cert, signing_key } = generate_simple_self_signed(
        names
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>(),
    )
    .context("generate local TLS certificate")?;
    let provider =
        rustls::crypto::CryptoProvider::get_default().context("install rustls crypto provider")?;
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let signing_key = provider
        .key_provider
        .load_private_key(private_key)
        .context("load local TLS private key")?;
    Ok(Arc::new(CertifiedKey::new(
        vec![cert.der().clone()],
        signing_key,
    )))
}

fn certified_key(certificate_pem: &str, private_key_pem: &str) -> Result<Arc<CertifiedKey>> {
    let mut certificates = BufReader::new(Cursor::new(certificate_pem.as_bytes()));
    let certificates = rustls_pemfile::certs(&mut certificates)
        .collect::<std::io::Result<Vec<_>>>()
        .context("parse certificate chain")?;
    let mut private_key = BufReader::new(Cursor::new(private_key_pem.as_bytes()));
    let private_key = rustls_pemfile::private_key(&mut private_key)
        .context("parse certificate private key")?
        .context("certificate private key is missing")?;
    let provider =
        rustls::crypto::CryptoProvider::get_default().context("install rustls crypto provider")?;
    let signing_key = provider
        .key_provider
        .load_private_key(private_key)
        .context("load certificate private key")?;
    Ok(Arc::new(CertifiedKey::new(certificates, signing_key)))
}

fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn certificate_validity(
    certificate_pem: &str,
) -> Result<(i64, i64, rustls::pki_types::CertificateDer<'static>)> {
    let mut reader = BufReader::new(Cursor::new(certificate_pem.as_bytes()));
    let first = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()
        .context("parse issued certificate")?
        .context("ACME response contains no certificate")?;
    let (_, certificate) = x509_parser::parse_x509_certificate(first.as_ref())
        .map_err(|error| anyhow::anyhow!("parse issued X.509 certificate: {error}"))?;
    Ok((
        certificate.validity().not_before.timestamp(),
        certificate.validity().not_after.timestamp(),
        first,
    ))
}
