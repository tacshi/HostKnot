use std::{
    collections::HashSet,
    net::IpAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    certificates::CertificateResolver,
    provider::{DnsIntent, DnsProvider},
    store::{Binding, Store},
};

#[derive(Clone)]
pub struct BindingManager {
    store: Store,
    provider: Arc<dyn DnsProvider>,
    certificates: Arc<CertificateResolver>,
    public_ips: Vec<IpAddr>,
    reserved_ports: HashSet<u16>,
    drain_duration: Duration,
    /// Wakes the reconciliation loop early after a failure lands a binding in
    /// a retryable state, instead of waiting out the idle interval.
    reconcile_nudge: Arc<tokio::sync::Notify>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreateBinding {
    pub hostname: String,
    pub upstream_scheme: String,
    pub upstream_port: u16,
    #[serde(default)]
    pub proxied: bool,
    #[serde(default)]
    pub insecure_tls: bool,
    #[serde(default)]
    pub replace_existing: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdateBinding {
    pub upstream_scheme: String,
    pub upstream_port: u16,
    #[serde(default)]
    pub proxied: bool,
    #[serde(default)]
    pub insecure_tls: bool,
}

impl BindingManager {
    pub fn new(
        store: Store,
        provider: Arc<dyn DnsProvider>,
        certificates: Arc<CertificateResolver>,
        public_ips: Vec<IpAddr>,
        reserved_ports: impl IntoIterator<Item = u16>,
        drain_duration: Duration,
    ) -> Self {
        let manager = Self {
            store,
            provider,
            certificates,
            public_ips,
            reserved_ports: reserved_ports.into_iter().collect(),
            drain_duration,
            reconcile_nudge: Arc::new(tokio::sync::Notify::new()),
        };
        if let Err(error) = manager.resume_drains() {
            tracing::error!(%error, "failed to resume binding drains");
        }
        manager
    }

    pub async fn create(&self, input: CreateBinding) -> Result<Binding> {
        let hostname = normalize_hostname(&input.hostname)?;
        if !matches!(input.upstream_scheme.as_str(), "http" | "https") {
            bail!("upstream scheme must be http or https");
        }
        if input.upstream_port == 0 || self.reserved_ports.contains(&input.upstream_port) {
            bail!(
                "port {} is one of Hostknot's own listeners (admin UI or proxy), so it cannot \
                 be bound — the admin UI is always reached directly at https://<VPS-IP>:9443. \
                 Bind the loopback port your application listens on instead.",
                input.upstream_port
            );
        }
        if self.public_ips.is_empty() {
            bail!("at least one public IP address is required");
        }
        let binding_id = Uuid::now_v7().to_string();
        self.store.create_binding(
            &binding_id,
            &hostname,
            &input.upstream_scheme,
            input.upstream_port,
            input.insecure_tls,
            input.proxied,
            input.replace_existing,
        )?;
        let intent = DnsIntent {
            binding_id: binding_id.clone(),
            hostname: hostname.clone(),
            public_ips: self.public_ips.clone(),
            proxied: input.proxied,
            replace_existing: input.replace_existing,
        };
        let receipt = match self.provider.apply(&intent).await {
            Ok(receipt) => receipt,
            Err(error) => {
                if crate::provider::is_conflict(&error) {
                    self.store.delete_binding(&binding_id)?;
                    return Err(error);
                }
                self.store
                    .mark_binding_error(&binding_id, "dns_pending", &error.to_string())?;
                self.reconcile_nudge.notify_one();
                return Err(error);
            }
        };
        self.store
            .mark_binding_certificate_pending(&binding_id, &receipt)?;
        // A certificate failure here is NOT fatal to the binding: DNS is in
        // place and reconciliation retries issuance in the background. Return
        // the binding so the UI shows "certificate pending" instead of
        // dead-ending the operator on an error page.
        match self.certificates.ensure_dns(&hostname).await {
            Ok(()) => {
                self.store.mark_binding_active(&binding_id)?;
                self.store
                    .record_event("binding", &format!("Binding activated: {hostname}"))?;
            }
            Err(error) => {
                self.store.mark_binding_error(
                    &binding_id,
                    "certificate_pending",
                    &error.to_string(),
                )?;
                self.store.record_event(
                    "binding",
                    &format!(
                        "Certificate issuance for {hostname} failed and will retry: {error:#}"
                    ),
                )?;
                self.reconcile_nudge.notify_one();
            }
        }
        let binding = self
            .store
            .binding(&binding_id)?
            .context("binding disappeared during creation")?;
        Ok(binding)
    }

    pub async fn remove(&self, id: &str) -> Result<()> {
        let binding = self.store.binding(id)?.context("binding does not exist")?;
        // Removal already ran and the route is draining; a second click must
        // be a harmless no-op, not a second revert that misreads its own
        // earlier deletion as drift.
        if binding.status == "draining" {
            return Ok(());
        }
        // A binding whose DNS apply never succeeded has no receipt and owns no
        // records, so there is nothing to revert.
        if let Some(receipt) = self.store.binding_receipt(id)?
            && let Err(error) = self.provider.revert(&receipt).await
        {
            self.store
                .mark_binding_error(id, "drifted", &error.to_string())?;
            self.reconcile_nudge.notify_one();
            return Err(error);
        }
        self.store.mark_binding_draining(id, self.drain_duration)?;
        self.store.record_event(
            "binding",
            &format!("Binding removal started: {}", binding.hostname),
        )?;
        self.schedule_drain(id.to_owned(), binding.hostname, self.drain_duration);
        Ok(())
    }

    pub async fn update(&self, id: &str, input: UpdateBinding) -> Result<()> {
        if !matches!(input.upstream_scheme.as_str(), "http" | "https") {
            bail!("upstream scheme must be http or https");
        }
        if input.upstream_port == 0 || self.reserved_ports.contains(&input.upstream_port) {
            bail!(
                "port {} is one of Hostknot's own listeners (admin UI or proxy), so it cannot \
                 be bound — the admin UI is always reached directly at https://<VPS-IP>:9443. \
                 Bind the loopback port your application listens on instead.",
                input.upstream_port
            );
        }
        let binding = self.store.binding(id)?.context("binding does not exist")?;
        if !matches!(binding.status.as_str(), "active" | "degraded") {
            bail!("only active bindings can be edited");
        }
        let receipt = if binding.proxied != input.proxied {
            let receipt = self
                .store
                .binding_receipt(id)?
                .context("binding has no DNS receipt")?;
            Some(
                self.provider
                    .set_proxy_mode(&receipt, input.proxied)
                    .await?,
            )
        } else {
            None
        };
        self.store.update_binding(
            id,
            &input.upstream_scheme,
            input.upstream_port,
            input.insecure_tls,
            input.proxied,
            receipt.as_ref(),
        )?;
        self.store
            .record_event("binding", &format!("Binding updated: {}", binding.hostname))?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<Binding>> {
        self.store.list_bindings()
    }

    pub fn port_is_bindable(&self, port: u16) -> bool {
        port != 0 && !self.reserved_ports.contains(&port)
    }

    pub async fn reconcile_nudged(&self) {
        self.reconcile_nudge.notified().await;
    }

    pub fn nudge_reconciliation(&self) {
        self.reconcile_nudge.notify_one();
    }

    pub async fn reconcile_once(&self) -> Result<bool> {
        let mut pending = false;
        for binding in self.store.list_bindings()? {
            match binding.status.as_str() {
                "dns_pending" => {
                    pending = true;
                    let intent = DnsIntent {
                        binding_id: binding.id.clone(),
                        hostname: binding.hostname.clone(),
                        public_ips: self.public_ips.clone(),
                        proxied: binding.proxied,
                        // Re-use the operator's original confirmation so a
                        // partially-failed, rolled-back replacement does not
                        // deadlock on its own restored records.
                        replace_existing: binding.replace_confirmed,
                    };
                    match self.provider.apply(&intent).await {
                        Ok(receipt) => {
                            self.store
                                .mark_binding_certificate_pending(&binding.id, &receipt)?;
                        }
                        Err(error) => self.store.mark_binding_error(
                            &binding.id,
                            "dns_pending",
                            &error.to_string(),
                        )?,
                    }
                }
                "certificate_pending" => {
                    pending = true;
                    match self.certificates.ensure_dns(&binding.hostname).await {
                        Ok(()) => {
                            self.store.mark_binding_active(&binding.id)?;
                            self.store.record_event(
                                "binding",
                                &format!("Binding activated: {}", binding.hostname),
                            )?;
                        }
                        Err(error) => self.store.mark_binding_error(
                            &binding.id,
                            "certificate_pending",
                            &error.to_string(),
                        )?,
                    }
                }
                "drifted" => {
                    // Set when a removal's revert failed. Keep retrying: once
                    // the operator resolves the external drift (or the
                    // transient provider error clears), the removal finishes.
                    pending = true;
                    match self.store.binding_receipt(&binding.id)? {
                        Some(receipt) => match self.provider.revert(&receipt).await {
                            Ok(()) => self.finish_removal(&binding.id, &binding.hostname)?,
                            Err(error) => self.store.mark_binding_error(
                                &binding.id,
                                "drifted",
                                &error.to_string(),
                            )?,
                        },
                        None => self.finish_removal(&binding.id, &binding.hostname)?,
                    }
                }
                _ => {}
            }
        }
        Ok(pending)
    }

    fn finish_removal(&self, id: &str, hostname: &str) -> Result<()> {
        self.store.mark_binding_draining(id, self.drain_duration)?;
        self.store
            .record_event("binding", &format!("Binding removal started: {hostname}"))?;
        self.schedule_drain(id.to_owned(), hostname.to_owned(), self.drain_duration);
        Ok(())
    }

    fn resume_drains(&self) -> Result<()> {
        for (id, hostname, drain_until) in self.store.draining_bindings()? {
            let remaining =
                Duration::from_secs(drain_until.saturating_sub(unix_now()).max(0) as u64);
            self.schedule_drain(id, hostname, remaining);
        }
        Ok(())
    }

    fn schedule_drain(&self, id: String, hostname: String, delay: Duration) {
        let store = self.store.clone();
        let certificates = self.certificates.clone();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            if let Err(error) = store.delete_binding(&id) {
                tracing::error!(%error, binding_id = id, "failed to finish binding drain");
                return;
            }
            certificates.remove(&hostname);
        });
    }
}

pub fn normalize_hostname(hostname: &str) -> Result<String> {
    let hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
    if hostname.is_empty()
        || hostname.contains('*')
        || hostname.contains('/')
        || hostname.parse::<IpAddr>().is_ok()
    {
        bail!("an exact DNS hostname is required");
    }
    let ascii = idna::domain_to_ascii_strict(&hostname)
        .map_err(|error| anyhow::anyhow!("invalid hostname: {error}"))?;
    if ascii.len() > 253 || !ascii.contains('.') {
        bail!("hostname must be a fully-qualified domain name");
    }
    Ok(ascii)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        certificates::{CertificateMode, CertificateResolver},
        provider::InMemoryDnsProvider,
        store::Store,
    };
    use tokio::io::AsyncWriteExt;

    fn manager(store: &Store, drain: Duration) -> BindingManager {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certificates = CertificateResolver::new(store.clone(), CertificateMode::Local).unwrap();
        BindingManager::new(
            store.clone(),
            Arc::new(InMemoryDnsProvider::new(Vec::new())),
            certificates,
            vec!["203.0.113.10".parse().unwrap()],
            Vec::<u16>::new(),
            drain,
        )
    }

    async fn assert_deleted_soon(store: &Store, id: &str, message: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while store.binding(id).unwrap().is_some() {
            assert!(tokio::time::Instant::now() < deadline, "{message}");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn restart_completes_a_drain_whose_window_already_passed() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store
            .create_binding("b1", "app.example.com", "http", 8080, false, false, false)
            .unwrap();
        store.mark_binding_draining("b1", Duration::ZERO).unwrap();
        // Let the stored drain deadline fall into the past before "restarting".
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let _manager = manager(&store, Duration::from_secs(300));
        assert_deleted_soon(&store, "b1", "expired drain never completed after restart").await;
    }

    #[tokio::test]
    async fn removing_a_binding_without_a_dns_receipt_succeeds() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store
            .create_binding("b1", "app.example.com", "http", 8080, false, false, false)
            .unwrap();
        let manager = manager(&store, Duration::ZERO);
        manager
            .remove("b1")
            .await
            .expect("a binding stuck in dns_pending must still be removable");
        assert_deleted_soon(&store, "b1", "receipt-less binding was never deleted").await;
    }

    #[tokio::test]
    async fn degraded_https_binding_is_not_healed_by_a_plain_http_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok")
                    .await;
            }
        });
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store
            .create_binding("b1", "app.example.com", "https", port, false, false, false)
            .unwrap();
        store.mark_binding_active("b1").unwrap();
        store
            .update_binding_health("b1", false, Some("HTTPS upstream connection failed"))
            .unwrap();

        manager(&store, Duration::from_secs(300))
            .reconcile_once()
            .await
            .unwrap();

        let binding = store.binding("b1").unwrap().unwrap();
        assert_eq!(binding.status, "degraded");
        assert_eq!(binding.health, "unavailable");
        server.abort();
    }
}
