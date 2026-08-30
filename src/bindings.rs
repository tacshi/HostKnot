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
    model::{Binding, BindingPathRoute, BindingStatus, PendingBindingUpdate},
    provider::{DnsIntent, DnsProvider},
    store::Store,
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
    pub replace_existing: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdateBinding {
    pub upstream_scheme: String,
    pub upstream_port: u16,
    #[serde(default)]
    pub proxied: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CreatePathRoute {
    pub path_prefix: String,
    pub upstream_scheme: String,
    pub upstream_port: u16,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UpdatePathRoute {
    pub path_prefix: String,
    pub upstream_scheme: String,
    pub upstream_port: u16,
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
        self.validate_local_upstream(&input.upstream_scheme, input.upstream_port)?;
        if self.public_ips.is_empty() {
            bail!("at least one public IP address is required");
        }
        let binding_id = Uuid::now_v7().to_string();
        let binding = self.store.create_binding(
            &binding_id,
            &hostname,
            &input.upstream_scheme,
            input.upstream_port,
            input.proxied,
            input.replace_existing,
        )?;
        let receipt = match self.apply_pending_dns(&binding).await {
            Ok(receipt) => receipt,
            Err(error) => {
                if crate::provider::is_conflict(&error) {
                    self.store.delete_binding(&binding_id)?;
                    return Err(error);
                }
                self.store.mark_binding_error(
                    &binding_id,
                    BindingStatus::DnsPending,
                    &error.to_string(),
                )?;
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
                self.record_event(&format!("Binding activated: {hostname}"));
            }
            Err(error) => {
                self.store.mark_binding_error(
                    &binding_id,
                    BindingStatus::CertificatePending,
                    &error.to_string(),
                )?;
                self.record_event(&format!(
                    "Certificate issuance for {hostname} failed and will retry: {error:#}"
                ));
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
        if binding.status == BindingStatus::Draining {
            return Ok(());
        }
        if binding.status == BindingStatus::Updating {
            bail!("this binding's previous update is still being reconciled");
        }
        if binding.status != BindingStatus::Removing {
            // Persist intent before the first provider write. A crash from
            // this point onward is resumed by `reconcile_once`.
            self.store.begin_binding_removal(id)?;
        }
        if let Err(error) = self.continue_removal(id, &binding.hostname).await {
            self.store
                .mark_binding_error(id, BindingStatus::Removing, &error.to_string())?;
            self.reconcile_nudge.notify_one();
            return Err(error);
        }
        Ok(())
    }

    pub async fn update(&self, id: &str, input: UpdateBinding) -> Result<()> {
        self.validate_local_upstream(&input.upstream_scheme, input.upstream_port)?;
        let binding = self.store.binding(id)?.context("binding does not exist")?;
        if !binding.status.is_editable() {
            bail!("only active bindings can be edited");
        }
        let update = PendingBindingUpdate {
            upstream_scheme: input.upstream_scheme,
            upstream_port: input.upstream_port,
            proxied: input.proxied,
        };
        if binding.proxied != update.proxied {
            self.store.begin_binding_update(id, &update)?;
            if let Err(error) = self.continue_update(id).await {
                self.store
                    .mark_binding_error(id, BindingStatus::Updating, &error.to_string())?;
                self.reconcile_nudge.notify_one();
                return Err(error);
            }
        } else {
            self.store.update_binding_local(id, &update)?;
        }
        self.record_event(&format!("Binding updated: {}", binding.hostname));
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<Binding>> {
        self.store.list_bindings()
    }

    pub fn port_is_bindable(&self, port: u16) -> bool {
        port != 0 && !self.reserved_ports.contains(&port)
    }

    pub fn create_path_route(
        &self,
        binding_id: &str,
        input: CreatePathRoute,
    ) -> Result<BindingPathRoute> {
        self.validate_local_upstream(&input.upstream_scheme, input.upstream_port)?;
        let path_prefix = normalize_path_prefix(&input.path_prefix)?;
        let binding = self
            .store
            .binding(binding_id)?
            .context("binding does not exist")?;
        if !binding.status.is_editable() {
            bail!("path routes can only be changed on active bindings");
        }
        if self
            .store
            .list_path_routes(binding_id)?
            .iter()
            .any(|route| route.path_prefix == path_prefix)
        {
            bail!("this path prefix already has a route");
        }
        let route = self.store.create_path_route(
            &Uuid::now_v7().to_string(),
            binding_id,
            &path_prefix,
            &input.upstream_scheme,
            input.upstream_port,
        )?;
        self.record_event(&format!(
            "Path route added: {}{} → {}://127.0.0.1:{}",
            binding.hostname, route.path_prefix, route.upstream_scheme, route.upstream_port
        ));
        Ok(route)
    }

    pub fn update_path_route(
        &self,
        binding_id: &str,
        route_id: &str,
        input: UpdatePathRoute,
    ) -> Result<()> {
        self.validate_local_upstream(&input.upstream_scheme, input.upstream_port)?;
        let path_prefix = normalize_path_prefix(&input.path_prefix)?;
        let binding = self
            .store
            .binding(binding_id)?
            .context("binding does not exist")?;
        if !binding.status.is_editable() {
            bail!("path routes can only be changed on active bindings");
        }
        let previous = self
            .store
            .path_route(route_id)?
            .filter(|route| route.binding_id == binding_id)
            .context("path route does not exist")?;
        if self
            .store
            .list_path_routes(binding_id)?
            .iter()
            .any(|route| route.id != route_id && route.path_prefix == path_prefix)
        {
            bail!("this path prefix already has a route");
        }
        if !self.store.update_path_route(
            route_id,
            binding_id,
            &path_prefix,
            &input.upstream_scheme,
            input.upstream_port,
        )? {
            bail!("path route does not exist");
        }
        self.record_event(&format!(
            "Path route updated: {}{} → {}{} ({}://127.0.0.1:{})",
            binding.hostname,
            previous.path_prefix,
            binding.hostname,
            path_prefix,
            input.upstream_scheme,
            input.upstream_port
        ));
        Ok(())
    }

    pub fn delete_path_route(&self, binding_id: &str, route_id: &str) -> Result<()> {
        let binding = self
            .store
            .binding(binding_id)?
            .context("binding does not exist")?;
        if !binding.status.is_editable() {
            bail!("path routes can only be changed on active bindings");
        }
        let route = self
            .store
            .path_route(route_id)?
            .filter(|route| route.binding_id == binding_id)
            .context("path route does not exist")?;
        if !self.store.delete_path_route(route_id, binding_id)? {
            bail!("path route does not exist");
        }
        self.record_event(&format!(
            "Path route removed: {}{} ({}://127.0.0.1:{})",
            binding.hostname, route.path_prefix, route.upstream_scheme, route.upstream_port
        ));
        Ok(())
    }

    pub fn list_path_routes(&self, binding_id: &str) -> Result<Vec<BindingPathRoute>> {
        self.store.list_path_routes(binding_id)
    }

    fn validate_local_upstream(&self, scheme: &str, port: u16) -> Result<()> {
        if !matches!(scheme, "http" | "https") {
            bail!("upstream scheme must be http or https");
        }
        if !self.port_is_bindable(port) {
            bail!(
                "port {port} is one of HostKnot's own listeners (admin UI or proxy), so it cannot \
                 be bound — the admin UI is always reached directly at https://<VPS-IP>:9443. \
                 Bind the loopback port your application listens on instead."
            );
        }
        Ok(())
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
            match binding.status {
                BindingStatus::DnsPending => {
                    pending = true;
                    match self.apply_pending_dns(&binding).await {
                        Ok(receipt) => {
                            self.store
                                .mark_binding_certificate_pending(&binding.id, &receipt)?;
                        }
                        Err(error) => self.store.mark_binding_error(
                            &binding.id,
                            BindingStatus::DnsPending,
                            &error.to_string(),
                        )?,
                    }
                }
                BindingStatus::CertificatePending => {
                    pending = true;
                    match self.certificates.ensure_dns(&binding.hostname).await {
                        Ok(()) => {
                            self.store.mark_binding_active(&binding.id)?;
                            self.record_event(&format!("Binding activated: {}", binding.hostname));
                        }
                        Err(error) => self.store.mark_binding_error(
                            &binding.id,
                            BindingStatus::CertificatePending,
                            &error.to_string(),
                        )?,
                    }
                }
                BindingStatus::Updating => {
                    pending = true;
                    if let Err(error) = self.continue_update(&binding.id).await {
                        self.store.mark_binding_error(
                            &binding.id,
                            BindingStatus::Updating,
                            &error.to_string(),
                        )?;
                    }
                }
                BindingStatus::Removing => {
                    pending = true;
                    if let Err(error) = self.continue_removal(&binding.id, &binding.hostname).await
                    {
                        self.store.mark_binding_error(
                            &binding.id,
                            BindingStatus::Removing,
                            &error.to_string(),
                        )?;
                    }
                }
                _ => {}
            }
        }
        Ok(pending)
    }

    async fn apply_pending_dns(&self, binding: &Binding) -> Result<crate::provider::DnsReceipt> {
        let plan = match self.store.binding_dns_plan(&binding.id)? {
            Some(plan) => plan,
            None => {
                let plan = self
                    .provider
                    .prepare(&DnsIntent {
                        binding_id: binding.id.clone(),
                        hostname: binding.hostname.clone(),
                        public_ips: self.public_ips.clone(),
                        proxied: binding.proxied,
                        // Re-use the operator's original confirmation so a
                        // partially-failed replacement can be replayed from
                        // its durable pre-image.
                        replace_existing: binding.replace_confirmed,
                    })
                    .await?;
                self.store.save_binding_dns_plan(&binding.id, &plan)?;
                plan
            }
        };
        self.provider.apply(&plan).await
    }

    async fn continue_update(&self, id: &str) -> Result<()> {
        let update = self
            .store
            .pending_binding_update(id)?
            .context("binding update journal is missing")?;
        let receipt = self
            .store
            .binding_receipt(id)?
            .context("binding has no DNS receipt")?;
        let receipt = self
            .provider
            .set_proxy_mode(&receipt, update.proxied)
            .await?;
        self.store.finish_binding_update(id, &update, &receipt)
    }

    async fn continue_removal(&self, id: &str, hostname: &str) -> Result<()> {
        let receipt = match self.store.binding_receipt(id)? {
            Some(receipt) => Some(receipt),
            None => match self.store.binding_dns_plan(id)? {
                Some(plan) => {
                    // A create may have crashed after a partial provider
                    // mutation but before saving its receipt. Finish that
                    // idempotent plan, journal the receipt, then revert it.
                    let receipt = self.provider.apply(&plan).await?;
                    self.store.save_binding_removal_receipt(id, &receipt)?;
                    Some(receipt)
                }
                None => None,
            },
        };
        if let Some(receipt) = receipt {
            self.provider.revert(&receipt).await?;
        }
        self.finish_removal(id, hostname)
    }

    fn finish_removal(&self, id: &str, hostname: &str) -> Result<()> {
        self.store.mark_binding_draining(id, self.drain_duration)?;
        self.schedule_drain(id.to_owned(), hostname.to_owned(), self.drain_duration);
        self.record_event(&format!("Binding removal started: {hostname}"));
        Ok(())
    }

    fn record_event(&self, message: &str) {
        if let Err(error) = self.store.record_event("binding", message) {
            tracing::warn!(%error, "failed to persist binding event");
        }
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

pub fn normalize_path_prefix(path_prefix: &str) -> Result<String> {
    let path_prefix = path_prefix.trim().trim_end_matches('/');
    if path_prefix.is_empty()
        || path_prefix == "/"
        || path_prefix.len() > 256
        || !path_prefix.starts_with('/')
        || path_prefix.contains(['?', '#', '%', '\\'])
        || !path_prefix.is_ascii()
    {
        bail!("path prefix must be an absolute ASCII path below /");
    }
    if path_prefix
        .split('/')
        .skip(1)
        .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        bail!("path prefix cannot contain empty, . or .. segments");
    }
    if !path_prefix.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'~')
    }) {
        bail!("path prefix contains unsupported characters");
    }
    Ok(path_prefix.to_owned())
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
        manager_with_provider(store, drain, Arc::new(InMemoryDnsProvider::new(Vec::new())))
    }

    fn manager_with_provider(
        store: &Store,
        drain: Duration,
        provider: Arc<dyn DnsProvider>,
    ) -> BindingManager {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let certificates = CertificateResolver::new(store.clone(), CertificateMode::Local).unwrap();
        BindingManager::new(
            store.clone(),
            provider,
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
            .create_binding("b1", "app.example.com", "http", 8080, false, false)
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
            .create_binding("b1", "app.example.com", "http", 8080, false, false)
            .unwrap();
        let manager = manager(&store, Duration::ZERO);
        manager
            .remove("b1")
            .await
            .expect("a binding stuck in dns_pending must still be removable");
        assert_deleted_soon(&store, "b1", "receipt-less binding was never deleted").await;
    }

    #[tokio::test]
    async fn removing_an_incomplete_binding_does_not_make_it_routable() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store
            .create_binding("b1", "app.example.com", "http", 8080, false, false)
            .unwrap();
        manager(&store, Duration::from_secs(300))
            .remove("b1")
            .await
            .unwrap();

        assert_eq!(
            store.binding("b1").unwrap().unwrap().status,
            BindingStatus::Draining
        );
        assert!(!store.hostname_is_routable("app.example.com").unwrap());
    }

    #[tokio::test]
    async fn create_recovery_replays_the_journal_and_preserves_the_dns_preimage() {
        let prior = crate::provider::DnsRecord {
            id: "prior".to_owned(),
            record_type: "CNAME".to_owned(),
            name: "app.example.com".to_owned(),
            content: "old.example.net".to_owned(),
            proxied: false,
            ttl: 300,
            comment: None,
        };
        let provider = Arc::new(InMemoryDnsProvider::new(vec![prior.clone()]));
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let binding = store
            .create_binding("b1", "app.example.com", "http", 8080, true, true)
            .unwrap();
        let plan = provider
            .prepare(&DnsIntent {
                binding_id: binding.id.clone(),
                hostname: binding.hostname.clone(),
                public_ips: vec!["203.0.113.10".parse().unwrap()],
                proxied: true,
                replace_existing: true,
            })
            .await
            .unwrap();
        store.save_binding_dns_plan(&binding.id, &plan).unwrap();

        // Simulate a crash after Cloudflare committed but before SQLite saved
        // the receipt. Recovery must reuse the journal instead of taking a
        // new pre-image of its own managed record.
        provider.apply(&plan).await.unwrap();
        let manager = manager_with_provider(&store, Duration::from_secs(300), provider.clone());
        manager.reconcile_once().await.unwrap();
        assert_eq!(provider.records().len(), 1);
        assert_eq!(
            store.binding("b1").unwrap().unwrap().status,
            BindingStatus::CertificatePending
        );
        manager.reconcile_once().await.unwrap();

        manager.remove("b1").await.unwrap();
        assert_eq!(provider.records(), vec![prior]);
    }

    #[tokio::test]
    async fn update_recovery_accepts_an_already_applied_proxy_mode() {
        let provider = Arc::new(InMemoryDnsProvider::new(Vec::new()));
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let binding = store
            .create_binding("b1", "app.example.com", "http", 8080, false, false)
            .unwrap();
        let plan = provider
            .prepare(&DnsIntent {
                binding_id: binding.id.clone(),
                hostname: binding.hostname.clone(),
                public_ips: vec!["203.0.113.10".parse().unwrap()],
                proxied: false,
                replace_existing: false,
            })
            .await
            .unwrap();
        let receipt = provider.apply(&plan).await.unwrap();
        store
            .mark_binding_certificate_pending(&binding.id, &receipt)
            .unwrap();
        store.mark_binding_active(&binding.id).unwrap();
        let update = PendingBindingUpdate {
            upstream_scheme: "https".to_owned(),
            upstream_port: 8443,
            proxied: true,
        };
        store.begin_binding_update(&binding.id, &update).unwrap();

        // Simulate the remote write winning just before process death.
        provider.set_proxy_mode(&receipt, true).await.unwrap();
        manager_with_provider(&store, Duration::from_secs(300), provider.clone())
            .reconcile_once()
            .await
            .unwrap();

        let recovered = store.binding(&binding.id).unwrap().unwrap();
        assert_eq!(recovered.status, BindingStatus::Active);
        assert_eq!(recovered.upstream_scheme, "https");
        assert_eq!(recovered.upstream_port, 8443);
        assert!(recovered.proxied);
        assert!(provider.records()[0].proxied);
    }

    #[tokio::test]
    async fn removal_recovery_accepts_records_that_are_already_reverted() {
        let provider = Arc::new(InMemoryDnsProvider::new(Vec::new()));
        let dir = tempfile::TempDir::new().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let binding = store
            .create_binding("b1", "app.example.com", "http", 8080, false, false)
            .unwrap();
        let plan = provider
            .prepare(&DnsIntent {
                binding_id: binding.id.clone(),
                hostname: binding.hostname.clone(),
                public_ips: vec!["203.0.113.10".parse().unwrap()],
                proxied: false,
                replace_existing: false,
            })
            .await
            .unwrap();
        let receipt = provider.apply(&plan).await.unwrap();
        store
            .mark_binding_certificate_pending(&binding.id, &receipt)
            .unwrap();
        store.mark_binding_active(&binding.id).unwrap();
        store.begin_binding_removal(&binding.id).unwrap();

        // Simulate death after the records were reverted but before the local
        // transition to draining was committed.
        provider.revert(&receipt).await.unwrap();
        manager_with_provider(&store, Duration::from_secs(300), provider.clone())
            .reconcile_once()
            .await
            .unwrap();

        assert!(provider.records().is_empty());
        assert_eq!(
            store.binding(&binding.id).unwrap().unwrap().status,
            BindingStatus::Draining
        );
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
            .create_binding("b1", "app.example.com", "https", port, false, false)
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
        assert_eq!(binding.status, BindingStatus::Degraded);
        assert_eq!(binding.health, crate::model::BindingHealth::Unavailable);
        server.abort();
    }
}
