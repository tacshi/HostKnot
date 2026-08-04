use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    provider::{DnsError, DnsIntent, DnsProvider, DnsReceipt, DnsRecord},
    store::{CloudflareConfiguration, Store},
};

#[derive(Clone, Debug)]
pub struct CloudflareEndpoints {
    pub authorization: Url,
    pub token: Url,
    pub api: Url,
}

impl Default for CloudflareEndpoints {
    fn default() -> Self {
        Self {
            authorization: Url::parse("https://dash.cloudflare.com/oauth2/auth")
                .expect("valid Cloudflare authorization URL"),
            token: Url::parse("https://dash.cloudflare.com/oauth2/token")
                .expect("valid Cloudflare token URL"),
            api: Url::parse("https://api.cloudflare.com/client/v4/")
                .expect("valid Cloudflare API URL"),
        }
    }
}

#[derive(Clone)]
pub struct Cloudflare {
    store: Store,
    endpoints: CloudflareEndpoints,
    client: Client,
    callback_url: Url,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

impl Cloudflare {
    pub fn new(store: Store, endpoints: CloudflareEndpoints, callback_url: Url) -> Result<Self> {
        Ok(Self {
            store,
            endpoints,
            client: Client::builder()
                .user_agent(concat!("hostknot/", env!("CARGO_PKG_VERSION")))
                .build()?,
            callback_url,
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn callback_url(&self) -> &Url {
        &self.callback_url
    }

    pub fn configured(&self) -> bool {
        self.store
            .cloudflare_configuration()
            .ok()
            .flatten()
            .is_some()
    }

    pub fn connected(&self) -> bool {
        self.store.cloudflare_connected().unwrap_or(false)
    }

    pub fn configure(&self, client_id: &str, client_secret: &str, scopes: &str) -> Result<()> {
        if client_id.trim().is_empty() || client_secret.trim().is_empty() {
            bail!("Cloudflare client ID and secret are required");
        }
        let scopes = normalize_scopes(scopes)?;
        self.store
            .configure_cloudflare(client_id.trim(), client_secret, &scopes)?;
        self.store
            .record_event("provider", "Cloudflare OAuth client configured")?;
        Ok(())
    }

    pub fn authorization_url(&self, session: &str) -> Result<Url> {
        let CloudflareConfiguration {
            client_id, scopes, ..
        } = self
            .store
            .cloudflare_configuration()?
            .context("Cloudflare is not configured")?;
        let attempt = self.store.create_oauth_attempt("cloudflare", session)?;
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(attempt.code_verifier.as_bytes()));
        let mut url = self.endpoints.authorization.clone();
        url.query_pairs_mut()
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", self.callback_url.as_str())
            .append_pair("response_type", "code")
            .append_pair("scope", &scopes)
            .append_pair("state", &attempt.state)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url)
    }

    pub async fn complete_authorization(
        &self,
        code: &str,
        state: &str,
        session: &str,
    ) -> Result<()> {
        if code.is_empty() || state.is_empty() {
            bail!("Cloudflare returned an incomplete authorization response");
        }
        let attempt = self
            .store
            .consume_oauth_attempt("cloudflare", state, session)?
            .context("invalid or expired OAuth state")?;
        let config = self
            .store
            .cloudflare_configuration()?
            .context("Cloudflare is not configured")?;
        let form = HashMap::from([
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.callback_url.as_str()),
            ("code_verifier", attempt.code_verifier.as_str()),
        ]);
        let response = self
            .client
            .post(self.endpoints.token.clone())
            .basic_auth(&config.client_id, Some(&config.client_secret))
            .form(&form)
            .send()
            .await
            .context("exchange Cloudflare authorization code")?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            tracing::warn!(%status, body = truncate_body(&body), "Cloudflare token exchange failed");
            bail!("Cloudflare token exchange failed with {status}");
        }
        let token: TokenResponse =
            serde_json::from_str(&body).context("decode Cloudflare token response")?;
        // Verify what was actually granted before reporting "connected":
        // a declined DNS Write scope or a missing refresh token would only
        // surface much later as an opaque failure.
        let granted = token.scope.as_deref().unwrap_or(&config.scopes);
        for required in ["zone.read", "dns.write"] {
            if !granted.split_whitespace().any(|scope| scope == required) {
                bail!(
                    "Cloudflare granted scopes '{granted}' but '{required}' is required; \
                     re-authorize and accept all requested permissions"
                );
            }
        }
        if token.refresh_token.is_none() {
            bail!(
                "Cloudflare did not return a refresh token; the connection would stop working \
                 when the access token expires. Ensure offline_access is granted."
            );
        }
        self.store.save_cloudflare_tokens(
            &token.access_token,
            token.refresh_token.as_deref(),
            token.expires_in,
            granted,
        )?;
        self.store
            .record_event("provider", "Cloudflare account connected")?;
        Ok(())
    }

    pub async fn disconnect(&self) -> Result<()> {
        // Best-effort token revocation at Cloudflare (RFC 7009 endpoint next
        // to the token endpoint); local disconnect proceeds regardless.
        if let Some(tokens) = self.store.cloudflare_tokens()?
            && let Some(config) = self.store.cloudflare_configuration()?
        {
            let mut revoke_url = self.endpoints.token.clone();
            let revoke_path = revoke_url.path().replace("/token", "/revoke");
            revoke_url.set_path(&revoke_path);
            for token in
                std::iter::once(tokens.access_token.as_str()).chain(tokens.refresh_token.as_deref())
            {
                if let Err(error) = self
                    .client
                    .post(revoke_url.clone())
                    .basic_auth(&config.client_id, Some(&config.client_secret))
                    .form(&[("token", token)])
                    .send()
                    .await
                {
                    tracing::warn!(%error, "Cloudflare token revocation failed; disconnecting locally anyway");
                }
            }
        }
        self.store.disconnect_cloudflare()?;
        self.store
            .record_event("provider", "Cloudflare account disconnected")?;
        Ok(())
    }

    pub fn cancel_authorization(&self, state: &str, session: &str) -> Result<()> {
        self.store
            .consume_oauth_attempt("cloudflare", state, session)?
            .context("invalid or expired OAuth state")?;
        Ok(())
    }

    async fn access_token(&self) -> Result<String> {
        let current = self
            .store
            .cloudflare_tokens()?
            .ok_or(DnsError::AuthorizationRequired)?;
        if current.expires_at > unix_now() + 30 {
            return Ok(current.access_token);
        }

        let _guard = self.refresh_lock.lock().await;
        let current = self
            .store
            .cloudflare_tokens()?
            .ok_or(DnsError::AuthorizationRequired)?;
        if current.expires_at > unix_now() + 30 {
            return Ok(current.access_token);
        }
        let refresh_token = current
            .refresh_token
            .as_deref()
            .ok_or(DnsError::AuthorizationRequired)?;
        let config = self
            .store
            .cloudflare_configuration()?
            .context("Cloudflare is not configured")?;
        let response = self
            .client
            .post(self.endpoints.token.clone())
            .basic_auth(&config.client_id, Some(&config.client_secret))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await
            .context("refresh Cloudflare access token")?;
        let status = response.status();
        let body = response.text().await?;
        if !status.is_success() {
            tracing::warn!(%status, body = truncate_body(&body), "Cloudflare token refresh failed");
            bail!("Cloudflare token refresh failed with {status}");
        }
        let token: TokenResponse =
            serde_json::from_str(&body).context("decode Cloudflare refresh response")?;
        self.store.save_cloudflare_tokens(
            &token.access_token,
            token.refresh_token.as_deref().or(Some(refresh_token)),
            token.expires_in,
            token.scope.as_deref().unwrap_or(&current.scopes),
        )?;
        self.store
            .record_event("provider", "Cloudflare access token refreshed")?;
        Ok(token.access_token)
    }

    async fn zones(&self, access_token: &str) -> Result<Vec<Zone>> {
        let mut zones = Vec::new();
        let mut page = 1_u32;
        loop {
            let mut url = self.endpoints.api.join("zones")?;
            url.query_pairs_mut()
                .append_pair("status", "active")
                .append_pair("per_page", "50")
                .append_pair("page", &page.to_string());
            let envelope: Envelope<Vec<Zone>> = self.get(access_token, url).await?;
            zones.extend(envelope.result);
            let total_pages = envelope
                .result_info
                .as_ref()
                .and_then(|info| info.total_pages)
                .unwrap_or(1);
            if page >= total_pages {
                break;
            }
            page += 1;
        }
        Ok(zones)
    }

    async fn records(
        &self,
        access_token: &str,
        zone_id: &str,
        hostname: &str,
    ) -> Result<Vec<DnsRecord>> {
        let mut records = Vec::new();
        let mut page = 1_u32;
        loop {
            let mut url = self
                .endpoints
                .api
                .join(&format!("zones/{zone_id}/dns_records"))?;
            url.query_pairs_mut()
                .append_pair("name", hostname)
                .append_pair("per_page", "100")
                .append_pair("page", &page.to_string());
            let envelope: Envelope<Vec<DnsRecord>> = self.get(access_token, url).await?;
            records.extend(envelope.result);
            let total_pages = envelope
                .result_info
                .as_ref()
                .and_then(|info| info.total_pages)
                .unwrap_or(1);
            if page >= total_pages {
                break;
            }
            page += 1;
        }
        Ok(records)
    }

    async fn create_record(
        &self,
        access_token: &str,
        zone_id: &str,
        record: &CreateRecord<'_>,
    ) -> Result<DnsRecord> {
        let url = self
            .endpoints
            .api
            .join(&format!("zones/{zone_id}/dns_records"))?;
        Ok(self
            .post::<_, Envelope<DnsRecord>>(access_token, url, record)
            .await?
            .result)
    }

    async fn delete_record(
        &self,
        access_token: &str,
        zone_id: &str,
        record_id: &str,
    ) -> Result<()> {
        let url = self
            .endpoints
            .api
            .join(&format!("zones/{zone_id}/dns_records/{record_id}"))?;
        let response = self
            .send_with_retry(|| self.client.delete(url.clone()).bearer_auth(access_token))
            .await?;
        // The envelope must be checked: Cloudflare can answer 200 with
        // success=false, and treating that as a completed delete would corrupt
        // the receipt bookkeeping.
        decode_envelope_response::<Envelope<serde_json::Value>>(response).await?;
        Ok(())
    }

    async fn update_record(
        &self,
        access_token: &str,
        zone_id: &str,
        record: &DnsRecord,
        proxied: bool,
    ) -> Result<DnsRecord> {
        let url = self
            .endpoints
            .api
            .join(&format!("zones/{zone_id}/dns_records/{}", record.id))?;
        let body = CreateRecord {
            record_type: &record.record_type,
            name: &record.name,
            content: &record.content,
            proxied,
            ttl: record.ttl,
            comment: record.comment.clone().unwrap_or_default(),
        };
        let response = self
            .send_with_retry(|| {
                self.client
                    .patch(url.clone())
                    .bearer_auth(access_token)
                    .json(&body)
            })
            .await?;
        Ok(decode_envelope_response::<Envelope<DnsRecord>>(response)
            .await?
            .result)
    }

    async fn get<T: DeserializeOwned>(&self, access_token: &str, url: Url) -> Result<T> {
        let response = self
            .send_with_retry(|| self.client.get(url.clone()).bearer_auth(access_token))
            .await?;
        decode_envelope_response(response).await
    }

    /// POSTs are sent exactly once: a retried create whose first attempt
    /// actually landed would leave an orphan DNS record outside the receipt.
    async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        access_token: &str,
        url: Url,
        body: &B,
    ) -> Result<T> {
        let response = self
            .client
            .post(url)
            .bearer_auth(access_token)
            .json(body)
            .send()
            .await?;
        decode_envelope_response(response).await
    }

    async fn send_with_retry(&self, build: impl Fn() -> RequestBuilder) -> Result<Response> {
        let mut delay = std::time::Duration::from_millis(100);
        for attempt in 0..4 {
            let response = build().send().await?;
            if response.status() != StatusCode::TOO_MANY_REQUESTS
                && !response.status().is_server_error()
            {
                return Ok(response);
            }
            if attempt == 3 {
                return Ok(response);
            }
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
                .map(std::time::Duration::from_secs)
                .unwrap_or(delay);
            tokio::time::sleep(retry_after.min(std::time::Duration::from_secs(5))).await;
            delay = (delay * 2).min(std::time::Duration::from_secs(2));
        }
        unreachable!("bounded retry loop always returns")
    }
}

#[async_trait]
impl DnsProvider for Cloudflare {
    async fn apply(&self, intent: &DnsIntent) -> Result<DnsReceipt> {
        let access_token = self.access_token().await?;
        let zones = self.zones(&access_token).await?;
        let zone = zones
            .into_iter()
            .filter(|zone| {
                intent.hostname == zone.name
                    || intent.hostname.ends_with(&format!(".{}", zone.name))
            })
            .max_by_key(|zone| zone.name.len())
            .context("no accessible active Cloudflare zone matches this hostname")?;
        let existing = self
            .records(&access_token, &zone.id, &intent.hostname)
            .await?;
        let conflicting: Vec<_> = existing
            .into_iter()
            .filter(|record| matches!(record.record_type.as_str(), "A" | "AAAA" | "CNAME"))
            .collect();
        if !conflicting.is_empty() && !intent.replace_existing {
            return Err(DnsError::Conflict.into());
        }
        if !conflicting.is_empty() {
            // Persist the pre-image durably BEFORE anything is deleted, so a
            // crash mid-replacement cannot silently lose the operator's
            // original records.
            self.store.record_event(
                "dns",
                &format!(
                    "Replacing existing records for {}: {}",
                    intent.hostname,
                    serde_json::to_string(&conflicting)?
                ),
            )?;
        }
        for record in &conflicting {
            self.delete_record(&access_token, &zone.id, &record.id)
                .await?;
        }
        let mut created = Vec::new();
        for public_ip in &intent.public_ips {
            let record_type = if public_ip.is_ipv4() { "A" } else { "AAAA" };
            let body = CreateRecord {
                record_type,
                name: &intent.hostname,
                content: &public_ip.to_string(),
                proxied: intent.proxied,
                ttl: 1,
                comment: format!("managed-by=hostknot binding={}", intent.binding_id),
            };
            match self.create_record(&access_token, &zone.id, &body).await {
                Ok(record) => created.push(record),
                Err(error) => {
                    for record in &created {
                        let _ = self
                            .delete_record(&access_token, &zone.id, &record.id)
                            .await;
                    }
                    for record in &conflicting {
                        let body = CreateRecord {
                            record_type: &record.record_type,
                            name: &record.name,
                            content: &record.content,
                            proxied: record.proxied,
                            ttl: record.ttl,
                            comment: record.comment.clone().unwrap_or_default(),
                        };
                        if let Err(restore_error) =
                            self.create_record(&access_token, &zone.id, &body).await
                        {
                            tracing::error!(%restore_error, record_id = record.id, "failed to restore DNS record after create failure");
                        }
                    }
                    return Err(error);
                }
            }
        }
        Ok(DnsReceipt {
            zone_id: zone.id,
            zone_name: zone.name,
            created,
            replaced: conflicting,
        })
    }

    async fn set_proxy_mode(&self, receipt: &DnsReceipt, proxied: bool) -> Result<DnsReceipt> {
        let access_token = self.access_token().await?;
        let hostname = receipt
            .created
            .first()
            .map(|record| record.name.as_str())
            .context("DNS receipt contains no managed records")?;
        let current = self
            .records(&access_token, &receipt.zone_id, hostname)
            .await?;
        for managed in &receipt.created {
            let unchanged = current.iter().any(|record| {
                record.id == managed.id
                    && record.record_type == managed.record_type
                    && record.name == managed.name
                    && record.content == managed.content
                    && record.proxied == managed.proxied
            });
            if !unchanged {
                return Err(DnsError::Drift.into());
            }
        }
        let mut updated = Vec::with_capacity(receipt.created.len());
        for record in &receipt.created {
            match self
                .update_record(&access_token, &receipt.zone_id, record, proxied)
                .await
            {
                Ok(record) => updated.push(record),
                Err(error) => {
                    for (changed, original) in updated.iter().zip(receipt.created.iter()) {
                        if let Err(rollback_error) = self
                            .update_record(
                                &access_token,
                                &receipt.zone_id,
                                changed,
                                original.proxied,
                            )
                            .await
                        {
                            tracing::error!(%rollback_error, record_id = changed.id, "failed to roll back DNS proxy-mode update");
                        }
                    }
                    return Err(error);
                }
            }
        }
        Ok(DnsReceipt {
            zone_id: receipt.zone_id.clone(),
            zone_name: receipt.zone_name.clone(),
            created: updated,
            replaced: receipt.replaced.clone(),
        })
    }

    async fn revert(&self, receipt: &DnsReceipt) -> Result<()> {
        let access_token = self.access_token().await?;
        let hostname = receipt
            .created
            .first()
            .or_else(|| receipt.replaced.first())
            .map(|record| record.name.as_str())
            .context("DNS receipt contains no records")?;
        let current = self
            .records(&access_token, &receipt.zone_id, hostname)
            .await?;
        for managed in &receipt.created {
            let unchanged = current.iter().any(|record| {
                record.id == managed.id
                    && record.record_type == managed.record_type
                    && record.name == managed.name
                    && record.content == managed.content
                    && record.proxied == managed.proxied
            });
            if !unchanged {
                return Err(DnsError::Drift.into());
            }
        }
        for record in &receipt.created {
            self.delete_record(&access_token, &receipt.zone_id, &record.id)
                .await?;
        }
        for record in &receipt.replaced {
            // Restore idempotently: an operator may already have re-created
            // the prior record by hand.
            let already_present = current.iter().any(|existing| {
                existing.record_type == record.record_type
                    && existing.name == record.name
                    && existing.content == record.content
            });
            if already_present {
                continue;
            }
            let body = CreateRecord {
                record_type: &record.record_type,
                name: &record.name,
                content: &record.content,
                proxied: record.proxied,
                ttl: record.ttl,
                comment: record.comment.clone().unwrap_or_default(),
            };
            self.create_record(&access_token, &receipt.zone_id, &body)
                .await?;
        }
        Ok(())
    }
}

fn normalize_scopes(scopes: &str) -> Result<String> {
    let mut scopes: Vec<_> = scopes.split_whitespace().collect();
    scopes.sort_unstable();
    scopes.dedup();
    if !scopes.contains(&"offline_access") {
        scopes.push("offline_access");
    }
    if !scopes.contains(&"zone.read") || !scopes.contains(&"dns.write") {
        bail!("Zone Read, DNS Write, and offline access scopes are required");
    }
    Ok(scopes.join(" "))
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: i64,
    scope: Option<String>,
}

#[derive(Clone, Deserialize)]
struct Zone {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct Envelope<T> {
    result: T,
    result_info: Option<ResultInfo>,
}

#[derive(Deserialize)]
struct ResultInfo {
    total_pages: Option<u32>,
}

#[derive(Serialize)]
struct CreateRecord<'a> {
    #[serde(rename = "type")]
    record_type: &'a str,
    name: &'a str,
    content: &'a str,
    proxied: bool,
    ttl: u32,
    comment: String,
}

fn truncate_body(body: &str) -> String {
    const LIMIT: usize = 256;
    if body.len() <= LIMIT {
        body.to_owned()
    } else {
        let cut = body
            .char_indices()
            .take_while(|(index, _)| *index < LIMIT)
            .last()
            .map(|(index, character)| index + character.len_utf8())
            .unwrap_or(0);
        format!("{}…", &body[..cut])
    }
}

async fn decode_envelope_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        bail!(
            "Cloudflare API request failed with {status}: {}",
            truncate_body(&body)
        );
    }
    let value: serde_json::Value =
        serde_json::from_str(&body).context("decode Cloudflare API response")?;
    if value.get("success").and_then(serde_json::Value::as_bool) == Some(false) {
        let messages = value
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|error| error.get("message").and_then(serde_json::Value::as_str))
            .collect::<Vec<_>>()
            .join("; ");
        bail!("Cloudflare API rejected the request: {messages}");
    }
    let decoded: T = serde_json::from_value(value).context("decode Cloudflare API response")?;
    Ok(decoded)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_secs() as i64
}
