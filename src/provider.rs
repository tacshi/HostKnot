use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct DnsIntent {
    pub binding_id: String,
    pub hostname: String,
    pub public_ips: Vec<IpAddr>,
    pub proxied: bool,
    pub replace_existing: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsReceipt {
    pub zone_id: String,
    pub zone_name: String,
    pub created: Vec<DnsRecord>,
    pub replaced: Vec<DnsRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub content: String,
    #[serde(default)]
    pub proxied: bool,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    #[serde(default)]
    pub comment: Option<String>,
}

fn default_ttl() -> u32 {
    1
}

/// Well-known provider failures that drive control flow (the conflict
/// confirmation interstitial, the drifted binding state). Providers bail with
/// these so callers can `downcast_ref` instead of matching error strings.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("DNS provider authorization is required")]
    AuthorizationRequired,
    #[error("DNS conflict: the hostname already has A, AAAA, or CNAME records")]
    Conflict,
    #[error("DNS drift detected; Hostknot left external records untouched")]
    Drift,
}

pub fn is_authorization_required(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<DnsError>(),
        Some(DnsError::AuthorizationRequired)
    )
}

pub fn is_conflict(error: &anyhow::Error) -> bool {
    matches!(error.downcast_ref::<DnsError>(), Some(DnsError::Conflict))
}

pub fn is_drift(error: &anyhow::Error) -> bool {
    matches!(error.downcast_ref::<DnsError>(), Some(DnsError::Drift))
}

#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn apply(&self, intent: &DnsIntent) -> anyhow::Result<DnsReceipt>;
    async fn set_proxy_mode(
        &self,
        receipt: &DnsReceipt,
        proxied: bool,
    ) -> anyhow::Result<DnsReceipt>;
    async fn revert(&self, receipt: &DnsReceipt) -> anyhow::Result<()>;
}

#[cfg(test)]
pub struct InMemoryDnsProvider {
    records: std::sync::Mutex<Vec<DnsRecord>>,
}

#[cfg(test)]
impl InMemoryDnsProvider {
    pub fn new(records: Vec<DnsRecord>) -> Self {
        Self {
            records: std::sync::Mutex::new(records),
        }
    }

    pub fn records(&self) -> Vec<DnsRecord> {
        self.records.lock().unwrap().clone()
    }
}

#[cfg(test)]
#[async_trait]
impl DnsProvider for InMemoryDnsProvider {
    async fn apply(&self, intent: &DnsIntent) -> anyhow::Result<DnsReceipt> {
        let mut records = self.records.lock().unwrap();
        let replaced = records
            .iter()
            .filter(|record| {
                record.name == intent.hostname
                    && matches!(record.record_type.as_str(), "A" | "AAAA" | "CNAME")
            })
            .cloned()
            .collect::<Vec<_>>();
        if !replaced.is_empty() && !intent.replace_existing {
            return Err(DnsError::Conflict.into());
        }
        records.retain(|record| !replaced.iter().any(|prior| prior.id == record.id));
        let created = intent
            .public_ips
            .iter()
            .enumerate()
            .map(|(index, address)| DnsRecord {
                id: format!("{}-{index}", intent.binding_id),
                record_type: if address.is_ipv4() { "A" } else { "AAAA" }.to_owned(),
                name: intent.hostname.clone(),
                content: address.to_string(),
                proxied: intent.proxied,
                ttl: 1,
                comment: Some("managed-by=hostknot".to_owned()),
            })
            .collect::<Vec<_>>();
        records.extend(created.clone());
        Ok(DnsReceipt {
            zone_id: "memory".to_owned(),
            zone_name: intent
                .hostname
                .split_once('.')
                .map(|(_, suffix)| suffix)
                .unwrap_or(&intent.hostname)
                .to_owned(),
            created,
            replaced,
        })
    }

    async fn set_proxy_mode(
        &self,
        receipt: &DnsReceipt,
        proxied: bool,
    ) -> anyhow::Result<DnsReceipt> {
        let mut records = self.records.lock().unwrap();
        for expected in &receipt.created {
            let current = records
                .iter_mut()
                .find(|record| record.id == expected.id)
                .ok_or_else(|| anyhow::Error::from(DnsError::Drift))?;
            if current.content != expected.content || current.proxied != expected.proxied {
                return Err(DnsError::Drift.into());
            }
            current.proxied = proxied;
        }
        let mut updated = receipt.clone();
        for record in &mut updated.created {
            record.proxied = proxied;
        }
        Ok(updated)
    }

    async fn revert(&self, receipt: &DnsReceipt) -> anyhow::Result<()> {
        let mut records = self.records.lock().unwrap();
        for expected in &receipt.created {
            if !records.iter().any(|record| {
                record.id == expected.id
                    && record.content == expected.content
                    && record.proxied == expected.proxied
            }) {
                return Err(DnsError::Drift.into());
            }
        }
        records.retain(|record| !receipt.created.iter().any(|item| item.id == record.id));
        records.extend(receipt.replaced.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_provider_round_trips_an_opaque_receipt() {
        let prior = DnsRecord {
            id: "prior".to_owned(),
            record_type: "CNAME".to_owned(),
            name: "app.example.com".to_owned(),
            content: "old.example.net".to_owned(),
            proxied: false,
            ttl: 300,
            comment: None,
        };
        let provider = InMemoryDnsProvider::new(vec![prior.clone()]);
        let receipt = provider
            .apply(&DnsIntent {
                binding_id: "binding".to_owned(),
                hostname: "app.example.com".to_owned(),
                public_ips: vec!["203.0.113.10".parse().unwrap()],
                proxied: true,
                replace_existing: true,
            })
            .await
            .unwrap();
        assert_eq!(provider.records()[0].record_type, "A");
        provider.revert(&receipt).await.unwrap();
        assert_eq!(provider.records()[0].id, prior.id);
    }
}
