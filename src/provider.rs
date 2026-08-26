use std::net::IpAddr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsIntent {
    pub binding_id: String,
    pub hostname: String,
    pub public_ips: Vec<IpAddr>,
    pub proxied: bool,
    pub replace_existing: bool,
}

/// A provider mutation plan is persisted before its first remote side effect.
/// Keeping the original DNS pre-image here makes `apply` safely repeatable
/// after a process crash or an ambiguous HTTP response.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsPlan {
    pub binding_id: String,
    pub hostname: String,
    pub public_ips: Vec<IpAddr>,
    pub proxied: bool,
    pub zone_id: String,
    pub zone_name: String,
    pub replaced: Vec<DnsRecord>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DnsReceipt {
    pub zone_id: String,
    pub zone_name: String,
    pub created: Vec<DnsRecord>,
    pub replaced: Vec<DnsRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
/// confirmation interstitial, the retryable removal state). Providers bail with
/// these so callers can `downcast_ref` instead of matching error strings.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("DNS provider authorization is required")]
    AuthorizationRequired,
    #[error("DNS conflict: the hostname already has A, AAAA, or CNAME records")]
    Conflict,
    #[error("DNS drift detected; HostKnot left external records untouched")]
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
    async fn prepare(&self, intent: &DnsIntent) -> anyhow::Result<DnsPlan>;
    async fn apply(&self, plan: &DnsPlan) -> anyhow::Result<DnsReceipt>;
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
    async fn prepare(&self, intent: &DnsIntent) -> anyhow::Result<DnsPlan> {
        let records = self.records.lock().unwrap();
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
        Ok(DnsPlan {
            binding_id: intent.binding_id.clone(),
            hostname: intent.hostname.clone(),
            public_ips: intent.public_ips.clone(),
            proxied: intent.proxied,
            zone_id: "memory".to_owned(),
            zone_name: intent
                .hostname
                .split_once('.')
                .map(|(_, suffix)| suffix)
                .unwrap_or(&intent.hostname)
                .to_owned(),
            replaced,
        })
    }

    async fn apply(&self, plan: &DnsPlan) -> anyhow::Result<DnsReceipt> {
        let mut records = self.records.lock().unwrap();
        records.retain(|record| {
            !plan
                .replaced
                .iter()
                .any(|prior| records_match_except_id(record, prior))
        });
        let managed_comment = format!("managed-by=hostknot binding={}", plan.binding_id);
        let mut created = Vec::new();
        for (index, address) in plan.public_ips.iter().enumerate() {
            let record_type = if address.is_ipv4() { "A" } else { "AAAA" };
            if let Some(record) = records.iter().find(|record| {
                record.record_type == record_type
                    && record.name == plan.hostname
                    && record.content == address.to_string()
                    && record.proxied == plan.proxied
                    && record.ttl == 1
                    && record.comment.as_deref() == Some(managed_comment.as_str())
            }) {
                created.push(record.clone());
                continue;
            }
            let record = DnsRecord {
                id: format!("{}-{index}", plan.binding_id),
                record_type: record_type.to_owned(),
                name: plan.hostname.clone(),
                content: address.to_string(),
                proxied: plan.proxied,
                ttl: 1,
                comment: Some(managed_comment.clone()),
            };
            records.push(record.clone());
            created.push(record);
        }
        Ok(DnsReceipt {
            zone_id: plan.zone_id.clone(),
            zone_name: plan.zone_name.clone(),
            created,
            replaced: plan.replaced.clone(),
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
                .iter()
                .find(|record| record.id == expected.id)
                .ok_or_else(|| anyhow::Error::from(DnsError::Drift))?;
            if current.record_type != expected.record_type
                || current.name != expected.name
                || current.content != expected.content
                || current.ttl != expected.ttl
                || !comments_match(&current.comment, &expected.comment)
                || (current.proxied != expected.proxied && current.proxied != proxied)
            {
                return Err(DnsError::Drift.into());
            }
        }
        for expected in &receipt.created {
            let current = records
                .iter_mut()
                .find(|record| record.id == expected.id)
                .expect("managed records were validated above");
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
        // Mirror the production adapter: absence is already-reverted, only a
        // modified record is drift.
        if records.iter().any(|record| {
            receipt.created.iter().any(|managed| {
                managed.comment.as_deref().is_some_and(|comment| {
                    !comment.is_empty() && record.comment.as_deref() == Some(comment)
                })
            }) && !receipt
                .created
                .iter()
                .any(|managed| records_match_except_id(record, managed))
        }) {
            return Err(DnsError::Drift.into());
        }
        for expected in &receipt.created {
            match records.iter().find(|record| record.id == expected.id) {
                Some(record) if !records_match_except_id(record, expected) => {
                    return Err(DnsError::Drift.into());
                }
                Some(_) | None => {}
            }
        }
        records.retain(|record| {
            !receipt
                .created
                .iter()
                .any(|item| item.id == record.id || records_match_except_id(record, item))
        });
        for replaced in &receipt.replaced {
            if !records.iter().any(|record| record.id == replaced.id) {
                records.push(replaced.clone());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
fn records_match_except_id(left: &DnsRecord, right: &DnsRecord) -> bool {
    left.record_type == right.record_type
        && left.name == right.name
        && left.content == right.content
        && left.proxied == right.proxied
        && left.ttl == right.ttl
        && comments_match(&left.comment, &right.comment)
}

#[cfg(test)]
fn comments_match(left: &Option<String>, right: &Option<String>) -> bool {
    left.as_deref().filter(|comment| !comment.is_empty())
        == right.as_deref().filter(|comment| !comment.is_empty())
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
        let plan = provider
            .prepare(&DnsIntent {
                binding_id: "binding".to_owned(),
                hostname: "app.example.com".to_owned(),
                public_ips: vec!["203.0.113.10".parse().unwrap()],
                proxied: true,
                replace_existing: true,
            })
            .await
            .unwrap();
        let receipt = provider.apply(&plan).await.unwrap();
        assert_eq!(provider.records()[0].record_type, "A");
        provider.revert(&receipt).await.unwrap();
        assert_eq!(provider.records()[0].id, prior.id);
    }

    #[tokio::test]
    async fn provider_drift_validation_happens_before_any_mutation() {
        let provider = InMemoryDnsProvider::new(Vec::new());
        let plan = provider
            .prepare(&DnsIntent {
                binding_id: "binding".to_owned(),
                hostname: "app.example.com".to_owned(),
                public_ips: vec![
                    "203.0.113.10".parse().unwrap(),
                    "2001:db8::10".parse().unwrap(),
                ],
                proxied: false,
                replace_existing: false,
            })
            .await
            .unwrap();
        let receipt = provider.apply(&plan).await.unwrap();
        provider.records.lock().unwrap()[1].ttl = 300;

        let error = provider.set_proxy_mode(&receipt, true).await.unwrap_err();
        assert!(is_drift(&error));
        assert!(provider.records().iter().all(|record| !record.proxied));

        let error = provider.revert(&receipt).await.unwrap_err();
        assert!(is_drift(&error));
        assert_eq!(provider.records().len(), 2);
    }

    #[tokio::test]
    async fn revert_restores_a_same_address_preimage_after_deleting_the_managed_record() {
        let prior = DnsRecord {
            id: "prior".to_owned(),
            record_type: "A".to_owned(),
            name: "app.example.com".to_owned(),
            content: "203.0.113.10".to_owned(),
            proxied: false,
            ttl: 300,
            comment: None,
        };
        let provider = InMemoryDnsProvider::new(vec![prior.clone()]);
        let plan = provider
            .prepare(&DnsIntent {
                binding_id: "binding".to_owned(),
                hostname: "app.example.com".to_owned(),
                public_ips: vec!["203.0.113.10".parse().unwrap()],
                proxied: true,
                replace_existing: true,
            })
            .await
            .unwrap();
        let receipt = provider.apply(&plan).await.unwrap();

        provider.revert(&receipt).await.unwrap();

        assert_eq!(provider.records(), vec![prior]);
    }

    #[tokio::test]
    async fn revert_accepts_a_provider_reissued_managed_record_id() {
        let provider = InMemoryDnsProvider::new(Vec::new());
        let plan = provider
            .prepare(&DnsIntent {
                binding_id: "binding".to_owned(),
                hostname: "app.example.com".to_owned(),
                public_ips: vec!["203.0.113.10".parse().unwrap()],
                proxied: false,
                replace_existing: false,
            })
            .await
            .unwrap();
        let receipt = provider.apply(&plan).await.unwrap();
        provider.records.lock().unwrap()[0].id = "replacement-id".to_owned();

        provider.revert(&receipt).await.unwrap();

        assert!(provider.records().is_empty());
    }
}
