use anyhow::{Context, Result, bail};
use rusqlite::{OptionalExtension, params};

use super::Store;
use crate::{
    model::{Binding, BindingHealth, BindingStatus, CertificateStatus, PendingBindingUpdate},
    provider::{DnsPlan, DnsReceipt},
};

impl Store {
    pub fn create_binding(
        &self,
        id: &str,
        hostname: &str,
        upstream_scheme: &str,
        upstream_port: u16,
        proxied: bool,
        replace_confirmed: bool,
    ) -> Result<Binding> {
        self.connection()?.execute(
            "INSERT INTO bindings(
               id, hostname, upstream_scheme, upstream_port, proxied,
               replace_confirmed, status, certificate_status, health, created_at, updated_at
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)",
            params![
                id,
                hostname,
                upstream_scheme,
                upstream_port,
                proxied,
                replace_confirmed,
                BindingStatus::DnsPending.as_str(),
                CertificateStatus::Pending.as_str(),
                BindingHealth::Unknown.as_str(),
                self.now()
            ],
        )?;
        self.invalidate_routes();
        self.binding(id)?
            .context("newly inserted binding was not found")
    }

    pub fn binding(&self, id: &str) -> Result<Option<Binding>> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT id, hostname, upstream_scheme, upstream_port, proxied,
                        status, certificate_status, health, last_error, replace_confirmed
                 FROM bindings WHERE id = ?1",
                [id],
                binding_from_row,
            )
            .optional()?)
    }

    pub fn list_bindings(&self) -> Result<Vec<Binding>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, hostname, upstream_scheme, upstream_port, proxied,
                    status, certificate_status, health, last_error, replace_confirmed
             FROM bindings ORDER BY hostname",
        )?;
        let rows = statement.query_map([], binding_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn active_binding(&self, hostname: &str) -> Result<Option<Binding>> {
        Ok(self
            .active_routing_table(hostname)?
            .map(|table| table.binding))
    }

    pub(super) fn binding_for_hostname(&self, hostname: &str) -> Result<Option<Binding>> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT id, hostname, upstream_scheme, upstream_port, proxied,
                        status, certificate_status, health, last_error, replace_confirmed
                 FROM bindings WHERE hostname = ?1",
                [hostname],
                binding_from_row,
            )
            .optional()?
            .filter(Binding::is_routable))
    }

    pub fn hostname_is_routable(&self, hostname: &str) -> Result<bool> {
        Ok(self.active_binding(hostname)?.is_some())
    }

    /// Persist the provider's complete pre-image before the first remote DNS
    /// write. Reconciliation can safely replay this plan after any crash.
    pub fn save_binding_dns_plan(&self, id: &str, plan: &DnsPlan) -> Result<()> {
        self.transition(
            "UPDATE bindings SET dns_plan = ?1, last_error = NULL,
               updated_at = ?2 WHERE id = ?3 AND status = 'dns_pending'",
            params![serde_json::to_string(plan)?, self.now(), id],
        )
    }

    /// Applies one lifecycle step, but only from the state the caller
    /// expects (encoded in the statement's WHERE clause). Steps are already
    /// serialized per binding; this makes a lost race fail loudly instead of
    /// silently overwriting a newer state.
    fn transition(&self, sql: &str, params: impl rusqlite::Params) -> Result<()> {
        let changed = self.connection()?.execute(sql, params)?;
        self.invalidate_routes();
        if changed == 0 {
            bail!("the binding changed state while this step ran; nothing was applied");
        }
        Ok(())
    }

    pub fn binding_dns_plan(&self, id: &str) -> Result<Option<DnsPlan>> {
        let plan: Option<String> = self
            .connection()?
            .query_row(
                "SELECT dns_plan FROM bindings WHERE id = ?1 AND dns_plan IS NOT NULL",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        plan.map(|plan| serde_json::from_str(&plan).context("decode DNS mutation plan"))
            .transpose()
    }

    pub fn mark_binding_certificate_pending(&self, id: &str, receipt: &DnsReceipt) -> Result<()> {
        self.transition(
            "UPDATE bindings SET zone_id = ?1, dns_receipt = ?2,
               dns_plan = NULL, status = ?3, certificate_status = ?4,
               last_error = NULL, updated_at = ?5 WHERE id = ?6 AND status = 'dns_pending'",
            params![
                receipt.zone_id,
                serde_json::to_string(receipt)?,
                BindingStatus::CertificatePending.as_str(),
                CertificateStatus::Pending.as_str(),
                self.now(),
                id
            ],
        )
    }

    pub fn mark_binding_active(&self, id: &str) -> Result<()> {
        self.transition(
            "UPDATE bindings SET status = ?1, certificate_status = ?2,
               health = ?3, last_error = NULL, pending_update = NULL,
               updated_at = ?4 WHERE id = ?5 AND status = 'certificate_pending'",
            params![
                BindingStatus::Active.as_str(),
                CertificateStatus::Active.as_str(),
                BindingHealth::Unknown.as_str(),
                self.now(),
                id,
            ],
        )
    }

    /// Records why a step in `status` failed. It never changes the status:
    /// if the binding has already moved on, the stale error is dropped.
    pub fn mark_binding_error(&self, id: &str, status: BindingStatus, error: &str) -> Result<()> {
        self.connection()?.execute(
            "UPDATE bindings SET last_error = ?1, updated_at = ?2 WHERE id = ?3 AND status = ?4",
            params![error, self.now(), id, status.as_str()],
        )?;
        self.invalidate_routes();
        Ok(())
    }

    pub fn update_binding_local(&self, id: &str, update: &PendingBindingUpdate) -> Result<()> {
        self.transition(
            "UPDATE bindings SET upstream_scheme = ?1, upstream_port = ?2,
               proxied = ?3, last_error = NULL, updated_at = ?4
             WHERE id = ?5 AND status IN ('active', 'degraded')",
            params![
                update.upstream_scheme,
                update.upstream_port,
                update.proxied,
                self.now(),
                id,
            ],
        )
    }

    /// Move an externally-visible edit into a durable intermediate state
    /// before changing the provider. The requested local values remain in the
    /// journal until the provider mutation and SQLite commit both finish.
    pub fn begin_binding_update(&self, id: &str, update: &PendingBindingUpdate) -> Result<()> {
        self.transition(
            "UPDATE bindings SET status = ?1, pending_update = ?2,
               last_error = NULL, updated_at = ?3
             WHERE id = ?4 AND status IN ('active', 'degraded')",
            params![
                BindingStatus::Updating.as_str(),
                serde_json::to_string(update)?,
                self.now(),
                id,
            ],
        )
    }

    pub fn pending_binding_update(&self, id: &str) -> Result<Option<PendingBindingUpdate>> {
        let update: Option<String> = self
            .connection()?
            .query_row(
                "SELECT pending_update FROM bindings
                 WHERE id = ?1 AND pending_update IS NOT NULL",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        update
            .map(|update| serde_json::from_str(&update).context("decode pending binding update"))
            .transpose()
    }

    pub fn finish_binding_update(
        &self,
        id: &str,
        update: &PendingBindingUpdate,
        receipt: &DnsReceipt,
    ) -> Result<()> {
        self.transition(
            "UPDATE bindings SET upstream_scheme = ?1, upstream_port = ?2,
               proxied = ?3, dns_receipt = ?4, pending_update = NULL,
               status = CASE WHEN health = ?5 THEN ?6 ELSE ?7 END,
               last_error = NULL, updated_at = ?8 WHERE id = ?9 AND status = 'updating'",
            params![
                update.upstream_scheme,
                update.upstream_port,
                update.proxied,
                serde_json::to_string(receipt)?,
                BindingHealth::Unavailable.as_str(),
                BindingStatus::Degraded.as_str(),
                BindingStatus::Active.as_str(),
                self.now(),
                id,
            ],
        )
    }

    pub fn begin_binding_removal(&self, id: &str) -> Result<()> {
        self.transition(
            "UPDATE bindings SET status = ?1, last_error = NULL, updated_at = ?2
             WHERE id = ?3 AND status NOT IN ('removing', 'draining', 'updating')",
            params![BindingStatus::Removing.as_str(), self.now(), id],
        )
    }

    pub fn binding_receipt(&self, id: &str) -> Result<Option<DnsReceipt>> {
        let receipt: Option<String> = self
            .connection()?
            .query_row(
                "SELECT dns_receipt FROM bindings WHERE id = ?1 AND dns_receipt IS NOT NULL",
                [id],
                |row| row.get(0),
            )
            .optional()?;
        receipt
            .map(|receipt| serde_json::from_str(&receipt).context("decode DNS receipt"))
            .transpose()
    }

    pub fn save_binding_removal_receipt(&self, id: &str, receipt: &DnsReceipt) -> Result<()> {
        self.transition(
            "UPDATE bindings SET zone_id = ?1, dns_receipt = ?2, dns_plan = NULL,
               updated_at = ?3 WHERE id = ?4 AND status = 'removing'",
            params![
                receipt.zone_id,
                serde_json::to_string(receipt)?,
                self.now(),
                id,
            ],
        )
    }

    pub fn mark_binding_draining(&self, id: &str, duration: std::time::Duration) -> Result<()> {
        self.transition(
            "UPDATE bindings SET status = ?1, drain_until = ?2, pending_update = NULL,
               dns_plan = NULL, last_error = NULL, updated_at = ?3
             WHERE id = ?4 AND status = 'removing'",
            params![
                BindingStatus::Draining.as_str(),
                self.now() + duration.as_secs() as i64,
                self.now(),
                id,
            ],
        )
    }

    /// Puts a binding straight into `status`, skipping the lifecycle guards.
    #[cfg(test)]
    pub(crate) fn set_binding_status_for_test(&self, id: &str, status: BindingStatus) {
        self.connection()
            .unwrap()
            .execute(
                "UPDATE bindings SET status = ?1 WHERE id = ?2",
                params![status.as_str(), id],
            )
            .unwrap();
        self.invalidate_routes();
    }

    /// Drops a binding that never reached the provider (a create refused
    /// over a DNS conflict).
    pub fn delete_binding(&self, id: &str) -> Result<()> {
        self.transition(
            "DELETE FROM bindings WHERE id = ?1 AND status = 'dns_pending' AND dns_receipt IS NULL",
            [id],
        )
    }

    /// Drops a binding whose drain finished. Returns false if it is not
    /// draining (already deleted, or a stale timer).
    pub fn delete_drained_binding(&self, id: &str) -> Result<bool> {
        let deleted = self.connection()?.execute(
            "DELETE FROM bindings WHERE id = ?1 AND status = 'draining'",
            [id],
        )?;
        self.invalidate_routes();
        Ok(deleted > 0)
    }

    pub fn draining_bindings(&self) -> Result<Vec<(String, String, i64)>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, hostname, drain_until FROM bindings
             WHERE status = ?1 AND drain_until IS NOT NULL",
        )?;
        let rows = statement.query_map([BindingStatus::Draining.as_str()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn update_binding_health(
        &self,
        id: &str,
        healthy: bool,
        error: Option<&str>,
    ) -> Result<()> {
        let (health, status) = if healthy {
            (BindingHealth::Healthy, BindingStatus::Active)
        } else {
            (BindingHealth::Unavailable, BindingStatus::Degraded)
        };
        self.connection()?.execute(
            "UPDATE bindings SET health = ?1, status = ?4,
               last_error = ?5, updated_at = ?6
             WHERE id = ?7 AND status IN (?2, ?3)",
            params![
                health.as_str(),
                BindingStatus::Active.as_str(),
                BindingStatus::Degraded.as_str(),
                status.as_str(),
                error,
                self.now(),
                id,
            ],
        )?;
        self.invalidate_routes();
        Ok(())
    }
}

fn binding_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Binding> {
    let status = row.get::<_, String>(5)?;
    let certificate_status = row.get::<_, String>(6)?;
    let health = row.get::<_, String>(7)?;
    Ok(Binding {
        id: row.get(0)?,
        hostname: row.get(1)?,
        upstream_scheme: row.get(2)?,
        upstream_port: row.get(3)?,
        proxied: row.get(4)?,
        status: BindingStatus::try_from(status.as_str()).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        certificate_status: CertificateStatus::try_from(certificate_status.as_str()).map_err(
            |error| {
                rusqlite::Error::FromSqlConversionFailure(
                    6,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            },
        )?,
        health: BindingHealth::try_from(health.as_str()).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                7,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        last_error: row.get(8)?,
        replace_confirmed: row.get(9)?,
    })
}
