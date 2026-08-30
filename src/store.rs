mod bindings;
mod path_routes;
mod schema;

use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::clock::Clock;
use crate::crypto::Vault;
use crate::model::{Binding, BindingPathRoute};

#[derive(Clone)]
pub struct Store {
    connection: Arc<Mutex<Connection>>,
    vault: Vault,
    clock: Clock,
    /// Short-lived per-hostname routing cache so the proxy hot path does not
    /// serialize every request on a SQLite query behind the global mutex.
    /// Any binding mutation clears it.
    route_cache: Arc<Mutex<RouteCache>>,
}

#[derive(Clone)]
struct RoutingTable {
    binding: Binding,
    path_routes: Vec<BindingPathRoute>,
}

type RouteCache = HashMap<String, (Instant, Option<RoutingTable>)>;

const ROUTE_CACHE_TTL: Duration = Duration::from_secs(2);

pub struct CloudflareConfiguration {
    pub client_id: String,
    pub client_secret: String,
    pub scopes: String,
}

pub struct CloudflareTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: i64,
    pub scopes: String,
}

pub struct OAuthAttempt {
    pub state: String,
    pub code_verifier: String,
}

pub struct StoredCertificate {
    pub identifier: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub not_after: i64,
    pub renew_at: i64,
}

pub struct Event {
    pub kind: String,
    pub message: String,
    pub created_at: i64,
}

impl Store {
    pub fn open(state_dir: &Path) -> Result<Self> {
        Self::open_with_clock(state_dir, Clock::system())
    }

    pub fn open_with_clock(state_dir: &Path, clock: Clock) -> Result<Self> {
        fs::create_dir_all(state_dir)
            .with_context(|| format!("create state directory {}", state_dir.display()))?;
        set_dir_permissions(state_dir)?;
        let master_key = ensure_master_key(&state_dir.join("master.key"))?;

        let connection = Connection::open(state_dir.join("hostknot.sqlite3"))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        schema::migrate(&connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            vault: Vault::new(master_key),
            clock,
            route_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    pub fn clock(&self) -> Clock {
        self.clock.clone()
    }

    fn now(&self) -> i64 {
        self.clock.now()
    }

    pub fn issue_bootstrap_if_unconfigured(&self) -> Result<Option<String>> {
        let mut connection = self.connection()?;
        let has_admin = connection
            .query_row("SELECT 1 FROM administrator LIMIT 1", [], |_| Ok(()))
            .optional()?
            .is_some();
        if has_admin {
            return Ok(None);
        }

        let token = random_token();
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO settings(key, value) VALUES('bootstrap_token_hash', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [hex::encode(token_hash(&token))],
        )?;
        transaction.execute(
            "INSERT INTO settings(key, value) VALUES('bootstrap_token_issued_at', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [self.now().to_string()],
        )?;
        transaction.execute(
            "INSERT INTO events(kind, message, created_at) VALUES('security', 'Bootstrap token issued', ?1)",
            [self.now()],
        )?;
        transaction.commit()?;
        Ok(Some(token))
    }

    /// Bootstrap tokens are printed to stdout (and thus the systemd journal),
    /// so an unused token must not remain a valid credential forever.
    const BOOTSTRAP_TOKEN_TTL: i64 = 60 * 60;

    pub fn bootstrap_valid(&self, token: &str) -> Result<bool> {
        let connection = self.connection()?;
        let expected: Option<String> = connection
            .query_row(
                "SELECT value FROM settings WHERE key = 'bootstrap_token_hash'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(expected) = expected else {
            return Ok(false);
        };
        let issued_at: Option<String> = connection
            .query_row(
                "SELECT value FROM settings WHERE key = 'bootstrap_token_issued_at'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let expired = issued_at
            .and_then(|value| value.parse::<i64>().ok())
            .is_none_or(|issued_at| self.now() > issued_at + Self::BOOTSTRAP_TOKEN_TTL);
        if expired {
            return Ok(false);
        }
        let supplied = hex::encode(token_hash(token));
        Ok(expected.as_bytes().ct_eq(supplied.as_bytes()).into())
    }

    pub fn complete_setup(&self, token: &str, password: &str, acme_email: &str) -> Result<String> {
        if password.chars().count() < 12 {
            bail!("password must contain at least 12 characters");
        }
        if !valid_email(acme_email) {
            bail!("a valid ACME contact email is required");
        }
        if !self.bootstrap_valid(token)? {
            bail!("invalid or already-used bootstrap token");
        }

        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .map_err(|error| anyhow::anyhow!("hash password: {error}"))?
            .to_string();
        let session = random_token();
        let csrf = random_token();
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO administrator(singleton, password_hash, created_at) VALUES(1, ?1, ?2)",
            params![password_hash, self.now()],
        )?;
        transaction.execute(
            "INSERT INTO settings(key, value) VALUES('acme_email', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [acme_email],
        )?;
        transaction.execute(
            "DELETE FROM settings WHERE key IN ('bootstrap_token_hash', 'bootstrap_token_issued_at')",
            [],
        )?;
        transaction.execute(
            "INSERT INTO sessions(token_hash, csrf_token, expires_at) VALUES(?1, ?2, ?3)",
            params![
                token_hash(&session).to_vec(),
                csrf,
                self.now() + 12 * 60 * 60
            ],
        )?;
        transaction.execute(
            "INSERT INTO events(kind, message, created_at) VALUES('security', 'Administrator created', ?1)",
            [self.now()],
        )?;
        transaction.commit()?;
        Ok(session)
    }

    pub fn is_configured(&self) -> Result<bool> {
        Ok(self
            .connection()?
            .query_row("SELECT 1 FROM administrator LIMIT 1", [], |_| Ok(()))
            .optional()?
            .is_some())
    }

    pub fn session_valid(&self, session: &str) -> Result<bool> {
        let expires_at: Option<i64> = self
            .connection()?
            .query_row(
                "SELECT expires_at FROM sessions WHERE token_hash = ?1",
                [token_hash(session).to_vec()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(expires_at.is_some_and(|expires_at| expires_at > self.now()))
    }

    pub fn verify_password(&self, password: &str) -> Result<bool> {
        let password_hash: Option<String> = self
            .connection()?
            .query_row(
                "SELECT password_hash FROM administrator WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        let Some(password_hash) = password_hash else {
            return Ok(false);
        };
        let parsed = PasswordHash::new(&password_hash)
            .map_err(|error| anyhow::anyhow!("parse stored password hash: {error}"))?;
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok())
    }

    pub fn create_session(&self) -> Result<String> {
        let session = random_token();
        let connection = self.connection()?;
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?1", [self.now()])?;
        connection.execute(
            "INSERT INTO sessions(token_hash, csrf_token, expires_at) VALUES(?1, ?2, ?3)",
            params![
                token_hash(&session).to_vec(),
                random_token(),
                self.now() + 12 * 60 * 60
            ],
        )?;
        Ok(session)
    }

    pub fn destroy_session(&self, session: &str) -> Result<()> {
        self.connection()?.execute(
            "DELETE FROM sessions WHERE token_hash = ?1",
            [token_hash(session).to_vec()],
        )?;
        Ok(())
    }

    pub fn reset_administrator(&self) -> Result<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute("DELETE FROM sessions", [])?;
        transaction.execute("DELETE FROM administrator", [])?;
        transaction.execute(
            "DELETE FROM settings WHERE key IN ('bootstrap_token_hash', 'bootstrap_token_issued_at')",
            [],
        )?;
        transaction.execute(
            "INSERT INTO events(kind, message, created_at) VALUES('security', 'Administrator reset from local CLI', ?1)",
            [self.now()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn session_csrf(&self, session: &str) -> Result<Option<String>> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT csrf_token FROM sessions WHERE token_hash = ?1 AND expires_at > ?2",
                params![token_hash(session).to_vec(), self.now()],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn configure_cloudflare(
        &self,
        client_id: &str,
        client_secret: &str,
        scopes: &str,
    ) -> Result<()> {
        let encrypted_secret = self.vault.seal("cloudflare.client_secret", client_secret)?;
        self.connection()?.execute(
            "INSERT INTO provider_configuration(provider, client_id, client_secret, scopes, updated_at)
             VALUES('cloudflare', ?1, ?2, ?3, ?4)
             ON CONFLICT(provider) DO UPDATE SET
               client_id = excluded.client_id,
               client_secret = excluded.client_secret,
               scopes = excluded.scopes,
               access_token = NULL,
               refresh_token = NULL,
               token_expires_at = NULL,
               updated_at = excluded.updated_at",
            params![client_id, encrypted_secret, scopes, self.now()],
        )?;
        Ok(())
    }

    pub fn cloudflare_configuration(&self) -> Result<Option<CloudflareConfiguration>> {
        let row: Option<(String, String, String)> = self
            .connection()?
            .query_row(
                "SELECT client_id, client_secret, scopes FROM provider_configuration WHERE provider = 'cloudflare'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        row.map(|(client_id, client_secret, scopes)| {
            Ok(CloudflareConfiguration {
                client_id,
                client_secret: self
                    .vault
                    .open("cloudflare.client_secret", &client_secret)?,
                scopes,
            })
        })
        .transpose()
    }

    pub fn cloudflare_connected(&self) -> Result<bool> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT 1 FROM provider_configuration WHERE provider = 'cloudflare' AND access_token IS NOT NULL",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn create_oauth_attempt(&self, provider: &str, session: &str) -> Result<OAuthAttempt> {
        let state = random_token();
        let code_verifier = random_token();
        let connection = self.connection()?;
        connection.execute(
            "DELETE FROM oauth_attempts WHERE expires_at <= ?1",
            [self.now()],
        )?;
        connection.execute(
            "INSERT INTO oauth_attempts(state_hash, provider, code_verifier, session_hash, expires_at)
             VALUES(?1, ?2, ?3, ?4, ?5)",
            params![
                token_hash(&state).to_vec(),
                provider,
                self.vault.seal("oauth.code_verifier", &code_verifier)?,
                token_hash(session).to_vec(),
                self.now() + 10 * 60
            ],
        )?;
        Ok(OAuthAttempt {
            state,
            code_verifier,
        })
    }

    /// The attempt is only released to the admin session that started the
    /// flow, so a leaked state value cannot be replayed by someone else.
    pub fn consume_oauth_attempt(
        &self,
        provider: &str,
        state: &str,
        session: &str,
    ) -> Result<Option<OAuthAttempt>> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let encrypted_verifier: Option<String> = transaction
            .query_row(
                "SELECT code_verifier FROM oauth_attempts
                 WHERE state_hash = ?1 AND provider = ?2 AND session_hash = ?3 AND expires_at > ?4",
                params![
                    token_hash(state).to_vec(),
                    provider,
                    token_hash(session).to_vec(),
                    self.now()
                ],
                |row| row.get(0),
            )
            .optional()?;
        transaction.execute(
            "DELETE FROM oauth_attempts WHERE state_hash = ?1",
            [token_hash(state).to_vec()],
        )?;
        transaction.commit()?;
        encrypted_verifier
            .map(|code_verifier| {
                Ok(OAuthAttempt {
                    state: state.to_owned(),
                    code_verifier: self.vault.open("oauth.code_verifier", &code_verifier)?,
                })
            })
            .transpose()
    }

    pub fn save_cloudflare_tokens(
        &self,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_in: i64,
        scopes: &str,
    ) -> Result<()> {
        self.connection()?.execute(
            "UPDATE provider_configuration SET
               access_token = ?1,
               refresh_token = ?2,
               token_expires_at = ?3,
               scopes = ?4,
               updated_at = ?5
             WHERE provider = 'cloudflare'",
            params![
                self.vault.seal("cloudflare.access_token", access_token)?,
                refresh_token
                    .map(|token| self.vault.seal("cloudflare.refresh_token", token))
                    .transpose()?,
                self.now() + expires_in,
                scopes,
                self.now()
            ],
        )?;
        Ok(())
    }

    pub fn cloudflare_tokens(&self) -> Result<Option<CloudflareTokens>> {
        let row: Option<(String, Option<String>, i64, String)> = self
            .connection()?
            .query_row(
                "SELECT access_token, refresh_token, token_expires_at, scopes
                 FROM provider_configuration
                 WHERE provider = 'cloudflare' AND access_token IS NOT NULL",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        row.map(|(access_token, refresh_token, expires_at, scopes)| {
            Ok(CloudflareTokens {
                access_token: self.vault.open("cloudflare.access_token", &access_token)?,
                refresh_token: refresh_token
                    .map(|token| self.vault.open("cloudflare.refresh_token", &token))
                    .transpose()?,
                expires_at,
                scopes,
            })
        })
        .transpose()
    }

    pub fn disconnect_cloudflare(&self) -> Result<()> {
        self.connection()?.execute(
            "UPDATE provider_configuration SET access_token = NULL, refresh_token = NULL,
             token_expires_at = NULL, updated_at = ?1 WHERE provider = 'cloudflare'",
            [self.now()],
        )?;
        Ok(())
    }

    fn invalidate_routes(&self) {
        if let Ok(mut cache) = self.route_cache.lock() {
            cache.clear();
        }
    }

    pub fn save_certificate(
        &self,
        identifier: &str,
        certificate_pem: &str,
        private_key_pem: &str,
        not_after: i64,
        renew_at: i64,
    ) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO certificates(
               identifier, certificate_pem, private_key_pem, not_after, renew_at, updated_at
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(identifier) DO UPDATE SET
               certificate_pem = excluded.certificate_pem,
               private_key_pem = excluded.private_key_pem,
               not_after = excluded.not_after,
               renew_at = excluded.renew_at,
               updated_at = excluded.updated_at",
            params![
                identifier,
                self.vault.seal("certificate.pem", certificate_pem)?,
                self.vault.seal("certificate.key", private_key_pem)?,
                not_after,
                renew_at,
                self.now()
            ],
        )?;
        Ok(())
    }

    pub fn certificates(&self) -> Result<Vec<StoredCertificate>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT identifier, certificate_pem, private_key_pem, not_after, renew_at
             FROM certificates ORDER BY identifier",
        )?;
        let encrypted = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        encrypted
            .into_iter()
            .map(
                |(identifier, certificate_pem, private_key_pem, not_after, renew_at)| {
                    Ok(StoredCertificate {
                        identifier,
                        certificate_pem: self.vault.open("certificate.pem", &certificate_pem)?,
                        private_key_pem: self.vault.open("certificate.key", &private_key_pem)?,
                        not_after,
                        renew_at,
                    })
                },
            )
            .collect()
    }

    pub fn update_certificate_renew_at(&self, identifier: &str, renew_at: i64) -> Result<()> {
        self.connection()?.execute(
            "UPDATE certificates SET renew_at = ?1, updated_at = ?2 WHERE identifier = ?3",
            params![renew_at, self.now(), identifier],
        )?;
        Ok(())
    }

    pub fn certificate_due(&self, identifier: &str) -> Result<bool> {
        let renew_at: Option<i64> = self
            .connection()?
            .query_row(
                "SELECT renew_at FROM certificates WHERE identifier = ?1",
                [identifier],
                |row| row.get(0),
            )
            .optional()?;
        Ok(renew_at.is_none_or(|renew_at| renew_at <= self.now()))
    }

    pub fn acme_email(&self) -> Result<Option<String>> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT value FROM settings WHERE key = 'acme_email'",
                [],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn save_secret(&self, key: &str, value: &str) -> Result<()> {
        self.connection()?.execute(
            "INSERT INTO secrets(key, value, updated_at) VALUES(?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            params![key, self.vault.seal(key, value)?, self.now()],
        )?;
        Ok(())
    }

    pub fn secret(&self, key: &str) -> Result<Option<String>> {
        let encrypted: Option<String> = self
            .connection()?
            .query_row("SELECT value FROM secrets WHERE key = ?1", [key], |row| {
                row.get(0)
            })
            .optional()?;
        encrypted
            .map(|value| self.vault.open(key, &value))
            .transpose()
    }

    pub fn remove_certificate(&self, identifier: &str) -> Result<()> {
        self.connection()?.execute(
            "DELETE FROM certificates WHERE identifier = ?1",
            [identifier],
        )?;
        Ok(())
    }

    pub fn record_event(&self, kind: &str, message: &str) -> Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO events(kind, message, created_at) VALUES(?1, ?2, ?3)",
            params![kind, message, self.now()],
        )?;
        // Cap history so a long-lived VPS cannot grow the table without bound.
        connection.execute(
            "DELETE FROM events WHERE id <= (SELECT MAX(id) FROM events) - 1000",
            [],
        )?;
        Ok(())
    }

    pub fn recent_events(&self, limit: u32) -> Result<Vec<Event>> {
        let connection = self.connection()?;
        let mut statement = connection
            .prepare("SELECT kind, message, created_at FROM events ORDER BY id DESC LIMIT ?1")?;
        let rows = statement.query_map([limit], |row| {
            Ok(Event {
                kind: row.get(0)?,
                message: row.get(1)?,
                created_at: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("state database mutex is poisoned"))
    }
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn valid_email(email: &str) -> bool {
    let (local, domain) = email.split_once('@').unwrap_or_default();
    !local.is_empty() && domain.contains('.') && !domain.ends_with('.')
}

fn ensure_master_key(path: &Path) -> Result<[u8; 32]> {
    if path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(path)?.permissions().mode();
            if mode & 0o077 != 0 {
                bail!(
                    "master key {} is readable by other users (mode {:o}); \
                     run: chmod 600 {}",
                    path.display(),
                    mode & 0o777,
                    path.display()
                );
            }
        }
        let bytes = fs::read(path)?;
        return bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("master key must contain exactly 32 bytes"));
    }
    let mut key = [0_u8; 32];
    rand::rng().fill_bytes(&mut key);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(&key)?;
    file.sync_all()?;
    Ok(key)
}

fn set_dir_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::BindingStatus;

    #[test]
    fn schema_v3_migrates_retryable_removals_and_rejects_invalid_states() {
        let state = tempfile::TempDir::new().unwrap();
        ensure_master_key(&state.path().join("master.key")).unwrap();
        let connection = Connection::open(state.path().join("hostknot.sqlite3")).unwrap();
        connection
            .execute_batch(
                "
                CREATE TABLE bindings (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    upstream_scheme TEXT NOT NULL,
                    upstream_port INTEGER NOT NULL,
                    insecure_tls INTEGER NOT NULL DEFAULT 0,
                    proxied INTEGER NOT NULL DEFAULT 1,
                    provider TEXT NOT NULL DEFAULT 'cloudflare',
                    zone_id TEXT,
                    dns_receipt TEXT,
                    status TEXT NOT NULL,
                    certificate_status TEXT NOT NULL,
                    health TEXT NOT NULL,
                    last_error TEXT,
                    drain_until INTEGER,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    replace_confirmed INTEGER NOT NULL DEFAULT 0
                );
                INSERT INTO bindings(
                    id, hostname, upstream_scheme, upstream_port, status,
                    certificate_status, health, created_at, updated_at
                ) VALUES(
                    'b1', 'app.example.com', 'http', 8080, 'drifted',
                    'active', 'healthy', 1, 1
                );
                PRAGMA user_version = 2;
                ",
            )
            .unwrap();
        drop(connection);

        let store = Store::open(state.path()).unwrap();
        assert_eq!(
            store.binding("b1").unwrap().unwrap().status,
            BindingStatus::Removing
        );
        assert!(store.binding_dns_plan("b1").unwrap().is_none());
        assert!(
            store
                .connection()
                .unwrap()
                .execute("UPDATE bindings SET status = 'typo' WHERE id = 'b1'", [])
                .is_err()
        );
    }

    #[test]
    fn schema_v4_adds_persistent_unique_path_routes_with_cascading_deletion() {
        let state = tempfile::TempDir::new().unwrap();
        ensure_master_key(&state.path().join("master.key")).unwrap();
        let connection = Connection::open(state.path().join("hostknot.sqlite3")).unwrap();
        connection
            .execute_batch(
                "
                CREATE TABLE bindings (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    upstream_scheme TEXT NOT NULL,
                    upstream_port INTEGER NOT NULL,
                    proxied INTEGER NOT NULL DEFAULT 1,
                    provider TEXT NOT NULL DEFAULT 'cloudflare',
                    zone_id TEXT,
                    dns_receipt TEXT,
                    status TEXT NOT NULL,
                    certificate_status TEXT NOT NULL,
                    health TEXT NOT NULL,
                    last_error TEXT,
                    drain_until INTEGER,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    replace_confirmed INTEGER NOT NULL DEFAULT 0,
                    dns_plan TEXT,
                    pending_update TEXT
                );
                INSERT INTO bindings(
                    id, hostname, upstream_scheme, upstream_port, status,
                    certificate_status, health, created_at, updated_at
                ) VALUES(
                    'b1', 'app.example.com', 'http', 3000, 'active',
                    'active', 'unknown', 1, 1
                );
                PRAGMA user_version = 3;
                ",
            )
            .unwrap();
        drop(connection);

        let store = Store::open(state.path()).unwrap();
        assert_eq!(
            store
                .connection()
                .unwrap()
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            4
        );
        store
            .create_path_route("r1", "b1", "/assets", "http", 8080)
            .unwrap();
        assert!(
            store
                .create_path_route("r2", "b1", "/assets", "http", 8081)
                .is_err()
        );
        drop(store);

        let reopened = Store::open(state.path()).unwrap();
        assert_eq!(reopened.list_path_routes("b1").unwrap().len(), 1);
        reopened.delete_binding("b1").unwrap();
        assert!(reopened.path_route("r1").unwrap().is_none());
    }

    #[test]
    fn health_updates_do_not_overwrite_transitional_operation_errors() {
        let state = tempfile::TempDir::new().unwrap();
        let store = Store::open(state.path()).unwrap();
        store
            .create_binding("b1", "app.example.com", "http", 8080, false, false)
            .unwrap();
        store.mark_binding_active("b1").unwrap();
        store.begin_binding_removal("b1").unwrap();
        store
            .mark_binding_error("b1", BindingStatus::Removing, "DNS drift")
            .unwrap();

        store
            .update_binding_health("b1", false, Some("upstream failed"))
            .unwrap();

        let binding = store.binding("b1").unwrap().unwrap();
        assert_eq!(binding.status, BindingStatus::Removing);
        assert_eq!(binding.last_error.as_deref(), Some("DNS drift"));
    }
}
