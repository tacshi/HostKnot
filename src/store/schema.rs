use anyhow::{Result, bail};
use rusqlite::Connection;

const CURRENT_SCHEMA_VERSION: i64 = 4;

pub(super) fn migrate(connection: &Connection) -> Result<()> {
    let schema_version: i64 = connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if schema_version > CURRENT_SCHEMA_VERSION {
        bail!("state database schema {schema_version} is newer than this HostKnot binary");
    }
    if schema_version < 1 {
        connection.execute_batch(
            "
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS administrator (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash BLOB PRIMARY KEY,
                csrf_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS provider_configuration (
                provider TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                client_secret TEXT NOT NULL,
                scopes TEXT NOT NULL,
                access_token TEXT,
                refresh_token TEXT,
                token_expires_at INTEGER,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oauth_attempts (
                state_hash BLOB PRIMARY KEY,
                provider TEXT NOT NULL,
                code_verifier TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bindings (
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
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS certificates (
                identifier TEXT PRIMARY KEY,
                certificate_pem TEXT NOT NULL,
                private_key_pem TEXT NOT NULL,
                not_after INTEGER NOT NULL,
                renew_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS secrets (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            PRAGMA user_version = 1;
            COMMIT;
            ",
        )?;
    }
    if schema_version < 2 {
        connection.execute_batch(
            "
            BEGIN IMMEDIATE;
            ALTER TABLE oauth_attempts ADD COLUMN session_hash BLOB;
            ALTER TABLE bindings ADD COLUMN replace_confirmed INTEGER NOT NULL DEFAULT 0;
            PRAGMA user_version = 2;
            COMMIT;
            ",
        )?;
    }
    if schema_version < 3 {
        connection.execute_batch(
            "
            BEGIN IMMEDIATE;
            ALTER TABLE bindings ADD COLUMN dns_plan TEXT;
            ALTER TABLE bindings ADD COLUMN pending_update TEXT;
            UPDATE bindings SET status = 'removing' WHERE status = 'drifted';
            CREATE TRIGGER bindings_status_insert_check
            BEFORE INSERT ON bindings
            WHEN NEW.status NOT IN (
              'dns_pending', 'certificate_pending', 'active', 'degraded',
              'updating', 'removing', 'draining'
            )
            BEGIN
              SELECT RAISE(ABORT, 'invalid binding status');
            END;
            CREATE TRIGGER bindings_status_update_check
            BEFORE UPDATE OF status ON bindings
            WHEN NEW.status NOT IN (
              'dns_pending', 'certificate_pending', 'active', 'degraded',
              'updating', 'removing', 'draining'
            )
            BEGIN
              SELECT RAISE(ABORT, 'invalid binding status');
            END;
            CREATE TRIGGER bindings_health_insert_check
            BEFORE INSERT ON bindings
            WHEN NEW.health NOT IN ('unknown', 'healthy', 'unavailable')
            BEGIN
              SELECT RAISE(ABORT, 'invalid binding health');
            END;
            CREATE TRIGGER bindings_health_update_check
            BEFORE UPDATE OF health ON bindings
            WHEN NEW.health NOT IN ('unknown', 'healthy', 'unavailable')
            BEGIN
              SELECT RAISE(ABORT, 'invalid binding health');
            END;
            CREATE TRIGGER bindings_certificate_status_insert_check
            BEFORE INSERT ON bindings
            WHEN NEW.certificate_status NOT IN ('pending', 'active')
            BEGIN
              SELECT RAISE(ABORT, 'invalid certificate status');
            END;
            CREATE TRIGGER bindings_certificate_status_update_check
            BEFORE UPDATE OF certificate_status ON bindings
            WHEN NEW.certificate_status NOT IN ('pending', 'active')
            BEGIN
              SELECT RAISE(ABORT, 'invalid certificate status');
            END;
            PRAGMA user_version = 3;
            COMMIT;
            ",
        )?;
    }
    if schema_version < 4 {
        connection.execute_batch(
            "
            BEGIN IMMEDIATE;
            CREATE TABLE binding_path_routes (
                id TEXT PRIMARY KEY,
                binding_id TEXT NOT NULL REFERENCES bindings(id) ON DELETE CASCADE,
                path_prefix TEXT NOT NULL,
                upstream_scheme TEXT NOT NULL CHECK (upstream_scheme IN ('http', 'https')),
                upstream_port INTEGER NOT NULL CHECK (upstream_port BETWEEN 1 AND 65535),
                health TEXT NOT NULL DEFAULT 'unknown',
                last_error TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(binding_id, path_prefix)
            );
            CREATE INDEX binding_path_routes_binding_prefix
                ON binding_path_routes(binding_id, path_prefix);
            CREATE TRIGGER binding_path_routes_health_insert_check
            BEFORE INSERT ON binding_path_routes
            WHEN NEW.health NOT IN ('unknown', 'healthy', 'unavailable')
            BEGIN
              SELECT RAISE(ABORT, 'invalid path route health');
            END;
            CREATE TRIGGER binding_path_routes_health_update_check
            BEFORE UPDATE OF health ON binding_path_routes
            WHEN NEW.health NOT IN ('unknown', 'healthy', 'unavailable')
            BEGIN
              SELECT RAISE(ABORT, 'invalid path route health');
            END;
            PRAGMA user_version = 4;
            COMMIT;
            ",
        )?;
    }
    Ok(())
}
