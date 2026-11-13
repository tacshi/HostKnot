use std::time::Instant;

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};

use super::{ROUTE_CACHE_TTL, RoutingTable, Store};
use crate::model::{BindingHealth, BindingPathRoute, ProxyRoute};

impl Store {
    pub fn create_path_route(
        &self,
        id: &str,
        binding_id: &str,
        path_prefix: &str,
        upstream_scheme: &str,
        upstream_port: u16,
    ) -> Result<BindingPathRoute> {
        self.connection()?.execute(
            "INSERT INTO binding_path_routes(
               id, binding_id, path_prefix, upstream_scheme, upstream_port,
               health, created_at, updated_at
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
            params![
                id,
                binding_id,
                path_prefix,
                upstream_scheme,
                upstream_port,
                BindingHealth::Unknown.as_str(),
                self.now(),
            ],
        )?;
        self.invalidate_routes();
        self.path_route(id)?.context("new path route was not found")
    }

    pub fn path_route(&self, id: &str) -> Result<Option<BindingPathRoute>> {
        Ok(self
            .connection()?
            .query_row(
                "SELECT id, binding_id, path_prefix, upstream_scheme, upstream_port,
                        health, last_error
                 FROM binding_path_routes WHERE id = ?1",
                [id],
                path_route_from_row,
            )
            .optional()?)
    }

    pub fn list_path_routes(&self, binding_id: &str) -> Result<Vec<BindingPathRoute>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT id, binding_id, path_prefix, upstream_scheme, upstream_port,
                    health, last_error
             FROM binding_path_routes WHERE binding_id = ?1
             ORDER BY path_prefix",
        )?;
        let rows = statement.query_map([binding_id], path_route_from_row)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn update_path_route(
        &self,
        id: &str,
        binding_id: &str,
        path_prefix: &str,
        upstream_scheme: &str,
        upstream_port: u16,
    ) -> Result<bool> {
        let changed = self.connection()?.execute(
            "UPDATE binding_path_routes
             SET path_prefix = ?1, upstream_scheme = ?2, upstream_port = ?3,
                 health = ?4, last_error = NULL, updated_at = ?5
             WHERE id = ?6 AND binding_id = ?7",
            params![
                path_prefix,
                upstream_scheme,
                upstream_port,
                BindingHealth::Unknown.as_str(),
                self.now(),
                id,
                binding_id,
            ],
        )?;
        self.invalidate_routes();
        Ok(changed == 1)
    }

    pub fn delete_path_route(&self, id: &str, binding_id: &str) -> Result<bool> {
        let changed = self.connection()?.execute(
            "DELETE FROM binding_path_routes WHERE id = ?1 AND binding_id = ?2",
            params![id, binding_id],
        )?;
        self.invalidate_routes();
        Ok(changed == 1)
    }

    pub fn active_proxy_route(&self, hostname: &str, path: &str) -> Result<Option<ProxyRoute>> {
        let Some(table) = self.active_routing_table(hostname)? else {
            return Ok(None);
        };
        // Match on the path as the upstream will resolve it, so `/api/../x`
        // reaches the service that actually serves `/x`.
        if let Some(route) = best_path_route(&table.path_routes, &routing_path(path)) {
            return Ok(Some(ProxyRoute {
                binding_id: table.binding.id,
                path_route_id: Some(route.id.clone()),
                hostname: table.binding.hostname,
                upstream_scheme: route.upstream_scheme.clone(),
                upstream_port: route.upstream_port,
                proxied: table.binding.proxied,
                health: route.health,
                last_error: route.last_error.clone(),
            }));
        }
        Ok(Some(ProxyRoute {
            binding_id: table.binding.id,
            path_route_id: None,
            hostname: table.binding.hostname,
            upstream_scheme: table.binding.upstream_scheme,
            upstream_port: table.binding.upstream_port,
            proxied: table.binding.proxied,
            health: table.binding.health,
            last_error: table.binding.last_error,
        }))
    }

    pub fn update_path_route_health(
        &self,
        id: &str,
        healthy: bool,
        error: Option<&str>,
    ) -> Result<()> {
        let health = if healthy {
            BindingHealth::Healthy
        } else {
            BindingHealth::Unavailable
        };
        self.connection()?.execute(
            "UPDATE binding_path_routes
             SET health = ?1, last_error = ?2, updated_at = ?3 WHERE id = ?4",
            params![health.as_str(), error, self.now(), id],
        )?;
        self.invalidate_routes();
        Ok(())
    }

    pub(super) fn active_routing_table(&self, hostname: &str) -> Result<Option<RoutingTable>> {
        let cache_key = hostname.to_ascii_lowercase();
        if let Ok(cache) = self.route_cache.lock()
            && let Some((cached_at, table)) = cache.get(&cache_key)
            && cached_at.elapsed() < ROUTE_CACHE_TTL
        {
            return Ok(table.clone());
        }
        let Some(binding) = self.binding_for_hostname(hostname)? else {
            self.cache_route(cache_key, None);
            return Ok(None);
        };
        let table = RoutingTable {
            path_routes: self.list_path_routes(&binding.id)?,
            binding,
        };
        self.cache_route(cache_key, Some(table.clone()));
        Ok(Some(table))
    }

    /// Hostnames come straight from clients, so the cache must stay bounded:
    /// past the cap, expired entries go first, then everything.
    fn cache_route(&self, key: String, table: Option<RoutingTable>) {
        let Ok(mut cache) = self.route_cache.lock() else {
            return;
        };
        if cache.len() >= ROUTE_CACHE_CAPACITY {
            cache.retain(|_, (cached_at, _)| cached_at.elapsed() < ROUTE_CACHE_TTL);
            if cache.len() >= ROUTE_CACHE_CAPACITY {
                cache.clear();
            }
        }
        cache.insert(key, (Instant::now(), table));
    }
}

const ROUTE_CACHE_CAPACITY: usize = 4096;

/// The request path as an upstream server resolves it: `%2e` decoded to `.`
/// and dot segments removed (RFC 3986 §5.2.4). Other escapes, including
/// `%2f`, are left alone because servers do not treat them as separators.
pub(crate) fn routing_path(path: &str) -> String {
    let decoded = path.replace("%2e", ".").replace("%2E", ".");
    let mut output: Vec<&str> = Vec::new();
    let segments: Vec<&str> = decoded.split('/').skip(1).collect();
    for (index, segment) in segments.iter().enumerate() {
        let last = index + 1 == segments.len();
        match *segment {
            "." => {
                if last {
                    output.push("");
                }
            }
            ".." => {
                output.pop();
                if last {
                    output.push("");
                }
            }
            other => output.push(other),
        }
    }
    format!("/{}", output.join("/"))
}

fn best_path_route<'a>(routes: &'a [BindingPathRoute], path: &str) -> Option<&'a BindingPathRoute> {
    routes
        .iter()
        .filter(|route| path_matches_prefix(path, &route.path_prefix))
        .max_by_key(|route| route.path_prefix.len())
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

fn path_route_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BindingPathRoute> {
    let health = row.get::<_, String>(5)?;
    Ok(BindingPathRoute {
        id: row.get(0)?,
        binding_id: row.get(1)?,
        path_prefix: row.get(2)?,
        upstream_scheme: row.get(3)?,
        upstream_port: row.get(4)?,
        health: BindingHealth::try_from(health.as_str()).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        last_error: row.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_cache_stays_bounded_under_random_hostnames() {
        let state = tempfile::TempDir::new().unwrap();
        let store = Store::open(state.path()).unwrap();
        for index in 0..(ROUTE_CACHE_CAPACITY * 3) {
            assert!(
                store
                    .active_routing_table(&format!("probe-{index}.example.com"))
                    .unwrap()
                    .is_none()
            );
        }
        assert!(store.route_cache.lock().unwrap().len() <= ROUTE_CACHE_CAPACITY);
    }

    #[test]
    fn routing_path_resolves_dot_segments_like_an_upstream_would() {
        assert_eq!(
            routing_path("/api/../internal/metrics"),
            "/internal/metrics"
        );
        assert_eq!(routing_path("/api/%2e%2e/internal"), "/internal");
        assert_eq!(routing_path("/api/%2E%2E/%2e/x"), "/x");
        assert_eq!(routing_path("/assets/./app.css"), "/assets/app.css");
        assert_eq!(routing_path("/../../etc"), "/etc");
        assert_eq!(routing_path("/api/v1/.."), "/api/");
        assert_eq!(routing_path("/api%2f..%2finternal"), "/api%2f..%2finternal");
        assert_eq!(routing_path("/"), "/");
        let routes = vec![route("/api")];
        assert!(best_path_route(&routes, &routing_path("/api/../internal")).is_none());
        assert!(best_path_route(&routes, &routing_path("/x/../api/users")).is_some());
    }

    #[test]
    fn best_path_route_uses_prefix_specificity_not_input_order() {
        let routes = vec![route("/assets"), route("/assets/private")];

        assert_eq!(
            best_path_route(&routes, "/assets/private/item.txt")
                .unwrap()
                .path_prefix,
            "/assets/private"
        );

        let reversed = routes.into_iter().rev().collect::<Vec<_>>();
        assert_eq!(
            best_path_route(&reversed, "/assets/private/item.txt")
                .unwrap()
                .path_prefix,
            "/assets/private"
        );
    }

    fn route(path_prefix: &str) -> BindingPathRoute {
        BindingPathRoute {
            id: path_prefix.to_owned(),
            binding_id: "binding".to_owned(),
            path_prefix: path_prefix.to_owned(),
            upstream_scheme: "http".to_owned(),
            upstream_port: 8080,
            health: BindingHealth::Unknown,
            last_error: None,
        }
    }
}
