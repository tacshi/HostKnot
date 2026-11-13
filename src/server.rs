//! The accept loop shared by every listener (admin, HTTP, HTTPS).
//!
//! All three are reachable from the internet without authentication, so each
//! connection is bounded: a per-address and a total connection cap, a TLS
//! handshake deadline, a header-read deadline (which hyper also applies to
//! idle keep-alive gaps), HTTP/2 keep-alive pings, and modest header buffers.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{Router, extract::Extension};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpListener,
    sync::watch,
};
use tokio_rustls::TlsAcceptor;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
const H2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
const H2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(20);
const H2_MAX_CONCURRENT_STREAMS: u32 = 256;
const H1_MAX_BUFFER: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnectionLimits {
    pub(crate) total: usize,
    pub(crate) per_address: usize,
}

impl ConnectionLimits {
    /// Public proxy listeners. Cloudflare edges are exempt from the
    /// per-address cap because many visitors share each edge address.
    pub(crate) const PROXY: Self = Self {
        total: 16_384,
        per_address: 256,
    };
    pub(crate) const ADMIN: Self = Self {
        total: 512,
        per_address: 64,
    };
}

/// Counts open connections per client address (IPv6 by /64, the unit a
/// single host usually controls) and in total.
#[derive(Clone)]
pub(crate) struct ConnectionLimiter {
    limits: ConnectionLimits,
    exempt: fn(IpAddr) -> bool,
    state: Arc<Mutex<LimiterState>>,
}

#[derive(Default)]
struct LimiterState {
    total: usize,
    per_address: HashMap<IpAddr, usize>,
}

pub(crate) struct ConnectionPermit {
    limiter: ConnectionLimiter,
    key: Option<IpAddr>,
}

impl ConnectionLimiter {
    pub(crate) fn new(limits: ConnectionLimits, exempt: fn(IpAddr) -> bool) -> Self {
        Self {
            limits,
            exempt,
            state: Arc::new(Mutex::new(LimiterState::default())),
        }
    }

    pub(crate) fn try_acquire(&self, peer: IpAddr) -> Option<ConnectionPermit> {
        let mut state = self.state.lock().unwrap();
        if state.total >= self.limits.total {
            return None;
        }
        let key = (!(self.exempt)(peer)).then(|| address_key(peer));
        if let Some(key) = key {
            let open = state.per_address.entry(key).or_default();
            if *open >= self.limits.per_address {
                return None;
            }
            *open += 1;
        }
        state.total += 1;
        Some(ConnectionPermit {
            limiter: self.clone(),
            key,
        })
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let mut state = self.limiter.state.lock().unwrap();
        state.total -= 1;
        if let Some(key) = self.key
            && let Some(open) = state.per_address.get_mut(&key)
        {
            *open -= 1;
            if *open == 0 {
                state.per_address.remove(&key);
            }
        }
    }
}

/// The unit a single client usually controls: an IPv4 address, or an IPv6
/// /64 (IPv4-mapped addresses count as IPv4).
pub(crate) fn address_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut segments = v6.segments();
                segments[4..].fill(0);
                IpAddr::from(segments)
            }
        },
    }
}

/// Serves `router` on `listener` until `shutdown` changes. Each request
/// carries the peer as `Extension<SocketAddr>`.
pub(crate) async fn serve(
    listener: TcpListener,
    router: Router,
    tls: Option<TlsAcceptor>,
    limiter: ConnectionLimiter,
    header_read_timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let (socket, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        // Persistent accept errors (EMFILE under fd
                        // exhaustion) must not busy-spin the loop.
                        tracing::warn!(%error, "listener accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Some(permit) = limiter.try_acquire(peer.ip()) else {
                    tracing::debug!(%peer, "connection refused: limit reached");
                    continue;
                };
                let _ = socket.set_nodelay(true);
                let router = router.clone();
                let tls = tls.clone();
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    match tls {
                        Some(acceptor) => {
                            let Ok(Ok(stream)) =
                                tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(socket))
                                    .await
                            else {
                                return;
                            };
                            serve_connection(stream, router, peer, header_read_timeout, shutdown)
                                .await;
                        }
                        None => {
                            serve_connection(socket, router, peer, header_read_timeout, shutdown)
                                .await;
                        }
                    }
                });
            }
        }
    }
}

async fn serve_connection<I>(
    io: I,
    router: Router,
    peer: SocketAddr,
    header_read_timeout: Duration,
    mut shutdown: watch::Receiver<bool>,
) where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = TowerToHyperService::new(router.layer(Extension(peer)));
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout)
        .max_buf_size(H1_MAX_BUFFER);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(H2_KEEP_ALIVE_INTERVAL)
        .keep_alive_timeout(H2_KEEP_ALIVE_TIMEOUT)
        .max_concurrent_streams(H2_MAX_CONCURRENT_STREAMS);
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    tokio::pin!(connection);
    let result = tokio::select! {
        result = connection.as_mut() => result,
        _ = shutdown.changed() => {
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    };
    if let Err(error) = result {
        tracing::debug!(%error, "connection ended");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limiter_caps_per_address_and_total_and_releases_on_drop() {
        let limiter = ConnectionLimiter::new(
            ConnectionLimits {
                total: 3,
                per_address: 2,
            },
            |ip| ip == IpAddr::from([198, 51, 100, 7]),
        );
        let attacker = IpAddr::from([203, 0, 113, 1]);
        let first = limiter.try_acquire(attacker).unwrap();
        let _second = limiter.try_acquire(attacker).unwrap();
        assert!(limiter.try_acquire(attacker).is_none());
        // Exempt peers skip the per-address cap but still count in total.
        let _edge = limiter
            .try_acquire(IpAddr::from([198, 51, 100, 7]))
            .unwrap();
        assert!(limiter.try_acquire(IpAddr::from([192, 0, 2, 1])).is_none());
        drop(first);
        assert!(limiter.try_acquire(attacker).is_some());
    }

    #[tokio::test]
    async fn idle_and_slow_connections_are_closed_and_free_their_slot() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let limiter = ConnectionLimiter::new(
            ConnectionLimits {
                total: 10,
                per_address: 1,
            },
            |_| false,
        );
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(serve(
            listener,
            Router::new().route("/", axum::routing::get(|| async { "ok" })),
            None,
            limiter,
            Duration::from_millis(300),
            shutdown_rx,
        ));

        // A client that trickles half a request head is cut off...
        let mut slow = tokio::net::TcpStream::connect(address).await.unwrap();
        slow.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();
        // ...and while it holds the only slot for its address, a second
        // connection from the same address is refused.
        let mut refused = tokio::net::TcpStream::connect(address).await.unwrap();
        let mut buffer = [0_u8; 64];
        let closed = tokio::time::timeout(Duration::from_secs(2), refused.read(&mut buffer))
            .await
            .expect("refused connection is closed promptly");
        assert!(matches!(closed, Ok(0) | Err(_)));
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), slow.read_to_end(&mut response))
            .await
            .expect("header read timeout closes the connection")
            .ok();

        // The slot is released, and an idle keep-alive connection is closed
        // after its response the same way.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut idle = tokio::net::TcpStream::connect(address).await.unwrap();
        idle.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), idle.read_to_end(&mut response))
            .await
            .expect("idle keep-alive connection is closed")
            .unwrap();
        assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn ipv6_addresses_share_a_budget_per_64() {
        let limiter = ConnectionLimiter::new(
            ConnectionLimits {
                total: 100,
                per_address: 1,
            },
            |_| false,
        );
        let _one = limiter
            .try_acquire("2001:db8:1:2::1".parse().unwrap())
            .unwrap();
        assert!(
            limiter
                .try_acquire("2001:db8:1:2:ffff::9".parse().unwrap())
                .is_none()
        );
        assert!(
            limiter
                .try_acquire("2001:db8:1:3::1".parse().unwrap())
                .is_some()
        );
    }
}
