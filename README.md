# Hostknot

**Bind a domain to any service on your VPS from your browser — no Nginx, no Caddy, no config files to hand-edit.**

Hostknot is a single Rust binary that turns "I deployed a service on port 3000, now I want `app.example.com` pointing at it with HTTPS" into a two-minute browser workflow. It combines four things that normally require separate tools:

- **A reverse proxy** on ports 80/443 with exact-host routing, HTTP/2, WebSockets, server-sent events, and streaming.
- **Automatic DNS** through your Cloudflare account (OAuth-authorized, no API token pasting), with safe conflict handling and rollback on unbind.
- **Automatic certificates** from Let's Encrypt — including a short-lived IP certificate so even the admin UI at `https://<your-ip>:9443` is served over trusted TLS.
- **A browser admin UI** rendered entirely from the binary: no CDN, no Node.js, no frontend build.

Everything persists in one SQLite database with encrypted credentials, survives restarts, and installs as a hardened systemd service.

## How it works

```
Browser ──▶ https://<VPS-IP>:9443  (admin UI: bind app.example.com → :3000)
                    │
                    ├─▶ Cloudflare API   creates A/AAAA records (OAuth)
                    └─▶ Let's Encrypt    issues the certificate (HTTP-01)

Visitors ─▶ https://app.example.com ──▶ Hostknot :443 ──▶ 127.0.0.1:3000
```

## Requirements

- A Linux VPS running systemd (`x86_64` or `aarch64`)
- Inbound TCP ports **80**, **443**, and **9443** open, with a public IPv4 or IPv6 address that reaches the machine
- A Cloudflare account with the target domain in an active zone
- A private Cloudflare OAuth client (created once during setup — [guide](docs/cloudflare-oauth.md))

## Quick start

**1. Install.** Download the release archive for your architecture (`x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl`), verify it against `SHA256SUMS`, then as root:

```sh
hostknot service install --public-ip <YOUR_VPS_IP>
```

`<YOUR_VPS_IP>` is the public IPv4 or IPv6 address the internet reaches your VPS on — it's published in DNS records and receives the admin UI's IP certificate. Unsure which it is? On the VPS:

```sh
curl -4 ifconfig.me
```

```sh
systemctl daemon-reload && systemctl enable --now hostknot
```

**2. Open the setup link.** The service log prints a one-time setup URL:

```sh
journalctl -u hostknot | grep 'setup URL'
```

It looks like `https://<YOUR_VPS_IP>:9443/setup?token=...`. The token is single-use and expires after one hour — restart the service or run `hostknot admin reset` for a fresh one. Before the URL appears, Hostknot obtains a trusted Let's Encrypt IP certificate over HTTP-01, so port 80 must already be reachable; if issuance fails, the UI still comes up on a self-signed fallback and keeps retrying.

**3. Create the administrator.** Open the URL, set an admin password (12+ characters) and an ACME contact email.

**4. Connect Cloudflare.** On the Cloudflare page in the UI:
   1. Create a **private** Authorization Code OAuth client in the Cloudflare dashboard.
   2. Register the exact callback URI the page displays, and grant **Zone Read**, **DNS Write**, and **offline access**.
   3. Paste the client ID and secret into Hostknot, then click **Authorize with Cloudflare**.

   Full walkthrough: [docs/cloudflare-oauth.md](docs/cloudflare-oauth.md).

**5. Bind a domain.** Click **New binding**, pick a discovered local port (or type one), enter the hostname, and bind. Hostknot creates the DNS records, obtains the certificate, and starts routing — typically within seconds.

## What to expect from bindings

- **Exact hostnames only.** `app.example.com` matches `app.example.com` — no wildcards, no path routing. Hostnames are immutable; to rename, create a replacement binding.
- **Editable after creation:** upstream port and protocol, the Cloudflare proxied/DNS-only mode, and the untrusted-upstream-certificate override.
- **Conflicts need confirmation.** If the hostname already has A/AAAA/CNAME records, Hostknot shows exactly what it would replace, saves the originals, and restores them on unbind.
- **Drift is never destroyed.** If someone changes the records outside Hostknot, unbinding stops and reports the drift instead of overwriting external changes; once resolved, removal completes automatically.
- **Unbinding drains.** DNS records are removed first, then the route keeps serving for five minutes so cached DNS doesn't hit a dead endpoint.
- **Everything survives restarts** — bindings, sessions, certificates, DNS receipts, and any half-finished work, which reconciliation resumes with backoff.

## Command reference

| Command | Purpose |
|---|---|
| `hostknot serve [--config <PATH>]` | Run the admin UI and proxy listeners (what the systemd unit runs) |
| `hostknot doctor [--config <PATH>] [--offline]` | Check IPs, ports, key permissions, database integrity, and outbound Cloudflare/ACME connectivity; exits non-zero if problems are found |
| `hostknot service install --public-ip <IP> [--binary <PATH>] [--root <PATH>]` | Install/upgrade the binary, default config, and hardened systemd unit |
| `hostknot admin reset [--state-dir <PATH>]` | Invalidate all sessions and print a new one-time setup token (bindings, credentials, and certificates are kept) |
| `hostknot version` | Print the version |

Defaults: `--config /etc/hostknot/config.toml`, `--state-dir /var/lib/hostknot`.

## Configuration

The installer writes `/etc/hostknot/config.toml`; most deployments never need to touch it.

| Key | Default | Description |
|---|---|---|
| `state_dir` | `/var/lib/hostknot` | Database, master key, and certificates |
| `admin_listen` | `0.0.0.0:9443` | Admin UI listener |
| `http_listen` / `https_listen` | `0.0.0.0:80` / `0.0.0.0:443` | Proxy listeners (80 also serves ACME challenges and redirects) |
| `public_ips` | from `--public-ip` | Addresses published in DNS records and used for the admin IP certificate |
| `admin_public_url` | `https://<IP>:9443/` | Public admin URL; also the base of the OAuth callback |
| `drain_seconds` | `300` | How long a route keeps serving after its DNS records are removed |
| `acme_directory_url` | Let's Encrypt production | ACME directory (point at a staging/test CA if needed) |
| `acme_root_certificate` | *(unset)* | Extra root to trust for the ACME directory (test CAs) |

### Files on disk

- `/usr/local/bin/hostknot`, `/etc/hostknot/config.toml`, `/etc/systemd/system/hostknot.service` — created by the installer.
- `/var/lib/hostknot/` (`master.key`, `hostknot.sqlite3`) — created by the service on first start under systemd's `StateDirectory`, owned by the service identity. The database and key are **one backup unit**; see [docs/operations.md](docs/operations.md) for backup, restore, and upgrade procedures.

## Security model

- **Least privilege.** The systemd unit runs under a private dynamic user with `CAP_NET_BIND_SERVICE` as its only capability, a read-only host filesystem, and a writable state directory.
- **Encrypted at rest.** OAuth secrets and tokens, ACME account credentials, and certificate keys are sealed with XChaCha20-Poly1305 under a mode-`0600` master key (context-bound so ciphertexts can't be swapped between columns). The service refuses to start if the key is readable by other users. Only Argon2id hashes are stored for the admin password.
- **Hardened admin surface.** HTTPS with a trusted IP certificate, HTTP-only same-site session cookies, per-session CSRF tokens with origin checks, per-IP login throttling, expiring single-use setup/reset tokens, OAuth state bound to the initiating session (PKCE S256), and strict security headers.
- **Contained proxying.** Upstreams are pinned to loopback — the proxy cannot be pointed at arbitrary hosts. Inbound `X-Forwarded-*` headers are overwritten, hop-by-hop headers are stripped, and upstream failures return an opaque 502. HTTPS upstream certificates are verified against the binding hostname unless explicitly overridden.

## Troubleshooting

Start with the built-in diagnostics — it checks the same things that make installs fail:

```sh
hostknot doctor --config /etc/hostknot/config.toml
```

The admin dashboard shows per-binding DNS/certificate/upstream status and an event history. [docs/operations.md](docs/operations.md) covers failure behavior, backup/restore, and upgrades.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
cargo build --release
```

The test suite runs against real seams: actual Hostknot processes, real HTTP/TLS/WebSocket clients, and protocol-level fakes for Cloudflare and ACME. Time-based behavior (token/session expiry, throttling, certificate renewal) is tested through an injected clock.

Browser tests (Playwright, drives a real Hostknot process through setup, OAuth, binding, and unbind):

```sh
npm ci && npx playwright install chromium
npm run test:browser
```

ACME issuance and renewal against a local [Pebble](https://github.com/letsencrypt/pebble) server:

```sh
docker run -d --name pebble --network host \
  -e PEBBLE_VA_NOSLEEP=1 ghcr.io/letsencrypt/pebble:2.7.0
docker cp pebble:/test/certs/pebble.minica.pem /tmp/pebble.minica.pem
```

```sh
HOSTKNOT_PEBBLE_DIRECTORY=https://localhost:14000/dir \
HOSTKNOT_PEBBLE_MANAGEMENT=https://localhost:15000 \
HOSTKNOT_PEBBLE_ROOT=/tmp/pebble.minica.pem \
HOSTKNOT_PEBBLE_HTTP_LISTEN=0.0.0.0:5002 \
cargo test --test acme_pebble -- --ignored
```

## License

MIT — see [LICENSE-MIT](LICENSE-MIT).
