use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::model::{Binding, BindingPathRoute, BindingStatus};
use crate::store::Event;

pub(super) trait HtmlStatus {
    fn into_response_with_status(self, status: StatusCode) -> Response;
}

impl HtmlStatus for Html<String> {
    fn into_response_with_status(self, status: StatusCode) -> Response {
        let mut response = self.into_response();
        *response.status_mut() = status;
        response
    }
}

/// Which top-bar tab is current on an authenticated page.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Nav {
    Bindings,
    Cloudflare,
}

/// A signed-in page: top bar with navigation and sign-out, then `body`.
pub(super) fn app_page(title: &str, head: &str, nav: Nav, csrf: &str, body: &str) -> String {
    let current = |tab: Nav| {
        if tab == nav {
            r#" aria-current="page""#
        } else {
            ""
        }
    };
    let bindings = current(Nav::Bindings);
    let cloudflare = current(Nav::Cloudflare);
    let csrf = escape_html(csrf);
    page_with_head(
        title,
        head,
        &format!(
            r#"<header class="topbar"><div class="topbar-inner">{BRAND}<nav class="tabs" aria-label="Main"><a href="/"{bindings}>Bindings</a><a href="/providers/cloudflare"{cloudflare}>Cloudflare</a></nav><form class="inline signout" method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}"><button class="ghost small" type="submit">Sign out</button></form></div></header>{body}"#
        ),
    )
}

/// A page outside a signed-in session (errors, interstitials): brand only.
pub(super) fn page(title: &str, body: &str) -> String {
    page_with_head(title, "", &bare(body))
}

pub(super) fn bare(body: &str) -> String {
    format!(r#"<header class="topbar"><div class="topbar-inner">{BRAND}</div></header>{body}"#)
}

/// Setup and sign-in: a single centered card.
pub(super) fn auth_page(title: &str, body: &str) -> String {
    page_with_head(
        title,
        "",
        &format!(r#"<main class="auth">{BRAND}{body}</main>"#),
    )
}

pub(super) fn page_with_head(title: &str, head: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><link rel="icon" href="/favicon.svg" type="image/svg+xml">{head}<title>{title} · HostKnot</title><style>{CSS}</style></head><body>{body}</body></html>"#
    )
}

/// A centered message with an icon, used for errors and confirmations.
pub(super) fn notice(
    tone: &str,
    eyebrow: &str,
    title: &str,
    message: &str,
    actions: &str,
) -> String {
    let icon = if tone == "info" {
        ICON_ARROW_OUT
    } else {
        ICON_ALERT
    };
    format!(
        r#"<main class="narrow"><section class="card notice {tone}"><div class="notice-icon">{icon}</div><span class="eyebrow">{eyebrow}</span><h1>{title}</h1><p class="error-detail">{message}</p>{actions}</section></main>"#
    )
}

/// Every failure the operator can hit renders as a styled page with a way
/// back — never a bare text response.
pub(super) fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    Html(page(
        title,
        &notice(
            "bad",
            "Something needs attention",
            &escape_html(title),
            &escape_html(message),
            r#"<div class="notice-actions"><a class="button" href="/">Back to bindings</a></div>"#,
        ),
    ))
    .into_response_with_status(status)
}

pub(super) fn dashboard_page(
    bindings: &[Binding],
    events: &[(Event, u32)],
    provider_connected: bool,
    csrf: &str,
    refresh_head: &str,
) -> String {
    let content = if bindings.is_empty() {
        empty_dashboard(provider_connected)
    } else {
        let rows = bindings
            .iter()
            .map(|binding| binding_row(binding, csrf))
            .collect::<String>();
        format!(
            r#"{stats}<section class="card table"><table><thead><tr><th>Hostname</th><th>Upstream</th><th>Status</th><th>Certificate</th><th>DNS</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>{rows}</tbody></table></section>"#,
            stats = binding_stats(bindings)
        )
    };
    let history = if events.is_empty() {
        r#"<p class="card-empty">Nothing has happened yet.</p>"#.to_owned()
    } else {
        let items = events
            .iter()
            .map(|(event, count)| {
                let repeat = if *count > 1 {
                    format!(r#" <span class="repeat">×{count}</span>"#)
                } else {
                    String::new()
                };
                let kind = escape_html(&event.kind);
                format!(
                    r#"<li><span class="tag {kind}">{kind}</span><span class="event-message">{}{repeat}</span><time>{}</time></li>"#,
                    escape_html(&event.message),
                    format_timestamp(event.created_at)
                )
            })
            .collect::<String>();
        format!("<ol>{items}</ol>")
    };
    app_page(
        "Bindings",
        refresh_head,
        Nav::Bindings,
        csrf,
        &format!(
            r#"<main><div class="page-head"><div><h1>Domain bindings</h1><p>Public hostnames routed to services on this server.</p></div><div class="head-actions"><a class="button" href="/bindings/new">{ICON_PLUS}New binding</a></div></div>{content}<section class="card events"><div class="card-head"><h2>Activity</h2></div>{history}</section></main>"#
        ),
    )
}

fn empty_dashboard(provider_connected: bool) -> String {
    let (provider_class, provider_step) = if provider_connected {
        ("done", r#"<span>DNS provider connected</span>"#)
    } else {
        (
            "",
            r#"<a href="/providers/cloudflare">Connect your DNS provider</a>"#,
        )
    };
    format!(
        r#"<section class="card empty"><div class="empty-mark">{KNOT}</div><h2>No bindings yet</h2><p>Point a domain at a service running on this server. HostKnot creates the DNS records and the HTTPS certificate, then starts routing.</p><ol class="checklist"><li class="{provider_class}">{provider_step}</li><li><a href="/bindings/new">Bind a hostname to a local port</a></li></ol></section>"#
    )
}

fn binding_stats(bindings: &[Binding]) -> String {
    let total = bindings.len();
    let serving = bindings
        .iter()
        .filter(|binding| binding.status == BindingStatus::Active)
        .count();
    let attention = bindings
        .iter()
        .filter(|binding| binding.status == BindingStatus::Degraded)
        .count();
    let in_progress = total - serving - attention;
    let attention_class = if attention > 0 { " bad" } else { "" };
    let progress_class = if in_progress > 0 { " info" } else { "" };
    format!(
        r#"<div class="stats"><div class="stat"><span>Bindings</span><strong>{total}</strong></div><div class="stat ok"><span>Serving</span><strong>{serving}</strong></div><div class="stat{attention_class}"><span>Need attention</span><strong>{attention}</strong></div><div class="stat{progress_class}"><span>In progress</span><strong>{in_progress}</strong></div></div>"#
    )
}

fn binding_row(binding: &Binding, csrf: &str) -> String {
    let csrf = escape_html(csrf);
    let id = &binding.id;
    let hostname = escape_html(&binding.hostname);
    let draining = binding.status == BindingStatus::Draining;
    let host = if matches!(
        binding.status,
        BindingStatus::Active | BindingStatus::Degraded | BindingStatus::Updating
    ) {
        format!(
            r#"<a class="host" href="https://{hostname}/" target="_blank" rel="noopener noreferrer">{hostname}</a>"#
        )
    } else {
        format!(r#"<span class="host">{hostname}</span>"#)
    };
    let health = if draining {
        "Cached traffic is still served briefly".to_owned()
    } else {
        format!("Upstream: {}", title_status(binding.health.as_str()))
    };
    let degraded = binding.status == BindingStatus::Degraded;
    let health_error = if degraded {
        binding
            .last_error
            .as_deref()
            .map(|error| {
                format!(
                    r#"<small class="health-error">{}</small>"#,
                    escape_html(error)
                )
            })
            .unwrap_or_default()
    } else {
        String::new()
    };
    let certificate = if draining {
        r#"<span class="meta"><i class="dot idle"></i>Retained during drain</span>"#.to_owned()
    } else {
        let error = if degraded {
            String::new()
        } else {
            binding
                .last_error
                .as_deref()
                .map(|error| format!("<small>{}</small>", escape_html(error)))
                .unwrap_or_default()
        };
        let status = binding.certificate_status.as_str();
        format!(
            r#"<span class="meta"><i class="dot {status}"></i>{}</span>{error}"#,
            title_status(status),
        )
    };
    let dns = if draining {
        r#"<span class="meta"><i class="dot idle"></i>Released</span>"#
    } else if binding.proxied {
        r#"<span class="meta"><i class="dot cloudflare"></i>Cloudflare proxied</span>"#
    } else {
        r#"<span class="meta"><i class="dot idle"></i>DNS only</span>"#
    };
    let actions = if matches!(
        binding.status,
        BindingStatus::Removing | BindingStatus::Draining
    ) {
        r#"<span class="muted">Removal in progress</span>"#.to_owned()
    } else if binding.status == BindingStatus::Updating {
        r#"<span class="muted">Update in progress</span>"#.to_owned()
    } else {
        let edit = if binding.status.is_editable() {
            format!(r#"<a class="button secondary small" href="/bindings/{id}/edit">Edit</a>"#)
        } else {
            String::new()
        };
        format!(
            r#"<div class="row-actions">{edit}<form class="inline" method="post" action="/bindings/{id}/remove"><input type="hidden" name="csrf" value="{csrf}"><button class="danger small" type="submit">Unbind</button></form></div>"#
        )
    };
    format!(
        r#"<tr data-binding-id="{id}"><td data-label="Hostname">{host}</td><td data-label="Upstream"><code class="upstream">{}://127.0.0.1:{}</code></td><td data-label="Status"><span class="pill {}">{}</span><small>{health}</small>{health_error}</td><td data-label="Certificate">{certificate}</td><td data-label="DNS">{dns}</td><td class="actions" data-label="Actions">{actions}</td></tr>"#,
        escape_html(&binding.upstream_scheme),
        binding.upstream_port,
        binding.status.as_str(),
        title_status(binding.status.as_str()),
    )
}

pub(super) fn binding_edit_page(
    binding: &Binding,
    routes: &[BindingPathRoute],
    csrf: &str,
) -> String {
    let hostname = escape_html(&binding.hostname);
    let binding_id = escape_html(&binding.id);
    let csrf_value = escape_html(csrf);
    let proxied = if binding.proxied { " checked" } else { "" };
    let upstream_port = binding.upstream_port;
    let protocol = protocol_select(&binding.upstream_scheme);
    let path_routes = path_routes_section(&binding_id, routes, &csrf_value);

    app_page(
        "Edit binding",
        "",
        Nav::Bindings,
        csrf,
        &format!(
            r#"<main class="narrow">{back}<div class="page-head"><div><span class="eyebrow">Binding</span><h1>{hostname}</h1><p>Hostnames are immutable. Create a replacement binding to use a different hostname.</p></div></div><form class="card" method="post" action="/bindings/{binding_id}"><input type="hidden" name="csrf" value="{csrf_value}"><div class="form-title"><h2>Default upstream</h2><p>Serves every request that no path route matches.</p></div><div class="callout">{ICON_LOCK}<div><strong>Public HTTPS is automatic</strong><span>These settings only control the connection to the local service.</span></div></div><div class="field-row"><label>Local service protocol{protocol}</label><label>Local port<input name="upstream_port" type="number" min="1" max="65535" value="{upstream_port}" required></label></div><small class="form-help field-note">Private and self-signed loopback certificates are accepted automatically.</small><label class="check"><input name="proxied" type="checkbox" value="true"{proxied}> Enable Cloudflare proxy</label><div class="form-actions"><a class="button ghost" href="/">Cancel</a><button type="submit">Save changes</button></div></form>{path_routes}</main>"#,
            back = back_link("/", "Bindings"),
        ),
    )
}

fn path_routes_section(binding_id: &str, routes: &[BindingPathRoute], csrf: &str) -> String {
    let route_table = if routes.is_empty() {
        r#"<p class="card-empty">No path routes. All requests use the default upstream.</p>"#
            .to_owned()
    } else {
        let rows = routes
            .iter()
            .map(|route| path_route_row(binding_id, route, csrf))
            .collect::<String>();
        format!(
            r#"<div class="table compact-table"><table><thead><tr><th>Path</th><th>Upstream</th><th>Health</th><th><span class="sr-only">Actions</span></th></tr></thead><tbody>{rows}</tbody></table></div>"#
        )
    };
    let protocol = protocol_select("http");

    format!(
        r#"<section class="card path-routes"><div class="card-head"><div><h2>Path routes</h2><p>Send a path prefix to another local service. The longest matching prefix wins; other requests use the default upstream.</p></div></div>{route_table}<form class="add-route" method="post" action="/bindings/{binding_id}/routes"><input type="hidden" name="csrf" value="{csrf}"><h3>Add path route</h3><div class="field-row three"><label>Path prefix<input name="path_prefix" placeholder="/assets" autocomplete="off" spellcheck="false" required></label><label>Local service protocol{protocol}</label><label>Local port<input name="upstream_port" type="number" min="1" max="65535" required></label></div><small class="form-help field-note">The complete request path is preserved. Trailing slashes are normalized.</small><div class="form-actions"><button class="secondary" type="submit">Add path route</button></div></form></section>"#
    )
}

fn path_route_row(binding_id: &str, route: &BindingPathRoute, csrf: &str) -> String {
    let route_id = escape_html(&route.id);
    let path_prefix = escape_html(&route.path_prefix);
    let upstream_scheme = escape_html(&route.upstream_scheme);
    let upstream_port = route.upstream_port;
    let health = route.health.as_str();
    let health_title = title_status(health);
    let health_error = route
        .last_error
        .as_deref()
        .map(|error| {
            format!(
                r#"<small class="health-error">{}</small>"#,
                escape_html(error)
            )
        })
        .unwrap_or_default();

    format!(
        r#"<tr data-route-id="{route_id}"><td data-label="Path"><code>{path_prefix}</code></td><td data-label="Upstream"><code class="upstream">{upstream_scheme}://127.0.0.1:{upstream_port}</code></td><td data-label="Health"><span class="pill {health}">{health_title}</span>{health_error}</td><td class="actions" data-label="Actions"><div class="row-actions"><a class="button secondary small" href="/bindings/{binding_id}/routes/{route_id}/edit">Edit</a><form class="inline" method="post" action="/bindings/{binding_id}/routes/{route_id}/remove"><input type="hidden" name="csrf" value="{csrf}"><button class="danger small" type="submit">Remove</button></form></div></td></tr>"#
    )
}

pub(super) fn protocol_select(selected: &str) -> String {
    let option = |value: &str, label: &str| {
        let selected = if selected == value { " selected" } else { "" };
        format!(r#"<option value="{value}"{selected}>{label}</option>"#)
    };
    format!(
        r#"<select name="upstream_scheme">{}{}</select>"#,
        option("http", "HTTP"),
        option("https", "HTTPS")
    )
}

pub(super) fn back_link(href: &str, label: &str) -> String {
    format!(r#"<a class="crumb" href="{href}">{ICON_ARROW_LEFT}{label}</a>"#)
}

pub(super) fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn format_timestamp(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|moment| {
            let format = time::format_description::parse_borrowed::<2>(
                "[year]-[month]-[day] [hour]:[minute] UTC",
            )
            .ok()?;
            moment.format(&format).ok()
        })
        .unwrap_or_else(|| unix.to_string())
}

pub(super) fn title_status(status: &str) -> String {
    status
        .split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(target_os = "linux")]
pub(super) fn discover_listening_ports() -> Vec<u16> {
    let mut ports = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let Ok(contents) = std::fs::read_to_string(path) else {
            continue;
        };
        for line in contents.lines().skip(1) {
            let columns: Vec<_> = line.split_whitespace().collect();
            if columns.len() > 3
                && columns[3] == "0A"
                && let Some((address, port)) = columns[1].split_once(':')
            {
                // Only offer sockets the proxy can actually reach: it
                // connects to 127.0.0.1, so a listener bound solely to a
                // public interface would always 502.
                let reachable_via_loopback = matches!(
                    address,
                    "0100007F"                                  // 127.0.0.1
                        | "00000000"                            // 0.0.0.0
                        | "00000000000000000000000001000000"    // ::1
                        | "00000000000000000000000000000000" // ::
                );
                if !reachable_via_loopback {
                    continue;
                }
                if let Ok(port) = u16::from_str_radix(port, 16) {
                    ports.push(port);
                }
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[cfg(not(target_os = "linux"))]
pub(super) fn discover_listening_ports() -> Vec<u16> {
    Vec::new()
}

// Icons are inline SVG: the CSP forbids data: URIs and HostKnot ships no
// static asset pipeline.
const KNOT: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.2 13.8a4 4 0 0 1 0-5.66l2.12-2.12a4 4 0 0 1 5.66 5.66l-1.06 1.06"/><path d="M13.8 10.2a4 4 0 0 1 0 5.66l-2.12 2.12a4 4 0 0 1-5.66-5.66l1.06-1.06"/></svg>"#;

const BRAND: &str = r#"<a class="brand" href="/"><span class="mark"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.2 13.8a4 4 0 0 1 0-5.66l2.12-2.12a4 4 0 0 1 5.66 5.66l-1.06 1.06"/><path d="M13.8 10.2a4 4 0 0 1 0 5.66l-2.12 2.12a4 4 0 0 1-5.66-5.66l1.06-1.06"/></svg></span><span class="brand-name">HostKnot</span></a>"#;

pub(super) const ICON_PLUS: &str = r#"<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>"#;

pub(super) const ICON_LOCK: &str = r#"<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4.5" y="10.5" width="15" height="10" rx="2.5"/><path d="M8 10.5V7.5a4 4 0 0 1 8 0v3"/></svg>"#;

pub(super) const ICON_CHECK: &str = r#"<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m5 12.5 4.5 4.5L19 7.5"/></svg>"#;

pub(super) const ICON_ALERT: &str = r#"<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.3 4.2 2.6 17.6A2 2 0 0 0 4.3 20.6h15.4a2 2 0 0 0 1.7-3L13.7 4.2a2 2 0 0 0-3.4 0z"/><path d="M12 9.5v4M12 17h.01"/></svg>"#;

pub(super) const ICON_ARROW_OUT: &str = r#"<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 5h5v5M19 5l-8 8"/><path d="M17 14v4a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 5 18V8.5A1.5 1.5 0 0 1 6.5 7H10"/></svg>"#;

const ICON_ARROW_LEFT: &str = r#"<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M19 12H5M11 18l-6-6 6-6"/></svg>"#;

/// The project logo doubles as the favicon, so README and UI never drift.
pub(super) const FAVICON_SVG: &str = include_str!("../../assets/logo.svg");

const CSS: &str = r#"
:root{
  color-scheme:light;
  --bg:#f7f7f7;--surface:#fff;--subtle:#fafafa;--hover:#f2f2f2;
  --line:#e6e6e6;--line-strong:#d4d4d4;
  --ink:#171717;--ink-2:#404040;--muted:#6b6b6b;--faint:#a3a3a3;
  --accent:#171717;--accent-ink:#fff;--accent-soft:#f0f0f0;--ring:rgb(23 23 23/.16);
  --primary:#171717;--primary-hover:#333;--on-primary:#fff;
  --ok:#1a7f43;--ok-bg:#f0f8f3;--ok-line:#cfe6d8;
  --warn:#9a5b00;--warn-bg:#fcf6ea;--warn-line:#eedcb5;
  --bad:#b8282e;--bad-bg:#fcf1f1;--bad-line:#efcfd0;
  --info:#2f63a3;--info-bg:#f1f5fa;--info-line:#d3e0ef;
  --idle:#6b6b6b;--idle-bg:#f3f3f3;--idle-line:#e2e2e2;
  --cloudflare:#f38020;
  --shadow-sm:0 1px 2px rgb(0 0 0/.04);
  --shadow:0 1px 2px rgb(0 0 0/.04),0 4px 14px -8px rgb(0 0 0/.08);
  --radius:12px;
  --sans:"Inter","InterVariable",ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;
  --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root{
  color-scheme:dark;
  --bg:#111;--surface:#191919;--subtle:#1d1d1d;--hover:#222;
  --line:#2a2a2a;--line-strong:#3a3a3a;
  --ink:#ededed;--ink-2:#c8c8c8;--muted:#929292;--faint:#626262;
  --accent:#ededed;--accent-ink:#111;--accent-soft:#262626;--ring:rgb(255 255 255/.18);
  --primary:#ededed;--primary-hover:#fff;--on-primary:#111;
  --ok:#6cc58f;--ok-bg:#16201a;--ok-line:#26402f;
  --warn:#d9a54c;--warn-bg:#231d12;--warn-line:#45381f;
  --bad:#e87a7e;--bad-bg:#261718;--bad-line:#4a2729;
  --info:#86aedb;--info-bg:#171e27;--info-line:#2a3a4d;
  --idle:#9a9a9a;--idle-bg:#1f1f1f;--idle-line:#333;
  --shadow-sm:none;
  --shadow:none;
}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;display:flex;flex-direction:column;background:var(--bg);color:var(--ink);font:14.5px/1.55 var(--sans);-webkit-font-smoothing:antialiased;font-feature-settings:"cv11","ss01"}
a{color:var(--ink);text-decoration:none}
a:hover{text-decoration:underline;text-underline-offset:3px}
p a,.checklist a,.auth-foot a{text-decoration:underline;text-decoration-color:var(--line-strong);text-underline-offset:3px}
p a:hover,.checklist a:hover{text-decoration-color:currentColor}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
h1,h2,h3{margin:0;color:var(--ink);letter-spacing:-.015em}
h1{font-size:1.6rem;line-height:1.25;font-weight:650;overflow-wrap:anywhere}
h2{font-size:1rem;line-height:1.4;font-weight:600}
h3{font-size:.95rem;font-weight:600}
p{margin:0;color:var(--muted)}
strong{font-weight:600;color:var(--ink)}
code{font-family:var(--mono);font-size:.84em;padding:2px 6px;border:1px solid var(--line);border-radius:6px;background:var(--subtle);color:var(--ink-2);overflow-wrap:anywhere}
.icon{width:16px;height:16px;flex:none}
.muted{color:var(--muted)}
.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}

/* Top bar */
.topbar{position:sticky;top:0;z-index:10;border-bottom:1px solid var(--line);background:color-mix(in srgb,var(--bg) 85%,transparent);backdrop-filter:saturate(1.6) blur(12px);-webkit-backdrop-filter:saturate(1.6) blur(12px)}
.topbar-inner{display:flex;align-items:center;gap:28px;max-width:1120px;height:58px;margin:0 auto;padding:0 24px}
.brand{display:inline-flex;align-items:center;gap:10px;color:var(--ink);font-size:15px;font-weight:650;letter-spacing:-.01em}
.brand:hover{text-decoration:none}
.mark{display:grid;place-items:center;width:26px;height:26px;border-radius:7px;background:var(--ink);color:var(--surface)}
.mark svg{width:17px;height:17px}
.tabs{display:flex;gap:2px;min-width:0}
.tabs a{padding:6px 11px;border-radius:7px;color:var(--muted);font-weight:550;white-space:nowrap}
.tabs a:hover{background:var(--hover);color:var(--ink);text-decoration:none}
.tabs a[aria-current=page]{background:var(--hover);color:var(--ink)}
.topbar .signout{margin-left:auto}

/* Layout */
main{flex:1;width:100%;max-width:1120px;margin:0 auto;padding:36px 24px 80px}
main.narrow{max-width:760px}
.crumb{display:inline-flex;align-items:center;gap:6px;margin-bottom:16px;color:var(--muted);font-size:13.5px;font-weight:550}
.crumb .icon{width:15px;height:15px}
.crumb:hover{color:var(--ink);text-decoration:none}
.page-head{display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:20px;margin-bottom:24px}
.page-head>div:first-child{min-width:0;flex:1 1 320px}
.page-head p{max-width:62ch;margin-top:6px}
.head-actions{display:flex;gap:10px}
.eyebrow{display:block;margin-bottom:6px;color:var(--muted);font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase}

/* Surfaces */
.card{border:1px solid var(--line);border-radius:var(--radius);background:var(--surface);box-shadow:var(--shadow)}
.card+.card,.card+details,details+.card{margin-top:20px}
.card-head{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:16px 20px;border-bottom:1px solid var(--line)}
.card-head p{margin-top:3px;font-size:13.5px}
.card-empty{padding:28px 20px;text-align:center;font-size:14px}
form.card{padding:24px}
.form-title{margin-bottom:20px}
.form-title p{margin-top:3px;font-size:13.5px}

/* Buttons */
button,.button{appearance:none;display:inline-flex;align-items:center;justify-content:center;gap:7px;height:36px;padding:0 15px;border:1px solid transparent;border-radius:8px;background:var(--primary);color:var(--on-primary);font:inherit;font-size:14px;font-weight:550;line-height:1;white-space:nowrap;text-decoration:none;cursor:pointer;transition:background-color .15s,border-color .15s,color .15s,box-shadow .15s}
button:hover,.button:hover{background:var(--primary-hover);text-decoration:none}
.secondary{border-color:var(--line-strong);background:var(--surface);color:var(--ink);box-shadow:var(--shadow-sm)}
.secondary:hover{background:var(--hover)}
.ghost{background:transparent;color:var(--muted)}
.ghost:hover{background:var(--hover);color:var(--ink)}
.danger{border-color:var(--line-strong);background:var(--surface);color:var(--bad);box-shadow:var(--shadow-sm)}
.danger:hover{border-color:var(--bad-line);background:var(--bad-bg)}
.danger.solid{border-color:transparent;background:var(--bad);color:#fff}
.danger.solid:hover{background:color-mix(in srgb,var(--bad) 88%,#000)}
.small{height:30px;padding:0 11px;font-size:13px}
.block{width:100%}
.inline{display:inline;margin:0}

/* Forms */
label{display:block;margin-bottom:18px;color:var(--ink-2);font-size:13.5px;font-weight:550}
input,select{display:block;width:100%;height:38px;margin-top:7px;padding:0 12px;border:1px solid var(--line-strong);border-radius:8px;background:var(--surface);color:var(--ink);font:inherit;font-size:14.5px;font-weight:400;box-shadow:var(--shadow-sm);transition:border-color .15s,box-shadow .15s}
input::placeholder{color:var(--faint)}
input:hover,select:hover{border-color:var(--faint)}
input:focus,select:focus{outline:none;border-color:var(--ink-2);box-shadow:0 0 0 3px var(--ring)}
input[name=hostname],input[name=path_prefix],input[name=client_id]{font-family:var(--mono);font-size:14px}
.form-help{display:block;margin-top:7px;color:var(--muted);font-size:12.5px;font-weight:400;line-height:1.5}
.field-row{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
.field-row.three{grid-template-columns:minmax(0,1.4fr) minmax(0,1fr) minmax(0,1fr)}
.field-row label{margin-bottom:0}
.field-note{margin:8px 0 20px}
.form-actions{display:flex;align-items:center;justify-content:flex-end;gap:10px;margin-top:22px;padding-top:18px;border-top:1px solid var(--line)}
.check{display:flex;align-items:center;gap:12px;color:var(--ink);cursor:pointer}
.check input{appearance:none;-webkit-appearance:none;position:relative;display:inline-block;flex:none;width:36px;height:20px;margin:0;padding:0;border:0;border-radius:999px;background:var(--line-strong);box-shadow:inset 0 1px 2px rgb(0 0 0/.12);cursor:pointer;transition:background-color .18s}
.check input::before{content:"";position:absolute;top:2px;left:2px;width:16px;height:16px;border-radius:50%;background:var(--surface);box-shadow:0 1px 3px rgb(0 0 0/.3);transition:transform .18s}
.check input:checked{background:var(--ink)}
.check input:checked::before{transform:translateX(16px)}
.check input:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.check-help{margin:-12px 0 4px 48px}
.form-error{display:flex;gap:10px;align-items:flex-start;margin-bottom:18px;padding:10px 12px;border:1px solid var(--bad-line);border-radius:8px;background:var(--bad-bg);color:var(--bad);font-size:13.5px}
.form-error .icon{margin-top:2px}

details{margin:0 0 18px}
summary{display:inline-flex;align-items:center;gap:8px;color:var(--ink-2);font-size:13.5px;font-weight:550;list-style:none;cursor:pointer}
summary::-webkit-details-marker{display:none}
summary::before{content:"";width:6px;height:6px;margin-top:-2px;border-right:1.6px solid currentColor;border-bottom:1.6px solid currentColor;transform:rotate(-45deg);transition:transform .15s}
details[open]>summary::before{margin-top:-4px;transform:rotate(45deg)}
.local-options[open] label{margin:14px 0 0}
.reconfigure{margin-top:20px}
.reconfigure form{margin-top:14px}

/* Callouts and notices */
.callout{display:flex;align-items:flex-start;gap:12px;margin-bottom:22px;padding:12px 14px;border:1px solid var(--ok-line);border-radius:10px;background:var(--ok-bg)}
.callout .icon{width:18px;height:18px;margin-top:1px;color:var(--ok)}
.callout strong{display:block;font-size:13.5px}
.callout span{display:block;color:var(--muted);font-size:13px}
.notice{padding:36px 32px;text-align:center}
.notice h1{font-size:1.4rem}
.notice p{max-width:52ch;margin:10px auto 0}
.notice .error-detail{overflow-wrap:anywhere}
.notice-icon{display:grid;place-items:center;width:44px;height:44px;margin:0 auto 16px;border-radius:12px;background:var(--bad-bg);color:var(--bad)}
.notice-icon .icon{width:22px;height:22px}
.notice.warn .notice-icon{background:var(--warn-bg);color:var(--warn)}
.notice.info .notice-icon{background:var(--accent-soft);color:var(--ink)}
.notice-actions,.notice form{display:flex;justify-content:center;gap:10px;margin-top:24px}

/* Auth */
.auth{max-width:420px;padding-top:72px;text-align:center}
.auth .brand{margin-bottom:24px;font-size:16px}
.auth .mark{width:30px;height:30px}
.auth form.card{padding:28px;text-align:left}
.auth h1{font-size:1.35rem}
.auth form>p{margin:4px 0 22px;font-size:14px}
.auth button[type=submit]{width:100%;height:38px;margin-top:4px}
.auth-foot{margin-top:20px;font-size:13px}

/* Dashboard */
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:20px}
.stat{padding:14px 16px;border:1px solid var(--line);border-radius:var(--radius);background:var(--surface);box-shadow:var(--shadow-sm)}
.stat span{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:12.5px;font-weight:550}
.stat strong{display:block;margin-top:4px;font-size:1.55rem;font-weight:650;line-height:1.1;letter-spacing:-.02em;font-variant-numeric:tabular-nums}
.stat.ok span::before,.stat.bad span::before,.stat.info span::before{content:"";width:7px;height:7px;border-radius:50%;background:var(--ok)}
.stat.bad span::before{background:var(--bad)}
.stat.bad strong{color:var(--bad)}
.stat.info span::before{background:var(--info)}
.empty{padding:48px 24px;text-align:center}
.empty p{max-width:52ch;margin:8px auto 0}
.empty-mark{display:grid;place-items:center;width:48px;height:48px;margin:0 auto 16px;border-radius:14px;background:var(--accent-soft);color:var(--ink-2)}
.empty-mark svg{width:24px;height:24px}
.checklist{display:inline-flex;flex-direction:column;gap:10px;margin:22px auto 0;padding:0;list-style:none;counter-reset:step;text-align:left}
.checklist li{display:flex;align-items:center;gap:10px;counter-increment:step;font-weight:550}
.checklist li::before{content:counter(step);display:grid;place-items:center;width:22px;height:22px;border:1px solid var(--line-strong);border-radius:50%;color:var(--muted);font-size:12px}
.checklist li.done{color:var(--muted)}
.checklist li.done::before{content:"✓";border-color:var(--ok-line);background:var(--ok-bg);color:var(--ok)}

/* Tables */
.table{overflow:hidden}
table{width:100%;border-collapse:collapse}
th{padding:10px 16px;border-bottom:1px solid var(--line);background:var(--subtle);color:var(--muted);font-size:12px;font-weight:600;text-align:left;white-space:nowrap}
td{padding:14px 16px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:0}
tbody tr{transition:background-color .12s}
tbody tr:hover{background:var(--subtle)}
td small{display:block;margin-top:5px;color:var(--muted);font-size:12.5px;line-height:1.45}
td small.health-error,.health-error{color:var(--bad)}
.host{color:var(--ink);font-weight:600;overflow-wrap:anywhere}
a.host:hover{text-decoration:underline}
code.upstream{display:inline-block;max-width:100%;overflow-x:auto;overflow-wrap:normal;white-space:nowrap}
.actions{text-align:right;white-space:nowrap}
.actions>.muted{font-size:13px}
.row-actions{display:flex;align-items:center;justify-content:flex-end;flex-wrap:nowrap;gap:8px}
.compact-table{border-bottom:1px solid var(--line)}
.compact-table th:first-child,.compact-table td:first-child{padding-left:20px}
.compact-table th:last-child,.compact-table td:last-child{padding-right:20px}

/* Status */
.pill{display:inline-flex;align-items:center;gap:6px;height:22px;padding:0 9px 0 8px;border:1px solid var(--idle-line);border-radius:999px;background:var(--idle-bg);color:var(--idle);font-size:12.5px;font-weight:550;white-space:nowrap}
.pill::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.pill.active,.pill.healthy{border-color:var(--ok-line);background:var(--ok-bg);color:var(--ok)}
.pill.degraded{border-color:var(--warn-line);background:var(--warn-bg);color:var(--warn)}
.pill.unavailable{border-color:var(--bad-line);background:var(--bad-bg);color:var(--bad)}
.pill.dns_pending,.pill.certificate_pending,.pill.updating{border-color:var(--info-line);background:var(--info-bg);color:var(--info)}
.pill.dns_pending::before,.pill.certificate_pending::before,.pill.updating::before,.pill.removing::before,.pill.draining::before{animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{50%{opacity:.3}}
.meta{display:inline-flex;align-items:center;gap:8px;color:var(--ink-2);white-space:nowrap}
.dot{flex:none;width:7px;height:7px;border-radius:50%;background:var(--faint)}
.dot.active{background:var(--ok)}
.dot.pending{background:var(--info)}
.dot.cloudflare{background:var(--cloudflare)}

/* Activity */
.events ol{margin:0;padding:6px 0;list-style:none}
.events li{display:grid;grid-template-columns:86px minmax(0,1fr) auto;align-items:baseline;gap:14px;padding:9px 20px}
.events li+li{border-top:1px solid var(--line)}
.tag{justify-self:start;padding:1px 7px;border:1px solid var(--idle-line);border-radius:5px;background:var(--idle-bg);color:var(--muted);font-size:11.5px;font-weight:600;text-transform:capitalize}
.tag.security{border-color:var(--warn-line);background:var(--warn-bg);color:var(--warn)}
.event-message{min-width:0;color:var(--ink-2);font-size:13.5px;overflow-wrap:anywhere}
.repeat{color:var(--faint);font-size:12px}
.events time{color:var(--faint);font-family:var(--mono);font-size:12px;white-space:nowrap}

/* Path routes */
.path-routes{margin-top:20px}
.add-route{padding:20px}
.add-route h3{margin-bottom:14px}
.add-route .form-actions{margin-top:0;padding-top:0;border:0}

/* Cloudflare */
.status-card{display:flex;align-items:center;gap:14px;padding:16px 20px}
.status-card .status-icon{display:grid;place-items:center;flex:none;width:36px;height:36px;border-radius:10px;background:var(--idle-bg);color:var(--idle)}
.status-card.good .status-icon{background:var(--ok-bg);color:var(--ok)}
.status-card.pending .status-icon{background:var(--info-bg);color:var(--info)}
.status-card .status-text{flex:1;min-width:0}
.status-card strong,.status-card span{display:block}
.status-card span{color:var(--muted);font-size:13.5px}
.step{padding:24px}
.step-head{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.step-num{display:grid;place-items:center;flex:none;width:28px;height:28px;border-radius:50%;background:var(--ink);color:var(--surface);font-size:13px;font-weight:700}
.step-label{display:block;color:var(--muted);font-size:11.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase}
.step>p{margin-bottom:12px}
.step>p:last-child{margin-bottom:0}
.step-actions{margin:16px 0 4px}
.step form{margin:0}
.oauth-settings{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;margin:18px 0;overflow:hidden;border:1px solid var(--line);border-radius:10px;background:var(--line)}
.oauth-settings>div{min-width:0;padding:12px 14px;background:var(--subtle)}
.oauth-settings .wide{grid-column:1/-1}
.oauth-settings dt{color:var(--muted);font-size:12px;font-weight:550}
.oauth-settings dd{margin:3px 0 0;color:var(--ink);font-weight:600}
.oauth-settings code{display:block;margin-top:2px;padding:8px 10px;overflow-x:auto;overflow-wrap:normal;white-space:nowrap;background:var(--surface);font-size:13px;font-weight:450;user-select:all;-webkit-user-select:all}

/* Card-style rows when six columns no longer fit comfortably. */
@media(max-width:1100px){
  .table table,.table tbody{display:block}
  .table thead{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
  .table tr{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px 20px;padding:18px 20px;border-bottom:1px solid var(--line)}
  .table tr:last-child{border-bottom:0}
  .table td{display:block;min-width:0;padding:0;border:0}
  .table td::before{content:attr(data-label);display:block;margin-bottom:6px;color:var(--muted);font-size:12px;font-weight:600}
  .table .actions{grid-column:1/-1;text-align:left;white-space:normal}
  .table .actions::before{display:none}
  .table .row-actions{justify-content:flex-start}
}
@media(max-width:720px){
  .stats{grid-template-columns:repeat(2,minmax(0,1fr))}
  .field-row,.field-row.three{grid-template-columns:1fr;gap:0}
  .field-row label{margin-bottom:18px}
  .field-row+.field-note{margin-top:-10px}
  .events li{grid-template-columns:auto minmax(0,1fr)}
  .events time{display:none}
}
@media(max-width:560px){
  .topbar-inner{gap:14px;padding:0 16px}
  .brand-name{display:none}
  main{padding:28px 16px 64px}
  h1{font-size:1.4rem}
  form.card,.step{padding:20px}
  .oauth-settings{grid-template-columns:1fr}
  .oauth-settings .wide{grid-column:auto}
  .table td:nth-child(-n+2){grid-column:1/-1}
  .auth{padding-top:40px}
  .auth .brand-name{display:inline}
}
@media(prefers-reduced-motion:reduce){*,*::before{animation:none!important;transition:none!important}}
"#;
