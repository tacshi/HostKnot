use axum::{
    http::StatusCode,
    response::{Html, IntoResponse, Response},
};

use crate::model::{Binding, BindingPathRoute};

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

pub(super) fn page(title: &str, body: &str) -> String {
    page_with_head(title, "", body)
}

pub(super) fn binding_edit_page(
    binding: &Binding,
    routes: &[BindingPathRoute],
    csrf: &str,
) -> String {
    let hostname = escape_html(&binding.hostname);
    let binding_id = escape_html(&binding.id);
    let csrf = escape_html(csrf);
    let http_selected = if binding.upstream_scheme == "http" {
        " selected"
    } else {
        ""
    };
    let https_selected = if binding.upstream_scheme == "https" {
        " selected"
    } else {
        ""
    };
    let proxied = if binding.proxied { " checked" } else { "" };
    let upstream_port = binding.upstream_port;
    let path_routes = path_routes_section(&binding_id, routes, &csrf);

    page(
        "Edit binding",
        &format!(
            r#"<main><a href="/">← Bindings</a><span class="eyebrow block">EDIT ROUTE</span><h1>{hostname}</h1><p>Hostnames are immutable. Create a replacement binding to use a different hostname.</p><form method="post" action="/bindings/{binding_id}"><input type="hidden" name="csrf" value="{csrf}"><div class="managed-tls"><strong>Public HTTPS is automatic</strong><span>These settings only control the connection to the local service.</span></div><label>Local service protocol<select name="upstream_scheme"><option value="http"{http_selected}>HTTP</option><option value="https"{https_selected}>HTTPS</option></select><small class="form-help">Private and self-signed loopback certificates are accepted automatically.</small></label><label>Local port<input name="upstream_port" type="number" min="1" max="65535" value="{upstream_port}" required></label><label class="check"><input name="proxied" type="checkbox" value="true"{proxied}> Enable Cloudflare proxy</label><button type="submit">Save changes</button></form>{path_routes}</main>"#
        ),
    )
}

fn path_routes_section(binding_id: &str, routes: &[BindingPathRoute], csrf: &str) -> String {
    let route_table = if routes.is_empty() {
        r#"<p class="muted">No path routes. All requests use the default upstream.</p>"#.to_owned()
    } else {
        let rows = routes
            .iter()
            .map(|route| path_route_row(binding_id, route, csrf))
            .collect::<String>();
        format!(
            r#"<section class="table compact-table"><table><thead><tr><th>Path</th><th>Upstream</th><th>Health</th><th>Actions</th></tr></thead><tbody>{rows}</tbody></table></section>"#
        )
    };

    format!(
        r#"<section class="path-routes"><span class="eyebrow block">PATH ROUTES</span><h2>Secondary services</h2><p>The longest matching path uses its configured service. Other requests continue to use the default upstream.</p>{route_table}<form method="post" action="/bindings/{binding_id}/routes"><input type="hidden" name="csrf" value="{csrf}"><h3>Add path route</h3><label>Path prefix<input name="path_prefix" placeholder="/assets" required><small class="form-help">The complete request path is preserved. Trailing slashes are normalized.</small></label><label>Local service protocol<select name="upstream_scheme"><option value="http" selected>HTTP</option><option value="https">HTTPS</option></select></label><label>Local port<input name="upstream_port" type="number" min="1" max="65535" required></label><button type="submit">Add path route</button></form></section>"#
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
        r#"<tr data-route-id="{route_id}"><td data-label="Path"><code>{path_prefix}</code></td><td data-label="Upstream"><code class="upstream">{upstream_scheme}://127.0.0.1:{upstream_port}</code></td><td data-label="Health"><span class="pill {health}">{health_title}</span>{health_error}</td><td class="actions" data-label="Actions"><div class="row-actions"><a class="button secondary" href="/bindings/{binding_id}/routes/{route_id}/edit">Edit</a><form class="inline" method="post" action="/bindings/{binding_id}/routes/{route_id}/remove"><input type="hidden" name="csrf" value="{csrf}"><button class="danger" type="submit">Remove</button></form></div></td></tr>"#
    )
}

/// Every failure the operator can hit renders as a styled page with a way
/// back — never a bare text response.
pub(super) fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    Html(page(
        title,
        &format!(
            r#"<main class="narrow"><span class="eyebrow">SOMETHING NEEDS ATTENTION</span><h1>{}</h1><p class="error-detail">{}</p><p><a class="button" href="/">Back to bindings</a></p></main>"#,
            escape_html(title),
            escape_html(message)
        ),
    ))
    .into_response_with_status(status)
}

pub(super) fn page_with_head(title: &str, head: &str, body: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">{head}<title>{title} · HostKnot</title><style>{CSS}</style></head><body>{body}</body></html>"#
    )
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

const CSS: &str = r#"
:root{color-scheme:dark;--bg:#101311;--panel:#181d1a;--line:#303a33;--ink:#f4f7f4;--muted:#9ba89f;--accent:#a7f3c3}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(circle at top right,#20352a 0,transparent 32rem),var(--bg);color:var(--ink);font:16px/1.5 ui-sans-serif,system-ui,sans-serif;min-height:100vh}
main{max-width:1050px;margin:0 auto;padding:64px 28px}
.narrow{max-width:620px}
.eyebrow{color:var(--accent);font-size:.75rem;font-weight:800;letter-spacing:.18em}
.block{display:block;margin-top:2rem}
header{display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:24px}
header>div{min-width:0}
nav{display:flex;align-items:center;flex-wrap:wrap;gap:18px}
h1{font-size:clamp(2.2rem,6vw,4rem);line-height:1;margin:.25rem 0 1rem;letter-spacing:-.05em;overflow-wrap:anywhere}
h2{margin-top:0}
p{color:var(--muted)}
a{color:var(--accent)}
form,.empty,.instructions,.status,.table,.events{margin-top:2rem;padding:28px;border:1px solid var(--line);border-radius:18px;background:color-mix(in srgb,var(--panel) 94%,transparent);box-shadow:0 24px 80px #0005}
.inline{margin:0;padding:0;border:0;background:none;box-shadow:none}
.status{display:flex;justify-content:space-between;gap:18px}
.status span,small,.muted{display:block;color:var(--muted)}
.form-help{margin-top:7px}
.health-error{margin-top:5px;color:#ffb4a9}
.managed-tls{display:flex;flex-direction:column;gap:3px;margin-bottom:22px;padding:14px 16px;border:1px solid #65d68b66;border-radius:12px;background:#112219}
.managed-tls span{color:var(--muted);font-size:.875rem}
.local-options{margin:-2px 0 20px;color:var(--muted)}
.local-options summary{width:max-content;max-width:100%;cursor:pointer;color:var(--accent)}
.local-options label{margin:16px 0 0}
.provider-actions{margin:1rem 0 0}
.next-step .button{margin-top:6px}
.reconfigure{margin-top:18px;color:var(--muted)}
.reconfigure summary{width:max-content;max-width:100%;cursor:pointer;color:var(--accent)}
.reconfigure form{margin-top:14px}
.step-label{display:block;margin-bottom:8px;color:var(--accent);font-size:.7rem;font-weight:800;letter-spacing:.14em}
.oauth-settings{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;margin:20px 0;border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--line)}
.oauth-settings>div{min-width:0;padding:14px 16px;background:#0d100e}
.oauth-settings .wide{grid-column:1/-1}
.oauth-settings dt{color:var(--muted);font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em}
.oauth-settings dd{margin:5px 0 0;color:var(--ink);font-weight:700}
.oauth-settings code{display:block;overflow-x:auto;overflow-wrap:normal;white-space:nowrap;padding:0;background:none;font-size:.875rem;font-weight:500}
label{display:block;color:var(--muted);font-size:.875rem;margin-bottom:20px}
input,select{width:100%;margin-top:7px;border:1px solid var(--line);border-radius:10px;background:#0d100e;color:var(--ink);font:inherit;padding:12px 14px;outline:none}
.check{display:flex;align-items:center;gap:10px}
.check input{width:auto;margin:0}
input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px #a7f3c322}
button,.button{display:inline-block;border:0;border-radius:999px;background:var(--accent);color:#102117;font:inherit;font-weight:800;padding:12px 20px;cursor:pointer;text-decoration:none;white-space:nowrap}
.secondary{border:1px solid var(--line);background:transparent;color:var(--accent)}
.danger{background:#ffb4a9;color:#3b0a06}
code{overflow-wrap:anywhere;background:#0b0e0c;padding:6px 9px;border-radius:8px;color:#d6ffe5}
code.upstream{display:inline-block;max-width:100%;overflow-x:auto;overflow-wrap:normal;white-space:nowrap}
.instructions code{display:block;padding:12px}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:14px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.1em}
.actions{white-space:nowrap}
.actions .inline{margin:0}
.row-actions{display:flex;align-items:center;gap:10px;flex-wrap:nowrap}
.row-actions button,.row-actions .button{padding:10px 16px}
.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:3px 10px}
.pill.active{border-color:#65d68b;color:var(--accent)}
.pill.healthy{border-color:#65d68b;color:var(--accent)}
.pill.degraded{border-color:#f2c94c88;color:#f2d98a}
.pill.unavailable{border-color:#ffb4a988;color:#ffb4a9}
.pill.removing,.pill.updating{border-color:#ffb4a988;color:#ffb4a9}
.pill.draining,.pill.dns_pending,.pill.certificate_pending{color:var(--muted)}
.check-help{margin:-12px 0 20px 30px}
.path-routes{margin-top:3rem}
.compact-table{margin-top:1rem}
.error-detail{overflow-wrap:anywhere}
.events ol{list-style:none;margin:0;padding:0}
.events li{display:flex;align-items:baseline;gap:12px;padding:10px 0;border-bottom:1px solid var(--line)}
.events li:last-child{border-bottom:0}
.events .tag{flex-shrink:0;border:1px solid var(--line);border-radius:6px;padding:1px 8px;color:var(--muted);font-size:.7rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.events .event-message{min-width:0;overflow-wrap:anywhere}
.events .repeat{color:var(--muted);font-size:.8rem}
.events time{margin-left:auto;flex-shrink:0;color:var(--muted);font-size:.8rem;white-space:nowrap}
@media(max-width:600px){.events time{display:none}}
@media(max-width:1100px){
  .table table,.table tbody{display:block}
  .table thead{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
  .table tr{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:20px;padding:22px 0;border-bottom:1px solid var(--line)}
  .table tr:first-child{padding-top:0}
  .table tr:last-child{padding-bottom:0;border-bottom:0}
  .table td{display:block;min-width:0;padding:0;border:0}
  .table td::before{content:attr(data-label);display:block;margin-bottom:7px;color:var(--muted);font-size:.75rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase}
  .table .actions{grid-column:1/-1;white-space:normal}
  .table .actions .inline{margin:0}
}
@media(max-width:900px){
  header{align-items:flex-start;flex-direction:column}
}
@media(max-width:500px){
  main{padding:40px 18px}
  form,.empty,.instructions,.status,.table,.events{padding:20px}
  .oauth-settings{grid-template-columns:1fr}
  .oauth-settings .wide{grid-column:auto}
  .table tr{grid-template-columns:1fr}
  .table .actions{grid-column:auto}
}
"#;
