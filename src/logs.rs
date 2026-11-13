//! Readable rendering of the service log for `hostknot logs`.
//!
//! The service writes one JSON object per line (tracing's JSON format) to the
//! systemd journal. Operators should not have to read raw JSON, so each line
//! becomes `time  LEVEL  message  key=value…`; anything that is not tracing
//! JSON (for example the plain-text setup link) passes through unchanged.

use serde_json::{Map, Value};

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";

pub fn format_line(line: &str, color: bool) -> String {
    let Ok(Value::Object(entry)) = serde_json::from_str::<Value>(line.trim()) else {
        return line.to_owned();
    };
    let Some(level) = entry.get("level").and_then(Value::as_str) else {
        return line.to_owned();
    };
    let timestamp = entry
        .get("timestamp")
        .and_then(Value::as_str)
        .map(short_timestamp)
        .unwrap_or_default();
    let empty = Map::new();
    let fields = entry
        .get("fields")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let message = fields.get("message").map(plain).unwrap_or_default();
    let extras = fields
        .iter()
        .filter(|(key, _)| key.as_str() != "message")
        .map(|(key, value)| format!("{key}={}", quoted(&plain(value))))
        .collect::<Vec<_>>()
        .join(" ");

    let level_text = format!("{level:<5}");
    if !color {
        let mut out = format!("{timestamp}  {level_text}  {message}");
        if !extras.is_empty() {
            out.push_str("  ");
            out.push_str(&extras);
        }
        return out;
    }
    let level_color = match level {
        "ERROR" => RED,
        "WARN" => YELLOW,
        _ => DIM,
    };
    let message = if matches!(level, "ERROR" | "WARN") {
        format!("{BOLD}{message}{RESET}")
    } else {
        message
    };
    let mut out = format!("{DIM}{timestamp}{RESET}  {level_color}{level_text}{RESET}  {message}");
    if !extras.is_empty() {
        out.push_str(&format!("  {DIM}{extras}{RESET}"));
    }
    out
}

/// `2026-11-13T07:46:12.123456Z` → `2026-11-13 07:46:12Z`.
fn short_timestamp(raw: &str) -> String {
    let trimmed = raw.split('.').next().unwrap_or(raw).replace('T', " ");
    if trimmed.len() == raw.len() || trimmed.ends_with('Z') {
        trimmed
    } else {
        format!("{trimmed}Z")
    }
}

fn plain(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn quoted(value: &str) -> String {
    if value.is_empty() || value.contains(char::is_whitespace) {
        format!("{value:?}")
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::format_line;

    #[test]
    fn tracing_json_becomes_one_readable_line() {
        let line = r#"{"timestamp":"2026-11-13T07:46:12.123456Z","level":"WARN","fields":{"message":"ACME order failed","identifier":"app.example.com","error":"connection reset"},"target":"hostknot::certificates"}"#;
        assert_eq!(
            format_line(line, false),
            r#"2026-11-13 07:46:12Z  WARN   ACME order failed  error="connection reset" identifier=app.example.com"#
        );
    }

    #[test]
    fn plain_text_passes_through() {
        let line = "Open this one-time setup URL: https://203.0.113.10:9443/setup?token=abc";
        assert_eq!(format_line(line, false), line);
        assert_eq!(
            format_line(r#"{"not":"tracing"}"#, false),
            r#"{"not":"tracing"}"#
        );
    }
}
