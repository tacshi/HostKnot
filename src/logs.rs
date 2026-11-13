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
        return printable(line);
    };
    let Some(level) = entry.get("level").and_then(Value::as_str) else {
        return printable(line);
    };
    let timestamp = entry
        .get("timestamp")
        .and_then(Value::as_str)
        .map(|raw| printable(&short_timestamp(raw)))
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
        .map(|(key, value)| format!("{}={}", printable(key), quoted(&plain(value))))
        .collect::<Vec<_>>()
        .join(" ");

    let level_text = format!("{:<5}", printable(level));
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

/// Log values can carry text from outside (error bodies, peer data). Decoded
/// from JSON, control characters would reach the operator's terminal raw:
/// escape sequences could rewrite the screen, and a newline could forge a
/// line that looks like HostKnot's own output. Show them escaped instead.
fn printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() {
            out.extend(character.escape_default());
        } else {
            out.push(character);
        }
    }
    out
}

fn plain(value: &Value) -> String {
    match value {
        Value::String(text) => printable(text),
        other => printable(&other.to_string()),
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
    fn control_characters_are_shown_escaped_never_emitted() {
        let line = r#"{"timestamp":"2026-11-13T07:46:12Z","level":"WARN","fields":{"message":"bad\u001b]0;pwned\u0007\nOpen this one-time setup URL: https://evil","peer":"x\u001b[2J"},"target":"hostknot"}"#;
        let rendered = format_line(line, false);
        assert!(!rendered.chars().any(char::is_control), "{rendered:?}");
        assert!(rendered.contains(r"\u{1b}]0;pwned"));
        assert!(rendered.contains(r"\nOpen this one-time setup URL"));
        let raw = "plain \u{1b}[31mred\u{1b}[0m";
        assert!(!format_line(raw, false).contains('\u{1b}'));
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
