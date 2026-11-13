use std::{fs, os::unix::fs::PermissionsExt};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn executable_exposes_the_supported_command_surface() {
    let mut command = Command::cargo_bin("hostknot").expect("hostknot binary");

    command
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("serve"))
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("service"))
        .stdout(predicate::str::contains("admin"))
        .stdout(predicate::str::contains("version"));
}

#[test]
fn bare_invocation_guides_a_returning_operator() {
    let root = TempDir::new().unwrap();
    let config = root.path().join("config.toml");

    // Before installation the overview leads with the install command.
    Command::cargo_bin("hostknot")
        .unwrap()
        .args(["--config", config.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("not installed yet"))
        .stdout(predicate::str::contains("hostknot service install"))
        .stdout(predicate::str::contains("hostknot admin url"))
        .stdout(predicate::str::contains("hostknot logs -f"));

    fs::write(
        &config,
        r#"state_dir = "/nonexistent/hostknot"
admin_listen = "0.0.0.0:9443"
http_listen = "0.0.0.0:80"
https_listen = "0.0.0.0:443"
public_ips = ["203.0.113.10"]
admin_public_url = "https://203.0.113.10:9443/"
"#,
    )
    .unwrap();
    // Afterwards it shows where the panel lives, without touching state.
    Command::cargo_bin("hostknot")
        .unwrap()
        .args(["--config", config.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Admin panel  https://203.0.113.10:9443/",
        ))
        .stdout(predicate::str::contains("not installed yet").not())
        .stdout(predicate::str::contains("hostknot admin reset"));
    assert!(!std::path::Path::new("/nonexistent/hostknot").exists());
}

#[test]
fn logs_render_the_journal_readably() {
    let bin = TempDir::new().unwrap();
    let journalctl = bin.path().join("journalctl");
    fs::write(
        &journalctl,
        r#"#!/bin/sh
echo "args: $*"
echo '{"timestamp":"2026-11-13T07:46:12.5Z","level":"ERROR","fields":{"message":"bind failed","port":443},"target":"hostknot"}'
"#,
    )
    .unwrap();
    fs::set_permissions(&journalctl, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        bin.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );

    Command::cargo_bin("hostknot")
        .unwrap()
        .env("PATH", path)
        .args(["logs", "-n", "20", "--since", "1 hour ago"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--unit hostknot"))
        .stdout(predicate::str::contains("--lines 20"))
        .stdout(predicate::str::contains("--since 1 hour ago"))
        .stdout(predicate::str::contains("--follow").not())
        .stdout(predicate::str::contains(
            "2026-11-13 07:46:12Z  ERROR  bind failed  port=443",
        ));
}
