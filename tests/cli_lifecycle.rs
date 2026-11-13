use std::{fs, os::unix::fs::PermissionsExt};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

#[test]
fn systemd_install_is_hardened_idempotent_and_doctor_can_validate_it() {
    let root = TempDir::new().unwrap();
    let binary = assert_cmd::cargo::cargo_bin!("hostknot");

    let mut install = Command::cargo_bin("hostknot").unwrap();
    install
        .args([
            "service",
            "install",
            "--root",
            root.path().to_str().unwrap(),
            "--binary",
            binary.to_str().unwrap(),
            "--public-ip",
            "203.0.113.10",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("installed"))
        .stdout(predicate::str::contains("sudo hostknot admin url"))
        .stdout(predicate::str::contains("https://203.0.113.10:9443/"))
        .stdout(predicate::str::contains("Run `hostknot` to see them again"));

    let unit = fs::read_to_string(root.path().join("etc/systemd/system/hostknot.service"))
        .expect("systemd unit");
    assert!(unit.contains("DynamicUser=yes"));
    assert!(unit.contains("StateDirectory=hostknot"));
    assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("NoNewPrivileges=yes"));
    // ReadWritePaths would conflict with the StateDirectory symlink under
    // ProtectSystem=strict, and a pre-created root-owned master key would be
    // unreadable by the DynamicUser service.
    assert!(!unit.contains("ReadWritePaths"));
    assert!(!root.path().join("var/lib/hostknot/master.key").exists());
    let config_path = root.path().join("etc/hostknot/config.toml");
    let original_config = fs::read_to_string(&config_path).unwrap();

    let mut reinstall = Command::cargo_bin("hostknot").unwrap();
    reinstall
        .args([
            "service",
            "install",
            "--root",
            root.path().to_str().unwrap(),
            "--binary",
            binary.to_str().unwrap(),
            "--public-ip",
            "203.0.113.10",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("upgraded"))
        .stdout(predicate::str::contains("systemctl restart hostknot"));
    assert_eq!(fs::read_to_string(&config_path).unwrap(), original_config);

    let mut doctor = Command::cargo_bin("hostknot").unwrap();
    doctor
        .args([
            "doctor",
            "--config",
            root.path()
                .join("etc/hostknot/config.toml")
                .to_str()
                .unwrap(),
            "--offline",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ready"))
        .stdout(predicate::str::contains("state directory"))
        .stdout(predicate::str::contains("public IP"));

    // A world-readable master key must fail doctor with a non-zero exit,
    // while still reporting the remaining checks.
    let state_dir = root.path().join("var/lib/hostknot");
    fs::create_dir_all(&state_dir).unwrap();
    let key_path = state_dir.join("master.key");
    fs::write(&key_path, [7_u8; 32]).unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();
    let mut failing_doctor = Command::cargo_bin("hostknot").unwrap();
    failing_doctor
        .args([
            "doctor",
            "--config",
            root.path()
                .join("etc/hostknot/config.toml")
                .to_str()
                .unwrap(),
            "--offline",
        ])
        .assert()
        .failure()
        .stdout(predicate::str::contains("[fail] master key permissions"))
        .stdout(predicate::str::contains("not ready"))
        .stdout(predicate::str::contains("listener"));
}

#[test]
fn admin_url_prints_a_fresh_setup_link_from_the_config() {
    let root = TempDir::new().unwrap();
    let config_path = root.path().join("config.toml");
    fs::write(
        &config_path,
        format!(
            r#"state_dir = "{}"
admin_listen = "127.0.0.1:9443"
http_listen = "127.0.0.1:80"
https_listen = "127.0.0.1:443"
public_ips = ["203.0.113.10"]
admin_public_url = "https://203.0.113.10:9443/"
"#,
            root.path().join("state").display()
        ),
    )
    .unwrap();

    let link = |output: &[u8]| {
        String::from_utf8_lossy(output)
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("https://203.0.113.10:9443/setup?token=")
                    .map(str::to_owned)
            })
            .expect("setup link in output")
    };
    let first = Command::cargo_bin("hostknot")
        .unwrap()
        .args(["admin", "url", "--config", config_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("expires in 1 hour"))
        .get_output()
        .stdout
        .clone();
    let second = Command::cargo_bin("hostknot")
        .unwrap()
        .args(["admin", "url", "--config", config_path.to_str().unwrap()])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    assert_ne!(link(&first), link(&second));

    Command::cargo_bin("hostknot")
        .unwrap()
        .args(["admin", "reset", "--config", config_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "https://203.0.113.10:9443/setup?token=",
        ));
}
