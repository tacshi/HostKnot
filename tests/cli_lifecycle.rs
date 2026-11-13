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
    assert!(unit.contains("LimitNOFILE=65536"));
    assert!(unit.contains("SystemCallFilter=@system-service"));
    assert!(unit.contains("SystemCallErrorNumber=EPERM"));
    assert!(unit.contains("UMask=0077"));
    // ReadWritePaths would conflict with the StateDirectory symlink under
    // ProtectSystem=strict, and a pre-created root-owned master key would be
    // unreadable by the DynamicUser service.
    assert!(!unit.contains("ReadWritePaths"));
    assert!(!root.path().join("var/lib/hostknot/master.key").exists());
    let config_path = root.path().join("etc/hostknot/config.toml");
    let original_config = fs::read_to_string(&config_path).unwrap();
    // The config names the path the service sees at runtime, not the
    // install root.
    assert!(original_config.contains("state_dir = \"/var/lib/hostknot\""));

    // A symlink planted at the staging path is replaced, never written through.
    let victim = root.path().join("victim");
    fs::write(&victim, "untouched").unwrap();
    let staged = root.path().join("usr/local/bin/hostknot.staged");
    std::os::unix::fs::symlink(&victim, &staged).unwrap();
    fs::remove_file(root.path().join("usr/local/bin/hostknot")).unwrap();

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
    assert_eq!(fs::read_to_string(&victim).unwrap(), "untouched");
    assert!(!staged.exists());
    assert!(root.path().join("usr/local/bin/hostknot").is_file());

    // Point doctor at the state inside the install root for the checks below.
    let state_dir = root.path().join("var/lib/hostknot");
    fs::write(
        &config_path,
        original_config.replace(
            "state_dir = \"/var/lib/hostknot\"",
            &format!("state_dir = \"{}\"", state_dir.display()),
        ),
    )
    .unwrap();

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

    // Before the service has ever run there is nothing to open, and the CLI
    // must not create state on its behalf.
    let state_dir = root.path().join("state");
    Command::cargo_bin("hostknot")
        .unwrap()
        .args(["admin", "url", "--config", config_path.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Start the service first"));
    assert!(!state_dir.exists());
    start_and_stop_service(&state_dir);

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

#[test]
fn admin_commands_explain_missing_root_instead_of_failing_obscurely() {
    let root = TempDir::new().unwrap();
    // Mirror systemd's DynamicUser layout: /var/lib/hostknot is a symlink
    // into a directory only root can traverse.
    let private = root.path().join("private");
    start_and_stop_service(&private.join("hostknot"));
    let state_dir = root.path().join("hostknot");
    std::os::unix::fs::symlink(private.join("hostknot"), &state_dir).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o000)).unwrap();
    let restore = || fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    if fs::read_dir(&private).is_ok() {
        // Running as root: permissions are not enforced, nothing to test.
        restore();
        return;
    }

    for command in ["url", "reset"] {
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
                state_dir.display()
            ),
        )
        .unwrap();
        Command::cargo_bin("hostknot")
            .unwrap()
            .args(["admin", command, "--config", config_path.to_str().unwrap()])
            .assert()
            .failure()
            .stderr(predicate::str::contains("Run this command with sudo"))
            .stderr(predicate::str::contains("File exists").not());
    }
    restore();
}

/// Lets the real service create its state directory, key, and database, as
/// systemd does on first start.
fn start_and_stop_service(state_dir: &std::path::Path) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let running = hostknot::HostKnot::start(hostknot::Config::for_test(
            state_dir,
            "127.0.0.1:0".parse().unwrap(),
        ))
        .await
        .unwrap();
        running.shutdown().await;
    });
}

#[test]
fn doctor_without_root_says_so_instead_of_claiming_the_state_is_missing() {
    let root = TempDir::new().unwrap();
    let private = root.path().join("private");
    fs::create_dir_all(private.join("hostknot")).unwrap();
    let state_dir = root.path().join("hostknot");
    std::os::unix::fs::symlink(private.join("hostknot"), &state_dir).unwrap();
    let config_path = root.path().join("config.toml");
    fs::write(
        &config_path,
        format!(
            r#"state_dir = "{}"
admin_listen = "127.0.0.1:0"
http_listen = "127.0.0.1:0"
https_listen = "127.0.0.1:0"
public_ips = ["203.0.113.10"]
admin_public_url = "https://203.0.113.10:9443/"
"#,
            state_dir.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o000)).unwrap();
    let running_as_root = fs::read_dir(&private).is_ok();
    let output = Command::cargo_bin("hostknot")
        .unwrap()
        .args([
            "doctor",
            "--offline",
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    if running_as_root {
        return;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success(), "{stdout}");
    assert!(stdout.contains("run: sudo hostknot doctor"), "{stdout}");
    assert!(
        !stdout.contains("will be created on first start"),
        "{stdout}"
    );
}
