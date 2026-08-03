use assert_cmd::Command;
use predicates::prelude::*;

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
