#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use serde_json::Value;

fn jtm() -> Command {
    let mut cmd = Command::cargo_bin("jtm").unwrap();
    cmd.env_remove("JTM_LOG");
    cmd
}

fn envelope(output: &std::process::Output) -> Value {
    let stdout = std::str::from_utf8(&output.stdout).unwrap();
    assert_eq!(
        stdout.lines().count(),
        1,
        "stdout must hold exactly one document: {stdout}"
    );
    serde_json::from_str(stdout).unwrap()
}

#[test]
fn version_json_prints_a_valid_envelope() {
    let output = jtm().args(["--version", "--json"]).output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let value = envelope(&output);
    assert_eq!(value["ok"], true);
    assert_eq!(value["command"], "version");
    assert_eq!(value["changed"], false);
    assert_eq!(value["data"]["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["warnings"], Value::Array(Vec::new()));
    assert_eq!(value["jtm_version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn version_prints_human_text() {
    jtm()
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("jtm {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn bad_flag_with_json_is_a_usage_envelope() {
    let output = jtm().args(["--json", "--no-such-flag"]).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let value = envelope(&output);
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["code"], "E_USAGE");
    assert_eq!(value["error"]["retryable"], false);
}

#[test]
fn bad_flag_without_json_exits_with_usage_code() {
    let output = jtm().arg("--no-such-flag").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn no_arguments_shows_help_and_exits_with_usage_code() {
    let output = jtm().output().unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn invalid_env_value_is_a_usage_envelope() {
    let output = jtm()
        .args(["--version", "--json"])
        .env("JTM_OFFLINE", "maybe")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let value = envelope(&output);
    assert_eq!(value["error"]["code"], "E_USAGE");
}

#[test]
fn verbose_logs_go_to_stderr_not_stdout() {
    let output = jtm()
        .args(["--version", "--json", "--verbose"])
        .output()
        .unwrap();
    assert!(output.status.success());
    envelope(&output);
    assert!(String::from_utf8_lossy(&output.stderr).contains("resolved context"));
}
