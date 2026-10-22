//! The `jtm-index` binary: usage errors and failures that need no network.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use assert_cmd::Command;
use serde_json::Value;

fn jtm_index() -> Command {
    let mut command = Command::cargo_bin("jtm-index").unwrap();
    // Nothing from the developer's or CI's environment may reach a test.
    command
        .env_remove("GITHUB_TOKEN")
        .env_remove("INDEX_SECRET_KEY");
    command
}

fn stdout_json(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}): {:?}", output.stdout))
}

#[test]
fn help_lists_the_generate_command() {
    let output = jtm_index().arg("--help").output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("generate"), "{text}");
}

#[test]
fn generate_help_documents_the_json_and_dry_run_flags() {
    let output = jtm_index().args(["generate", "--help"]).output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for flag in [
        "--json",
        "--dry-run",
        "--secret-key",
        "--secret-key-env",
        "--previous",
    ] {
        assert!(text.contains(flag), "{flag} is missing from:\n{text}");
    }
}

#[test]
fn a_usage_error_with_json_is_one_envelope_on_stdout() {
    let output = jtm_index()
        .args(["generate", "--json", "--no-such-flag"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let json = stdout_json(&output);
    assert_eq!(json["ok"], false);
    assert_eq!(json["error"]["code"], "E_USAGE");
    assert_eq!(json["error"]["retryable"], false);
}

#[test]
fn a_usage_error_without_json_goes_to_stderr() {
    let output = jtm_index()
        .args(["generate", "--no-such-flag"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output.stderr.is_empty());
}

#[test]
fn a_run_without_a_key_fails_before_touching_anything() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("release");
    let output = jtm_index()
        .args(["generate", "--json", "--plugin-dir"])
        .arg(dir.path())
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let json = stdout_json(&output);
    assert_eq!(json["error"]["code"], "E_USAGE");
    assert!(
        json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--secret-key")
    );
    assert!(!out.exists());
}

#[test]
fn a_missing_plugin_directory_fails_with_the_plugin_code() {
    let dir = tempfile::tempdir().unwrap();
    let output = jtm_index()
        .args(["generate", "--json", "--dry-run", "--plugin-dir"])
        .arg(dir.path().join("nowhere"))
        .arg("--out")
        .arg(dir.path().join("release"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5));
    let json = stdout_json(&output);
    assert_eq!(json["ok"], false);
    assert_eq!(json["command"], "generate");
    assert_eq!(json["error"]["code"], "E_PLUGIN_INVALID");
}

#[test]
fn the_key_variable_is_read_from_the_environment_but_never_printed() {
    let dir = tempfile::tempdir().unwrap();
    let output = jtm_index()
        .env("INDEX_SECRET_KEY", "SECRET-MARKER-9876 is not a key")
        .args([
            "generate",
            "--json",
            "--secret-key-env",
            "INDEX_SECRET_KEY",
            "--plugin-dir",
        ])
        .arg(dir.path())
        .arg("--out")
        .arg(dir.path().join("release"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let everything = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!everything.contains("SECRET-MARKER-9876"), "{everything}");
    assert_eq!(stdout_json(&output)["error"]["code"], "E_USAGE");
}
