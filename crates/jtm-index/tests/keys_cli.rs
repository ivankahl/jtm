//! The ceremony commands end to end: build an unsigned `keys.json`, co-sign it with two of
//! three throwaway root keys the way the offline machine does, then verify it.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::Path;

use assert_cmd::Command;
use jtm_security::testing::TestKey;

const EXPIRES: &str = "2027-01-17T08:00:00Z";
const NOW: &str = "2026-12-18T08:00:00Z";

fn manifest(name: &str, roots: &[TestKey]) -> String {
    let keys = roots
        .iter()
        .map(|k| format!("\"{}\"", k.public_str()))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "schema = 1\nname = \"{name}\"\ndisplay_name = \"{name}\"\ndescription = \"d\"\n\
         homepage = \"https://example.org\"\nlicense = \"MIT\"\nmin_jtm = \"0.1.0\"\n\
         [versions]\nscheme = \"semver-loose\"\n\
         [index]\nurl = \"https://example.org/{{os}}-{{arch}}.json\"\n\
         signing_keys = [{keys}]\nthreshold = 2\nformat = 1\n\
         [layout]\nbin_dirs = [\"bin\"]\n"
    )
}

fn plugins(dir: &Path, roots: &[TestKey]) {
    for name in ["alpha", "beta"] {
        fs::create_dir_all(dir.join("plugins").join(name)).unwrap();
        fs::write(
            dir.join("plugins").join(name).join("plugin.toml"),
            manifest(name, roots),
        )
        .unwrap();
    }
}

fn tool(dir: &Path) -> Command {
    let mut cmd = Command::cargo_bin("jtm-index").unwrap();
    cmd.current_dir(dir);
    cmd
}

fn build(dir: &Path, index: &TestKey) {
    tool(dir)
        .args(["keys", "build", "--plugins", "plugins", "--sequence", "4"])
        .args(["--now", NOW])
        .arg("--index-key")
        .arg(format!("{}@{EXPIRES}", index.public_str()))
        .assert()
        .success();
}

#[test]
fn build_sign_and_verify_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let roots = [
        TestKey::generate(),
        TestKey::generate(),
        TestKey::generate(),
    ];
    plugins(dir.path(), &roots);
    build(dir.path(), &TestKey::generate());

    let data = fs::read(dir.path().join("keys.json")).unwrap();
    let sigs = [roots[0].sign(&data), roots[2].sign(&data)].concat();
    fs::write(dir.path().join("keys.json.minisig"), sigs).unwrap();

    let out = tool(dir.path())
        .args([
            "keys",
            "verify",
            "--plugins",
            "plugins",
            "--now",
            NOW,
            "--json",
        ])
        .args(["--previous-sequence", "3"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["ok"], true);
    assert_eq!(report["sequence"], 4);
    assert_eq!(
        report["plugins"],
        serde_json::json!(["alpha", "beta", "marketplace"])
    );
    assert_eq!(report["signers"].as_array().unwrap().len(), 2);
}

#[test]
fn verify_exits_5_with_a_json_error_when_the_threshold_is_not_met() {
    let dir = tempfile::tempdir().unwrap();
    let roots = [
        TestKey::generate(),
        TestKey::generate(),
        TestKey::generate(),
    ];
    plugins(dir.path(), &roots);
    build(dir.path(), &TestKey::generate());
    let data = fs::read(dir.path().join("keys.json")).unwrap();
    fs::write(dir.path().join("keys.json.minisig"), roots[1].sign(&data)).unwrap();

    let out = tool(dir.path())
        .args([
            "keys",
            "verify",
            "--plugins",
            "plugins",
            "--now",
            NOW,
            "--json",
        ])
        .assert()
        .code(5)
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["error"]["code"], "E_SIGNATURE_INVALID");
}

#[test]
fn verify_against_replacement_roots_for_a_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let old = [
        TestKey::generate(),
        TestKey::generate(),
        TestKey::generate(),
    ];
    let new = [
        TestKey::generate(),
        TestKey::generate(),
        TestKey::generate(),
    ];
    plugins(dir.path(), &old);
    build(dir.path(), &TestKey::generate());
    let data = fs::read(dir.path().join("keys.json")).unwrap();
    let cross = [
        old[0].sign(&data),
        old[1].sign(&data),
        new[1].sign(&data),
        new[2].sign(&data),
    ]
    .concat();
    fs::write(dir.path().join("keys.json.minisig"), cross).unwrap();

    let mut cmd = tool(dir.path());
    cmd.args(["keys", "verify", "--plugins", "plugins", "--now", NOW]);
    cmd.args(["--root-threshold", "2"]);
    for key in &new {
        cmd.args(["--root-key", &key.public_str()]);
    }
    cmd.assert().success();
}

#[test]
fn build_rejects_a_key_expiring_too_far_out_with_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    plugins(dir.path(), &[TestKey::generate(), TestKey::generate()]);
    tool(dir.path())
        .args(["keys", "build", "--plugins", "plugins", "--sequence", "1"])
        .args(["--now", NOW])
        .arg("--index-key")
        .arg(format!(
            "{}@2028-01-01T00:00:00Z",
            TestKey::generate().public_str()
        ))
        .assert()
        .code(2);
    assert!(!dir.path().join("keys.json").exists());
}
