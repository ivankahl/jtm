#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use jtm_security::testing::TestKey;
use serde_json::{Value, json};

struct Home {
    dir: tempfile::TempDir,
}

impl Home {
    fn new() -> Home {
        Home {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn jtm(&self) -> Command {
        let mut cmd = Command::cargo_bin("jtm").unwrap();
        cmd.env_remove("JTM_LOG")
            .env_remove("JTM_CONFIG")
            .env("JTM_HOME", self.dir.path());
        cmd
    }

    /// Runs `args` with `--json` and returns the exit code and the one envelope on stdout.
    fn json(&self, args: &[&str]) -> (i32, Value) {
        let output = self.jtm().arg("--json").args(args).output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(stdout.lines().count(), 1, "one envelope: {stdout}");
        (
            output.status.code().unwrap(),
            serde_json::from_str(&stdout).unwrap(),
        )
    }

    fn trust_file(&self) -> Value {
        let text = std::fs::read(self.dir.path().join("state").join("trust.json")).unwrap();
        serde_json::from_slice(&text).unwrap()
    }
}

#[test]
fn add_persists_the_key_with_its_scope() {
    let home = Home::new();
    let key = TestKey::generate();
    let public = key.public_str();
    let (code, value) = home.json(&["trust", "add", &public, "--scope", "demo"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["ok"], true);
    assert_eq!(value["command"], "trust add");
    assert_eq!(value["changed"], true);
    assert_eq!(value["data"]["key"]["key"], public.as_str());
    assert_eq!(
        value["data"]["key"]["key_id"],
        key.public().id().to_string()
    );
    assert_eq!(value["data"]["key"]["scope"], json!(["demo"]));

    let stored = home.trust_file();
    assert_eq!(stored["keys"][0]["key"], public.as_str());
    assert_eq!(stored["keys"][0]["scope"], json!(["demo"]));

    let (_, again) = home.json(&["trust", "add", &public, "--scope", "demo"]);
    assert_eq!(again["changed"], false, "re-running is a no-op");

    let (_, wider) = home.json(&["trust", "add", &public, "--scope", "acme/flyway"]);
    assert_eq!(wider["changed"], true);
    assert_eq!(
        wider["data"]["key"]["scope"],
        json!(["acme/flyway", "demo"])
    );
}

#[test]
fn list_reports_every_key() {
    let home = Home::new();
    let (code, empty) = home.json(&["trust", "list"]);
    assert_eq!(code, 0);
    assert_eq!(empty["data"]["keys"], json!([]));
    assert_eq!(empty["changed"], false);

    let (a, b) = (TestKey::generate(), TestKey::generate());
    home.json(&["trust", "add", &a.public_str(), "--scope", "demo"]);
    home.json(&[
        "trust",
        "add",
        &b.public_str(),
        "--scope",
        "other",
        "--scope",
        "demo",
    ]);
    let (_, list) = home.json(&["trust", "list"]);
    let keys = list["data"]["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0]["key"], a.public_str().as_str());
    assert_eq!(keys[1]["scope"], json!(["demo", "other"]));
}

#[test]
fn remove_by_scope_then_entirely() {
    let home = Home::new();
    let key = TestKey::generate();
    let public = key.public_str();
    home.json(&[
        "trust", "add", &public, "--scope", "demo", "--scope", "other",
    ]);

    let (_, partial) = home.json(&["trust", "remove", &public, "--scope", "other"]);
    assert_eq!(partial["changed"], true);
    assert_eq!(partial["data"]["remaining"]["scope"], json!(["demo"]));

    let id = key.public().id().to_string();
    let (_, removed) = home.json(&["trust", "remove", &id]);
    assert_eq!(removed["changed"], true);
    assert_eq!(removed["data"]["remaining"], Value::Null);
    assert_eq!(home.trust_file()["keys"], json!([]));

    let (code, missing) = home.json(&["trust", "remove", &id]);
    assert_eq!(code, 0);
    assert_eq!(missing["changed"], false);
    assert_eq!(missing["warnings"][0]["code"], "W_KEY_NOT_TRUSTED");
}

#[test]
fn bad_input_is_a_usage_error() {
    let home = Home::new();
    let key = TestKey::generate().public_str();
    for args in [
        vec!["trust", "add", "RWnotakey", "--scope", "demo"],
        vec!["trust", "add", key.as_str(), "--scope", "*"],
        vec!["trust", "add", key.as_str()],
        vec!["trust", "remove", "nonsense"],
    ] {
        let (code, value) = home.json(&args);
        assert_eq!(code, 2, "{args:?}: {value}");
        assert_eq!(value["error"]["code"], "E_USAGE", "{args:?}");
    }
    assert!(!home.dir.path().join("state").join("trust.json").exists());
}

#[test]
fn human_output_names_the_key_and_scope() {
    let home = Home::new();
    let key = TestKey::generate();
    let id = key.public().id().to_string();
    home.jtm()
        .args(["trust", "add", &key.public_str(), "--scope", "demo"])
        .assert()
        .success()
        .stdout(format!("key {id} is trusted for demo\n"));
    let output = home.jtm().args(["trust", "list"]).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with(&id), "{stdout}");
}

#[test]
fn a_corrupt_trust_file_is_reported_not_reset() {
    let home = Home::new();
    let state = home.dir.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("trust.json"), "{ broken").unwrap();
    let (code, value) = home.json(&["trust", "list"]);
    assert_eq!(code, 1);
    assert_eq!(value["error"]["code"], "E_INTERNAL");
    assert_eq!(
        std::fs::read_to_string(state.join("trust.json")).unwrap(),
        "{ broken"
    );
}
