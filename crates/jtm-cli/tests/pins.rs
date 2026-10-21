//! `jtm pin`, `unpin`, `current`, `which` and `exec` end to end.

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::fs;
use std::path::Path;

use common::Fixture;
use serde_json::Value;

fn ready() -> Fixture {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["install", "demo@1.0.0", "demo@1.1.0"]);
    assert_eq!(code, 0, "{value}");
    f
}

/// Runs `args` with `--json` in `dir`.
fn json_in(f: &Fixture, dir: &Path, args: &[&str]) -> (i32, Value) {
    let output = f
        .jtm()
        .current_dir(dir)
        .env_remove("JTM_SESSION_DEMO")
        .arg("--json")
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1, "one envelope: {stdout}");
    (
        output.status.code().unwrap(),
        serde_json::from_str(&stdout).unwrap(),
    )
}

/// Adds an sdkmanrc interop entry to the fixture plugin.
fn with_sdkmanrc(f: &Fixture) {
    let path = f
        .home
        .path()
        .join("plugins")
        .join("demo@0123abc")
        .join("plugin.toml");
    let mut text = fs::read_to_string(&path).unwrap();
    text.push_str("\n[[interop]]\nfile = \".sdkmanrc\"\nparser = \"keyvalue\"\nkey = \"demo\"\n");
    fs::write(path, text).unwrap();
}

#[test]
fn pin_writes_jtm_toml_and_is_idempotent() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    let (code, value) = json_in(&f, project.path(), &["pin", "demo@1.1"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["command"], "pin");
    assert_eq!(value["changed"], true);
    assert_eq!(value["data"]["format"], "native");
    assert_eq!(value["data"]["value"], "1.1");
    assert_eq!(
        fs::read_to_string(project.path().join(".jtm.toml")).unwrap(),
        "[tools]\ndemo = \"1.1\"\n"
    );
    let (code, again) = json_in(&f, project.path(), &["pin", "demo@1.1"]);
    assert_eq!(code, 0);
    assert_eq!(again["changed"], false);
}

#[test]
fn pin_exact_and_dry_run() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    let (code, value) = json_in(
        &f,
        project.path(),
        &["pin", "demo@1", "--exact", "--dry-run"],
    );
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["value"], "default:1.1.0");
    assert_eq!(value["data"]["dry_run"], true);
    assert_eq!(value["changed"], false);
    assert!(!project.path().join(".jtm.toml").exists());
}

#[test]
fn pin_format_writes_the_chosen_file() {
    let f = ready();
    with_sdkmanrc(&f);
    let project = tempfile::tempdir().unwrap();
    fs::write(project.path().join(".sdkmanrc"), "# keep me\nother=1\n").unwrap();
    let (code, value) = json_in(
        &f,
        project.path(),
        &["pin", "demo@1.0.0", "--format", "sdkmanrc"],
    );
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["format"], "sdkmanrc");
    assert_eq!(
        fs::read_to_string(project.path().join(".sdkmanrc")).unwrap(),
        "# keep me\nother=1\ndemo=1.0.0\n"
    );
    assert!(!project.path().join(".jtm.toml").exists());

    let (code, value) = json_in(
        &f,
        project.path(),
        &["pin", "demo@1", "--format", "tool-versions"],
    );
    assert_eq!(code, 2, "{value}");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("sdkmanrc")
    );
}

#[test]
fn pin_needs_a_version_and_a_known_tool() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    let (code, _) = json_in(&f, project.path(), &["pin", "demo"]);
    assert_eq!(code, 2);
    let (code, value) = json_in(&f, project.path(), &["pin", "nope@1"]);
    assert_eq!(code, 3, "{value}");
    assert_eq!(value["error"]["code"], "E_TOOL_UNKNOWN");
}

#[test]
fn unpin_removes_the_pin() {
    let f = ready();
    with_sdkmanrc(&f);
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join(".jtm.toml"),
        "# c\n[tools]\ndemo = \"1.1\"\n",
    )
    .unwrap();
    fs::write(project.path().join(".sdkmanrc"), "demo=1.1\n").unwrap();
    let child = project.path().join("sub");
    fs::create_dir(&child).unwrap();
    let (code, value) = json_in(&f, &child, &["unpin", "demo"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["changed"], true);
    assert_eq!(value["data"]["removed"].as_array().unwrap().len(), 2);
    assert_eq!(
        fs::read_to_string(project.path().join(".jtm.toml")).unwrap(),
        "# c\n[tools]\n"
    );
    let (code, again) = json_in(&f, &child, &["unpin", "demo"]);
    assert_eq!(code, 0);
    assert_eq!(again["changed"], false);
}

#[test]
fn current_reports_the_winning_layer() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    let (_, value) = json_in(&f, project.path(), &["current"]);
    // The builtin plugins are listed too.
    let demo = value["data"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["tool"] == "demo")
        .unwrap();
    assert!(demo["layer"].is_null(), "{value}");

    f.json(&["default", "demo@1.0.0"]);
    let (_, value) = json_in(&f, project.path(), &["current", "demo"]);
    let demo = &value["data"]["tools"][0];
    assert_eq!(demo["layer"], "default");
    assert_eq!(demo["version"], "1.0.0");

    fs::write(
        project.path().join(".jtm.toml"),
        "[tools]\ndemo = \"1.1\"\n",
    )
    .unwrap();
    let (code, value) = json_in(&f, project.path(), &["current", "demo"]);
    assert_eq!(code, 0, "{value}");
    let demo = &value["data"]["tools"][0];
    assert_eq!(demo["layer"], "project");
    assert_eq!(demo["requested"], "1.1");
    assert_eq!(demo["version"], "1.1.0");
    assert_eq!(demo["installed"], true);
    assert!(demo["origin"].as_str().unwrap().ends_with(".jtm.toml"));
    assert_eq!(
        Path::new(demo["path"].as_str().unwrap()),
        f.install_dir("1.1.0")
    );

    let output = f
        .jtm()
        .current_dir(project.path())
        .env("JTM_SESSION_DEMO", "default:1.0.0")
        .args(["--json", "current", "demo"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["data"]["tools"][0]["layer"], "session");
    assert_eq!(value["data"]["tools"][0]["origin"], "JTM_SESSION_DEMO");
}

#[test]
fn which_finds_the_executable_and_its_layer() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join(".jtm.toml"),
        "[tools]\ndemo = \"1.0\"\n",
    )
    .unwrap();
    let (code, value) = json_in(&f, project.path(), &["which", "demo"]);
    assert_eq!(code, 0, "{value}");
    let data = &value["data"];
    assert_eq!(data["tool"], "demo");
    assert_eq!(data["layer"], "project");
    let path = Path::new(data["path"].as_str().unwrap());
    assert!(
        path.starts_with(f.install_dir("1.0.0").join("bin")),
        "{value}"
    );

    let (code, value) = json_in(&f, project.path(), &["which", "no-such-command-anywhere"]);
    assert_eq!(code, 3, "{value}");

    // A path is never joined onto the bin dirs, so a file elsewhere is not the tool's.
    let elsewhere = project.path().join(".jtm.toml");
    for command in [elsewhere.to_str().unwrap(), "../demo"] {
        let (code, value) = json_in(&f, project.path(), &["which", command]);
        assert_eq!(code, 3, "{command}: {value}");
        assert_eq!(value["error"]["code"], "E_TOOL_UNKNOWN", "{value}");
    }
}

#[test]
fn exec_runs_with_the_requested_version() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    let (code, value) = json_in(&f, project.path(), &["exec", "demo@1.0", "--", "demo"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["command"], "exec");
    assert_eq!(value["data"]["exit_code"], 0);
    assert_eq!(value["data"]["stdout"].as_str().unwrap().trim(), "demo");

    // The child sees the tool's environment.
    let probe = if cfg!(windows) {
        vec!["cmd", "/c", "echo %DEMO_HOME%"]
    } else {
        vec!["sh", "-c", "echo $DEMO_HOME"]
    };
    let mut args = vec!["exec", "demo@1.1", "--"];
    args.extend(&probe);
    let (code, value) = json_in(&f, project.path(), &args);
    assert_eq!(code, 0, "{value}");
    assert_eq!(
        Path::new(value["data"]["stdout"].as_str().unwrap().trim()),
        f.install_dir("1.1.0")
    );
}

#[test]
fn exec_passes_the_exit_code_through() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    let fail = if cfg!(windows) {
        vec!["cmd", "/c", "exit 3"]
    } else {
        vec!["sh", "-c", "exit 3"]
    };
    let output = f
        .jtm()
        .current_dir(project.path())
        .args(["exec", "demo@1.0", "--"])
        .args(&fail)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
}

#[cfg(unix)]
#[test]
fn exec_reports_a_signal_as_128_plus_its_number() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    let output = f
        .jtm()
        .current_dir(project.path())
        .args(["exec", "demo@1.0", "--", "sh", "-c", "kill -9 $$"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(137));
}

#[test]
fn exec_shows_warnings_before_running_the_command() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join(".jtm.toml"),
        "[tools]\ndemo = \"9.9\"\n",
    )
    .unwrap();
    let probe = if cfg!(windows) {
        vec!["cmd", "/c", "exit 0"]
    } else {
        vec!["sh", "-c", "exit 0"]
    };
    let output = f
        .jtm()
        .current_dir(project.path())
        .env_remove("JTM_SESSION_DEMO")
        .arg("exec")
        .arg("--")
        .args(&probe)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("warning[W_NOT_INSTALLED]"), "{stderr}");
}

#[test]
fn activation_uses_the_locked_version() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join(".jtm.toml"),
        "[tools]\ndemo = \"1.0\"\n",
    )
    .unwrap();
    let (code, value) = json_in(&f, project.path(), &["lock"]);
    assert_eq!(code, 0, "{value}");
    // Widen the pin; the lock still says 1.0.0, which satisfies it.
    fs::write(project.path().join(".jtm.toml"), "[tools]\ndemo = \"1\"\n").unwrap();
    let (code, value) = json_in(&f, project.path(), &["lock"]);
    assert_eq!(code, 0, "{value}");
    let (_, value) = json_in(&f, project.path(), &["current", "demo"]);
    let demo = &value["data"]["tools"][0];
    assert_eq!(demo["requested"], "1");
    assert_eq!(demo["version"], "1.0.0", "{value}");
    // --no-lock ignores it and prefers the highest installed match.
    let (_, value) = json_in(&f, project.path(), &["--no-lock", "current", "demo"]);
    assert_eq!(value["data"]["tools"][0]["version"], "1.1.0", "{value}");
}

#[test]
fn conflicts_name_both_files_and_the_winner_in_json() {
    let f = ready();
    with_sdkmanrc(&f);
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join(".jtm.toml"),
        "[tools]\ndemo = \"1.1\"\n",
    )
    .unwrap();
    fs::write(project.path().join(".sdkmanrc"), "demo=1.0\n").unwrap();
    for args in [&["current"][..], &["sync", "--dry-run"][..]] {
        let (code, value) = json_in(&f, project.path(), args);
        assert_eq!(code, 0, "{args:?}: {value}");
        let warning = value["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["code"] == "W_PIN_CONFLICT")
            .unwrap_or_else(|| panic!("{args:?}: {value}"));
        let details = &warning["details"];
        assert_eq!(details["tool"], "demo");
        assert!(
            details["winner"]["file"]
                .as_str()
                .unwrap()
                .ends_with(".jtm.toml")
        );
        assert_eq!(details["winner"]["value"], "default:1.1");
        assert!(
            details["others"][0]["file"]
                .as_str()
                .unwrap()
                .ends_with(".sdkmanrc")
        );
    }
}

#[test]
fn pin_from_a_subdirectory_writes_the_project_file() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    fs::write(project.path().join(".jtm.toml"), "[tools]\n").unwrap();
    let sub = project.path().join("module");
    fs::create_dir(&sub).unwrap();
    let (code, value) = json_in(&f, &sub, &["pin", "demo@1.1"]);
    assert_eq!(code, 0, "{value}");
    assert!(!sub.join(".jtm.toml").exists());
    assert_eq!(
        fs::read_to_string(project.path().join(".jtm.toml")).unwrap(),
        "[tools]\ndemo = \"1.1\"\n"
    );
}

#[test]
fn an_invalid_session_value_is_ignored_and_can_be_unset() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    let output = f
        .jtm()
        .current_dir(project.path())
        .env("JTM_SESSION_DEMO", "not a spec!")
        .args(["--json", "use", "demo", "--unset"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(output.status.code(), Some(0), "{value}");
    assert_eq!(value["warnings"][0]["code"], "W_SESSION_INVALID", "{value}");
    let changes = value["data"]["changes"].as_array().unwrap();
    assert!(
        changes
            .iter()
            .any(|c| c["name"] == "JTM_SESSION_DEMO" && c.get("value").is_none()),
        "{value}"
    );
}
