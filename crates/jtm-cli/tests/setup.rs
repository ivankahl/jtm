//! `jtm self setup` end to end on Unix, checked by starting new shells that read only their rc
//! files. The Windows registry path is tested in `setup/windows/tests.rs`.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::panic, clippy::print_stderr)]

mod common;

use std::fs;
use std::path::Path;
use std::process::Command;

use common::Fixture;
use serde_json::Value;

fn ready() -> (Fixture, tempfile::TempDir) {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["default", "demo@1.0.0", "--install"]);
    assert_eq!(code, 0, "{value}");
    (f, tempfile::tempdir().unwrap())
}

fn setup(f: &Fixture, home: &Path, shell: &str, args: &[&str]) -> (i32, Value) {
    let output = f
        .jtm()
        .env("HOME", home)
        .env("SHELL", shell)
        .env_remove("ZDOTDIR")
        .env_remove("XDG_CONFIG_HOME")
        .args(["--json", "self", "setup"])
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    (
        output.status.code().unwrap(),
        serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("{stdout}")),
    )
}

#[test]
fn setup_needs_yes_without_a_terminal_and_is_idempotent() {
    let (f, home) = ready();
    let (code, value) = setup(&f, home.path(), "/bin/bash", &[]);
    assert_eq!(code, 7, "{value}");
    assert_eq!(value["error"]["code"], "E_INPUT_REQUIRED");
    assert!(
        value["error"]["details"]["resolve"]
            .as_str()
            .unwrap()
            .contains("--yes")
    );
    assert!(!home.path().join(".bashrc").exists());

    let (code, value) = setup(&f, home.path(), "/bin/bash", &["--dry-run"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["changed"], false);
    assert!(!home.path().join(".bashrc").exists());

    fs::write(home.path().join(".bashrc"), "alias ll='ls -l'\n").unwrap();
    let (code, value) = setup(&f, home.path(), "/bin/bash", &["--yes"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["changed"], true);
    let current = f.home.path().join("current").join("demo");
    assert_eq!(
        value["data"]["path"][0],
        current.join("bin").display().to_string()
    );
    assert_eq!(
        value["data"]["vars"]["DEMO_HOME"],
        current.display().to_string()
    );
    let rc = fs::read_to_string(home.path().join(".bashrc")).unwrap();
    assert!(rc.starts_with("alias ll='ls -l'\n"), "{rc}");
    assert_eq!(rc.matches("# >>> jtm >>>").count(), 1);

    let (code, again) = setup(&f, home.path(), "/bin/bash", &["--yes"]);
    assert_eq!(code, 0);
    assert_eq!(again["changed"], false);
    assert_eq!(fs::read_to_string(home.path().join(".bashrc")).unwrap(), rc);
}

/// Starts `shell` as a new interactive shell with only `home`'s rc files, and prints where
/// `demo` comes from and `DEMO_HOME`.
fn new_terminal(f: &Fixture, home: &Path, shell: &str, script: &str) -> Option<String> {
    if Command::new(shell)
        .arg("-c")
        .arg("exit 0")
        .output()
        .is_err()
    {
        eprintln!("{shell} is not installed; skipping");
        return None;
    }
    let output = Command::new(shell)
        .args(["-i", "-c", script])
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin")
        .env("TERM", "dumb")
        .env("JTM_HOME", f.home.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(String::from_utf8(output.stdout).unwrap())
}

#[test]
fn a_new_terminal_runs_the_default_in_bash_zsh_and_fish() {
    let current = |f: &Fixture| f.home.path().join("current").join("demo");
    for (shell, path, script) in [
        ("bash", "/bin/bash", "command -v demo; echo \"$DEMO_HOME\""),
        (
            "zsh",
            "/usr/bin/zsh",
            "command -v demo; echo \"$DEMO_HOME\"",
        ),
        ("fish", "/usr/bin/fish", "command -v demo; echo $DEMO_HOME"),
    ] {
        let (f, home) = ready();
        let (code, value) = setup(&f, home.path(), path, &["--yes"]);
        assert_eq!(code, 0, "{shell}: {value}");
        let Some(out) = new_terminal(&f, home.path(), shell, script) else {
            continue;
        };
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "{shell}: {out}");
        assert_eq!(
            Path::new(lines[0]),
            current(&f).join("bin").join("demo"),
            "{shell}"
        );
        assert_eq!(Path::new(lines[1]), current(&f), "{shell}");
        // The program found through the link is the default version.
        assert_eq!(fs::read(current(&f).join("VERSION")).unwrap(), b"1.0.0");

        // A later default reaches new terminals with no rc change.
        let rc_before = fs::read_dir(home.path()).unwrap().count();
        let (code, value) = f.json(&["default", "demo@1.1.0", "--install"]);
        assert_eq!(code, 0, "{value}");
        assert_eq!(fs::read(current(&f).join("VERSION")).unwrap(), b"1.1.0");
        assert_eq!(fs::read_dir(home.path()).unwrap().count(), rc_before);
    }
}
