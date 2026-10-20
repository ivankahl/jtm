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

/// The rc file `self setup` edits for bash: `.bash_profile` on macOS, `.bashrc` elsewhere.
fn bash_rc(home: &Path) -> std::path::PathBuf {
    home.join(if cfg!(target_os = "macos") {
        ".bash_profile"
    } else {
        ".bashrc"
    })
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
    assert!(!bash_rc(home.path()).exists());

    let (code, value) = setup(&f, home.path(), "/bin/bash", &["--dry-run"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["changed"], false);
    assert!(!bash_rc(home.path()).exists());

    fs::write(bash_rc(home.path()), "alias ll='ls -l'\n").unwrap();
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
    let rc = fs::read_to_string(bash_rc(home.path())).unwrap();
    assert!(rc.starts_with("alias ll='ls -l'\n"), "{rc}");
    assert_eq!(rc.matches("# >>> jtm >>>").count(), 1);

    let (code, again) = setup(&f, home.path(), "/bin/bash", &["--yes"]);
    assert_eq!(code, 0);
    assert_eq!(again["changed"], false);
    assert_eq!(fs::read_to_string(bash_rc(home.path())).unwrap(), rc);
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
    // A new macOS terminal starts a login shell, which is why setup writes .bash_profile there.
    let login: &[&str] = if shell == "bash" && cfg!(target_os = "macos") {
        &["-l"]
    } else {
        &[]
    };
    let output = Command::new(shell)
        .args(login)
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

#[test]
fn a_new_terminal_applies_project_pins_on_cd() {
    let project = tempfile::tempdir().unwrap();
    fs::write(
        project.path().join(".jtm.toml"),
        "[tools]\ndemo = \"1.0\"\n",
    )
    .unwrap();
    let dir = project.path().display();
    // bash runs the hook from PROMPT_COMMAND, which `-c` never reaches, so it is called here;
    // zsh and fish run it on the directory change itself.
    for (shell, path, script) in [
        (
            "bash",
            "/bin/bash",
            format!("cd '{dir}' && _jtm_hook && echo \"$DEMO_HOME\""),
        ),
        (
            "zsh",
            "/usr/bin/zsh",
            format!("cd '{dir}' && echo \"$DEMO_HOME\""),
        ),
        (
            "fish",
            "/usr/bin/fish",
            format!("cd '{dir}'; and echo $DEMO_HOME"),
        ),
    ] {
        let (f, home) = ready();
        let (code, value) = setup(&f, home.path(), path, &["--yes"]);
        assert_eq!(code, 0, "{shell}: {value}");
        assert_eq!(value["data"]["hook"], true, "{shell}: {value}");
        let Some(out) = new_terminal(&f, home.path(), shell, &script) else {
            continue;
        };
        assert_eq!(
            Path::new(out.trim()),
            f.install_dir("1.0.0"),
            "{shell}: the pin applies, not the default link"
        );
    }
}

#[test]
fn no_hook_leaves_the_shell_hook_out_and_a_rerun_adds_it_back() {
    let (f, home) = ready();
    let (code, value) = setup(&f, home.path(), "/bin/bash", &["--yes", "--no-hook"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["hook"], false);
    let rc = fs::read_to_string(bash_rc(home.path())).unwrap();
    assert!(!rc.contains("shell-init"), "{rc}");
    assert!(rc.contains("env.sh"), "{rc}");

    let (code, value) = setup(&f, home.path(), "/bin/bash", &["--yes"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["changed"], true);
    let rc = fs::read_to_string(bash_rc(home.path())).unwrap();
    assert!(rc.contains("shell-init bash"), "{rc}");
    assert_eq!(rc.matches("# >>> jtm >>>").count(), 1);
}

#[test]
fn a_login_shell_without_a_hook_gets_the_environment_and_a_warning() {
    let (f, home) = ready();
    let (code, value) = setup(&f, home.path(), "/bin/tcsh", &["--yes"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["data"]["hook"], false);
    assert_eq!(value["warnings"][0]["code"], "W_SHELL_HOOK_SKIPPED");
    let profile = fs::read_to_string(home.path().join(".profile")).unwrap();
    assert!(profile.contains("env.sh") && !profile.contains("shell-init"));
}

#[test]
fn an_unreadable_rc_file_is_never_overwritten() {
    let (f, home) = ready();
    let original = b"# caf\xe9\nalias ll='ls -l'\n";
    fs::write(bash_rc(home.path()), original).unwrap();
    let (code, value) = setup(&f, home.path(), "/bin/bash", &["--yes"]);
    assert_ne!(code, 0, "{value}");
    assert_eq!(value["error"]["code"], "E_IO");
    assert_eq!(fs::read(bash_rc(home.path())).unwrap(), original);
}

#[test]
fn uninstalling_the_default_clears_it_from_the_env_files() {
    let (f, home) = ready();
    let (code, value) = setup(&f, home.path(), "/bin/bash", &["--yes"]);
    assert_eq!(code, 0, "{value}");
    let env_sh = f.home.path().join("env.sh");
    assert!(fs::read_to_string(&env_sh).unwrap().contains("DEMO_HOME"));

    let (code, value) = f.json(&["uninstall", "demo@1.0.0"]);
    assert_eq!(code, 0, "{value}");
    assert!(!fs::read_to_string(&env_sh).unwrap().contains("DEMO_HOME"));
}
