//! `jtm env`, `jtm use` and `jtm shell-init`, end to end and in real shells where installed.

#![allow(clippy::unwrap_used, clippy::panic, clippy::print_stderr)]

mod common;

use std::path::Path;
use std::process::Command;

use common::Fixture;
use serde_json::Value;

fn ready() -> Fixture {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["install", "demo@1.0.0", "demo@1.1.0"]);
    assert_eq!(code, 0, "{value}");
    f
}

fn change<'v>(changes: &'v Value, name: &str) -> Option<&'v Value> {
    changes
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
}

#[test]
fn use_reports_the_changes_in_json() {
    let f = ready();
    let (code, value) = f.json(&["use", "demo@1.0"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["command"], "use");
    assert_eq!(value["changed"], true);
    let data = &value["data"];
    assert_eq!(data["tool"], "demo");
    assert_eq!(data["version"], "1.0.0");
    let changes = &data["changes"];
    let home = f.install_dir("1.0.0");
    assert_eq!(
        change(changes, "DEMO_HOME").unwrap()["value"],
        home.display().to_string()
    );
    assert_eq!(
        change(changes, "JTM_SESSION_DEMO").unwrap()["value"],
        "default:1.0.0"
    );
    let path = change(changes, "PATH").unwrap()["value"].as_str().unwrap();
    assert!(
        path.starts_with(&home.join("bin").display().to_string()),
        "{path}"
    );
}

#[test]
fn use_needs_an_installed_version_or_install() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["use", "demo@1.0"]);
    assert_eq!(code, 7, "{value}");
    assert_eq!(value["error"]["code"], "E_INPUT_REQUIRED");
    let (code, value) = f.json(&["use", "demo@1.0", "--install"]);
    assert_eq!(code, 0, "{value}");
}

#[test]
fn use_without_the_hook_explains_shell_init() {
    let f = ready();
    let output = f.jtm().args(["use", "demo@1.0"]).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("shell-init"), "{stderr}");
}

#[test]
fn env_applies_project_pins_and_nothing_else() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join(".jtm.toml"),
        "[tools]\ndemo = \"1.1\"\n",
    )
    .unwrap();
    let output = f
        .jtm()
        .current_dir(project.path())
        .args(["env", "--json"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["ok"], true, "{value}");
    let changes = &value["data"]["changes"];
    assert_eq!(
        change(changes, "DEMO_HOME").unwrap()["value"],
        f.install_dir("1.1.0").display().to_string()
    );
    assert_eq!(
        change(changes, "JTM_PROJECT_DEMO").unwrap()["value"],
        "default:1.1.0"
    );

    // Outside the project nothing is overridden.
    let elsewhere = tempfile::tempdir().unwrap();
    let output = f
        .jtm()
        .current_dir(elsewhere.path())
        .args(["env", "--json"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        change(&value["data"]["changes"], "DEMO_HOME").is_none(),
        "{value}"
    );
}

#[test]
fn a_pinned_version_that_is_not_installed_is_a_warning() {
    let f = ready();
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join(".jtm.toml"),
        "[tools]\ndemo = \"2.0.0-rc-1\"\n",
    )
    .unwrap();
    let output = f
        .jtm()
        .current_dir(project.path())
        .args(["env", "--json"])
        .output()
        .unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["warnings"][0]["code"], "W_NOT_INSTALLED", "{value}");
}

#[test]
fn shell_init_json_carries_the_script() {
    let f = ready();
    let (code, value) = f.json(&["shell-init", "bash"]);
    assert_eq!(code, 0, "{value}");
    assert!(value["data"]["script"].as_str().unwrap().contains("jtm()"));
    let (code, value) = f.json(&["shell-init", "cmd"]);
    assert_eq!(code, 2, "{value}");
}

/// Runs `script` in `shell` with the fixture's environment, or `None` when the shell is not
/// installed.
fn run_shell(f: &Fixture, shell: &str, args: &[&str], script: &str) -> Option<String> {
    let found = Command::new(shell)
        .args(["-c", "exit 0"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .or_else(|| {
            Command::new(shell)
                .args(["-NoProfile", "-Command", "exit 0"])
                .output()
                .ok()
        });
    if found.is_none() {
        eprintln!("{shell} is not installed; skipping");
        return None;
    }
    let output = Command::new(shell)
        .args(args)
        .arg(script)
        .env("JTM_HOME", f.home.path())
        .env_remove("JTM_CONFIG")
        .env_remove("JTM_LOG")
        .env_remove("JTM_SAVED")
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{shell}: {stdout}\n{stderr}");
    Some(stdout)
}

fn check(f: &Fixture, out: &str) {
    let lines: Vec<&str> = out.lines().map(str::trim).collect();
    assert_eq!(lines.len(), 4, "{out}");
    let home = f.install_dir("1.0.0");
    assert_eq!(Path::new(lines[0]), home);
    assert!(Path::new(lines[1]).starts_with(home.join("bin")), "{out}");
    assert_eq!(lines[2], "default:1.0.0");
    assert_eq!(lines[3], "unset");
}

#[cfg(unix)]
#[test]
fn bash_and_zsh_apply_and_undo_use() {
    let f = ready();
    let exe = f.exe();
    for shell in ["bash", "zsh"] {
        let script = format!(
            r#"eval "$('{exe}' shell-init {shell})"
jtm use demo@1.0
echo "$DEMO_HOME"
command -v demo
echo "$JTM_SESSION_DEMO"
jtm use demo --unset
echo "${{DEMO_HOME-unset}}""#,
            exe = exe.display()
        );
        if let Some(out) = run_shell(&f, shell, &["-c"], &script) {
            check(&f, &out);
        }
    }
}

#[cfg(unix)]
#[test]
fn fish_applies_and_undoes_use() {
    let f = ready();
    let script = format!(
        r#"'{exe}' shell-init fish | source
jtm use demo@1.0
echo $DEMO_HOME
command -v demo
echo $JTM_SESSION_DEMO
jtm use demo --unset
if set -q DEMO_HOME; echo $DEMO_HOME; else; echo unset; end"#,
        exe = f.exe().display()
    );
    if let Some(out) = run_shell(&f, "fish", &["-c"], &script) {
        check(&f, &out);
    }
}

#[test]
fn powershell_applies_and_undoes_use() {
    let f = ready();
    let script = format!(
        r#"Invoke-Expression ((& '{exe}' shell-init pwsh) -join "`n")
jtm use demo@1.0
Write-Output $env:DEMO_HOME
Write-Output (Get-Command demo).Source
Write-Output $env:JTM_SESSION_DEMO
jtm use demo --unset
if ($null -eq $env:DEMO_HOME) {{ 'unset' }} else {{ $env:DEMO_HOME }}"#,
        exe = f.exe().display()
    );
    if let Some(out) = run_shell(&f, "pwsh", &["-NoProfile", "-Command"], &script) {
        check(&f, &out);
    }
}

/// A project pinning `demo@1.1` with a subdirectory, and an unrelated directory.
fn project() -> (tempfile::TempDir, tempfile::TempDir) {
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join(".jtm.toml"),
        "[tools]\ndemo = \"1.1\"\n",
    )
    .unwrap();
    std::fs::create_dir(project.path().join("sub")).unwrap();
    (project, tempfile::tempdir().unwrap())
}

/// Entering the project applies its pin; `jtm use` overrides it until the next directory
/// change; leaving restores the original environment.
fn check_switching(f: &Fixture, out: &str) {
    let lines: Vec<&str> = out.lines().map(str::trim).collect();
    assert_eq!(lines.len(), 5, "{out}");
    assert_eq!(Path::new(lines[0]), f.install_dir("1.1.0"), "{out}");
    assert_eq!(Path::new(lines[1]), f.install_dir("1.0.0"), "{out}");
    assert_eq!(Path::new(lines[2]), f.install_dir("1.1.0"), "{out}");
    assert_eq!(lines[3], "unset", "{out}");
    let tools = f.home.path().join("tools").display().to_string();
    assert!(
        !lines[4].contains(&tools),
        "PATH still has jtm entries: {out}"
    );
}

#[cfg(unix)]
#[test]
fn bash_and_zsh_switch_on_directory_change() {
    let f = ready();
    let (project, other) = project();
    for shell in ["bash", "zsh"] {
        let script = format!(
            r#"eval "$('{exe}' shell-init {shell})"
cd '{project}'; _jtm_hook
echo "$DEMO_HOME"
jtm use demo@1.0
echo "$DEMO_HOME"
cd sub; _jtm_hook
echo "$DEMO_HOME"
cd '{other}'; _jtm_hook
echo "${{DEMO_HOME-unset}}"
echo "$PATH""#,
            exe = f.exe().display(),
            project = project.path().display(),
            other = other.path().display(),
        );
        if let Some(out) = run_shell(&f, shell, &["-c"], &script) {
            check_switching(&f, &out);
        }
    }
}

#[cfg(unix)]
#[test]
fn fish_switches_on_directory_change() {
    let f = ready();
    let (project, other) = project();
    // fish runs the hook itself when PWD changes.
    let script = format!(
        r#"'{exe}' shell-init fish | source
cd '{project}'
echo $DEMO_HOME
jtm use demo@1.0
echo $DEMO_HOME
cd sub
echo $DEMO_HOME
cd '{other}'
if set -q DEMO_HOME; echo $DEMO_HOME; else; echo unset; end
echo "$PATH""#,
        exe = f.exe().display(),
        project = project.path().display(),
        other = other.path().display(),
    );
    if let Some(out) = run_shell(&f, "fish", &["-c"], &script) {
        check_switching(&f, &out);
    }
}

#[test]
fn powershell_switches_on_directory_change() {
    let f = ready();
    let (project, other) = project();
    let script = format!(
        r#"Invoke-Expression ((& '{exe}' shell-init pwsh) -join "`n")
Set-Location '{project}'; _jtm_hook
Write-Output $env:DEMO_HOME
jtm use demo@1.0
Write-Output $env:DEMO_HOME
Set-Location sub; _jtm_hook
Write-Output $env:DEMO_HOME
Set-Location '{other}'; _jtm_hook
if ($null -eq $env:DEMO_HOME) {{ 'unset' }} else {{ $env:DEMO_HOME }}
Write-Output $env:PATH"#,
        exe = f.exe().display(),
        project = project.path().display(),
        other = other.path().display(),
    );
    if let Some(out) = run_shell(&f, "pwsh", &["-NoProfile", "-Command"], &script) {
        check_switching(&f, &out);
    }
}

#[test]
fn the_hook_prints_nothing_when_nothing_changes() {
    let f = ready();
    let (project, _other) = project();
    let first = f
        .jtm()
        .current_dir(project.path())
        .args(["hook-env", "--shell", "bash"])
        .output()
        .unwrap();
    assert!(first.status.success());
    let script = String::from_utf8(first.stdout).unwrap();
    assert!(script.contains("DEMO_HOME"), "{script}");

    // Apply the first run's changes to the next run's environment.
    let mut cmd = f.jtm();
    cmd.current_dir(project.path())
        .args(["hook-env", "--shell", "bash"]);
    for line in script.lines() {
        let line = line.strip_prefix("export ").unwrap();
        let (name, value) = line.split_once('=').unwrap();
        cmd.env(name, value.trim_matches('\''));
    }
    let second = cmd.output().unwrap();
    assert!(second.status.success());
    assert_eq!(String::from_utf8(second.stdout).unwrap(), "");
}
