use std::path::PathBuf;

use jtm_core::ErrorCode;
use jtm_core::doctor::{Check, Finding, Report, Status};

use super::*;
use crate::setup::{START, rc_block};

fn rc_with_hook(dir: &std::path::Path, shell: Shell) -> PathBuf {
    let rc = dir.join(".bashrc");
    let block = rc_block(None, Some(shell), Some("/opt/jtm/bin/jtm"));
    std::fs::write(&rc, block).unwrap();
    rc
}

fn inputs<'a>(
    rc: Option<(PathBuf, Option<Shell>)>,
    pinned: &'a [String],
    active: bool,
) -> Hook<'a> {
    Hook { rc, pinned, active }
}

fn codes(check: &Check) -> Vec<&'static str> {
    check.findings.iter().map(|f| f.code).collect()
}

#[test]
fn a_loaded_hook_passes() {
    let dir = tempfile::tempdir().unwrap();
    let rc = rc_with_hook(dir.path(), Shell::Bash);
    let check = hook_check(&inputs(Some((rc.clone(), Some(Shell::Bash))), &[], true));
    assert_eq!(check.status, Status::Ok, "{check:?}");
    assert!(
        check.summary.contains(&rc.display().to_string()),
        "{}",
        check.summary
    );
    assert!(check.notes.is_empty(), "{:?}", check.notes);
}

#[test]
fn a_hook_that_is_loaded_but_not_active_here_is_a_note_without_pins() {
    let dir = tempfile::tempdir().unwrap();
    let rc = rc_with_hook(dir.path(), Shell::Bash);
    let check = hook_check(&inputs(Some((rc, Some(Shell::Bash))), &[], false));
    assert_eq!(check.status, Status::Ok, "{check:?}");
    assert!(
        check
            .notes
            .iter()
            .any(|n| n.contains("not active in this shell")),
        "{:?}",
        check.notes
    );
}

#[test]
fn a_pinned_project_without_an_active_hook_is_warned_about() {
    let dir = tempfile::tempdir().unwrap();
    let rc = rc_with_hook(dir.path(), Shell::Bash);
    let pinned = vec!["demo".to_owned()];
    let check = hook_check(&inputs(Some((rc, Some(Shell::Bash))), &pinned, false));
    assert_eq!(check.status, Status::Warning, "{check:?}");
    assert_eq!(codes(&check), ["W_SHELL_HOOK_INACTIVE"]);
    let finding = &check.findings[0];
    assert!(finding.message.contains("demo"), "{finding:?}");
    assert!(
        finding.hint.as_deref().unwrap().contains("new terminal"),
        "{finding:?}"
    );
}

#[test]
fn an_rc_file_without_the_hook_names_the_file_and_the_fix() {
    let dir = tempfile::tempdir().unwrap();
    let rc = dir.path().join(".bashrc");
    std::fs::write(&rc, "export FOO=1\n").unwrap();
    let check = hook_check(&inputs(Some((rc.clone(), Some(Shell::Bash))), &[], false));
    assert_eq!(codes(&check), ["W_SHELL_HOOK_MISSING"]);
    let finding = &check.findings[0];
    assert!(
        finding.message.contains(&rc.display().to_string()),
        "{finding:?}"
    );
    assert!(
        finding.hint.as_deref().unwrap().contains("jtm self setup"),
        "{finding:?}"
    );
}

#[test]
fn a_block_written_with_no_hook_does_not_count() {
    let dir = tempfile::tempdir().unwrap();
    let rc = dir.path().join(".bashrc");
    let block = rc_block(
        Some(std::path::Path::new("/data/env.sh")),
        Some(Shell::Bash),
        None,
    );
    assert!(block.contains(START));
    std::fs::write(&rc, block).unwrap();
    let check = hook_check(&inputs(Some((rc, Some(Shell::Bash))), &[], false));
    assert_eq!(codes(&check), ["W_SHELL_HOOK_MISSING"]);
}

#[test]
fn a_missing_rc_file_counts_as_no_hook() {
    let dir = tempfile::tempdir().unwrap();
    let rc = dir.path().join(".zshrc");
    let check = hook_check(&inputs(Some((rc, Some(Shell::Zsh))), &[], false));
    assert_eq!(codes(&check), ["W_SHELL_HOOK_MISSING"]);
}

#[test]
fn a_login_shell_without_a_hook_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let rc = dir.path().join(".profile");
    let check = hook_check(&inputs(Some((rc, None)), &[], false));
    assert_eq!(codes(&check), ["W_SHELL_HOOK_MISSING"]);
    assert!(
        check.findings[0]
            .hint
            .as_deref()
            .unwrap()
            .contains("bash, zsh, fish or pwsh")
    );
}

#[test]
fn an_rc_file_that_cannot_be_read_fails_with_its_own_code() {
    let dir = tempfile::tempdir().unwrap();
    // A directory where the file belongs can be opened but not read as a file.
    let rc = dir.path().join(".bashrc");
    std::fs::create_dir(&rc).unwrap();
    let check = hook_check(&inputs(Some((rc, Some(Shell::Bash))), &[], false));
    assert_eq!(check.status, Status::Failed, "{check:?}");
    assert!(
        matches!(codes(&check).as_slice(), ["E_IO"] | ["E_PERMISSION"]),
        "{check:?}"
    );
}

#[test]
fn an_rc_file_that_cannot_be_located_skips_the_check() {
    let check = hook_check(&inputs(None, &[], false));
    assert_eq!(check.status, Status::Skipped, "{check:?}");
}

#[test]
fn the_human_report_shows_status_code_message_and_hint() {
    let mut path = Check::pass("path", "1 current link bin directory is on PATH");
    path.push(
        Finding::warning("W_PATH_MISSING", "/x/bin is not on PATH").hint("run `jtm self setup`"),
    );
    let mut links = Check::pass("current_links", "");
    links.push(Finding::error(ErrorCode::Io, "the link is gone").hint("run `jtm default`"));
    let tls = Check::skipped("tls", "offline").note("the connection test was skipped");
    let report = Report {
        checks: vec![path, links, tls],
    };
    let mut out = Vec::new();
    report.render_human(&mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    insta::assert_snapshot!(text);
}

#[test]
fn shell_init_outside_the_jtm_block_does_not_count_as_the_hook() {
    let dir = tempfile::tempdir().unwrap();
    let rc = dir.path().join(".bashrc");
    let block = rc_block(
        Some(std::path::Path::new("/data/env.sh")),
        Some(Shell::Bash),
        None,
    );
    std::fs::write(
        &rc,
        format!("# eval \"$(other shell-init)\"\n{block}alias x='shell-init'\n"),
    )
    .unwrap();
    let check = hook_check(&inputs(Some((rc, Some(Shell::Bash))), &[], false));
    assert_eq!(codes(&check), ["W_SHELL_HOOK_MISSING"]);
}

#[test]
fn a_human_run_leaves_the_warnings_to_the_report() {
    let mut check = Check::pass("path", "");
    check.push(Finding::warning("W_PATH_MISSING", "not on PATH").hint("run `jtm self setup`"));
    let report = Report {
        checks: vec![check],
    };
    assert!(outcome(report.clone(), false).warnings.is_empty());
    let json = outcome(report, true);
    assert_eq!(json.warnings.len(), 1);
    assert_eq!(json.warnings[0].code, "W_PATH_MISSING");
    assert_eq!(json.warnings[0].details["hint"], "run `jtm self setup`");
}
