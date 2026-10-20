use std::path::PathBuf;

use super::*;

fn plan() -> SetupPlan {
    SetupPlan {
        path: vec![PathBuf::from("/data/current/demo/bin")],
        vars: vec![("DEMO_HOME".to_owned(), "/data/current/demo".to_owned())],
    }
}

#[test]
fn env_files_put_bin_dirs_first_once_and_set_variables() {
    insta::assert_snapshot!("env_sh", env_sh(&plan()));
    insta::assert_snapshot!("env_fish", env_fish(&plan()));
}

#[test]
fn the_rc_block_is_appended_once_and_replaced_in_place() {
    let block = rc_block(Path::new("/data/env.sh"), false);
    let fresh = update_rc(None, &block).unwrap();
    assert_eq!(fresh, block);
    assert_eq!(
        update_rc(Some(&fresh), &block),
        None,
        "re-running is a no-op"
    );

    let existing = "alias ll='ls -l'\nexport EDITOR=vim";
    let added = update_rc(Some(existing), &block).unwrap();
    assert!(
        added.starts_with("alias ll='ls -l'\nexport EDITOR=vim\n\n# >>> jtm >>>\n"),
        "{added}"
    );
    assert_eq!(update_rc(Some(&added), &block), None);

    // A changed block replaces the old one where it stands.
    let moved = rc_block(Path::new("/elsewhere/env.sh"), false);
    let with_tail = format!("{added}echo after\n");
    let replaced = update_rc(Some(&with_tail), &moved).unwrap();
    assert!(replaced.contains("/elsewhere/env.sh"), "{replaced}");
    assert!(!replaced.contains("/data/env.sh"), "{replaced}");
    assert!(
        replaced.ends_with("# <<< jtm <<<\necho after\n"),
        "{replaced}"
    );
    assert_eq!(replaced.matches("# >>> jtm >>>").count(), 1);
}

#[test]
fn rc_blocks_quote_paths() {
    insta::assert_snapshot!(
        "rc_posix",
        rc_block(Path::new("/home/o'neil/jtm/env.sh"), false)
    );
    insta::assert_snapshot!(
        "rc_fish",
        rc_block(Path::new("/home/o'neil/jtm/env.fish"), true)
    );
}

#[test]
fn windows_path_merge_prepends_missing_entries_only() {
    let add = [
        r"C:\Users\u\AppData\Local\jtm\current\java\bin".to_owned(),
        r"C:\Users\u\AppData\Local\jtm\current\maven\bin".to_owned(),
    ];
    assert_eq!(
        merge_path(r"%USERPROFILE%\bin;C:\tools", &add).as_deref(),
        Some(
            r"C:\Users\u\AppData\Local\jtm\current\java\bin;C:\Users\u\AppData\Local\jtm\current\maven\bin;%USERPROFILE%\bin;C:\tools"
        )
    );
    // Entries compare case-insensitively and ignoring a trailing backslash.
    let present = r"c:\users\u\appdata\local\jtm\current\JAVA\bin\;C:\Users\u\AppData\Local\jtm\current\maven\bin";
    assert_eq!(merge_path(present, &add), None);
    assert_eq!(merge_path("", &add[..1]).as_deref(), Some(add[0].as_str()));
}

#[test]
fn windows_path_prune_removes_stale_entries_only() {
    let stale = [r"C:\jtm\current\java\bin".to_owned()];
    assert_eq!(
        prune_path(r"c:\JTM\current\java\bin\;%USERPROFILE%\bin", &stale).as_deref(),
        Some(r"%USERPROFILE%\bin")
    );
    assert_eq!(prune_path(r"%USERPROFILE%\bin", &stale), None);
}

#[test]
fn an_unreadable_rc_file_is_an_error_not_a_missing_one() {
    let dir = tempfile::tempdir().unwrap();
    let rc = dir.path().join(".bashrc");
    std::fs::write(&rc, b"# caf\xe9\n").unwrap();
    assert_eq!(read_existing(&rc).unwrap_err().code(), "E_IO");
    assert_eq!(read_existing(&dir.path().join("missing")).unwrap(), None);
}

#[test]
fn the_rc_file_follows_the_login_shell() {
    let home = Path::new("/home/u");
    let env = |shell: &'static str| {
        move |key: &str| match key {
            "SHELL" => Some(shell.to_owned()),
            _ => None,
        }
    };
    assert_eq!(
        rc_file(home, Os::Linux, &env("/bin/bash")),
        (home.join(".bashrc"), false)
    );
    assert_eq!(
        rc_file(home, Os::Macos, &env("/bin/bash")),
        (home.join(".bash_profile"), false)
    );
    assert_eq!(
        rc_file(home, Os::Linux, &env("/usr/bin/zsh")),
        (home.join(".zshrc"), false)
    );
    assert_eq!(
        rc_file(home, Os::Linux, &env("/usr/bin/fish")),
        (home.join(".config/fish/conf.d/jtm.fish"), true)
    );
    assert_eq!(
        rc_file(home, Os::Linux, &env("/bin/tcsh")),
        (home.join(".profile"), false)
    );
}
