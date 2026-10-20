use std::fs;

use super::*;
use crate::setup::rc_block;
use crate::shell::Shell;

#[test]
fn rc_files_cover_every_shell_setup_may_have_written_for() {
    let env = |key: &str| match key {
        "HOME" => Some("/home/u".to_owned()),
        "ZDOTDIR" => Some("/home/u/.zsh".to_owned()),
        "XDG_CONFIG_HOME" => Some("relative".to_owned()),
        _ => None,
    };
    let files: Vec<String> = rc_files(&env)
        .iter()
        .map(|p| p.display().to_string())
        .collect();
    assert_eq!(
        files,
        [
            "/home/u/.bashrc",
            "/home/u/.bash_profile",
            "/home/u/.profile",
            "/home/u/.zsh/.zshrc",
            "/home/u/.config/fish/conf.d/jtm.fish",
        ]
    );
    assert!(rc_files(&|_| None).is_empty());
}

#[test]
fn only_jtms_block_is_taken_out_of_an_rc_file() {
    let dir = tempfile::tempdir().unwrap();
    let block = rc_block(
        Some(Path::new("/data/env.sh")),
        Some(Shell::Bash),
        Some("/bin/jtm"),
    );

    let rc = dir.path().join(".bashrc");
    fs::write(&rc, format!("alias ll='ls -l'\n\n{block}echo after\n")).unwrap();
    let Some(Step::Edit { text, .. }) = rc_step(&rc).unwrap() else {
        panic!("expected an edit");
    };
    assert_eq!(text, "alias ll='ls -l'\necho after\n");

    // A file holding only jtm's block is jtm's own and goes.
    let fish = dir.path().join("jtm.fish");
    fs::write(&fish, &block).unwrap();
    assert_eq!(rc_step(&fish).unwrap(), Some(Step::File(fish.clone())));

    // Files without the block, and missing files, are left alone.
    let plain = dir.path().join(".zshrc");
    fs::write(&plain, "export EDITOR=vim\n").unwrap();
    assert_eq!(rc_step(&plain).unwrap(), None);
    assert_eq!(rc_step(&dir.path().join("missing")).unwrap(), None);
}

#[test]
fn purge_refuses_the_root_and_the_home_directory_and_its_parents() {
    let home = Path::new("/home/u");
    for dir in ["/", "/home", "/home/u"] {
        let err = check_purge(Path::new(dir), Some(home)).unwrap_err();
        assert_eq!(err.code(), "E_USAGE", "{dir}");
    }
    check_purge(Path::new("/home/u/.local/share/jtm"), Some(home)).unwrap();
    check_purge(Path::new("/opt/jtm"), None).unwrap();
}
