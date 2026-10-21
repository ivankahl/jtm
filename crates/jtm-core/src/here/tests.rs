use std::fs;

use super::*;

/// A temp dir holding `bin/tool` and, beside `bin`, a file `outside`.
fn setup() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::write(bin.join("tool"), "").unwrap();
    fs::write(root.path().join("outside"), "").unwrap();
    (root, bin)
}

#[test]
fn finds_a_bare_command_in_the_dirs() {
    let (_root, bin) = setup();
    assert_eq!(
        find_in_dirs("tool", std::slice::from_ref(&bin), Os::Linux),
        Some(bin.join("tool"))
    );
    assert_eq!(find_in_dirs("missing", &[bin], Os::Linux), None);
}

#[test]
fn never_resolves_a_path_against_the_dirs() {
    let (root, bin) = setup();
    let absolute = root.path().join("outside");
    let dirs = [bin];
    for command in [
        absolute.to_str().unwrap(),
        "../outside",
        "./tool",
        "sub/tool",
        "sub\\tool",
        "..",
        ".",
        "",
        "C:tool",
    ] {
        assert_eq!(find_in_dirs(command, &dirs, Os::Linux), None, "{command}");
        assert_eq!(find_in_dirs(command, &dirs, Os::Windows), None, "{command}");
    }
}

#[test]
fn a_bare_name_is_one_plain_file_name() {
    assert!(is_bare_name("java"));
    assert!(is_bare_name("mvn.cmd"));
    assert!(!is_bare_name("bin/java"));
    assert!(!is_bare_name("/usr/bin/java"));
    assert!(!is_bare_name("..\\java"));
    assert!(!is_bare_name("C:java"));
    assert!(!is_bare_name("ja\0va"));
    assert!(!is_bare_name(".."));
    assert!(!is_bare_name(""));
}
