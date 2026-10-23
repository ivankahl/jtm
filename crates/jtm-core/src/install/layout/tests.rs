use super::*;

fn layout(toml: &str) -> Layout {
    let key = jtm_security::testing::TestKey::generate().public_str();
    let text = format!(
        r#"
schema = 1
name = "demo"
display_name = "Demo"
[versions]
scheme = "semver-loose"
[index]
url = "https://example.test/demo-{{os}}-{{arch}}.json"
signing_keys = ["{key}"]
format = 1
[layout]
{toml}
"#
    );
    jtm_plugin::Manifest::parse(&text).unwrap().layout
}

fn tree(files: &[&str]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for file in files {
        let path = dir.path().join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        if !file.ends_with('/') {
            fs::write(path, b"x").unwrap();
        }
    }
    dir
}

#[test]
fn auto_strips_a_single_top_level_directory() {
    let dir = tree(&["tool-1.0/bin/demo"]);
    let placed = apply(
        "demo",
        dir.path(),
        &layout("bin_dirs = [\"bin\"]"),
        Os::Linux,
    )
    .unwrap();
    assert_eq!(placed.root, dir.path().join("tool-1.0"));
    assert_eq!(placed.home, PathBuf::new());
}

#[test]
fn auto_keeps_several_top_level_entries() {
    let dir = tree(&["bin/demo", "README"]);
    let placed = apply(
        "demo",
        dir.path(),
        &layout("bin_dirs = [\"bin\"]"),
        Os::Linux,
    )
    .unwrap();
    assert_eq!(placed.root, dir.path());
}

#[test]
fn auto_keeps_a_single_top_level_file() {
    let dir = tree(&["demo"]);
    let placed = apply("demo", dir.path(), &layout("bin_dirs = [\".\"]"), Os::Linux).unwrap();
    assert_eq!(placed.root, dir.path());
}

#[test]
fn a_count_is_applied_by_the_extractor_not_here() {
    let l = layout("strip_components = 0\nbin_dirs = [\"bin\"]");
    assert_eq!(extract_strip(&l), 0);
    let dir = tree(&["tool-1.0/bin/demo"]);
    assert_eq!(
        apply("demo", dir.path(), &l, Os::Linux).unwrap().root,
        dir.path()
    );
    assert_eq!(
        extract_strip(&layout("strip_components = 2\nbin_dirs = [\"bin\"]")),
        2
    );
    assert_eq!(extract_strip(&layout("bin_dirs = [\"bin\"]")), 0);
}

#[test]
fn home_subdir_applies_only_on_its_os() {
    let l = layout("bin_dirs = [\"bin\"]\nhome_subdir = { macos = \"Contents/Home\" }");
    let dir = tree(&["jdk/Contents/Home/bin/demo"]);
    let mac = apply("demo", dir.path(), &l, Os::Macos).unwrap();
    assert_eq!(mac.home, PathBuf::from("Contents/Home"));
    assert_eq!(mac.home_dir(), dir.path().join("jdk/Contents/Home"));
    let linux = apply("demo", dir.path(), &l, Os::Linux).unwrap();
    assert_eq!(linux.home, PathBuf::new());
}

#[test]
fn a_missing_home_subdir_is_a_layout_mismatch() {
    let l = layout("bin_dirs = [\"bin\"]\nhome_subdir = { macos = \"Contents/Home\" }");
    let dir = tree(&["jdk/bin/demo"]);
    let err = apply("demo", dir.path(), &l, Os::Macos).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
}

#[test]
fn a_home_subdir_that_is_a_file_is_a_layout_mismatch() {
    let l = layout("bin_dirs = [\"bin\"]\nhome_subdir = { macos = \"Contents/Info.plist\" }");
    let dir = tree(&["jdk/Contents/Info.plist", "jdk/Contents/Home/bin/demo"]);
    let err = apply("demo", dir.path(), &l, Os::Macos).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
}

#[test]
fn an_empty_archive_is_a_layout_mismatch() {
    let dir = tree(&["only/"]);
    let err = apply(
        "demo",
        dir.path(),
        &layout("bin_dirs = [\"bin\"]"),
        Os::Linux,
    )
    .unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
}

#[test]
fn every_bin_dir_must_hold_a_file() {
    let l = layout("bin_dirs = [\"bin\", \"lib/bin\"]");
    let good = tree(&["t/bin/anything", "t/lib/bin/other.cmd"]);
    let placed = apply("demo", good.path(), &l, Os::Linux).unwrap();
    check_bin_dirs("demo", &placed, &l).unwrap();

    for files in [&["t/demo"][..], &["t/bin/x", "t/lib/bin/empty/"][..]] {
        let bad = tree(files);
        let placed = apply("demo", bad.path(), &l, Os::Linux).unwrap();
        let err = check_bin_dirs("demo", &placed, &l).unwrap_err();
        assert_eq!(err.code(), "E_PLUGIN_INVALID", "{files:?}");
    }
}

const CANDIDATES: &str = "bin_dirs = [\"bin\"]\nhome_subdir = { macos = [\"Contents/Home\", \"*/Contents/Home\", \"\"] }";
/// The same candidates without the archive root, so that none may match.
const BUNDLES_ONLY: &str =
    "bin_dirs = [\"bin\"]\nhome_subdir = { macos = [\"Contents/Home\", \"*/Contents/Home\"] }";

fn mac_home_with(toml: &str, files: &[&str]) -> Result<PathBuf> {
    let dir = tree(files);
    apply("demo", dir.path(), &layout(toml), Os::Macos).map(|p| {
        assert_eq!(p.root, dir.path().join("t"));
        p.home
    })
}

fn mac_home(files: &[&str]) -> Result<PathBuf> {
    mac_home_with(CANDIDATES, files)
}

#[test]
fn the_first_candidate_home_that_exists_wins() {
    // An app bundle.
    let home = mac_home(&["t/Contents/Home/bin/java", "t/Contents/Info.plist"]).unwrap();
    assert_eq!(home, PathBuf::from("Contents/Home"));
    // A bundle beside other directories, found through `*`.
    let home = mac_home(&["t/zulu-17.jdk/Contents/Home/bin/java", "t/legal/LICENSE"]).unwrap();
    assert_eq!(home, PathBuf::from("zulu-17.jdk/Contents/Home"));
    // No bundle: the root.
    let home = mac_home(&["t/bin/java", "t/lib/x"]).unwrap();
    assert_eq!(home, PathBuf::new());
    // Only existence counts: a `Contents/Home` without bin files still wins, and its bin dirs are
    // checked separately.
    let home = mac_home(&["t/Contents/Home/README", "t/bin/java"]).unwrap();
    assert_eq!(home, PathBuf::from("Contents/Home"));
}

#[test]
fn an_ambiguous_star_candidate_fails_instead_of_falling_through() {
    // Two bundles: `*` is ambiguous, which is an error even with the root as a fallback.
    let files = [
        "t/a.jdk/Contents/Home/bin/java",
        "t/b.jdk/Contents/Home/README",
        "t/bin/java",
    ];
    let err = mac_home(&files).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
    let message = err.to_string();
    assert!(message.contains("ambiguous"), "{message}");
    assert!(
        message.contains("`a.jdk/Contents/Home`, `b.jdk/Contents/Home`"),
        "{message}"
    );
    // Directories that `*` reaches but the rest of the path does not fit are no matches.
    let home = mac_home(&["t/a.jdk/Contents/Home/bin/java", "t/b.jdk/Contents/README"]).unwrap();
    assert_eq!(home, PathBuf::from("a.jdk/Contents/Home"));
}

#[test]
fn no_match_names_every_candidate_tried() {
    let err = mac_home_with(BUNDLES_ONLY, &["t/lib/x", "t/README"]).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
    let message = err.to_string();
    assert!(
        message.contains("`Contents/Home`, `*/Contents/Home`"),
        "{message}"
    );
}

#[test]
fn a_star_matches_only_safe_names() {
    for name in ["zulu-17.jdk", "jdk_8u512+b1.jdk", "Z9"] {
        let file = format!("t/{name}/Contents/Home/bin/java");
        let home = mac_home(&[&file, "t/bin/java"]).unwrap();
        assert_eq!(home, Path::new(name).join("Contents/Home"), "{name}");
    }
    for name in [
        "Zulu 17.jdk",
        "-rf",
        ".hidden",
        "jdk$(x)",
        "jdk;x",
        "j\u{e9}k",
    ] {
        let file = format!("t/{name}/Contents/Home/bin/java");
        let err = mac_home(&[&file, "t/bin/java"]).unwrap_err();
        assert_eq!(err.code(), "E_PLUGIN_INVALID", "{name}");
        assert!(
            err.to_string().contains("may hold only ASCII"),
            "{name}: {err}"
        );
    }
    // A name the rest of the path does not fit is never looked at.
    let home = mac_home(&["t/Some Docs/README", "t/bin/java"]).unwrap();
    assert_eq!(home, PathBuf::new());
}

#[cfg(unix)]
#[test]
fn a_bin_dir_that_cannot_be_read_is_an_io_error_not_a_mismatch() {
    use std::os::unix::fs::PermissionsExt as _;
    let l = layout("bin_dirs = [\"bin\"]");
    let dir = tree(&["t/bin/tool"]);
    let bin = dir.path().join("t/bin");
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o300)).unwrap();
    let readable = fs::read_dir(&bin).is_ok();
    let placed = apply("demo", dir.path(), &l, Os::Linux).unwrap();
    let checked = check_bin_dirs("demo", &placed, &l);
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
    if readable {
        // Running as root, permissions do not stop the read.
        checked.unwrap();
    } else {
        assert_eq!(checked.unwrap_err().code(), "E_PERMISSION");
    }
}

#[cfg(unix)]
#[test]
fn a_star_never_matches_a_link() {
    // Zulu's links to its bundle's home beside the bundle are not candidates for `*`.
    let dir = tree(&["t/zulu-17.jdk/Contents/Home/bin/java"]);
    std::os::unix::fs::symlink("zulu-17.jdk", dir.path().join("t/alias.jdk")).unwrap();
    std::os::unix::fs::symlink("zulu-17.jdk/Contents/Home/bin", dir.path().join("t/bin")).unwrap();
    let placed = apply("demo", dir.path(), &layout(CANDIDATES), Os::Macos).unwrap();
    assert_eq!(placed.home, PathBuf::from("zulu-17.jdk/Contents/Home"));

    // A link out of the archive is never a home, and fails the install rather than handing
    // the choice to the archive root.
    let outside = tree(&["Contents/Home/bin/java"]);
    let dir = tree(&["t/bin/java"]);
    std::os::unix::fs::symlink(
        outside.path().join("Contents"),
        dir.path().join("t/Contents"),
    )
    .unwrap();
    let err = apply("demo", dir.path(), &layout(CANDIDATES), Os::Macos).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
    assert!(
        err.to_string().contains("leads out of the archive"),
        "{err}"
    );
}

/// A link that is broken (a loop included), or leads out of the archive to a place where the
/// rest of the path is missing, fails the install instead of reading as "no match".
#[cfg(unix)]
#[test]
fn a_broken_or_escaping_link_never_hands_over_to_the_next_candidate() {
    for (target, why) in [
        ("/", "leads out of the archive"),
        ("/nonexistent-jtm-target", "is broken"),
        ("missing", "is broken"),
        // A link to itself never resolves.
        ("Contents", "is broken"),
    ] {
        let dir = tree(&["t/bin/java"]);
        std::os::unix::fs::symlink(target, dir.path().join("t/Contents")).unwrap();
        let err = apply("demo", dir.path(), &layout(CANDIDATES), Os::Macos).unwrap_err();
        assert_eq!(err.code(), "E_PLUGIN_INVALID", "{target}");
        assert!(err.to_string().contains(why), "{target}: {err}");
    }
}

/// The bin dirs are checked by `check_bin_dirs` after `apply`, so a home only has to exist.
#[test]
fn a_home_is_chosen_before_its_bin_dirs_hold_files() {
    for toml in [
        "bin_dirs = [\"bin\"]\nhome_subdir = { macos = \"Contents/Home\" }",
        CANDIDATES,
    ] {
        let l = layout(toml);
        let dir = tree(&["t/Contents/Home/bin/"]);
        let placed = apply("demo", dir.path(), &l, Os::Macos).unwrap();
        assert_eq!(placed.home, PathBuf::from("Contents/Home"));
        let err = check_bin_dirs("demo", &placed, &l).unwrap_err();
        assert_eq!(err.code(), "E_PLUGIN_INVALID");
    }
}

#[test]
fn a_candidate_that_is_not_relative_fails_instead_of_falling_through() {
    // Validation rejects this; a layout built some other way fails even when an earlier
    // candidate would match.
    let mut l = layout(CANDIDATES);
    l.home_subdir.insert(
        "macos".to_owned(),
        jtm_plugin::manifest::HomeCandidates(vec!["Contents/Home".to_owned(), "/abs".to_owned()]),
    );
    let dir = tree(&["t/Contents/Home/bin/java"]);
    let err = apply("demo", dir.path(), &l, Os::Macos).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
    assert!(err.to_string().contains("not a relative path"), "{err}");
}

/// Linux file names may be any bytes; one that is not UTF-8 is never a safe name.
#[cfg(target_os = "linux")]
#[test]
fn a_star_never_matches_a_name_that_is_not_utf8() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tree(&["t/README"]);
    let bad = dir
        .path()
        .join("t")
        .join(std::ffi::OsStr::from_bytes(b"jdk\xff"));
    fs::create_dir_all(bad.join("Contents/Home/bin")).unwrap();
    fs::write(bad.join("Contents/Home/bin/java"), b"x").unwrap();
    let err = apply("demo", dir.path(), &layout(BUNDLES_ONLY), Os::Macos).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
    assert!(err.to_string().contains("may hold only ASCII"), "{err}");
}

/// Names from the archive are escaped in messages, so they cannot drive the terminal.
#[cfg(unix)]
#[test]
fn archive_names_in_errors_are_escaped() {
    let files = [
        "t/a\u{1b}]0;x\u{7}.jdk/Contents/Home/bin/java",
        "t/b.jdk/Contents/Home/bin/java",
    ];
    let message = mac_home(&files).unwrap_err().to_string();
    assert!(message.contains("ambiguous"), "{message}");
    assert!(
        !message.contains('\u{1b}') && !message.contains('\u{7}'),
        "{message}"
    );
    assert!(message.contains(r"a\u{1b}]0;x\u{7}.jdk"), "{message}");

    // A backtick cannot end the quotes around a name early.
    let files = [
        "t/a`, `b.jdk/Contents/Home/bin/java",
        "t/c.jdk/Contents/Home/bin/java",
    ];
    let message = mac_home(&files).unwrap_err().to_string();
    assert!(
        message.contains(r"`a\`, \`b.jdk/Contents/Home`"),
        "{message}"
    );

    let message = mac_home(&[files[0], "t/bin/java"]).unwrap_err().to_string();
    assert!(message.contains("may hold only ASCII"), "{message}");
    assert!(!message.contains('\u{1b}'), "{message}");
}

#[cfg(unix)]
#[test]
fn a_looping_link_in_a_bin_dir_is_not_a_file_and_not_an_error() {
    let l = layout("bin_dirs = [\"bin\"]");
    let dir = tree(&["t/bin/zz-tool"]);
    std::os::unix::fs::symlink("loop", dir.path().join("t/bin/loop")).unwrap();
    let placed = apply("demo", dir.path(), &l, Os::Linux).unwrap();
    check_bin_dirs("demo", &placed, &l).unwrap();
    fs::remove_file(placed.home_dir().join("bin/zz-tool")).unwrap();
    let err = check_bin_dirs("demo", &placed, &l).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
}

#[cfg(unix)]
#[test]
fn a_bin_dir_whose_parent_cannot_be_searched_is_an_io_error_not_a_mismatch() {
    use std::os::unix::fs::PermissionsExt as _;
    let l = layout("bin_dirs = [\"sub/bin\"]");
    let dir = tree(&["t/sub/bin/tool", "t/other"]);
    let placed = apply("demo", dir.path(), &l, Os::Linux).unwrap();
    let sub = placed.home_dir().join("sub");
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o600)).unwrap();
    let searchable = fs::metadata(sub.join("bin")).is_ok();
    let checked = check_bin_dirs("demo", &placed, &l);
    fs::set_permissions(&sub, fs::Permissions::from_mode(0o755)).unwrap();
    if searchable {
        // Running as root, permissions do not stop the lookup.
        checked.unwrap();
    } else {
        assert_eq!(checked.unwrap_err().code(), "E_PERMISSION");
    }
}
