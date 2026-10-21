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
    // checked after `post_extract`.
    let home = mac_home(&["t/Contents/Home/README", "t/bin/java"]).unwrap();
    assert_eq!(home, PathBuf::from("Contents/Home"));
}

#[test]
fn a_star_candidate_needs_exactly_one_match() {
    // Two bundles: `*` is ambiguous, so the root wins.
    let files = [
        "t/a.jdk/Contents/Home/bin/java",
        "t/b.jdk/Contents/Home/bin/java",
    ];
    assert_eq!(mac_home(&files).unwrap(), PathBuf::new());
    // Without the root as a fallback, nothing matches.
    let err = mac_home_with(BUNDLES_ONLY, &files).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
    let message = err.to_string();
    assert!(
        message.contains("`Contents/Home`, `*/Contents/Home`"),
        "{message}"
    );
}

#[test]
fn no_candidate_existing_is_a_layout_mismatch() {
    let err = mac_home_with(BUNDLES_ONLY, &["t/lib/x", "t/README"]).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
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

    // A link out of the archive is never a home, even when it is the only match.
    let outside = tree(&["Contents/Home/bin/java"]);
    let dir = tree(&["t/README"]);
    std::os::unix::fs::symlink(outside.path(), dir.path().join("t/Contents")).unwrap();
    let err = apply("demo", dir.path(), &layout(BUNDLES_ONLY), Os::Macos).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
}

/// `post_extract` runs between `apply` and `check_bin_dirs` and may fill the bin dirs, so a
/// home only has to exist.
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

/// Linux file names may be any bytes; the receipt records the home as text.
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
}
