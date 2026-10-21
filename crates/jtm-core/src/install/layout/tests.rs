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
