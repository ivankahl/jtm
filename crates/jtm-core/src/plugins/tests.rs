use super::*;
use crate::platform::Os;
use jtm_security::testing::TestKey;

fn manifest(name: &str) -> String {
    let key = TestKey::generate().public_str();
    format!(
        r#"
schema = 1
name = "{name}"
display_name = "Demo"
[versions]
scheme = "semver-loose"
[index]
url = "https://example.test/demo-{{os}}-{{arch}}.json"
signing_keys = ["{key}"]
format = 1
[layout]
bin_dirs = ["bin"]
"#
    )
}

fn dirs() -> (tempfile::TempDir, Dirs) {
    let home = tempfile::tempdir().unwrap();
    let dirs = Dirs::resolve(Os::host().unwrap(), Some(home.path()), None, &|_| None).unwrap();
    (home, dirs)
}

fn add(dirs: &Dirs, dir: &str, text: &str) {
    let path = dirs.plugins().join(dir);
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("plugin.toml"), text).unwrap();
}

fn builtin(name: &'static str, declared: &str) -> [BuiltinManifest; 1] {
    [BuiltinManifest {
        name,
        text: Box::leak(manifest(declared).into_boxed_str()),
    }]
}

#[test]
fn builtin_manifests_are_found_and_preapproved() {
    let builtin = builtin("demo", "demo");
    let registry = Registry { builtin: &builtin };
    let plugin = registry.find("demo").unwrap();
    assert_eq!(plugin.manifest.name, "demo");
    assert_eq!(plugin.origin, ManifestOrigin::Builtin);
    assert_eq!(plugin.location, "builtin");
    assert_eq!(
        plugin.sha256,
        jtm_security::sha256_hex(builtin[0].text.as_bytes())
    );
    assert_eq!(registry.names(), ["demo"]);
}

/// ADR 0002: jtm never loads a tool definition from disk, neither a third-party plugin
/// directory nor the old builtin working copy, even when one shadows a builtin name.
#[test]
fn a_manifest_on_disk_is_never_read() {
    let (_home, dirs) = dirs();
    add(&dirs, "acme--widget@abc123", &manifest("acme/widget"));
    add(&dirs, "demo@abc", &manifest("demo"));
    add(&dirs, "builtin/other", &manifest("other"));
    let builtin = builtin("demo", "demo");
    let registry = Registry { builtin: &builtin };
    assert_eq!(registry.names(), ["demo"]);
    for name in ["acme/widget", "other"] {
        assert_eq!(registry.find(name).unwrap_err().code(), "E_TOOL_UNKNOWN");
    }
    assert_eq!(registry.find("demo").unwrap().location, "builtin");
}

#[test]
fn unknown_plugins_and_mismatched_names_fail() {
    let builtin = builtin("demo", "other");
    let registry = Registry { builtin: &builtin };
    assert_eq!(registry.find("nope").unwrap_err().code(), "E_TOOL_UNKNOWN");
    assert_eq!(
        registry.find("demo").unwrap_err().code(),
        "E_PLUGIN_INVALID"
    );
}

#[test]
fn a_builtin_manifest_with_hooks_is_invalid() {
    let text = format!("{}[hooks]\npost_extract = \"post\"\n", manifest("demo"));
    let builtin = [BuiltinManifest {
        name: "demo",
        text: Box::leak(text.into_boxed_str()),
    }];
    let registry = Registry { builtin: &builtin };
    let err = registry.find("demo").unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
    assert!(err.to_string().contains("[hooks]"), "{err}");
}

// --- the old builtin working copy ---

#[test]
fn an_old_working_copy_and_what_its_repair_left_are_removed() {
    let (_home, dirs) = dirs();
    let copy = dirs.plugins().join("builtin");
    fs::create_dir_all(copy.join("demo")).unwrap();
    fs::write(copy.join("demo").join("plugin.toml"), manifest("demo")).unwrap();
    let temp = dirs.plugins().join(".jtm-builtin-left");
    fs::write(&temp, "partial").unwrap();
    fs::create_dir_all(dirs.locks()).unwrap();
    let lock = dirs.locks().join(".builtin-working-copy.lock");
    fs::write(&lock, "").unwrap();

    remove_old_working_copy(&dirs);
    assert!(!copy.exists());
    assert!(!temp.exists());
    assert!(!lock.exists());
    assert!(!dirs.plugins().exists(), "the empty plugins dir is removed");
}

#[test]
fn removing_the_old_working_copy_keeps_everything_else() {
    let (_home, dirs) = dirs();
    fs::create_dir_all(dirs.plugins().join("builtin")).unwrap();
    add(&dirs, "acme--widget@abc123", &manifest("acme/widget"));
    let other = dirs.plugins().join(".tmp-not-ours");
    fs::write(&other, "x").unwrap();

    remove_old_working_copy(&dirs);
    assert!(!dirs.plugins().join("builtin").exists());
    assert!(
        dirs.plugins()
            .join("acme--widget@abc123")
            .join("plugin.toml")
            .is_file()
    );
    assert!(other.is_file());
}

#[test]
fn without_an_old_working_copy_nothing_is_touched() {
    let (_home, dirs) = dirs();
    remove_old_working_copy(&dirs);
    assert!(!dirs.plugins().exists(), "nothing is created");

    // Leftovers are only cleaned up with the copy itself.
    fs::create_dir_all(dirs.plugins()).unwrap();
    let temp = dirs.plugins().join(".jtm-builtin-left");
    fs::write(&temp, "partial").unwrap();
    remove_old_working_copy(&dirs);
    assert!(temp.is_file());
}

#[cfg(unix)]
#[test]
fn an_old_working_copy_that_is_a_link_is_removed_without_following_it() {
    let (_home, dirs) = dirs();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("keep"), "keep").unwrap();
    fs::create_dir_all(dirs.plugins()).unwrap();
    let copy = dirs.plugins().join("builtin");
    std::os::unix::fs::symlink(outside.path(), &copy).unwrap();

    remove_old_working_copy(&dirs);
    assert!(fs::symlink_metadata(&copy).is_err());
    assert_eq!(
        fs::read_to_string(outside.path().join("keep")).unwrap(),
        "keep"
    );
}
