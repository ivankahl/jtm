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
[executables]
unix = ["demo"]
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

#[test]
fn finds_external_plugins_by_name() {
    let (_home, dirs) = dirs();
    let text = manifest("acme/widget");
    add(&dirs, "acme--widget@abc123", &text);
    let registry = Registry {
        dirs: &dirs,
        builtin: &[],
    };
    let plugin = registry.find("acme/widget").unwrap();
    assert_eq!(plugin.manifest.name, "acme/widget");
    assert_eq!(plugin.origin, ManifestOrigin::External);
    assert_eq!(plugin.sha256, jtm_security::sha256_hex(text.as_bytes()));
    assert_eq!(registry.names().unwrap(), ["acme/widget"]);
}

#[test]
fn builtin_manifests_win_and_are_preapproved() {
    let (_home, dirs) = dirs();
    add(&dirs, "demo@abc", &manifest("demo"));
    let text: &'static str = Box::leak(manifest("demo").into_boxed_str());
    let builtin = [BuiltinManifest { name: "demo", text }];
    let registry = Registry {
        dirs: &dirs,
        builtin: &builtin,
    };
    let plugin = registry.find("demo").unwrap();
    assert_eq!(plugin.origin, ManifestOrigin::Builtin);
    assert_eq!(registry.names().unwrap(), ["demo"]);
}

#[test]
fn the_builtin_working_copy_is_never_read() {
    let (_home, dirs) = dirs();
    let path = dirs.builtin_plugins().join("demo");
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("plugin.toml"), manifest("demo")).unwrap();
    let registry = Registry {
        dirs: &dirs,
        builtin: &[],
    };
    assert_eq!(registry.find("demo").unwrap_err().code(), "E_TOOL_UNKNOWN");
}

#[test]
fn unknown_plugins_and_mismatched_names_fail() {
    let (_home, dirs) = dirs();
    add(&dirs, "demo@abc", &manifest("other"));
    let registry = Registry {
        dirs: &dirs,
        builtin: &[],
    };
    assert_eq!(registry.find("nope").unwrap_err().code(), "E_TOOL_UNKNOWN");
    assert_eq!(
        registry.find("demo").unwrap_err().code(),
        "E_PLUGIN_INVALID"
    );
}

#[test]
fn several_revisions_are_refused() {
    let (_home, dirs) = dirs();
    add(&dirs, "demo@abc", &manifest("demo"));
    add(&dirs, "demo@def", &manifest("demo"));
    let registry = Registry {
        dirs: &dirs,
        builtin: &[],
    };
    assert_eq!(registry.find("demo").unwrap_err().code(), "E_USAGE");
}
