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

/// The test manifest with a `post_extract` hook whose script is `source`.
fn with_hook(source: &str) -> String {
    format!(
        "{}[hooks]\npost_extract = \"post\"\nscript_sha256 = \"{}\"\n",
        manifest("acme/widget"),
        jtm_security::sha256_hex(source.as_bytes())
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
    let builtin = [BuiltinManifest {
        name: "demo",
        text,
        script: None,
    }];
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

#[test]
fn external_plugins_read_their_script() {
    let (_home, dirs) = dirs();
    let source = "function post() end";
    add(&dirs, "acme--widget@abc123", &with_hook(source));
    let registry = Registry {
        dirs: &dirs,
        builtin: &[],
    };
    let err = registry.find("acme/widget").unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
    assert!(err.to_string().contains("plugin.lua"), "{err}");

    fs::write(
        dirs.plugins().join("acme--widget@abc123/plugin.lua"),
        source,
    )
    .unwrap();
    let plugin = registry.find("acme/widget").unwrap();
    assert_eq!(plugin.script.as_deref(), Some(source));
    assert!(
        plugin
            .script(crate::platform::Platform::LinuxX64)
            .unwrap()
            .is_some()
    );
}

#[test]
fn a_script_that_does_not_compile_is_an_invalid_plugin() {
    let (_home, dirs) = dirs();
    add(&dirs, "acme--widget@abc123", &with_hook("function ("));
    fs::write(
        dirs.plugins().join("acme--widget@abc123/plugin.lua"),
        "function (",
    )
    .unwrap();
    let registry = Registry {
        dirs: &dirs,
        builtin: &[],
    };
    let plugin = registry.find("acme/widget").unwrap();
    let err = plugin
        .script(crate::platform::Platform::LinuxX64)
        .unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
}

#[test]
fn a_script_that_is_not_utf8_or_too_large_is_an_invalid_plugin() {
    let (_home, dirs) = dirs();
    add(&dirs, "acme--widget@abc123", &manifest("acme/widget"));
    let script = dirs.plugins().join("acme--widget@abc123/plugin.lua");
    let registry = Registry {
        dirs: &dirs,
        builtin: &[],
    };
    for bytes in [vec![0xff, 0xfe], vec![b'-'; 1024 * 1024 + 1]] {
        fs::write(&script, bytes).unwrap();
        let err = registry.find("acme/widget").unwrap_err();
        assert_eq!(err.code(), "E_PLUGIN_INVALID", "{err}");
    }
}

#[test]
fn a_script_that_does_not_match_its_hash_is_an_invalid_plugin() {
    let (_home, dirs) = dirs();
    add(
        &dirs,
        "acme--widget@abc123",
        &with_hook("function post() end"),
    );
    fs::write(
        dirs.plugins().join("acme--widget@abc123/plugin.lua"),
        "function post() jtm.fs.remove('bin') end",
    )
    .unwrap();
    let registry = Registry {
        dirs: &dirs,
        builtin: &[],
    };
    let err = registry.find("acme/widget").unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
    assert!(err.to_string().contains("script_sha256"), "{err}");
}

#[test]
fn a_script_no_hook_names_is_not_loaded() {
    let (_home, dirs) = dirs();
    add(&dirs, "acme--widget@abc123", &manifest("acme/widget"));
    fs::write(
        dirs.plugins().join("acme--widget@abc123/plugin.lua"),
        "function x() end",
    )
    .unwrap();
    let registry = Registry {
        dirs: &dirs,
        builtin: &[],
    };
    let plugin = registry.find("acme/widget").unwrap();
    assert!(plugin.script.is_none());
    assert!(
        plugin
            .script(crate::platform::Platform::LinuxX64)
            .unwrap()
            .is_none()
    );
}

// --- the builtin working copy ---

/// Builtin manifests with large files, so each repair takes long enough to overlap.
fn big_builtin() -> &'static [BuiltinManifest] {
    let text: &'static str =
        Box::leak(format!("{}# {}\n", manifest("demo"), "x".repeat(1 << 20)).into_boxed_str());
    let script: &'static str = Box::leak("-- y\n".repeat(1 << 18).into_boxed_str());
    Box::leak(Box::new([
        BuiltinManifest {
            name: "demo",
            text,
            script: Some(script),
        },
        BuiltinManifest {
            name: "other",
            text,
            script: None,
        },
    ]))
}

#[test]
fn a_context_without_builtin_manifests_leaves_the_working_copy_alone() {
    let (_home, dirs) = dirs();
    sync_working_copy(&dirs, big_builtin()).unwrap();
    let copy = dirs.builtin_plugins().join("demo").join("plugin.toml");
    assert!(copy.is_file());
    assert_eq!(
        sync_working_copy(&dirs, &[]).unwrap(),
        Vec::<PathBuf>::new()
    );
    assert!(copy.is_file(), "the working copy was removed");
}

#[test]
fn concurrent_repairs_never_remove_each_others_files() {
    let (_home, dirs) = dirs();
    let builtin = big_builtin();
    for round in 0..5 {
        // A stale copy, so every process repairs both files at once.
        for name in ["demo", "other"] {
            let dir = dirs.builtin_plugins().join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("plugin.toml"), format!("stale {round}")).unwrap();
        }
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| sync_working_copy(&dirs, builtin)))
                .collect();
            for handle in handles {
                handle.join().unwrap().unwrap();
            }
        });
        for found in builtin {
            let dir = dirs.builtin_plugins().join(found.name);
            assert_eq!(
                fs::read(dir.join("plugin.toml")).unwrap(),
                found.text.as_bytes()
            );
        }
        // No temporary file is left anywhere in the working copy.
        assert!(sync_working_copy(&dirs, builtin).unwrap().is_empty());
    }
}
