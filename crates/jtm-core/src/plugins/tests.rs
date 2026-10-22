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
    let path = working_copy_dir(&dirs, builtin_set(0)).join("demo");
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
    add(
        &dirs,
        "acme--widget@abc123",
        &with_hook("function post() end"),
    );
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
fn a_script_no_hook_names_is_never_read() {
    let (_home, dirs) = dirs();
    add(&dirs, "acme--widget@abc123", &manifest("acme/widget"));
    let script = dirs.plugins().join("acme--widget@abc123/plugin.lua");
    let registry = Registry {
        dirs: &dirs,
        builtin: &[],
    };
    for bytes in [vec![0xff, 0xfe], vec![b'-'; 1024 * 1024 + 1]] {
        fs::write(&script, bytes).unwrap();
        let plugin = registry.find("acme/widget").unwrap();
        assert!(plugin.script.is_none());
    }
    // Nor is a `plugin.lua` that is not even a file.
    fs::remove_file(&script).unwrap();
    fs::create_dir(&script).unwrap();
    assert!(registry.find("acme/widget").unwrap().script.is_none());
}

#[test]
fn parse_reads_the_script_only_when_a_hook_is_named() {
    let text = manifest("acme/widget");
    let plugin = parse(
        text.as_bytes(),
        || panic!("the script was read although no hook is named"),
        ManifestOrigin::External,
        "test",
        "acme/widget",
    )
    .unwrap();
    assert!(plugin.script.is_none());

    let source = "function post() end";
    let mut reads = 0;
    let plugin = parse(
        with_hook(source).as_bytes(),
        || {
            reads += 1;
            Ok(Some(source.to_owned()))
        },
        ManifestOrigin::External,
        "test",
        "acme/widget",
    )
    .unwrap();
    assert_eq!(reads, 1);
    assert_eq!(plugin.script.as_deref(), Some(source));
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

/// The `demo` manifest, the same on every call, so the sets built from it have stable keys.
fn demo_manifest() -> &'static str {
    static TEXT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    TEXT.get_or_init(|| manifest("demo"))
}

/// Two builtin manifests whose files are padded by about `pad` bytes.
fn builtin_set(pad: usize) -> &'static [BuiltinManifest] {
    let text: &'static str =
        Box::leak(format!("{}# {}\n", demo_manifest(), "x".repeat(pad)).into_boxed_str());
    let script: &'static str = Box::leak("-- y\n".repeat(pad / 4 + 1).into_boxed_str());
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

/// Builtin manifests with larger files, so the repairs started at once overlap.
fn big_builtin() -> &'static [BuiltinManifest] {
    builtin_set(1 << 16)
}

/// The names of the repair's temporary files left in `<data>/plugins`.
fn temp_files(dirs: &Dirs) -> Vec<String> {
    fs::read_dir(dirs.plugins())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(TEMP_PREFIX))
        .collect()
}

#[test]
fn a_context_without_builtin_manifests_leaves_the_working_copy_alone() {
    let (_home, dirs) = dirs();
    sync_working_copy(&dirs, builtin_set(0)).unwrap();
    let copy = working_copy_dir(&dirs, builtin_set(0))
        .join("demo")
        .join("plugin.toml");
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
            let dir = working_copy_dir(&dirs, builtin).join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("plugin.toml"), format!("stale {round}")).unwrap();
            fs::write(dir.join("plugin.toml~"), "backup").unwrap();
        }
        // And unknown entries, so every process tries to remove the same ones.
        let stray = working_copy_dir(&dirs, builtin).join("stray");
        fs::create_dir_all(stray.join("nested")).unwrap();
        fs::write(stray.join("nested").join("file"), "x").unwrap();
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| sync_working_copy(&dirs, builtin)))
                .collect();
            for handle in handles {
                handle.join().unwrap().unwrap();
            }
        });
        for found in builtin {
            let dir = working_copy_dir(&dirs, builtin).join(found.name);
            assert_eq!(
                fs::read(dir.join("plugin.toml")).unwrap(),
                found.text.as_bytes()
            );
            assert!(!dir.join("plugin.toml~").exists());
        }
        assert!(!stray.exists());
        // No temporary file is left in the working copy or beside it.
        assert!(sync_working_copy(&dirs, builtin).unwrap().is_empty());
        assert_eq!(temp_files(&dirs), Vec::<String>::new());
    }
}

#[test]
fn temporary_files_a_killed_process_left_are_swept() {
    let (_home, dirs) = dirs();
    fs::create_dir_all(dirs.plugins()).unwrap();
    let left = dirs.plugins().join(format!("{TEMP_PREFIX}left"));
    let other = dirs.plugins().join(".tmp-not-ours");
    for path in [&left, &other] {
        fs::write(path, "partial").unwrap();
    }
    sync_working_copy(&dirs, builtin_set(0)).unwrap();
    assert!(!left.exists(), "a leftover temporary file is removed");
    assert!(other.exists(), "only jtm's own temporary files are touched");
}

#[test]
fn a_repair_already_running_elsewhere_is_not_waited_for() {
    let (_home, dirs) = dirs();
    let held = lock_working_copy(&dirs).unwrap().unwrap();
    fs::create_dir_all(dirs.plugins()).unwrap();
    let left = dirs.plugins().join(format!("{TEMP_PREFIX}in-progress"));
    fs::write(&left, "partial").unwrap();
    assert_eq!(
        sync_working_copy(&dirs, builtin_set(0)).unwrap(),
        Vec::<PathBuf>::new()
    );
    assert!(
        left.exists(),
        "the lock holder's temporary file is left alone"
    );
    assert!(
        !working_copy_dir(&dirs, builtin_set(0))
            .join("demo")
            .exists()
    );
    drop(held);
    assert!(!sync_working_copy(&dirs, builtin_set(0)).unwrap().is_empty());
    assert!(
        working_copy_dir(&dirs, builtin_set(0))
            .join("demo")
            .join("plugin.toml")
            .is_file()
    );
}

/// A target no rename can replace: a directory that is not empty.
fn unreplaceable(dirs: &Dirs) -> PathBuf {
    fs::create_dir_all(dirs.plugins()).unwrap();
    let target = working_copy_dir(dirs, builtin_set(0))
        .join("demo")
        .join("plugin.toml");
    fs::create_dir_all(target.join("inside")).unwrap();
    target
}

#[test]
fn a_rename_that_cannot_work_fails_at_once_and_leaves_no_temp_file() {
    let (_home, dirs) = dirs();
    let target = unreplaceable(&dirs);
    let tries = std::cell::Cell::new(0);
    let result = write_replacing_with(&dirs.plugins(), &target, b"new", |_| {
        tries.set(tries.get() + 1);
        false
    });
    assert!(result.is_err());
    assert_eq!(tries.get(), 1, "a lasting failure is not retried");
    assert_eq!(temp_files(&dirs), Vec::<String>::new());
}

#[test]
fn a_refused_rename_is_retried_a_few_times_then_fails() {
    let (_home, dirs) = dirs();
    let target = unreplaceable(&dirs);
    let tries = std::cell::Cell::new(0);
    let result = write_replacing_with(&dirs.plugins(), &target, b"new", |_| {
        tries.set(tries.get() + 1);
        true
    });
    assert!(result.is_err());
    assert_eq!(tries.get(), 3, "the rename is tried three times in all");
    assert!(target.join("inside").is_dir());
    assert_eq!(temp_files(&dirs), Vec::<String>::new());
}

#[test]
fn only_a_refused_rename_on_windows_counts_as_transient() {
    let denied = io::Error::from(io::ErrorKind::PermissionDenied);
    let missing = io::Error::from(io::ErrorKind::NotFound);
    assert_eq!(rename_refused(&denied), cfg!(windows));
    assert!(!rename_refused(&missing));
}

// --- one working copy per embedded set ---

/// A builtin set with one manifest, `demo`, that differs from every other set by `tag`.
fn tagged_set(tag: &str) -> &'static [BuiltinManifest] {
    let text: &'static str = Box::leak(format!("{}# {tag}\n", demo_manifest()).into_boxed_str());
    Box::leak(Box::new([BuiltinManifest {
        name: "demo",
        text,
        script: None,
    }]))
}

/// Sets the modification time of a file or directory.
fn set_mtime(path: &Path, time: SystemTime) {
    let mut options = fs::OpenOptions::new();
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // FILE_WRITE_ATTRIBUTES, and FILE_FLAG_BACKUP_SEMANTICS so a directory can be opened.
        options.access_mode(0x100).custom_flags(0x0200_0000);
    }
    #[cfg(not(windows))]
    options.read(true);
    options.open(path).unwrap().set_modified(time).unwrap();
}

fn days_ago(days: u64) -> SystemTime {
    SystemTime::now() - Duration::from_secs(days * 24 * 60 * 60)
}

/// Marks the working copy of `builtin` as last used `days` ago.
fn age_copy(dirs: &Dirs, builtin: &[BuiltinManifest], days: u64) {
    set_mtime(
        &working_copy_dir(dirs, builtin).join(LAST_USED),
        days_ago(days),
    );
}

#[test]
fn the_key_is_short_hex_and_follows_the_files_not_their_order() {
    let key = working_copy_key(builtin_set(0));
    assert_eq!(key.len(), KEY_LEN);
    assert!(key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert!(is_working_copy(&format!("{COPY_PREFIX}{key}")));

    let mut reversed = builtin_set(0).to_vec();
    reversed.reverse();
    assert_eq!(working_copy_key(&reversed), key);

    // A script moving from one plugin to another is a different set.
    let mut moved = builtin_set(0).to_vec();
    moved[1].script = moved[0].script.take();
    assert_ne!(working_copy_key(&moved), key);
    assert_ne!(
        working_copy_key(tagged_set("a")),
        working_copy_key(tagged_set("b"))
    );
}

#[test]
fn two_sets_used_alternately_each_settle_after_their_first_sync() {
    let (_home, dirs) = dirs();
    let (old, new) = (tagged_set("old"), tagged_set("new"));
    assert!(!sync_working_copy(&dirs, old).unwrap().is_empty());
    assert!(!sync_working_copy(&dirs, new).unwrap().is_empty());
    for _ in 0..3 {
        assert_eq!(
            sync_working_copy(&dirs, old).unwrap(),
            Vec::<PathBuf>::new()
        );
        assert_eq!(
            sync_working_copy(&dirs, new).unwrap(),
            Vec::<PathBuf>::new()
        );
    }
    for set in [old, new] {
        let text = fs::read_to_string(
            working_copy_dir(&dirs, set)
                .join("demo")
                .join("plugin.toml"),
        );
        assert_eq!(text.unwrap(), set[0].text);
    }
}

#[test]
fn each_sync_marks_its_copy_as_used() {
    let (_home, dirs) = dirs();
    let builtin = builtin_set(0);
    sync_working_copy(&dirs, builtin).unwrap();
    let marker = working_copy_dir(&dirs, builtin).join(LAST_USED);
    set_mtime(&marker, days_ago(3));
    sync_working_copy(&dirs, builtin).unwrap();
    let used = fs::metadata(&marker).unwrap().modified().unwrap();
    assert!(used > days_ago(1), "the marker was not refreshed");

    // A missing marker is put back without counting as a repair.
    fs::remove_file(&marker).unwrap();
    assert_eq!(
        sync_working_copy(&dirs, builtin).unwrap(),
        Vec::<PathBuf>::new()
    );
    assert!(marker.is_file());
}

#[test]
fn copies_unused_for_30_days_are_removed_and_the_current_one_never_is() {
    let (_home, dirs) = dirs();
    let (current, stale, recent) = (
        tagged_set("current"),
        tagged_set("stale"),
        tagged_set("recent"),
    );
    for set in [current, stale, recent] {
        sync_working_copy(&dirs, set).unwrap();
    }
    age_copy(&dirs, stale, 31);
    age_copy(&dirs, recent, 29);
    // Even a current copy whose marker is long out of date is kept, and marked again.
    age_copy(&dirs, current, 365);
    // External plugins and anything else not named like a copy are never touched.
    let others = [
        "acme--widget@abc123",
        "builtin-not-a-key",
        "builtin-0123456789ABCDEF",
    ];
    for name in others {
        let dir = dirs.plugins().join(name);
        fs::create_dir_all(&dir).unwrap();
        set_mtime(&dir, days_ago(365));
    }

    assert_eq!(
        sync_working_copy(&dirs, current).unwrap(),
        Vec::<PathBuf>::new()
    );
    assert!(!working_copy_dir(&dirs, stale).exists());
    assert!(working_copy_dir(&dirs, recent).join("demo").is_dir());
    assert!(working_copy_dir(&dirs, current).join("demo").is_dir());
    for name in others {
        assert!(dirs.plugins().join(name).is_dir(), "{name} was removed");
    }
    assert_eq!(temp_files(&dirs), Vec::<String>::new());

    // A removed copy's binary simply unpacks it again on its next run.
    assert!(!sync_working_copy(&dirs, stale).unwrap().is_empty());
    assert!(working_copy_dir(&dirs, stale).join("demo").is_dir());
}

#[test]
fn the_legacy_shared_copy_is_removed_once_stale() {
    let (_home, dirs) = dirs();
    let legacy = dirs.plugins().join(LEGACY_COPY);
    fs::create_dir_all(legacy.join("demo")).unwrap();
    fs::write(legacy.join("demo").join("plugin.toml"), "old").unwrap();
    sync_working_copy(&dirs, builtin_set(0)).unwrap();
    assert!(legacy.is_dir(), "a copy in recent use is kept");

    // Without a marker, the directory's own modification time says when it was last used.
    set_mtime(&legacy, days_ago(31));
    sync_working_copy(&dirs, builtin_set(0)).unwrap();
    assert!(!legacy.exists());
}

#[test]
fn a_stale_copy_whose_removal_was_cut_short_is_swept() {
    let (_home, dirs) = dirs();
    let left = dirs.plugins().join(format!("{TEMP_PREFIX}stale-builtin"));
    fs::create_dir_all(left.join("demo")).unwrap();
    fs::write(left.join("demo").join("plugin.toml"), "old").unwrap();
    sync_working_copy(&dirs, builtin_set(0)).unwrap();
    assert!(!left.exists());
}

#[test]
fn nothing_is_removed_while_another_process_holds_the_lock() {
    let (_home, dirs) = dirs();
    let stale = tagged_set("stale");
    sync_working_copy(&dirs, stale).unwrap();
    age_copy(&dirs, stale, 31);
    let held = lock_working_copy(&dirs).unwrap().unwrap();
    sync_working_copy(&dirs, builtin_set(0)).unwrap();
    assert!(working_copy_dir(&dirs, stale).is_dir());
    drop(held);
    sync_working_copy(&dirs, builtin_set(0)).unwrap();
    assert!(!working_copy_dir(&dirs, stale).exists());
}

#[cfg(unix)]
#[test]
fn a_marker_replaced_by_a_link_is_never_followed() {
    let (_home, dirs) = dirs();
    let builtin = builtin_set(0);
    sync_working_copy(&dirs, builtin).unwrap();
    let outside = tempfile::tempdir().unwrap();
    let victim = outside.path().join("victim");
    fs::write(&victim, "keep").unwrap();
    set_mtime(&victim, days_ago(10));
    let marker = working_copy_dir(&dirs, builtin).join(LAST_USED);
    fs::remove_file(&marker).unwrap();
    std::os::unix::fs::symlink(&victim, &marker).unwrap();

    sync_working_copy(&dirs, builtin).unwrap();
    assert!(fs::symlink_metadata(&marker).unwrap().is_file());
    assert_eq!(fs::read_to_string(&victim).unwrap(), "keep");
    assert!(fs::metadata(&victim).unwrap().modified().unwrap() < days_ago(9));
}
