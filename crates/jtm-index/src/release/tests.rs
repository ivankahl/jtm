use std::fs;
use std::path::{Path, PathBuf};

use jtm_core::{ErrorCode, Platform};
use jtm_security::Timestamp;

use super::*;
use crate::candidate::Target;
use crate::confirm::Confirmed;
use crate::publish::{self, Request as Publish};
use crate::signing::Signer;
use crate::testing::{MinisignKey, confirmed_entry, minisign_key};
use crate::writer::{Binding, Settings, Validity};

/// 2026-10-19T03:00:00Z
const NOW: Timestamp = Timestamp::from_unix(1_792_378_800);
const DAY: i64 = 86_400;

fn at(days: i64) -> Timestamp {
    Timestamp::from_unix(NOW.unix() + days * DAY)
}

fn manifest(name: &str, url_file: &str, root: &str) -> String {
    format!(
        r#"
schema = 1
name = "{name}"
display_name = "Demo"

[versions]
scheme = "semver-loose"

[index]
url = "https://github.com/jtm-dev/index/releases/latest/download/{url_file}"
signing_keys = ["{root}"]
keys_url = "https://github.com/jtm-dev/index/releases/latest/download/keys.json"
format = 1

[layout]
bin_dirs = ["bin"]
"#
    )
}

fn signer(key: &MinisignKey) -> Signer {
    Signer::from_secret_key(&key.secret_file, None).unwrap()
}

/// A release being assembled: a root key that signs `keys.json`, the index key it lists, and
/// the directories a run needs.
struct Release {
    root: MinisignKey,
    index_key: MinisignKey,
    published: tempfile::TempDir,
    plugins: tempfile::TempDir,
}

impl Release {
    fn new() -> Release {
        Release {
            root: minisign_key(),
            index_key: minisign_key(),
            published: tempfile::tempdir().unwrap(),
            plugins: tempfile::tempdir().unwrap(),
        }
    }

    fn dir(&self) -> &Path {
        self.published.path()
    }

    /// A plugin directory with a manifest trusting this release's root key.
    fn plugin(&self, name: &str, url_file: &str) -> PathBuf {
        self.plugin_with_root(name, url_file, &self.root.public)
    }

    fn plugin_with_root(&self, name: &str, url_file: &str, root: &str) -> PathBuf {
        let dir = self.plugins.path().join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("plugin.toml"), manifest(name, url_file, root)).unwrap();
        dir
    }

    /// `keys.json` listing the index key for `scope`, until `expires_in` days from now, signed
    /// by `signer_key`.
    fn keys(&self, sequence: u64, scope: &[&str], expires_in: i64, signer_key: &MinisignKey) {
        let keys = serde_json::json!({
            "format": 1,
            "sequence": sequence,
            "threshold": 1,
            "keys": [{
                "key": self.index_key.public,
                "scope": scope,
                "expires": at(expires_in).to_string()
            }]
        });
        let data = serde_json::to_vec_pretty(&keys).unwrap();
        let signature = signer(signer_key).sign("keys.json", &data, NOW).unwrap();
        fs::write(self.dir().join("keys.json"), data).unwrap();
        fs::write(self.dir().join("keys.json.minisig"), signature).unwrap();
    }

    /// Publishes `plugin`'s index files, signed by `key`, valid for `days` from now.
    fn publish(
        &self,
        binding: &Binding,
        entries: Vec<crate::confirm::ConfirmedEntry>,
        key: &MinisignKey,
        days: u32,
    ) {
        publish::publish(&Publish {
            binding,
            confirmed: &Confirmed {
                entries,
                warnings: Vec::new(),
            },
            previous_dir: None,
            previous_keys: &[],
            out_dir: self.dir(),
            signer: Some(&signer(key)),
            settings: Settings {
                now: NOW,
                validity: Validity::days(days).unwrap(),
            },
            dry_run: false,
        })
        .unwrap();
    }

    fn check(&self, plugin_dirs: &[PathBuf]) -> Result<Report> {
        self.check_with(plugin_dirs, &[], NOW, 14)
    }

    fn check_with(
        &self,
        plugin_dirs: &[PathBuf],
        root_keys: &[String],
        now: Timestamp,
        min_key_days: u32,
    ) -> Result<Report> {
        verify(&super::Request {
            published: self.dir(),
            plugin_dirs,
            root_keys,
            now,
            min_key_days,
        })
    }
}

fn platform_binding() -> Binding {
    Binding {
        plugin: "demo".to_owned(),
        platform_independent: false,
        variants: Vec::new(),
    }
}

fn independent_binding() -> Binding {
    Binding {
        plugin: "tool".to_owned(),
        platform_independent: true,
        variants: Vec::new(),
    }
}

fn linux_and_windows() -> Vec<crate::confirm::ConfirmedEntry> {
    vec![
        confirmed_entry(None, "1.0.0", Target::Platform(Platform::LinuxX64)),
        confirmed_entry(None, "1.0.0", Target::Platform(Platform::WindowsX64)),
    ]
}

fn code(result: Result<Report>) -> ErrorCode {
    result.expect_err("the release should be refused").code()
}

#[test]
fn a_release_signed_by_a_delegated_key_is_accepted_for_every_platform_it_holds() {
    let release = Release::new();
    release.keys(3, &["demo"], 60, &release.root);
    release.publish(
        &platform_binding(),
        linux_and_windows(),
        &release.index_key,
        30,
    );
    let plugin = release.plugin("demo", "demo-{os}-{arch}.json");

    let report = release.check(&[plugin]).unwrap();

    assert_eq!(report.plugins.len(), 1);
    let demo = &report.plugins[0];
    assert_eq!(demo.plugin, "demo");
    assert_eq!(demo.keys_sequence, Some(3));
    let mut files: Vec<(&str, &str, u64)> = demo
        .files
        .iter()
        .map(|f| (f.file.as_str(), f.platform.as_str(), f.sequence))
        .collect();
    files.sort_unstable();
    assert_eq!(
        files,
        [
            ("demo-linux-x64.json", "linux-x64", 1),
            ("demo-windows-x64.json", "windows-x64", 1)
        ]
    );
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
}

#[test]
fn a_platform_independent_plugin_is_checked_as_any() {
    let release = Release::new();
    release.keys(1, &["tool"], 60, &release.root);
    release.publish(
        &independent_binding(),
        vec![confirmed_entry(None, "2.0.0", Target::Any)],
        &release.index_key,
        30,
    );
    let plugin = release.plugin("tool", "tool-any.json");
    let report = release.check(&[plugin]).unwrap();
    assert_eq!(report.plugins[0].files[0].platform, "any");
    assert_eq!(report.plugins[0].files[0].file, "tool-any.json");
}

#[test]
fn a_key_nobody_delegated_to_is_untrusted() {
    let release = Release::new();
    release.keys(1, &["demo"], 60, &release.root);
    release.publish(
        &platform_binding(),
        linux_and_windows(),
        &minisign_key(),
        30,
    );
    let plugin = release.plugin("demo", "demo-{os}-{arch}.json");
    assert_eq!(code(release.check(&[plugin])), ErrorCode::KeyUntrusted);
}

#[test]
fn a_key_delegated_for_another_plugin_is_untrusted() {
    let release = Release::new();
    release.keys(1, &["tool"], 60, &release.root);
    release.publish(
        &platform_binding(),
        linux_and_windows(),
        &release.index_key,
        30,
    );
    let plugin = release.plugin("demo", "demo-{os}-{arch}.json");
    assert_eq!(code(release.check(&[plugin])), ErrorCode::KeyUntrusted);
}

#[test]
fn a_delegated_key_that_has_expired_cannot_sign() {
    let release = Release::new();
    release.keys(1, &["demo"], 10, &release.root);
    release.publish(
        &platform_binding(),
        linux_and_windows(),
        &release.index_key,
        30,
    );
    let plugin = release.plugin("demo", "demo-{os}-{arch}.json");
    let result = release.check_with(&[plugin], &[], at(11), 14);
    assert_eq!(code(result), ErrorCode::SignatureInvalid);
}

#[test]
fn a_key_that_expires_soon_is_a_warning_not_a_failure() {
    let release = Release::new();
    release.keys(1, &["demo"], 5, &release.root);
    release.publish(
        &platform_binding(),
        linux_and_windows(),
        &release.index_key,
        30,
    );
    let plugin = release.plugin("demo", "demo-{os}-{arch}.json");

    let report = release.check(&[plugin]).unwrap();

    assert_eq!(report.warnings.len(), 1);
    assert_eq!(report.warnings[0].code, "W_KEY_EXPIRES_SOON");
    assert!(report.warnings[0].message.contains("demo"));
    assert!(report.warnings[0].message.contains(&at(5).to_string()));
}

#[test]
fn a_missing_keys_file_is_refused() {
    let release = Release::new();
    release.keys(1, &["demo"], 60, &release.root);
    release.publish(
        &platform_binding(),
        linux_and_windows(),
        &release.index_key,
        30,
    );
    fs::remove_file(release.dir().join("keys.json")).unwrap();
    let plugin = release.plugin("demo", "demo-{os}-{arch}.json");
    let result = release.check(&[plugin]);
    assert_eq!(code(result), ErrorCode::SignatureInvalid);
}

#[test]
fn a_keys_file_not_signed_by_the_root_is_refused_and_says_why() {
    let release = Release::new();
    release.keys(1, &["demo"], 60, &minisign_key());
    release.publish(
        &platform_binding(),
        linux_and_windows(),
        &release.index_key,
        30,
    );
    let plugin = release.plugin("demo", "demo-{os}-{arch}.json");
    let err = release.check(&[plugin]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::SignatureInvalid);
    assert!(err.to_string().contains("keys.json"), "{err}");
}

#[test]
fn an_expired_index_is_refused() {
    let release = Release::new();
    release.keys(1, &["demo"], 90, &release.root);
    release.publish(
        &platform_binding(),
        linux_and_windows(),
        &release.index_key,
        30,
    );
    let plugin = release.plugin("demo", "demo-{os}-{arch}.json");
    let result = release.check_with(&[plugin], &[], at(31), 14);
    assert_eq!(code(result), ErrorCode::IndexExpired);
}

#[test]
fn a_changed_byte_is_refused() {
    let release = Release::new();
    release.keys(1, &["demo"], 60, &release.root);
    release.publish(
        &platform_binding(),
        linux_and_windows(),
        &release.index_key,
        30,
    );
    let file = release.dir().join("demo-linux-x64.json");
    let text = fs::read_to_string(&file).unwrap().replace("1.0.0", "6.6.6");
    fs::write(&file, text).unwrap();
    let plugin = release.plugin("demo", "demo-{os}-{arch}.json");
    assert_eq!(code(release.check(&[plugin])), ErrorCode::SignatureInvalid);
}

#[test]
fn a_manifest_url_that_names_a_file_the_release_does_not_hold_is_explained() {
    let release = Release::new();
    release.keys(1, &["demo"], 60, &release.root);
    release.publish(
        &platform_binding(),
        linux_and_windows(),
        &release.index_key,
        30,
    );
    let plugin = release.plugin("demo", "idx-{os}-{arch}.json");
    let err = release.check(&[plugin]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::IndexInvalid);
    assert!(err.to_string().contains("idx-windows-x64.json"), "{err}");
    assert!(err.to_string().contains("demo-windows-x64.json"), "{err}");
}

#[test]
fn a_release_without_the_plugins_files_is_refused() {
    let release = Release::new();
    release.keys(1, &["demo", "tool"], 60, &release.root);
    release.publish(
        &platform_binding(),
        linux_and_windows(),
        &release.index_key,
        30,
    );
    let demo = release.plugin("demo", "demo-{os}-{arch}.json");
    let tool = release.plugin("tool", "tool-any.json");
    let err = release.check(&[demo, tool]).unwrap_err();
    assert_eq!(err.code(), ErrorCode::IndexInvalid);
    assert!(err.to_string().contains("tool"), "{err}");
}

#[test]
fn root_keys_given_on_the_command_line_replace_the_manifests_for_a_rehearsal() {
    let release = Release::new();
    release.keys(1, &["demo"], 60, &release.root);
    release.publish(
        &platform_binding(),
        linux_and_windows(),
        &release.index_key,
        30,
    );
    let placeholder = minisign_key().public;
    let plugin = release.plugin_with_root("demo", "demo-{os}-{arch}.json", &placeholder);

    assert_eq!(
        code(release.check(std::slice::from_ref(&plugin))),
        ErrorCode::SignatureInvalid
    );
    let report = release
        .check_with(
            &[plugin],
            std::slice::from_ref(&release.root.public),
            NOW,
            14,
        )
        .unwrap();
    assert_eq!(report.plugins[0].files.len(), 2);
}

#[test]
fn checking_leaves_no_state_behind_in_the_release_directory() {
    let release = Release::new();
    release.keys(1, &["demo"], 60, &release.root);
    release.publish(
        &platform_binding(),
        linux_and_windows(),
        &release.index_key,
        30,
    );
    let mut before: Vec<_> = fs::read_dir(release.dir())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    before.sort();
    let plugin = release.plugin("demo", "demo-{os}-{arch}.json");
    release.check(&[plugin]).unwrap();
    let mut after: Vec<_> = fs::read_dir(release.dir())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    after.sort();
    assert_eq!(before, after);
}
