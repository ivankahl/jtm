use std::collections::BTreeMap;
use std::sync::{Arc, Barrier};

use jtm_archive::testing::{E, exe, file, tar_gz};
use jtm_fetch::DownloadCache;
use jtm_security::ArchiveKind;
use jtm_security::testing::TestKey;

use std::io;

use super::*;
use crate::platform::Os;

const PLATFORM: Platform = Platform::LinuxX64;

struct Fixture {
    _home: tempfile::TempDir,
    dirs: Dirs,
    manifest: Manifest,
    cache: DownloadCache,
    mirrors: BTreeMap<String, String>,
}

fn manifest() -> Manifest {
    Manifest::parse(&manifest_text("")).unwrap()
}

fn manifest_text(extra: &str) -> String {
    let key = TestKey::generate().public_str();
    format!(
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
bin_dirs = ["bin"]
{extra}
"#
    )
}

fn good_archive() -> Vec<u8> {
    tar_gz(&[
        exe("demo-1.0.0/bin/demo", b"#!/bin/sh"),
        exe("demo-1.0.0/bin/demo.cmd", b"@echo off"),
        file("demo-1.0.0/README", b"readme"),
    ])
}

impl Fixture {
    fn new() -> Fixture {
        let home = tempfile::tempdir().unwrap();
        let dirs = Dirs::resolve(Os::host().unwrap(), Some(home.path()), None, &|_| None).unwrap();
        let cache = DownloadCache::new(dirs.downloads());
        Fixture {
            _home: home,
            dirs,
            manifest: manifest(),
            cache,
            mirrors: BTreeMap::new(),
        }
    }

    /// Puts `archive` in the download cache and returns its index entry.
    fn seed(&self, archive: &[u8]) -> IndexEntry {
        let sha256 = jtm_security::sha256_hex(archive);
        fs::create_dir_all(self.dirs.downloads()).unwrap();
        fs::write(self.dirs.downloads().join(&sha256), archive).unwrap();
        entry(&sha256, archive.len() as u64)
    }

    fn archives(&self) -> Archives<'_> {
        Archives {
            cache: &self.cache,
            client: None,
            mirrors: &self.mirrors,
        }
    }

    fn install(&self, entry: &IndexEntry, force: bool) -> Result<Installed> {
        let request = InstallRequest {
            manifest: &self.manifest,
            manifest_sha256: "ab",
            entry,
            platform: PLATFORM,
            index_sequence: 7,
            force,
            script: None,
        };
        install(
            &self.dirs,
            &self.archives(),
            &request,
            &jtm_archive::Limits::default(),
            &mut |_| {},
        )
    }

    fn dest(&self) -> PathBuf {
        self.dirs.install_dir("demo", "default", "1.0.0")
    }

    fn tmp_entries(&self) -> Vec<PathBuf> {
        fs::read_dir(self.dirs.tools_tmp())
            .map(|d| d.map(|e| e.unwrap().path()).collect())
            .unwrap_or_default()
    }
}

fn entry(sha256: &str, size: u64) -> IndexEntry {
    IndexEntry {
        variant: "default".into(),
        version: "1.0.0".into(),
        tags: vec![],
        url: "https://example.test/demo-1.0.0.tar.gz".into(),
        archive: ArchiveKind::TarGz,
        size,
        sha256: sha256.into(),
        provenance: vec![],
    }
}

#[test]
fn installs_and_writes_a_receipt() {
    let f = Fixture::new();
    let entry = f.seed(&good_archive());
    let mut events = Vec::new();
    let request = InstallRequest {
        manifest: &f.manifest,
        manifest_sha256: "ab",
        entry: &entry,
        platform: PLATFORM,
        index_sequence: 7,
        force: false,
        script: None,
    };
    let done = install(
        &f.dirs,
        &f.archives(),
        &request,
        &jtm_archive::Limits::default(),
        &mut |p| events.push(p),
    )
    .unwrap();

    assert_eq!(done.status, Status::Installed);
    assert_eq!(done.path, f.dest());
    assert!(f.dest().join("bin/demo").is_file());
    assert!(f.dest().join("README").is_file());
    assert_eq!(events, [Progress::Verified, Progress::Extracted]);

    let receipt = Receipt::read(&f.dest()).unwrap();
    assert_eq!(receipt, done.receipt);
    assert_eq!(receipt.plugin, "demo");
    assert_eq!(receipt.manifest_sha256, "ab");
    assert_eq!(receipt.variant, "default");
    assert_eq!(receipt.version, "1.0.0");
    assert_eq!(receipt.platform, "linux-x64");
    assert_eq!(receipt.url, entry.url);
    assert_eq!(receipt.sha256, entry.sha256);
    assert_eq!(receipt.size, entry.size);
    assert_eq!(receipt.index_sequence, 7);
    assert_eq!(receipt.home, "");
    assert!(Timestamp::parse(&receipt.installed_at).is_some());
    assert!(f.tmp_entries().is_empty());
}

#[test]
fn a_second_install_is_a_no_op() {
    let f = Fixture::new();
    let entry = f.seed(&good_archive());
    let first = f.install(&entry, false).unwrap();
    let second = f.install(&entry, false).unwrap();
    assert_eq!(second.status, Status::AlreadyInstalled);
    assert_eq!(second.receipt, first.receipt);
}

#[test]
fn force_reinstalls() {
    let f = Fixture::new();
    let entry = f.seed(&good_archive());
    f.install(&entry, false).unwrap();
    fs::write(f.dest().join("stray"), b"x").unwrap();
    let again = f.install(&entry, true).unwrap();
    assert_eq!(again.status, Status::Installed);
    assert!(!f.dest().join("stray").exists());
    assert!(f.dest().join("bin/demo").is_file());
}

#[test]
fn a_receipt_for_other_bytes_is_reinstalled() {
    let f = Fixture::new();
    let entry = f.seed(&good_archive());
    f.install(&entry, false).unwrap();
    let mut receipt = Receipt::read(&f.dest()).unwrap();
    receipt.sha256 = "0".repeat(64);
    receipt.write(&f.dest()).unwrap();
    assert_eq!(f.install(&entry, false).unwrap().status, Status::Installed);
}

#[test]
fn concurrent_installs_of_one_version_install_once() {
    let f = Arc::new(Fixture::new());
    let entry = Arc::new(f.seed(&good_archive()));
    let threads = 6;
    let barrier = Arc::new(Barrier::new(threads));
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let (f, entry, barrier) = (Arc::clone(&f), Arc::clone(&entry), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                f.install(&entry, false).unwrap().status
            })
        })
        .collect();
    let statuses: Vec<Status> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(
        statuses.iter().filter(|s| **s == Status::Installed).count(),
        1,
        "{statuses:?}"
    );
    assert!(f.dest().join("bin/demo").is_file());
    assert!(f.tmp_entries().is_empty());
}

#[test]
fn a_failed_install_leaves_no_install_dir_but_keeps_the_download() {
    let f = Fixture::new();
    // No `bin` dir, so the bin dir check fails after extraction.
    let archive = tar_gz(&[file("demo-1.0.0/lib/other", b"x")]);
    let entry = f.seed(&archive);
    let err = f.install(&entry, false).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
    assert!(!f.dest().exists());
    assert!(f.tmp_entries().is_empty());
    assert!(f.dirs.downloads().join(&entry.sha256).is_file());
}

/// A fixture whose manifest runs `body` as its `post_extract` hook, with a short time limit.
fn hooked(body: &str) -> (Fixture, Script) {
    let mut f = Fixture::new();
    let source = format!("function post(ctx)\n{body}\nend");
    let text = manifest_text(&format!(
        "[hooks]\npost_extract = \"post\"\nscript_sha256 = \"{}\"",
        jtm_security::sha256_hex(source.as_bytes())
    ));
    f.manifest = Manifest::parse(&text).unwrap();
    let host = jtm_plugin::script::Host {
        platform: PLATFORM.as_str().into(),
        os: PLATFORM.os().as_str().into(),
        arch: PLATFORM.arch().as_str().into(),
    };
    let script = Script::new("demo", &source, &text, None, host)
        .unwrap()
        .with_limits(jtm_plugin::script::Limits {
            time: std::time::Duration::from_millis(200),
            ..jtm_plugin::script::Limits::default()
        });
    (f, script)
}

impl Fixture {
    fn install_with(&self, entry: &IndexEntry, script: &Script) -> Result<Installed> {
        let request = InstallRequest {
            manifest: &self.manifest,
            manifest_sha256: "ab",
            entry,
            platform: PLATFORM,
            index_sequence: 7,
            force: false,
            script: Some(script),
        };
        install(
            &self.dirs,
            &self.archives(),
            &request,
            &jtm_archive::Limits::default(),
            &mut |_| {},
        )
    }
}

#[test]
fn post_extract_runs_inside_the_install_dir_before_the_bin_dir_check() {
    let (f, script) = hooked(
        r#"
        assert(ctx.version == "1.0.0" and ctx.home == "")
        jtm.fs.rename("bin/demo-real", "bin/demo")
        jtm.fs.rename("bin/demo-real.cmd", "bin/demo.cmd")
        jtm.fs.remove("README")
        "#,
    );
    let entry = f.seed(&tar_gz(&[
        exe("demo-1.0.0/bin/demo-real", b"#!/bin/sh"),
        exe("demo-1.0.0/bin/demo-real.cmd", b"@echo off"),
        file("demo-1.0.0/README", b"readme"),
    ]));
    let done = f.install_with(&entry, &script).unwrap();
    assert_eq!(done.status, Status::Installed);
    assert!(f.dest().join("bin/demo").is_file());
    assert!(!f.dest().join("README").exists());
    assert!(f.tmp_entries().is_empty());
}

#[test]
fn a_post_extract_limit_breach_leaves_no_install_dir_but_keeps_the_download() {
    let (f, script) = hooked("while true do end");
    let entry = f.seed(&good_archive());
    let err = f.install_with(&entry, &script).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_SCRIPT_LIMIT");
    assert!(!f.dest().exists());
    assert!(f.tmp_entries().is_empty());
    assert!(f.dirs.downloads().join(&entry.sha256).is_file());
}

#[test]
fn post_extract_cannot_touch_files_outside_the_install_dir() {
    let (f, script) = hooked("jtm.fs.remove('../../../../outside')");
    let outside = f.dirs.tools_tmp().join("../../outside");
    fs::create_dir_all(f.dirs.tools_tmp()).unwrap();
    fs::write(&outside, "keep").unwrap();
    let entry = f.seed(&good_archive());
    let err = f.install_with(&entry, &script).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_SCRIPT_LIMIT");
    assert!(outside.is_file());
    assert!(!f.dest().exists());
}

#[test]
fn a_failing_post_extract_hook_is_an_invalid_plugin() {
    let (f, script) = hooked("error('broken')");
    let entry = f.seed(&good_archive());
    let err = f.install_with(&entry, &script).unwrap_err();
    assert_eq!(err.code(), "E_PLUGIN_INVALID");
    assert!(!f.dest().exists());
}

#[test]
fn a_post_extract_hook_without_its_script_is_refused() {
    let (f, _script) = hooked("");
    let entry = f.seed(&good_archive());
    let err = f.install(&entry, false).unwrap_err();
    assert_eq!(err.code(), "E_INTERNAL");
    assert!(!f.dest().exists());
}

#[test]
fn an_unsafe_archive_leaves_nothing_behind() {
    let f = Fixture::new();
    let archive = tar_gz(&[E::Symlink(
        "demo-1.0.0/bin/demo".into(),
        "../../../x".into(),
    )]);
    let entry = f.seed(&archive);
    let err = f.install(&entry, false).unwrap_err();
    assert_eq!(err.code(), "E_ARCHIVE_UNSAFE");
    assert!(!f.dest().exists());
    assert!(f.tmp_entries().is_empty());
}

#[test]
fn a_killed_install_leaves_no_partial_install_and_is_cleaned_up() {
    let f = Fixture::new();
    let entry = f.seed(&good_archive());
    // What an install killed mid-extraction leaves: a temporary directory, never the install
    // dir, since that only appears through the final rename.
    let stale = f.dirs.tools_tmp().join("demo@default@1.0.0@killed");
    fs::create_dir_all(stale.join("demo-1.0.0/bin")).unwrap();
    fs::write(stale.join("demo-1.0.0/bin/demo"), b"partial").unwrap();
    assert!(!f.dest().exists());
    // Another version's temporary directory may belong to a running install.
    let other = f.dirs.tools_tmp().join("demo@default@2.0.0@running");
    fs::create_dir_all(&other).unwrap();
    // Including one whose version starts with this one's.
    let longer = f.dirs.tools_tmp().join("demo@default@1.0.0.1@running");
    fs::create_dir_all(&longer).unwrap();

    assert_eq!(f.install(&entry, false).unwrap().status, Status::Installed);
    assert!(!stale.exists());
    assert!(other.exists());
    assert!(longer.exists());
    assert_eq!(fs::read(f.dest().join("bin/demo")).unwrap(), b"#!/bin/sh");
}

#[test]
fn a_directory_without_a_receipt_is_not_an_install() {
    let f = Fixture::new();
    let entry = f.seed(&good_archive());
    fs::create_dir_all(f.dest().join("bin")).unwrap();
    assert_eq!(f.install(&entry, false).unwrap().status, Status::Installed);
    assert!(Receipt::read(&f.dest()).is_some());
}

#[test]
fn offline_without_a_cached_archive_fails() {
    let f = Fixture::new();
    let entry = entry(&"a".repeat(64), 10);
    assert_eq!(f.install(&entry, false).unwrap_err().code(), "E_OFFLINE");
}

#[test]
fn a_tampered_cached_archive_is_never_extracted() {
    let f = Fixture::new();
    let entry = f.seed(&good_archive());
    let mut tampered = good_archive();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    fs::write(f.dirs.downloads().join(&entry.sha256), &tampered).unwrap();
    assert_eq!(f.install(&entry, false).unwrap_err().code(), "E_OFFLINE");
    assert!(!f.dest().exists());
}

#[test]
fn install_paths_must_be_one_directory() {
    let f = Fixture::new();
    let id = |variant: &str, version: &str| VersionId {
        tool: "demo".into(),
        variant: variant.into(),
        version: version.into(),
    };
    assert!(id("default", "1.0.0").install_dir(&f.dirs).is_ok());
    assert!(id("default", "1/../../x").install_dir(&f.dirs).is_err());
    assert!(id(".", "x").install_dir(&f.dirs).is_err());
    assert_eq!(id("default", "1.0.0").to_string(), "demo@default:1.0.0");
}

#[test]
fn only_windows_sharing_failures_mean_in_use() {
    let sharing = io::Error::from_raw_os_error(32);
    assert!(held_open(&sharing, true));
    assert!(held_open(&io::Error::from_raw_os_error(5), true));
    assert!(!held_open(&sharing, false));
    assert!(!held_open(&io::Error::other("disk full"), true));
}
