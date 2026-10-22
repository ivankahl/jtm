use std::fs;
use std::path::Path;

use jtm_core::Platform;
use jtm_security::PublicKey;

use super::*;
use crate::candidate::Target;
use crate::confirm::Confirmed;
use crate::testing::{MinisignKey, confirmed_entry, minisign_key};
use crate::writer::{Binding, Settings, Validity};

/// 2026-10-19T03:00:00Z
const NOW: Timestamp = Timestamp::from_unix(1_792_378_800);
const DAY: i64 = 86_400;

fn at(days: i64) -> Timestamp {
    Timestamp::from_unix(NOW.unix() + days * DAY)
}

fn binding() -> Binding {
    Binding {
        plugin: "demo".to_owned(),
        platform_independent: false,
        variants: vec!["alpha".to_owned()],
    }
}

fn entry(version: &str, platform: Platform) -> crate::confirm::ConfirmedEntry {
    confirmed_entry(Some("alpha"), version, Target::Platform(platform))
}

fn confirmed(entries: Vec<crate::confirm::ConfirmedEntry>) -> Confirmed {
    Confirmed {
        entries,
        warnings: Vec::new(),
    }
}

fn two_platforms() -> Confirmed {
    confirmed(vec![
        entry("1.0.0", Platform::LinuxX64),
        entry("1.0.0", Platform::WindowsX64),
    ])
}

fn signer(key: &MinisignKey) -> Signer {
    Signer::from_secret_key(&key.secret_file, None).unwrap()
}

struct Run<'a> {
    binding: Binding,
    confirmed: Confirmed,
    previous: Option<&'a Path>,
    previous_keys: Vec<PublicKey>,
    out: &'a Path,
    signer: Option<&'a Signer>,
    now: Timestamp,
    dry_run: bool,
}

impl<'a> Run<'a> {
    fn new(confirmed: Confirmed, out: &'a Path, signer: &'a Signer) -> Run<'a> {
        Run {
            binding: binding(),
            confirmed,
            previous: None,
            previous_keys: Vec::new(),
            out,
            signer: Some(signer),
            now: NOW,
            dry_run: false,
        }
    }

    fn keyless(confirmed: Confirmed, out: &'a Path) -> Run<'a> {
        Run {
            binding: binding(),
            confirmed,
            previous: None,
            previous_keys: Vec::new(),
            out,
            signer: None,
            now: NOW,
            dry_run: false,
        }
    }

    fn go(&self) -> Result<Report> {
        publish(&Request {
            binding: &self.binding,
            confirmed: &self.confirmed,
            previous_dir: self.previous,
            previous_keys: &self.previous_keys,
            out_dir: self.out,
            signer: self.signer,
            settings: Settings {
                now: self.now,
                validity: Validity::days(30).unwrap(),
            },
            dry_run: self.dry_run,
        })
    }
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------------------------
// A first publish
// ---------------------------------------------------------------------------------------------

#[test]
fn a_run_writes_each_file_beside_its_signature() {
    let out = tempfile::tempdir().unwrap();
    let key = minisign_key();
    let report = Run::new(two_platforms(), out.path(), &signer(&key))
        .go()
        .unwrap();
    assert_eq!(
        names(out.path()),
        [
            "demo-linux-x64.json",
            "demo-linux-x64.json.minisig",
            "demo-windows-x64.json",
            "demo-windows-x64.json.minisig"
        ]
    );
    assert!(report.changed);
    assert!(!report.dry_run);
    assert_eq!(report.public_key.as_deref(), Some(key.public.as_str()));
}

#[test]
fn the_written_files_verify_with_the_client_loader() {
    let out = tempfile::tempdir().unwrap();
    let key = minisign_key();
    Run::new(two_platforms(), out.path(), &signer(&key))
        .go()
        .unwrap();
    for platform in ["linux-x64", "windows-x64"] {
        let file = format!("demo-{platform}.json");
        let data = fs::read(out.path().join(&file)).unwrap();
        let signature = fs::read(out.path().join(format!("{file}.minisig"))).unwrap();
        let index = verify::load_previous(
            &[PublicKey::parse(&key.public).unwrap()],
            "demo",
            &file,
            &data,
            &signature,
            NOW,
        )
        .unwrap();
        assert_eq!(index.platform, platform);
        assert_eq!(index.sequence, 1);
    }
}

#[test]
fn the_report_describes_each_file() {
    let out = tempfile::tempdir().unwrap();
    let key = minisign_key();
    let report = Run::new(two_platforms(), out.path(), &signer(&key))
        .go()
        .unwrap();
    // Files follow the platform order of the specification: Windows, macOS, Linux.
    let [windows, linux] = report.files.as_slice() else {
        panic!("{:?}", report.files);
    };
    assert_eq!(linux.file, "demo-linux-x64.json");
    assert_eq!(linux.signature_file, "demo-linux-x64.json.minisig");
    assert_eq!(linux.platform, "linux-x64");
    assert_eq!(linux.action, Action::Created);
    assert_eq!(linux.sequence, 1);
    assert_eq!(linux.generated, "2026-10-19T03:00:00Z");
    assert_eq!(linux.expires, "2026-11-18T03:00:00Z");
    assert_eq!(linux.entries, 1);
    let on_disk = fs::read(out.path().join(&linux.file)).unwrap();
    assert_eq!(linux.sha256, jtm_security::sha256_hex(&on_disk));
    assert_eq!(windows.platform, "windows-x64");
}

#[test]
fn the_report_serialises_for_json_output() {
    let out = tempfile::tempdir().unwrap();
    let key = minisign_key();
    let report = Run::new(two_platforms(), out.path(), &signer(&key))
        .go()
        .unwrap();
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["plugin"], "demo");
    assert_eq!(json["changed"], true);
    assert_eq!(json["dry_run"], false);
    assert_eq!(json["files"][0]["action"], "created");
    assert_eq!(json["files"][0]["sequence"], 1);
    // Warnings travel beside the data, in the envelope.
    assert!(json.get("warnings").is_none());
}

#[test]
fn nothing_secret_reaches_the_report() {
    let out = tempfile::tempdir().unwrap();
    let key = minisign_key();
    let report = Run::new(two_platforms(), out.path(), &signer(&key))
        .go()
        .unwrap();
    let json = serde_json::to_string(&report).unwrap();
    let secret_line = key.secret_file.lines().nth(1).unwrap();
    assert!(!json.contains(secret_line), "{json}");
}

// ---------------------------------------------------------------------------------------------
// Dry runs and keys
// ---------------------------------------------------------------------------------------------

#[test]
fn a_dry_run_reports_the_plan_and_writes_nothing() {
    let parent = tempfile::tempdir().unwrap();
    let out = parent.path().join("release");
    let signer = signer(&minisign_key());
    let mut run = Run::new(two_platforms(), &out, &signer);
    run.dry_run = true;
    let report = run.go().unwrap();
    assert!(report.dry_run);
    assert!(report.changed);
    assert_eq!(report.files.len(), 2);
    assert!(!out.exists(), "a dry run must not create the output");
}

#[test]
fn a_dry_run_needs_no_key() {
    let parent = tempfile::tempdir().unwrap();
    let out = parent.path().join("release");
    let mut run = Run::keyless(two_platforms(), &out);
    run.dry_run = true;
    let report = run.go().unwrap();
    assert_eq!(report.public_key, None);
    assert_eq!(report.files[0].action, Action::Created);
}

#[test]
fn a_real_run_without_a_key_is_refused_and_writes_nothing() {
    let parent = tempfile::tempdir().unwrap();
    let out = parent.path().join("release");
    let run = Run::keyless(two_platforms(), &out);
    let err = run.go().unwrap_err();
    assert_eq!(err.code().as_str(), "E_USAGE");
    assert!(!out.exists());
}

#[test]
fn a_file_the_writer_refuses_stops_the_run_before_anything_is_written() {
    let parent = tempfile::tempdir().unwrap();
    let out = parent.path().join("release");
    let key = minisign_key();
    let bad = confirmed(vec![
        entry("1.0.0", Platform::LinuxX64),
        confirmed_entry(
            Some("gamma"),
            "1.0.0",
            Target::Platform(Platform::WindowsX64),
        ),
    ]);
    let err = Run::new(bad, &out, &signer(&key)).go().unwrap_err();
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
    assert!(!out.exists());
}

// ---------------------------------------------------------------------------------------------
// Later publishes
// ---------------------------------------------------------------------------------------------

#[test]
fn running_again_with_the_same_input_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let key = minisign_key();
    let signer = signer(&key);
    Run::new(two_platforms(), dir.path(), &signer).go().unwrap();
    let before: Vec<Vec<u8>> = names(dir.path())
        .iter()
        .map(|n| fs::read(dir.path().join(n)).unwrap())
        .collect();

    let mut again = Run::new(two_platforms(), dir.path(), &signer);
    again.previous = Some(dir.path());
    again.now = at(1);
    let report = again.go().unwrap();

    assert!(!report.changed);
    assert!(report.files.iter().all(|f| f.action == Action::Unchanged));
    assert!(report.files.iter().all(|f| f.sequence == 1));
    let after: Vec<Vec<u8>> = names(dir.path())
        .iter()
        .map(|n| fs::read(dir.path().join(n)).unwrap())
        .collect();
    assert_eq!(before, after);
}

#[test]
fn an_unchanged_publish_into_a_new_directory_carries_the_files_over() {
    let previous = tempfile::tempdir().unwrap();
    let out = tempfile::tempdir().unwrap();
    let key = minisign_key();
    let signer = signer(&key);
    Run::new(two_platforms(), previous.path(), &signer)
        .go()
        .unwrap();

    let mut again = Run::new(two_platforms(), out.path(), &signer);
    again.previous = Some(previous.path());
    again.now = at(1);
    let report = again.go().unwrap();

    assert!(!report.changed);
    assert_eq!(names(out.path()), names(previous.path()));
    for name in names(previous.path()) {
        assert_eq!(
            fs::read(out.path().join(&name)).unwrap(),
            fs::read(previous.path().join(&name)).unwrap(),
            "{name}"
        );
    }
}

#[test]
fn a_change_publishes_the_next_sequence_for_that_platform_only() {
    let dir = tempfile::tempdir().unwrap();
    let key = minisign_key();
    let signer = signer(&key);
    Run::new(two_platforms(), dir.path(), &signer).go().unwrap();

    let newer = confirmed(vec![
        entry("1.0.0", Platform::LinuxX64),
        entry("1.1.0", Platform::LinuxX64),
        entry("1.0.0", Platform::WindowsX64),
    ]);
    let mut run = Run::new(newer, dir.path(), &signer);
    run.previous = Some(dir.path());
    run.now = at(1);
    let report = run.go().unwrap();

    let by_platform: Vec<(&str, u64, Action)> = report
        .files
        .iter()
        .map(|f| (f.platform.as_str(), f.sequence, f.action))
        .collect();
    assert_eq!(
        by_platform,
        [
            ("windows-x64", 1, Action::Unchanged),
            ("linux-x64", 2, Action::Updated)
        ]
    );
    let file = "demo-linux-x64.json";
    let data = fs::read(dir.path().join(file)).unwrap();
    let signature = fs::read(dir.path().join(format!("{file}.minisig"))).unwrap();
    let index = verify::load_previous(
        &[PublicKey::parse(&key.public).unwrap()],
        "demo",
        file,
        &data,
        &signature,
        at(1),
    )
    .unwrap();
    assert_eq!(index.sequence, 2);
    assert_eq!(index.entries.len(), 2);
    // Replacing a file leaves nothing else behind.
    assert_eq!(names(dir.path()).len(), 4);
}

#[test]
fn a_run_dated_before_the_previous_one_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let key = minisign_key();
    let signer = signer(&key);
    let mut first = Run::new(two_platforms(), dir.path(), &signer);
    first.now = at(10);
    first.go().unwrap();

    let mut earlier = Run::new(two_platforms(), dir.path(), &signer);
    earlier.previous = Some(dir.path());
    earlier.now = at(5);
    let err = earlier.go().unwrap_err();
    assert_eq!(err.code().as_str(), "E_INDEX_ROLLBACK");
}

// ---------------------------------------------------------------------------------------------
// Reading the previous publish
// ---------------------------------------------------------------------------------------------

fn published() -> (tempfile::TempDir, MinisignKey) {
    let dir = tempfile::tempdir().unwrap();
    let key = minisign_key();
    Run::new(two_platforms(), dir.path(), &signer(&key))
        .go()
        .unwrap();
    (dir, key)
}

fn rerun(previous: &Path, key: &MinisignKey) -> Result<Report> {
    let out = tempfile::tempdir().unwrap();
    let signer = signer(key);
    let mut run = Run::new(two_platforms(), out.path(), &signer);
    run.previous = Some(previous);
    run.now = at(1);
    run.go()
}

#[test]
fn a_previous_file_with_tampered_bytes_is_refused() {
    let (dir, key) = published();
    let path = dir.path().join("demo-linux-x64.json");
    let mut data = fs::read(&path).unwrap();
    // A sequence number of 9 instead of 1 would silently raise every future sequence.
    let text = String::from_utf8(data.clone())
        .unwrap()
        .replace("\"sequence\": 1", "\"sequence\": 9");
    data = text.into_bytes();
    fs::write(&path, data).unwrap();
    let err = rerun(dir.path(), &key).unwrap_err();
    assert_eq!(err.code().as_str(), "E_SIGNATURE_INVALID");
}

#[test]
fn a_previous_file_without_a_signature_is_refused() {
    let (dir, key) = published();
    fs::remove_file(dir.path().join("demo-linux-x64.json.minisig")).unwrap();
    let err = rerun(dir.path(), &key).unwrap_err();
    assert_eq!(err.code().as_str(), "E_SIGNATURE_INVALID");
    assert!(err.to_string().contains(".minisig"), "{err}");
}

#[test]
fn a_previous_file_signed_by_another_key_is_refused_unless_that_key_is_given() {
    let (dir, _old) = published();
    let new_key = minisign_key();
    let err = rerun(dir.path(), &new_key).unwrap_err();
    assert_eq!(err.code().as_str(), "E_KEY_UNTRUSTED");

    let out = tempfile::tempdir().unwrap();
    let signer = signer(&new_key);
    let mut run = Run::new(two_platforms(), out.path(), &signer);
    run.previous = Some(dir.path());
    run.previous_keys = vec![PublicKey::parse(&_old.public).unwrap()];
    run.now = at(1);
    let report = run.go().unwrap();
    // The content is the same, so the old files are carried over, signature and all.
    assert!(!report.changed);
}

#[test]
fn a_previous_directory_without_this_plugins_files_is_refused() {
    let empty = tempfile::tempdir().unwrap();
    fs::write(empty.path().join("other-linux-x64.json"), b"{}").unwrap();
    let err = rerun(empty.path(), &minisign_key()).unwrap_err();
    assert_eq!(err.code().as_str(), "E_USAGE");
    assert!(err.to_string().contains("demo"), "{err}");
}

#[test]
fn a_missing_previous_directory_is_refused() {
    let parent = tempfile::tempdir().unwrap();
    let err = rerun(&parent.path().join("nowhere"), &minisign_key()).unwrap_err();
    assert_eq!(err.code().as_str(), "E_USAGE");
}

#[test]
fn a_previous_directory_cannot_be_read_without_any_key() {
    let (dir, _key) = published();
    let out = tempfile::tempdir().unwrap();
    let mut run = Run::keyless(two_platforms(), out.path());
    run.dry_run = true;
    run.previous = Some(dir.path());
    let err = run.go().unwrap_err();
    assert_eq!(err.code().as_str(), "E_USAGE");
    assert!(err.to_string().contains("--previous-key"), "{err}");
}

#[test]
fn a_dry_run_can_read_the_previous_publish_with_its_public_key() {
    let (dir, key) = published();
    let parent = tempfile::tempdir().unwrap();
    let out = parent.path().join("release");
    let mut run = Run::keyless(two_platforms(), &out);
    run.dry_run = true;
    run.previous = Some(dir.path());
    run.previous_keys = vec![PublicKey::parse(&key.public).unwrap()];
    run.now = at(1);
    let report = run.go().unwrap();
    assert!(!report.changed);
    assert!(!out.exists());
}

// ---------------------------------------------------------------------------------------------
// From downloads to a verified index
// ---------------------------------------------------------------------------------------------

#[test]
fn artifacts_confirmed_by_the_real_step_become_an_index_the_client_accepts() {
    use std::collections::BTreeMap;

    use crate::candidate::{Candidate, ClaimedHash, HashAlgorithm};
    use crate::confirm::{Confirmer, Options};
    use crate::context::Context;
    use crate::sources::SourcesFile;
    use crate::testing::{Mock, client};

    // The FIPS 180 vector for "abc": the expected digest is the standard's, not recomputed.
    const SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let mock = Mock::start();
    mock.serve("/vendor/tool-1.0.0.zip", b"abc".to_vec());
    let ctx = Context::new(client()).with_mirrors(BTreeMap::from([(
        "https://vendor.test/".to_owned(),
        mock.url("/vendor/"),
    )]));
    let sources = SourcesFile::parse(
        "sources.toml",
        "schema = 1\n\
         [[source]]\nid = \"src-a\"\nadapter = \"gradle\"\nrole = \"primary\"\n\
         [[source]]\nid = \"src-b\"\nadapter = \"gradle\"\nrole = \"confirm\"\n",
    )
    .unwrap();
    let candidate = |source: &str| Candidate {
        source: source.to_owned(),
        variant: None,
        version: "1.0.0".to_owned(),
        target: Target::Any,
        tags: vec!["ga".to_owned()],
        url: "https://vendor.test/tool-1.0.0.zip".to_owned(),
        archive: jtm_security::ArchiveKind::Zip,
        size: None,
        hash: ClaimedHash::new(HashAlgorithm::Sha256, SHA256, "checksum"),
        signature_url: None,
        distribution_version: None,
    };
    let confirmed = Confirmer::new(&ctx, &sources, BTreeMap::new(), Options::default())
        .confirm(vec![candidate("src-a"), candidate("src-b")])
        .unwrap();

    let out = tempfile::tempdir().unwrap();
    let key = minisign_key();
    let signer = signer(&key);
    let mut run = Run::new(confirmed, out.path(), &signer);
    run.binding = Binding {
        plugin: "tool".to_owned(),
        platform_independent: true,
        variants: Vec::new(),
    };
    run.go().unwrap();

    let data = fs::read(out.path().join("tool-any.json")).unwrap();
    let signature = fs::read(out.path().join("tool-any.json.minisig")).unwrap();
    let index = verify::load_previous(
        &[PublicKey::parse(&key.public).unwrap()],
        "tool",
        "tool-any.json",
        &data,
        &signature,
        NOW,
    )
    .unwrap();
    let [entry] = index.entries.as_slice() else {
        panic!("{:?}", index.entries);
    };
    assert_eq!(index.platform, "any");
    assert_eq!(entry.variant, "default");
    assert_eq!(entry.version, "1.0.0");
    assert_eq!(entry.size, 3);
    assert_eq!(entry.sha256, SHA256);
    assert_eq!(entry.url, "https://vendor.test/tool-1.0.0.zip");
    assert_eq!(entry.provenance, ["src-a", "src-b"]);
}
