use jtm_core::Platform;
use jtm_security::{ArchiveKind, IndexFile};
use serde_json::{Value, json};

use super::*;
use crate::confirm::{ClaimRecord, Confirmation, Provenance};

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
        variants: vec!["alpha".to_owned(), "beta".to_owned()],
    }
}

fn independent_binding() -> Binding {
    Binding {
        plugin: "demo".to_owned(),
        platform_independent: true,
        variants: Vec::new(),
    }
}

fn settings(now: Timestamp) -> Settings {
    Settings {
        now,
        validity: Validity::days(30).unwrap(),
    }
}

fn provenance(sources: &[&str]) -> Provenance {
    Provenance {
        confirmation: Confirmation::Independent,
        sources: sources.iter().map(|s| (*s).to_owned()).collect(),
        claims: vec![ClaimRecord {
            source: sources[0].to_owned(),
            algorithm: crate::HashAlgorithm::Sha256,
            origin: "https://x.test/sum".to_owned(),
        }],
        signatures: Vec::new(),
        fetched_at: "2026-10-19T02:00:00Z".to_owned(),
    }
}

fn entry(variant: Option<&str>, version: &str, target: Target) -> ConfirmedEntry {
    ConfirmedEntry {
        variant: variant.map(str::to_owned),
        version: version.to_owned(),
        target,
        tags: vec!["ga".to_owned()],
        url: format!("https://vendor.test/{version}.zip"),
        archive: ArchiveKind::Zip,
        size: 1234,
        sha256: "ab".repeat(32),
        distribution_version: None,
        provenance: provenance(&["src-a", "src-b"]),
    }
}

fn linux(variant: &str, version: &str) -> ConfirmedEntry {
    entry(Some(variant), version, Target::Platform(Platform::LinuxX64))
}

fn confirmed(entries: Vec<ConfirmedEntry>) -> Confirmed {
    Confirmed {
        entries,
        warnings: Vec::new(),
    }
}

fn write_new(entries: Vec<ConfirmedEntry>) -> Written {
    write(
        &binding(),
        &confirmed(entries),
        &BTreeMap::new(),
        &settings(NOW),
    )
    .unwrap()
}

fn json_of(output: &Output) -> Value {
    serde_json::from_slice(&output.bytes).unwrap()
}

/// What the previous publish left behind for a platform, as the command reads it back.
fn previous_of(output: &Output) -> Previous {
    let index = load_unsigned(&output.bytes);
    Previous {
        index,
        bytes: output.bytes.clone(),
        signature: b"previous signature".to_vec(),
    }
}

/// Parses with the client's rules, signing with a throwaway key.
fn load_unsigned(bytes: &[u8]) -> IndexFile {
    let signer = Signer::ephemeral().unwrap();
    crate::verify::sign_and_load(&signer, "demo", "demo-x.json", bytes, NOW)
        .unwrap()
        .index
}

fn previous_map(output: &Output) -> BTreeMap<String, Previous> {
    BTreeMap::from([(output.platform.clone(), previous_of(output))])
}

// ---------------------------------------------------------------------------------------------
// The file
// ---------------------------------------------------------------------------------------------

#[test]
fn an_entry_becomes_the_file_the_spec_describes() {
    let written = write_new(vec![linux("alpha", "21.0.5+11")]);
    let [file] = written.files.as_slice() else {
        panic!("expected one file: {:?}", written.files);
    };
    assert_eq!(file.file, "demo-linux-x64.json");
    assert_eq!(file.platform, "linux-x64");
    assert_eq!(
        json_of(file),
        json!({
            "format": 1,
            "plugin": "demo",
            "platform": "linux-x64",
            "sequence": 1,
            "generated": "2026-10-19T03:00:00Z",
            "expires": "2026-11-18T03:00:00Z",
            "entries": [{
                "variant": "alpha",
                "version": "21.0.5+11",
                "tags": ["ga"],
                "url": "https://vendor.test/21.0.5+11.zip",
                "archive": "zip",
                "size": 1234,
                "sha256": "ab".repeat(32),
                "provenance": ["src-a", "src-b"]
            }]
        })
    );
}

#[test]
fn the_text_is_stable_down_to_field_order_and_the_final_newline() {
    let written = write_new(vec![linux("alpha", "1.0.0")]);
    let text = String::from_utf8(written.files[0].bytes.clone()).unwrap();
    let expected = format!(
        r#"{{
  "format": 1,
  "plugin": "demo",
  "platform": "linux-x64",
  "sequence": 1,
  "generated": "2026-10-19T03:00:00Z",
  "expires": "2026-11-18T03:00:00Z",
  "entries": [
    {{
      "variant": "alpha",
      "version": "1.0.0",
      "tags": [
        "ga"
      ],
      "url": "https://vendor.test/1.0.0.zip",
      "archive": "zip",
      "size": 1234,
      "sha256": "{}",
      "provenance": [
        "src-a",
        "src-b"
      ]
    }}
  ]
}}
"#,
        "ab".repeat(32)
    );
    assert_eq!(text, expected);
}

#[test]
fn the_same_input_gives_byte_identical_files_whatever_order_it_arrives_in() {
    let entries = vec![
        linux("beta", "2.0.0"),
        linux("alpha", "10.0.0"),
        linux("alpha", "9.0.0"),
        entry(
            Some("alpha"),
            "1.0.0",
            Target::Platform(Platform::WindowsX64),
        ),
    ];
    let first = write_new(entries.clone());
    let mut shuffled = entries;
    shuffled.reverse();
    let second = write_new(shuffled);
    let bytes = |w: &Written| -> Vec<(String, Vec<u8>)> {
        w.files
            .iter()
            .map(|f| (f.file.clone(), f.bytes.clone()))
            .collect()
    };
    assert_eq!(bytes(&first), bytes(&second));
    assert_eq!(first.files.len(), 2);
}

#[test]
fn entries_are_ordered_by_variant_then_version() {
    let written = write_new(vec![
        linux("beta", "1.0.0"),
        linux("alpha", "2.0.0"),
        linux("alpha", "1.0.0"),
    ]);
    let entries = json_of(&written.files[0])["entries"].clone();
    let listed: Vec<(&str, &str)> = entries
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["variant"].as_str().unwrap(),
                e["version"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        listed,
        [("alpha", "1.0.0"), ("alpha", "2.0.0"), ("beta", "1.0.0")]
    );
}

#[test]
fn tags_and_provenance_are_sorted_and_free_of_repeats() {
    let mut e = linux("alpha", "1.0.0");
    e.tags = vec!["lts".to_owned(), "ga".to_owned(), "lts".to_owned()];
    e.provenance = provenance(&["src-b", "src-a"]);
    e.provenance.signatures = Vec::new();
    let written = write_new(vec![e]);
    let entry = &json_of(&written.files[0])["entries"][0];
    assert_eq!(entry["tags"], json!(["ga", "lts"]));
    assert_eq!(entry["provenance"], json!(["src-a", "src-b"]));
}

#[test]
fn provenance_carries_the_labels_of_the_confirmation() {
    let mut e = linux("alpha", "1.0.0");
    e.provenance.confirmation = Confirmation::SourceAndComputed;
    e.provenance.sources = vec!["foojay".to_owned()];
    let written = write_new(vec![e]);
    let entry = &json_of(&written.files[0])["entries"][0];
    assert_eq!(entry["provenance"], json!(["computed:sha256", "foojay"]));
}

#[test]
fn one_file_is_written_for_each_platform() {
    let written = write_new(vec![
        entry(
            Some("alpha"),
            "1.0.0",
            Target::Platform(Platform::MacosAarch64),
        ),
        entry(
            Some("alpha"),
            "1.0.0",
            Target::Platform(Platform::LinuxMuslX64),
        ),
        entry(
            Some("alpha"),
            "1.0.0",
            Target::Platform(Platform::WindowsX64),
        ),
    ]);
    let names: Vec<&str> = written.files.iter().map(|f| f.file.as_str()).collect();
    assert_eq!(
        names,
        [
            "demo-windows-x64.json",
            "demo-macos-aarch64.json",
            "demo-linux-musl-x64.json"
        ]
    );
    for file in &written.files {
        assert_eq!(json_of(file)["platform"], file.platform.as_str());
    }
}

#[test]
fn a_platform_independent_plugin_writes_the_any_index() {
    let written = write(
        &independent_binding(),
        &confirmed(vec![entry(None, "3.9.9", Target::Any)]),
        &BTreeMap::new(),
        &settings(NOW),
    )
    .unwrap();
    let [file] = written.files.as_slice() else {
        panic!("expected one file");
    };
    assert_eq!(file.file, "demo-any.json");
    let json = json_of(file);
    assert_eq!(json["platform"], "any");
    assert_eq!(json["entries"][0]["variant"], "default");
}

#[test]
fn the_file_name_follows_the_directory_name_of_a_namespaced_plugin() {
    let mut binding = independent_binding();
    binding.plugin = "acme/tool".to_owned();
    let written = write(
        &binding,
        &confirmed(vec![entry(None, "1.0.0", Target::Any)]),
        &BTreeMap::new(),
        &settings(NOW),
    )
    .unwrap();
    // The client looks for `<dir_name>-<platform>.json`.
    assert_eq!(written.files[0].file, "acme--tool-any.json");
    assert_eq!(json_of(&written.files[0])["plugin"], "acme/tool");
}

// ---------------------------------------------------------------------------------------------
// Refusing input that could not be published faithfully
// ---------------------------------------------------------------------------------------------

fn refused(binding: &Binding, entries: Vec<ConfirmedEntry>) -> Error {
    write(
        binding,
        &confirmed(entries),
        &BTreeMap::new(),
        &settings(NOW),
    )
    .unwrap_err()
}

#[test]
fn nothing_to_write_is_refused_rather_than_published_as_an_empty_index() {
    let err = refused(&binding(), Vec::new());
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
}

#[test]
fn a_platform_independent_plugin_refuses_a_platform_entry() {
    let err = refused(
        &independent_binding(),
        vec![entry(None, "1.0.0", Target::Platform(Platform::LinuxX64))],
    );
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
    assert!(err.to_string().contains("platform-independent"), "{err}");
}

#[test]
fn a_per_platform_plugin_refuses_an_any_entry() {
    let err = refused(&binding(), vec![entry(Some("alpha"), "1.0.0", Target::Any)]);
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
    assert!(err.to_string().contains("`any`"), "{err}");
}

#[test]
fn a_variant_the_plugin_does_not_publish_is_refused() {
    let err = refused(&binding(), vec![linux("gamma", "1.0.0")]);
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
    assert!(err.to_string().contains("gamma"), "{err}");
}

#[test]
fn a_plugin_with_variants_refuses_an_entry_without_one() {
    let err = refused(
        &binding(),
        vec![entry(None, "1.0.0", Target::Platform(Platform::LinuxX64))],
    );
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
}

#[test]
fn a_plugin_without_variants_refuses_a_named_one() {
    let err = refused(
        &independent_binding(),
        vec![entry(Some("alpha"), "1.0.0", Target::Any)],
    );
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
}

#[test]
fn the_same_version_twice_in_one_index_is_refused() {
    let err = refused(
        &binding(),
        vec![linux("alpha", "1.0.0"), linux("alpha", "1.0.0")],
    );
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
    assert!(err.to_string().contains("1.0.0"), "{err}");
}

// ---------------------------------------------------------------------------------------------
// Validity
// ---------------------------------------------------------------------------------------------

#[test]
fn expiry_is_the_configured_validity_after_generation() {
    let written = write(
        &binding(),
        &confirmed(vec![linux("alpha", "1.0.0")]),
        &BTreeMap::new(),
        &Settings {
            now: NOW,
            validity: Validity::days(7).unwrap(),
        },
    )
    .unwrap();
    let file = &written.files[0];
    assert_eq!(file.generated, NOW);
    assert_eq!(file.expires, at(7));
    assert_eq!(json_of(file)["expires"], "2026-10-26T03:00:00Z");
}

#[test]
fn the_validity_is_between_a_day_and_the_ninety_days_of_an_index_key() {
    assert!(Validity::days(0).is_err());
    assert!(Validity::days(1).is_ok());
    assert!(Validity::days(90).is_ok());
    let err = Validity::days(91).unwrap_err();
    assert_eq!(err.code().as_str(), "E_USAGE");
    assert_eq!(Validity::default(), Validity::days(30).unwrap());
}

// ---------------------------------------------------------------------------------------------
// Sequence, renewal and rollback
// ---------------------------------------------------------------------------------------------

fn first() -> Written {
    write_new(vec![linux("alpha", "1.0.0")])
}

#[test]
fn the_first_publish_of_a_platform_starts_at_sequence_one() {
    let written = first();
    assert_eq!(written.files[0].sequence, 1);
    assert_eq!(written.files[0].action, Action::Created);
}

#[test]
fn a_change_raises_the_sequence_by_exactly_one() {
    let before = first();
    let after = write(
        &binding(),
        &confirmed(vec![linux("alpha", "1.0.0"), linux("alpha", "1.1.0")]),
        &previous_map(&before.files[0]),
        &settings(at(1)),
    )
    .unwrap();
    let file = &after.files[0];
    assert_eq!(file.action, Action::Updated);
    assert_eq!(file.sequence, 2);
    assert_eq!(json_of(file)["sequence"], 2);
    assert_eq!(file.generated, at(1));
    assert_eq!((file.added, file.removed), (1, 0));
    assert_eq!(file.entries, 2);
}

#[test]
fn a_changed_hash_for_an_existing_version_counts_as_a_change() {
    let before = first();
    let mut changed = linux("alpha", "1.0.0");
    changed.sha256 = "cd".repeat(32);
    let after = write(
        &binding(),
        &confirmed(vec![changed]),
        &previous_map(&before.files[0]),
        &settings(at(1)),
    )
    .unwrap();
    assert_eq!(after.files[0].action, Action::Updated);
    assert_eq!(after.files[0].sequence, 2);
}

#[test]
fn removed_versions_are_counted() {
    let before = write_new(vec![linux("alpha", "1.0.0"), linux("alpha", "1.1.0")]);
    let after = write(
        &binding(),
        &confirmed(vec![linux("alpha", "1.1.0")]),
        &previous_map(&before.files[0]),
        &settings(at(1)),
    )
    .unwrap();
    assert_eq!((after.files[0].added, after.files[0].removed), (0, 1));
}

#[test]
fn an_unchanged_index_keeps_its_sequence_times_bytes_and_signature() {
    let before = first();
    let after = write(
        &binding(),
        &confirmed(vec![linux("alpha", "1.0.0")]),
        &previous_map(&before.files[0]),
        &settings(at(1)),
    )
    .unwrap();
    let file = &after.files[0];
    assert_eq!(file.action, Action::Unchanged);
    assert_eq!(file.sequence, 1);
    assert_eq!(file.bytes, before.files[0].bytes);
    assert_eq!(file.signature.as_deref(), Some(&b"previous signature"[..]));
    assert_eq!(file.generated, NOW);
    assert_eq!(file.expires, at(30));
    assert!(!after.changed());
}

#[test]
fn an_unchanged_index_is_reissued_once_less_than_half_its_validity_remains() {
    let before = first();
    // 16 days in: 14 of 30 days remain, which is less than half.
    let after = write(
        &binding(),
        &confirmed(vec![linux("alpha", "1.0.0")]),
        &previous_map(&before.files[0]),
        &settings(at(16)),
    )
    .unwrap();
    let file = &after.files[0];
    assert_eq!(file.action, Action::Renewed);
    assert_eq!(file.sequence, 2);
    assert_eq!(file.generated, at(16));
    assert_eq!(file.expires, at(46));
    assert!(file.signature.is_none());
    assert!(after.changed());
}

#[test]
fn an_unchanged_index_with_exactly_half_its_validity_left_is_reissued() {
    let before = first();
    let after = write(
        &binding(),
        &confirmed(vec![linux("alpha", "1.0.0")]),
        &previous_map(&before.files[0]),
        &settings(at(15)),
    )
    .unwrap();
    assert_eq!(after.files[0].action, Action::Renewed);
}

#[test]
fn an_unchanged_index_that_has_expired_is_reissued() {
    let before = first();
    let after = write(
        &binding(),
        &confirmed(vec![linux("alpha", "1.0.0")]),
        &previous_map(&before.files[0]),
        &settings(at(60)),
    )
    .unwrap();
    assert_eq!(after.files[0].action, Action::Renewed);
    assert_eq!(after.files[0].sequence, 2);
}

#[test]
fn going_back_in_time_is_refused() {
    let before = write(
        &binding(),
        &confirmed(vec![linux("alpha", "1.0.0")]),
        &BTreeMap::new(),
        &settings(at(10)),
    )
    .unwrap();
    let err = write(
        &binding(),
        &confirmed(vec![linux("alpha", "1.1.0")]),
        &previous_map(&before.files[0]),
        &settings(at(9)),
    )
    .unwrap_err();
    assert_eq!(err.code().as_str(), "E_INDEX_ROLLBACK");
}

#[test]
fn a_sequence_that_cannot_grow_is_refused() {
    let before = first();
    let mut previous = previous_of(&before.files[0]);
    previous.index.sequence = u64::MAX;
    let err = write(
        &binding(),
        &confirmed(vec![linux("alpha", "1.1.0")]),
        &BTreeMap::from([("linux-x64".to_owned(), previous)]),
        &settings(at(1)),
    )
    .unwrap_err();
    assert_eq!(err.code().as_str(), "E_INDEX_ROLLBACK");
}

#[test]
fn a_new_platform_starts_at_one_while_others_continue() {
    let before = first();
    let after = write(
        &binding(),
        &confirmed(vec![
            linux("alpha", "1.0.0"),
            entry(
                Some("alpha"),
                "1.0.0",
                Target::Platform(Platform::WindowsX64),
            ),
        ]),
        &previous_map(&before.files[0]),
        &settings(at(1)),
    )
    .unwrap();
    let by_platform: Vec<(&str, u64, Action)> = after
        .files
        .iter()
        .map(|f| (f.platform.as_str(), f.sequence, f.action))
        .collect();
    assert_eq!(
        by_platform,
        [
            ("windows-x64", 1, Action::Created),
            ("linux-x64", 1, Action::Unchanged)
        ]
    );
}

#[test]
fn a_platform_that_had_an_index_and_now_has_no_entries_is_refused() {
    let before = first();
    let err = write(
        &binding(),
        &confirmed(vec![entry(
            Some("alpha"),
            "1.0.0",
            Target::Platform(Platform::WindowsX64),
        )]),
        &previous_map(&before.files[0]),
        &settings(at(1)),
    )
    .unwrap_err();
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
    assert!(err.to_string().contains("linux-x64"), "{err}");
}

#[test]
fn a_previous_index_for_another_plugin_is_refused() {
    let before = first();
    let mut previous = previous_of(&before.files[0]);
    previous.index.plugin = "other".to_owned();
    let err = write(
        &binding(),
        &confirmed(vec![linux("alpha", "1.0.0")]),
        &BTreeMap::from([("linux-x64".to_owned(), previous)]),
        &settings(at(1)),
    )
    .unwrap_err();
    assert_eq!(err.code().as_str(), "E_INDEX_BINDING");
}

#[test]
fn a_previous_index_filed_under_another_platform_is_refused() {
    let before = first();
    let previous = previous_of(&before.files[0]);
    let err = write(
        &binding(),
        &confirmed(vec![entry(
            Some("alpha"),
            "1.0.0",
            Target::Platform(Platform::WindowsX64),
        )]),
        &BTreeMap::from([("windows-x64".to_owned(), previous)]),
        &settings(at(1)),
    )
    .unwrap_err();
    assert_eq!(err.code().as_str(), "E_INDEX_BINDING");
}

#[test]
fn a_new_hash_for_a_published_version_is_called_out() {
    // A client's lockfile treats this as an attack until proven otherwise (section 9).
    let before = first();
    let mut rebuilt = linux("alpha", "1.0.0");
    rebuilt.sha256 = "cd".repeat(32);
    let after = write(
        &binding(),
        &confirmed(vec![rebuilt]),
        &previous_map(&before.files[0]),
        &settings(at(1)),
    )
    .unwrap();
    assert_eq!(after.files[0].changed, 1);
    let [warning] = after.warnings.as_slice() else {
        panic!("expected one warning: {:?}", after.warnings);
    };
    assert_eq!(warning.code, "W_HASH_CHANGED");
    assert!(warning.message.contains("alpha 1.0.0"), "{warning:?}");
    assert!(
        warning.message.contains("E_LOCK_INDEX_MISMATCH"),
        "{warning:?}"
    );
}

#[test]
fn a_republished_index_does_not_warn() {
    let before = first();
    let after = write(
        &binding(),
        &confirmed(vec![linux("alpha", "1.0.0")]),
        &previous_map(&before.files[0]),
        &settings(at(20)),
    )
    .unwrap();
    assert!(after.warnings.is_empty(), "{:?}", after.warnings);
}

#[test]
fn every_written_file_is_accepted_by_the_client_loader() {
    let signer = Signer::ephemeral().unwrap();
    let written = write_new(vec![
        linux("alpha", "1.0.0"),
        linux("beta", "2.0.0"),
        entry(
            Some("alpha"),
            "1.0.0",
            Target::Platform(Platform::MacosAarch64),
        ),
    ]);
    for file in &written.files {
        let signed = verify::sign_and_load(&signer, "demo", &file.file, &file.bytes, NOW).unwrap();
        assert_eq!(signed.index.platform, file.platform);
        assert_eq!(signed.index.sequence, file.sequence);
        assert_eq!(signed.index.entries.len(), file.entries);
    }
}
