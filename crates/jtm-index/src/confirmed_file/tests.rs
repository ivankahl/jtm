use std::collections::BTreeSet;

use jtm_core::Platform;

use super::*;
use crate::candidate::Target;
use crate::confirm::{Confirmation, Confirmed, ConfirmedEntry, SignatureRecord, SignatureStatus};
use crate::testing::confirmed_entry;

fn linux(version: &str) -> ConfirmedEntry {
    confirmed_entry(Some("alpha"), version, Target::Platform(Platform::LinuxX64))
}

fn confirmed(entries: Vec<ConfirmedEntry>) -> Confirmed {
    Confirmed {
        entries,
        warnings: vec!["a note that is not kept".to_owned()],
    }
}

const ONE: &str = r#"{
  "format": 1,
  "plugin": "demo",
  "entries": [
    {
      "variant": "alpha",
      "version": "1.0.0",
      "platform": "linux-x64",
      "tags": [
        "ga"
      ],
      "url": "https://vendor.test/1.0.0.zip",
      "archive": "zip",
      "size": 1234,
      "sha256": "abababababababababababababababababababababababababababababababab",
      "provenance": [
        "src-a",
        "src-b"
      ]
    }
  ]
}
"#;

#[test]
fn the_text_is_pretty_json_with_a_final_newline_and_no_timestamps() {
    let text = render("demo", &confirmed(vec![linux("1.0.0")])).unwrap();
    assert_eq!(text, ONE);
}

#[test]
fn the_order_of_the_input_does_not_change_the_text() {
    let a = confirmed(vec![
        linux("2.0.0"),
        confirmed_entry(
            Some("alpha"),
            "1.0.0",
            Target::Platform(Platform::WindowsX64),
        ),
        linux("1.0.0"),
        confirmed_entry(
            Some("aardvark"),
            "9.0.0",
            Target::Platform(Platform::LinuxX64),
        ),
    ]);
    let mut reversed = a.clone();
    reversed.entries.reverse();
    let text = render("demo", &a).unwrap();
    assert_eq!(text, render("demo", &reversed).unwrap());
    let order: Vec<(String, String, String)> = parse("demo", text.as_bytes())
        .unwrap()
        .entries
        .iter()
        .map(|e| {
            (
                e.variant.clone().unwrap(),
                e.version.clone(),
                e.target.to_string(),
            )
        })
        .collect();
    assert_eq!(
        order,
        [
            ("aardvark", "9.0.0", "linux-x64"),
            ("alpha", "1.0.0", "linux-x64"),
            ("alpha", "1.0.0", "windows-x64"),
            ("alpha", "2.0.0", "linux-x64"),
        ]
        .map(|(a, b, c)| (a.to_owned(), b.to_owned(), c.to_owned()))
    );
}

#[test]
fn a_file_reads_back_as_the_entries_that_were_written() {
    let mut any = confirmed_entry(None, "3.9.0", Target::Any);
    any.tags = vec!["rc".to_owned(), "ga".to_owned()];
    any.provenance.signatures.push(SignatureRecord {
        source: "src-a".to_owned(),
        url: "https://vendor.test/x.asc".to_owned(),
        status: SignatureStatus::Verified {
            fingerprint: "ABCD".to_owned(),
        },
    });
    let mut computed = linux("1.0.0");
    computed.provenance.confirmation = Confirmation::SourceAndComputed;
    computed.provenance.sources = vec!["foojay".to_owned()];
    let original = confirmed(vec![any, computed]);

    let text = render("demo", &original).unwrap();
    let back = parse("demo", text.as_bytes()).unwrap();

    assert!(back.warnings.is_empty());
    assert_eq!(back.entries.len(), 2);
    let find = |c: &Confirmed, version: &str| {
        c.entries
            .iter()
            .find(|e| e.version == version)
            .unwrap()
            .clone()
    };
    for version in ["3.9.0", "1.0.0"] {
        let (was, now) = (find(&original, version), find(&back, version));
        assert_eq!(was.variant, now.variant);
        assert_eq!(was.target, now.target);
        assert_eq!(was.url, now.url);
        assert_eq!(was.archive, now.archive);
        assert_eq!(was.size, now.size);
        assert_eq!(was.sha256, now.sha256);
        assert_eq!(
            was.tags.iter().collect::<BTreeSet<_>>(),
            now.tags.iter().collect::<BTreeSet<_>>()
        );
        assert_eq!(was.provenance.labels(), now.provenance.labels());
    }
    // Writing what was read gives the same text: nothing is lost or added on the way.
    assert_eq!(render("demo", &back).unwrap(), text);
    assert!(text.contains("\"signature:pgp\""));
    assert!(text.contains("\"computed:sha256\""));
}

fn refused(text: &str) -> String {
    let err = parse("demo", text.as_bytes()).unwrap_err();
    assert_eq!(err.code(), jtm_core::ErrorCode::IndexInvalid, "{err}");
    err.to_string()
}

#[test]
fn a_file_for_another_plugin_is_refused() {
    let text = ONE.replace("\"plugin\": \"demo\"", "\"plugin\": \"other\"");
    assert!(refused(&text).contains("other"));
}

#[test]
fn an_unknown_format_is_refused() {
    let text = ONE.replace("\"format\": 1", "\"format\": 2");
    assert!(refused(&text).contains("format"));
}

#[test]
fn an_unknown_field_is_refused() {
    let text = ONE.replace("\"size\": 1234,", "\"size\": 1234, \"extra\": true,");
    assert!(refused(&text).contains("extra"));
}

#[test]
fn a_malformed_digest_is_refused() {
    let digest = "ab".repeat(32);
    let text = ONE.replace(&digest, "AB");
    assert!(refused(&text).contains("sha256"));
}

#[test]
fn an_unknown_platform_or_archive_is_refused() {
    assert!(refused(&ONE.replace("linux-x64", "plan9-x64")).contains("platform"));
    assert!(refused(&ONE.replace("\"zip\"", "\"rar\"")).contains("archive"));
}

#[test]
fn a_provenance_label_nobody_produces_is_refused() {
    assert!(refused(&ONE.replace("\"src-b\"", "\"verified:by-me\"")).contains("verified:by-me"));
}

#[test]
fn the_same_artifact_twice_is_refused() {
    let two = confirmed(vec![linux("1.0.0"), linux("1.0.0")]);
    // The renderer keeps what it is given; the reader refuses the repeat.
    let text = render("demo", &two).unwrap();
    assert!(refused(&text).contains("twice"));
}

#[test]
fn text_that_is_not_json_is_refused_without_echoing_it() {
    let message = refused("this is secret-looking text");
    assert!(!message.contains("secret-looking"));
}

#[test]
fn a_file_with_no_entries_is_refused() {
    let text = r#"{"format": 1, "plugin": "demo", "entries": []}"#;
    assert!(refused(text).contains("no entries"));
}

#[test]
fn nothing_is_written_for_no_entries() {
    let err = render("demo", &confirmed(Vec::new())).unwrap_err();
    assert!(err.to_string().contains("no confirmed entries"), "{err}");
}

#[test]
fn an_entry_without_provenance_is_refused() {
    let start = ONE.find(r#""provenance": ["#).unwrap();
    let end = start + ONE[start..].find(']').unwrap() + 1;
    let text = format!("{}\"provenance\": []{}", &ONE[..start], &ONE[end..]);
    assert!(refused(&text).contains("provenance"));
}

#[test]
fn a_file_over_the_size_limit_is_refused() {
    let big = vec![b' '; MAX_CONFIRMED_FILE + 1];
    let err = parse("demo", &big).unwrap_err();
    assert!(err.to_string().contains("larger"), "{err}");
}
