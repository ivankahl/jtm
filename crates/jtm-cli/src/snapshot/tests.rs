#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::path::Path;

use super::*;

/// The listing format and code generator, exactly as `build.rs` includes them.
#[path = "../../build/snapshot.rs"]
mod listing;

use listing::{IndexFile, KeysFile, Listing, code, signature_file};

fn sample() -> Listing {
    Listing {
        indices: vec![
            IndexFile {
                plugin: "java".to_owned(),
                platform: "linux-x64".to_owned(),
                file: "java-linux-x64.json".to_owned(),
            },
            IndexFile {
                plugin: "maven".to_owned(),
                platform: "any".to_owned(),
                file: "maven-any.json".to_owned(),
            },
        ],
        keys: vec![KeysFile {
            url: "https://example.test/latest/download/keys.json".to_owned(),
            file: "keys.json".to_owned(),
        }],
    }
}

/// A snapshot directory holding `listing`, with every file and signature written.
fn snapshot_dir(listing: &Listing) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    for file in listing.files() {
        fs::write(dir.path().join(file), file).unwrap();
        fs::write(dir.path().join(signature_file(file)), "sig").unwrap();
    }
    fs::write(dir.path().join(listing::LISTING), listing.to_toml()).unwrap();
    dir
}

#[test]
fn the_compiled_snapshot_is_what_the_snapshot_directory_lists() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("snapshot");
    let Some(listing) = Listing::read(&dir).unwrap() else {
        assert_eq!(SNAPSHOT, Snapshot::default(), "no listing embeds nothing");
        return;
    };
    let read = |name: &str| fs::read(dir.join(name)).unwrap();
    assert_eq!(SNAPSHOT.indices.len(), listing.indices.len());
    for (embedded, listed) in SNAPSHOT.indices.iter().zip(&listing.indices) {
        assert_eq!(embedded.plugin, listed.plugin);
        assert_eq!(embedded.platform, listed.platform);
        assert_eq!(embedded.data, read(&listed.file));
        assert_eq!(embedded.signature, read(&signature_file(&listed.file)));
    }
    assert_eq!(SNAPSHOT.keys.len(), listing.keys.len());
    for (embedded, listed) in SNAPSHOT.keys.iter().zip(&listing.keys) {
        assert_eq!(embedded.url, listed.url);
        assert_eq!(embedded.data, read(&listed.file));
        assert_eq!(embedded.signature, read(&signature_file(&listed.file)));
    }
}

#[test]
fn a_listing_round_trips_through_toml() {
    let text = sample().to_toml();
    assert!(
        text.starts_with("# Written by `cargo xtask embed-snapshot`"),
        "{text}"
    );
    assert_eq!(Listing::parse(&text).unwrap(), sample());
    assert_eq!(
        Listing::parse(&Listing::default().to_toml()).unwrap(),
        Listing::default()
    );
}

#[test]
fn a_listing_is_parsed_strictly() {
    let index = |file: &str| {
        format!("format = 1\n[[index]]\nplugin = \"p\"\nplatform = \"any\"\nfile = \"{file}\"\n")
    };
    let cases = [
        ("format = 2\n".to_owned(), "`format` must be 1"),
        ("index = []\n".to_owned(), "`format` must be 1"),
        (
            "format = 1\nextra = true\n".to_owned(),
            "unknown key `extra`",
        ),
        (
            format!("{}sha256 = \"x\"\n", index("p-any.json")),
            "unknown key `sha256`",
        ),
        (
            "format = 1\n[[keys]]\nurl = \"u\"\n".to_owned(),
            "`keys.file` must be a string",
        ),
        ("format = 1\nindex = 3\n".to_owned(), "must be an array"),
        (index("../p-any.json"), "not a plain file name"),
        (index("dir/p-any.json"), "not a plain file name"),
        (index("dir\\\\p-any.json"), "not a plain file name"),
        (index(".hidden"), "not a plain file name"),
        (index(""), "not a plain file name"),
        (index("snapshot.toml"), "not a plain file name"),
        (
            format!(
                "{}[[keys]]\nurl = \"u\"\nfile = \"p-any.json\"\n",
                index("p-any.json")
            ),
            "listed twice",
        ),
    ];
    for (text, expected) in cases {
        let err = Listing::parse(&text).unwrap_err();
        assert!(err.contains(expected), "{text}: {err}");
    }
}

#[test]
fn reading_needs_every_listed_file_and_signature() {
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(Listing::read(empty.path()).unwrap(), None);
    assert_eq!(
        Listing::read(&empty.path().join("absent")).unwrap(),
        None,
        "no directory is no snapshot"
    );

    let dir = snapshot_dir(&sample());
    assert_eq!(Listing::read(dir.path()).unwrap(), Some(sample()));
    for missing in ["maven-any.json", "keys.json.minisig"] {
        let dir = snapshot_dir(&sample());
        fs::remove_file(dir.path().join(missing)).unwrap();
        let err = Listing::read(dir.path()).unwrap_err();
        assert!(err.contains(missing), "{missing}: {err}");
    }
}

#[test]
fn the_generated_code_embeds_each_listed_file_and_its_signature() {
    assert_eq!(
        code(Path::new("/nowhere"), None),
        "jtm_core::indices::Snapshot {\n    indices: &[\n    ],\n    keys: &[\n    ],\n}"
    );

    let dir = snapshot_dir(&sample());
    let generated = code(dir.path(), Some(&sample()));
    let include = |name: &str| {
        format!(
            "include_bytes!({:?})",
            dir.path().join(name).display().to_string()
        )
    };
    let expected = format!(
        "jtm_core::indices::Snapshot {{\n    indices: &[\n        \
         jtm_core::indices::EmbeddedIndex {{ plugin: \"java\", platform: \"linux-x64\", \
         data: {}, signature: {} }},\n        \
         jtm_core::indices::EmbeddedIndex {{ plugin: \"maven\", platform: \"any\", \
         data: {}, signature: {} }},\n    ],\n    keys: &[\n        \
         jtm_core::indices::EmbeddedKeysFile {{ url: \
         \"https://example.test/latest/download/keys.json\", data: {}, signature: {} }},\n    \
         ],\n}}",
        include("java-linux-x64.json"),
        include("java-linux-x64.json.minisig"),
        include("maven-any.json"),
        include("maven-any.json.minisig"),
        include("keys.json"),
        include("keys.json.minisig"),
    );
    assert_eq!(generated, expected);
}
