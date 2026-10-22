//! The listing of an embedded index snapshot, `snapshot/snapshot.toml` (SPEC.md section 8).
//!
//! `cargo xtask embed-snapshot` copies signed indices, `keys.json` and their signatures into
//! `snapshot/` and writes this listing beside them; `build.rs` reads it to embed the files with
//! `include_bytes!`. Both include this file, so they cannot disagree on the format.
//!
//! The listing only says which file is which. Every embedded copy is verified at runtime like
//! any other, so a wrong entry makes a copy unusable, never trusted.

// Each includer uses its own half: `build.rs` reads and generates code, `xtask` writes.
#![allow(dead_code)]

use std::fmt::Write as _;
use std::io;
use std::path::Path;

/// The listing's file name inside the snapshot directory.
pub(crate) const LISTING: &str = "snapshot.toml";

const FORMAT: i64 = 1;

/// What a snapshot directory holds. A file's signature sits beside it as `<file>.minisig`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Listing {
    pub(crate) indices: Vec<IndexFile>,
    pub(crate) keys: Vec<KeysFile>,
}

/// A signed index for one plugin and platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndexFile {
    pub(crate) plugin: String,
    pub(crate) platform: String,
    pub(crate) file: String,
}

/// A signed keys file, identified by the `keys_url` manifests name it with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeysFile {
    pub(crate) url: String,
    pub(crate) file: String,
}

/// The name of `file`'s detached signature.
pub(crate) fn signature_file(file: &str) -> String {
    format!("{file}.minisig")
}

/// Refuses anything but a plain file name, so a listing can never point outside its directory.
pub(crate) fn check_file_name(name: &str) -> Result<(), String> {
    let plain = !name.is_empty()
        && !name.starts_with('.')
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'));
    if plain && name != LISTING {
        Ok(())
    } else {
        Err(format!("{name:?} is not a plain file name"))
    }
}

impl Listing {
    /// Every listed file, indices first, without signatures.
    pub(crate) fn files(&self) -> impl Iterator<Item = &str> {
        self.indices
            .iter()
            .map(|i| i.file.as_str())
            .chain(self.keys.iter().map(|k| k.file.as_str()))
    }

    /// The listing as TOML, with a header saying where it came from.
    pub(crate) fn to_toml(&self) -> String {
        let mut table = toml::Table::new();
        table.insert("format".to_owned(), FORMAT.into());
        let indices = self
            .indices
            .iter()
            .map(|i| {
                let mut t = toml::Table::new();
                t.insert("plugin".to_owned(), i.plugin.clone().into());
                t.insert("platform".to_owned(), i.platform.clone().into());
                t.insert("file".to_owned(), i.file.clone().into());
                toml::Value::Table(t)
            })
            .collect::<Vec<_>>();
        let keys = self
            .keys
            .iter()
            .map(|k| {
                let mut t = toml::Table::new();
                t.insert("url".to_owned(), k.url.clone().into());
                t.insert("file".to_owned(), k.file.clone().into());
                toml::Value::Table(t)
            })
            .collect::<Vec<_>>();
        table.insert("index".to_owned(), indices.into());
        table.insert("keys".to_owned(), keys.into());
        format!(
            "# Written by `cargo xtask embed-snapshot`; build.rs embeds the files listed here.\n\
             # Each is verified at runtime like any other copy.\n\n{table}"
        )
    }

    /// Parses a listing, refusing unknown keys, another format and names that are not plain.
    pub(crate) fn parse(text: &str) -> Result<Listing, String> {
        let mut table: toml::Table = text.parse().map_err(|e| format!("{e}"))?;
        match table.remove("format") {
            Some(toml::Value::Integer(FORMAT)) => {}
            other => return Err(format!("`format` must be {FORMAT}, got {other:?}")),
        }
        let indices = take_tables(&mut table, "index")?
            .into_iter()
            .map(|mut t| {
                let entry = IndexFile {
                    plugin: take_str(&mut t, "index", "plugin")?,
                    platform: take_str(&mut t, "index", "platform")?,
                    file: take_str(&mut t, "index", "file")?,
                };
                no_more(&t, "index")?;
                Ok(entry)
            })
            .collect::<Result<Vec<_>, String>>()?;
        let keys = take_tables(&mut table, "keys")?
            .into_iter()
            .map(|mut t| {
                let entry = KeysFile {
                    url: take_str(&mut t, "keys", "url")?,
                    file: take_str(&mut t, "keys", "file")?,
                };
                no_more(&t, "keys")?;
                Ok(entry)
            })
            .collect::<Result<Vec<_>, String>>()?;
        no_more(&table, "the listing")?;
        let listing = Listing { indices, keys };
        let mut seen = std::collections::BTreeSet::new();
        for file in listing.files() {
            check_file_name(file)?;
            if !seen.insert(file) {
                return Err(format!("{file} is listed twice"));
            }
        }
        Ok(listing)
    }

    /// Reads `<dir>/snapshot.toml`, and checks that every listed file and its signature exist.
    /// `None` when there is no listing: the build embeds no snapshot.
    pub(crate) fn read(dir: &Path) -> Result<Option<Listing>, String> {
        let path = dir.join(LISTING);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        let listing = Listing::parse(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        for file in listing.files() {
            for name in [file.to_owned(), signature_file(file)] {
                if !dir.join(&name).is_file() {
                    return Err(format!(
                        "{} lists {file}, but {} is missing",
                        path.display(),
                        dir.join(&name).display()
                    ));
                }
            }
        }
        Ok(Some(listing))
    }
}

/// A Rust expression for the `jtm_core::indices::Snapshot` that embeds `listing`'s files from
/// `dir`. No listing gives the empty snapshot.
pub(crate) fn code(dir: &Path, listing: Option<&Listing>) -> String {
    let include =
        |name: &str| format!("include_bytes!({:?})", dir.join(name).display().to_string());
    let mut code = String::from("jtm_core::indices::Snapshot {\n    indices: &[\n");
    for index in listing.map(|l| l.indices.as_slice()).unwrap_or_default() {
        let _ = writeln!(
            code,
            "        jtm_core::indices::EmbeddedIndex {{ plugin: {:?}, platform: {:?}, data: {}, \
             signature: {} }},",
            index.plugin,
            index.platform,
            include(&index.file),
            include(&signature_file(&index.file))
        );
    }
    code.push_str("    ],\n    keys: &[\n");
    for keys in listing.map(|l| l.keys.as_slice()).unwrap_or_default() {
        let _ = writeln!(
            code,
            "        jtm_core::indices::EmbeddedKeysFile {{ url: {:?}, data: {}, signature: {} }},",
            keys.url,
            include(&keys.file),
            include(&signature_file(&keys.file))
        );
    }
    code.push_str("    ],\n}");
    code
}

fn take_tables(table: &mut toml::Table, key: &str) -> Result<Vec<toml::Table>, String> {
    match table.remove(key) {
        None => Ok(Vec::new()),
        Some(toml::Value::Array(items)) => items
            .into_iter()
            .map(|item| match item {
                toml::Value::Table(t) => Ok(t),
                other => Err(format!("`{key}` must hold tables, got {other:?}")),
            })
            .collect(),
        Some(other) => Err(format!("`{key}` must be an array of tables, got {other:?}")),
    }
}

fn take_str(table: &mut toml::Table, section: &str, key: &str) -> Result<String, String> {
    match table.remove(key) {
        Some(toml::Value::String(s)) => Ok(s),
        other => Err(format!("`{section}.{key}` must be a string, got {other:?}")),
    }
}

fn no_more(table: &toml::Table, section: &str) -> Result<(), String> {
    match table.keys().next() {
        None => Ok(()),
        Some(key) => Err(format!("unknown key `{key}` in {section}")),
    }
}
