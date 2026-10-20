//! Version index files and the loader that verifies them before parsing (SPEC.md section 8).
//!
//! [`load`] is the only way to obtain an [`IndexFile`]: the signature is checked over the raw
//! bytes, and only bytes that pass reach the JSON parser. Binding, rollback and expiry checks
//! need the request and the trust state, so they run afterwards.

use std::collections::BTreeSet;
use std::fmt;

use jtm_plugin::Candidate;
use jtm_plugin::names::{check_name_segment, check_plugin_name, check_version_or_alias};
use serde::Deserialize;

use crate::error::{Error, Result};
use crate::key::Keyring;
use crate::signature::{self, Subject, Verified};
use crate::time::Timestamp;

/// The only index format this build understands.
pub const INDEX_FORMAT: u64 = 1;
/// The largest index file accepted. Real indices are a few hundred KiB.
pub const MAX_INDEX_FILE: usize = 64 * 1024 * 1024;
/// The longest URL accepted in an entry.
const MAX_URL_LEN: usize = 2048;

/// A verified, validated version index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexFile {
    pub plugin: String,
    pub platform: String,
    pub sequence: u64,
    pub generated: Timestamp,
    pub expires: Timestamp,
    pub entries: Vec<IndexEntry>,
}

/// One installable version for one platform.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexEntry {
    pub variant: String,
    pub version: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub url: String,
    pub archive: ArchiveKind,
    pub size: u64,
    /// Lowercase hex SHA-256 of the archive.
    pub sha256: String,
    /// Which independent sources agreed on the hash. Informational only.
    #[serde(default)]
    pub provenance: Vec<String>,
}

impl Candidate for IndexEntry {
    fn variant(&self) -> &str {
        &self.variant
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn tags(&self) -> &[String] {
        &self.tags
    }
}

/// The archive format of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum ArchiveKind {
    #[serde(rename = "zip")]
    Zip,
    #[serde(rename = "tar.gz")]
    TarGz,
    #[serde(rename = "tar.xz")]
    TarXz,
}

impl ArchiveKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ArchiveKind::Zip => "zip",
            ArchiveKind::TarGz => "tar.gz",
            ArchiveKind::TarXz => "tar.xz",
        }
    }
}

impl fmt::Display for ArchiveKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An index that passed signature verification and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedIndex {
    pub index: IndexFile,
    /// Lowercase hex SHA-256 of the raw bytes, for rollback checks.
    pub sha256: String,
    /// Which keys signed it.
    pub verified: Verified,
}

/// Verifies `data` against `keyring` for `subject`, then parses and validates it.
///
/// Nothing in `data` is parsed unless the signature check passes, so an unsigned or tampered
/// file never reaches the JSON parser.
pub fn load(
    data: &[u8],
    signatures: &[u8],
    keyring: &Keyring,
    subject: Subject<'_>,
    now: Timestamp,
) -> Result<LoadedIndex> {
    let invalid = |message: String| Error::Invalid {
        file: subject.file.to_owned(),
        message,
    };
    if data.len() > MAX_INDEX_FILE {
        return Err(invalid(format!("larger than {MAX_INDEX_FILE} bytes")));
    }
    let verified = signature::verify(data, signatures, keyring, subject, now)?;
    let index = parse_verified(data).map_err(invalid)?;
    Ok(LoadedIndex {
        index,
        sha256: crate::sha256_hex(data),
        verified,
    })
}

/// Parses bytes whose signature has already been verified. Private so no caller can skip
/// verification.
fn parse_verified(data: &[u8]) -> std::result::Result<IndexFile, String> {
    let raw: RawIndex = serde_json::from_slice(data).map_err(|e| e.to_string())?;
    raw.validate()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIndex {
    format: u64,
    plugin: String,
    platform: String,
    sequence: u64,
    generated: String,
    expires: String,
    entries: Vec<IndexEntry>,
}

impl RawIndex {
    fn validate(self) -> std::result::Result<IndexFile, String> {
        if self.format != INDEX_FORMAT {
            return Err(format!(
                "format {} is not supported; this jtm reads format {INDEX_FORMAT}",
                self.format
            ));
        }
        check_plugin_name(&self.plugin).map_err(|(_, m)| format!("plugin: {m}"))?;
        check_platform(&self.platform)?;
        let time = |field: &str, value: &str| {
            Timestamp::parse(value).ok_or_else(|| {
                format!("{field}: `{value}` is not a UTC time like 2026-10-19T03:00:00Z")
            })
        };
        let generated = time("generated", &self.generated)?;
        let expires = time("expires", &self.expires)?;
        if expires <= generated {
            return Err("expires must be later than generated".to_owned());
        }
        let mut seen = BTreeSet::new();
        for (i, entry) in self.entries.iter().enumerate() {
            check_entry(entry).map_err(|m| format!("entries[{i}].{m}"))?;
            if !seen.insert((entry.variant.as_str(), entry.version.as_str())) {
                return Err(format!(
                    "entries[{i}]: `{}` version `{}` is listed twice",
                    entry.variant, entry.version
                ));
            }
        }
        Ok(IndexFile {
            plugin: self.plugin,
            platform: self.platform,
            sequence: self.sequence,
            generated,
            expires,
            entries: self.entries,
        })
    }
}

/// A platform such as `linux-musl-x64`, or `any` for platform-independent tools. Whether it is
/// the platform that was asked for is the binding check's job.
fn check_platform(platform: &str) -> std::result::Result<(), String> {
    check_name_segment(platform, "platform").map_err(|(_, m)| format!("platform: {m}"))
}

fn check_entry(entry: &IndexEntry) -> std::result::Result<(), String> {
    check_name_segment(&entry.variant, "variant").map_err(|(_, m)| format!("variant: {m}"))?;
    check_version_or_alias(&entry.version).map_err(|(_, m)| format!("version: {m}"))?;
    for (i, tag) in entry.tags.iter().enumerate() {
        check_name_segment(tag, "tag").map_err(|(_, m)| format!("tags[{i}]: {m}"))?;
    }
    let url_ok = entry.url.len() <= MAX_URL_LEN
        && entry.url.starts_with("https://")
        && entry.url.len() > "https://".len()
        && entry.url.bytes().all(|b| b.is_ascii_graphic());
    if !url_ok {
        return Err(format!(
            "url: `{}` is not an https URL of printable ASCII",
            entry.url
        ));
    }
    if entry.size == 0 {
        return Err("size: must be greater than 0".to_owned());
    }
    let hex_ok = entry.sha256.len() == 64
        && entry
            .sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !hex_ok {
        return Err("sha256: must be 64 lowercase hex characters".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
