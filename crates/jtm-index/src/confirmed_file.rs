//! The confirmed entries of one plugin as a file that people review and the publisher signs.
//!
//! The daily run confirms every hash and writes the result here; a person reads the diff of this
//! file in a pull request; the publish run turns exactly this file into signed indices without
//! asking any upstream again. What was reviewed is what is signed.
//!
//! The file holds what an index entry holds, and nothing that changes from run to run: no
//! download time, no sequence, no expiry. The same confirmed entries always give the same
//! text, whatever order they arrive in, so an unchanged upstream is an empty diff. Provenance is
//! kept as the labels the index will carry (`adoptium-api`, `signature:pgp`, `computed:sha256`).
//! The fuller record of which claims and signatures backed an entry is not kept; it is in the
//! log of the run that confirmed it.

use std::collections::BTreeSet;

use jtm_security::ArchiveKind;
use serde::{Deserialize, Serialize};

use crate::candidate::Target;
use crate::confirm::{Confirmed, ConfirmedEntry, Provenance};
use crate::error::{Error, Result};

/// The only layout understood.
pub const FORMAT: u64 = 1;
/// The largest confirmed file read.
pub const MAX_CONFIRMED_FILE: usize = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    format: u64,
    plugin: String,
    entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    variant: Option<String>,
    version: String,
    platform: String,
    tags: Vec<String>,
    url: String,
    archive: String,
    size: u64,
    sha256: String,
    provenance: Vec<String>,
}

impl Entry {
    fn of(entry: &ConfirmedEntry) -> Entry {
        let tags: BTreeSet<&String> = entry.tags.iter().collect();
        let labels: BTreeSet<String> = entry.provenance.labels().into_iter().collect();
        Entry {
            variant: entry.variant.clone(),
            version: entry.version.clone(),
            platform: entry.target.as_str().to_owned(),
            tags: tags.into_iter().cloned().collect(),
            url: entry.url.clone(),
            archive: entry.archive.as_str().to_owned(),
            size: entry.size,
            sha256: entry.sha256.clone(),
            provenance: labels.into_iter().collect(),
        }
    }

    fn key(&self) -> (&str, &str, &str) {
        (
            self.variant.as_deref().unwrap_or(""),
            &self.version,
            &self.platform,
        )
    }

    fn into_confirmed(self) -> Result<ConfirmedEntry> {
        let bad = |what: &str, why: String| Error::Invalid {
            message: format!(
                "confirmed file: {} {} on {}: {what}: {why}",
                self.variant.as_deref().unwrap_or("(no variant)"),
                self.version,
                self.platform
            ),
        };
        let target = Target::parse(&self.platform)
            .ok_or_else(|| bad("platform", format!("`{}` is not a platform", self.platform)))?;
        let archive: ArchiveKind = serde_json::from_value(serde_json::Value::String(
            self.archive.clone(),
        ))
        .map_err(|_| {
            bad(
                "archive",
                format!("`{}` is not an archive kind", self.archive),
            )
        })?;
        let lowercase_hex = self
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if self.sha256.len() != 64 || !lowercase_hex {
            return Err(bad(
                "sha256",
                "must be 64 lowercase hexadecimal characters".to_owned(),
            ));
        }
        let provenance = Provenance::from_labels(&self.provenance)
            .map_err(|label| bad("provenance", format!("`{label}` is not a known label")))?;
        Ok(ConfirmedEntry {
            variant: self.variant,
            version: self.version,
            target,
            tags: self.tags,
            url: self.url,
            archive,
            size: self.size,
            sha256: self.sha256,
            distribution_version: None,
            provenance,
        })
    }
}

/// Renders `confirmed` as the text of a confirmed file for `plugin`: pretty JSON with two-space
/// indentation and a final newline, entries ordered by variant, version and platform.
pub fn render(plugin: &str, confirmed: &Confirmed) -> Result<String> {
    let mut entries: Vec<Entry> = confirmed.entries.iter().map(Entry::of).collect();
    entries.sort_by(|a, b| a.key().cmp(&b.key()));
    let file = File {
        format: FORMAT,
        plugin: plugin.to_owned(),
        entries,
    };
    let mut text = serde_json::to_string_pretty(&file).map_err(|e| Error::Invalid {
        message: format!("confirmed file: {e}"),
    })?;
    text.push('\n');
    Ok(text)
}

/// Reads a confirmed file written for `plugin`. Whatever it holds is checked again by the index
/// writer and by the client's loader before anything is signed; this only refuses what cannot
/// be turned into entries, with messages that never repeat the file's text.
pub fn parse(plugin: &str, bytes: &[u8]) -> Result<Confirmed> {
    let invalid = |message: String| Error::Invalid {
        message: format!("confirmed file: {message}"),
    };
    if bytes.len() > MAX_CONFIRMED_FILE {
        return Err(invalid(format!("larger than {MAX_CONFIRMED_FILE} bytes")));
    }
    let file: File = serde_json::from_slice(bytes).map_err(|e| {
        // serde_json messages name the field or position, never the offending text.
        invalid(e.to_string())
    })?;
    if file.format != FORMAT {
        return Err(invalid(format!(
            "format {} is not supported; this jtm-index reads format {FORMAT}",
            file.format
        )));
    }
    if file.plugin != plugin {
        return Err(invalid(format!(
            "it is for `{}`, not `{plugin}`",
            file.plugin
        )));
    }
    if file.entries.is_empty() {
        return Err(invalid("it has no entries".to_owned()));
    }
    let mut seen = BTreeSet::new();
    for entry in &file.entries {
        let (variant, version, platform) = entry.key();
        if !seen.insert((variant.to_owned(), version.to_owned(), platform.to_owned())) {
            return Err(invalid(format!(
                "`{version}` on {platform} is listed twice for variant `{variant}`"
            )));
        }
    }
    let entries = file
        .entries
        .into_iter()
        .map(Entry::into_confirmed)
        .collect::<Result<Vec<_>>>()?;
    Ok(Confirmed {
        entries,
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod tests;
