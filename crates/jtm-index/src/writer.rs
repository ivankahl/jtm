//! Turning confirmed entries into index files (SPEC.md sections 8 and 9).
//!
//! [`write`] produces one file per platform. Its output is a pure function of its inputs: the
//! same confirmed entries, previous files and settings always give byte-identical files, in
//! the order and spelling below, so a diff between two publishes shows only what changed.
//!
//! # The file
//!
//! Pretty-printed JSON with two-space indentation and a final newline. Fields appear in the
//! order of the specification's example. Entries are ordered by variant, then version, as
//! plain strings; tags and provenance labels are sorted and free of repeats. The signed bytes
//! are exactly these bytes.
//!
//! # Sequence, time and expiry
//!
//! `sequence` of a platform is one more than the previous publish's, or 1 for a platform
//! that has never been published. It is never reused, lowered or skipped. `generated` is the
//! time of the run and `expires` is `generated` plus the [`Validity`].
//!
//! A run that finds an index unchanged does not publish a new one: its sequence, times,
//! bytes and signature stay as they were, so a daily run costs clients nothing. Only when
//! less than half of the validity is left, or it has run out, is the same content issued
//! again under the next sequence with fresh times, so a quiet upstream never lets an index
//! expire (the freeze protection of section 9 works only if there is something newer to
//! find). Time never goes backwards: a run dated before the previous `generated` is refused.
//!
//! # Binding
//!
//! `plugin` and `platform` are inside the signed bytes. The plugin comes from the manifest,
//! and a platform-independent plugin (one whose index URL names no platform) writes only
//! `any`, while any other plugin never does, so a file cannot be published under a name the
//! client's binding check would refuse.

use std::collections::{BTreeMap, BTreeSet};

use jtm_core::dirs::dir_name;
use jtm_security::{IndexEntry, IndexFile, Timestamp};
use serde::Serialize;

use crate::candidate::Target;
use crate::confirm::{Confirmed, ConfirmedEntry};
use crate::error::{Error, Result};
use crate::signing::Signer;
use crate::verify;

/// The format of the files written, which is the only one clients read.
const FORMAT: u64 = jtm_security::index::INDEX_FORMAT;
/// Seconds in a day.
const DAY: i64 = 86_400;
/// The longest validity: an index key lives 90 days (SPEC.md section 9), and an index that
/// outlives the key that signed it could not be verified.
pub const MAX_VALIDITY_DAYS: u32 = 90;
/// The validity used unless the caller says otherwise, as in the example of section 8.
pub const DEFAULT_VALIDITY_DAYS: u32 = 30;

/// How long a published index is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validity(i64);

impl Validity {
    /// A validity of `days`, between 1 and [`MAX_VALIDITY_DAYS`].
    // SPEC-QUESTION: section 8 shows a 30-day validity and section 9 gives index keys 90 days,
    // but nothing says how long an index may be valid. The default is 30 days and the limits
    // are 1 to 90 days, so an index never outlives the key that could have signed it.
    pub fn days(days: u32) -> Result<Validity> {
        if (1..=MAX_VALIDITY_DAYS).contains(&days) {
            Ok(Validity(i64::from(days) * DAY))
        } else {
            Err(Error::Usage {
                message: format!(
                    "the validity must be between 1 and {MAX_VALIDITY_DAYS} days, not {days}"
                ),
            })
        }
    }

    /// The validity in seconds.
    pub const fn seconds(self) -> i64 {
        self.0
    }
}

impl Default for Validity {
    fn default() -> Validity {
        Validity(i64::from(DEFAULT_VALIDITY_DAYS) * DAY)
    }
}

/// What the plugin says about the files it publishes, so a file can only be written in a form
/// its clients will ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// The plugin name as the manifest spells it.
    pub plugin: String,
    /// Whether the manifest's index URL names no platform, so only `any` is published.
    pub platform_independent: bool,
    /// The plugin's variants. Empty for a plugin without variants, whose entries are all
    /// published as `default`.
    pub variants: Vec<String>,
}

/// Settings of one run.
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// The time of the run: `generated` of every file written.
    pub now: Timestamp,
    pub validity: Validity,
}

/// A previously published file, already verified and parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Previous {
    pub index: IndexFile,
    /// The published bytes.
    pub bytes: Vec<u8>,
    /// The published `.minisig`.
    pub signature: Vec<u8>,
}

/// What a run does with one platform's file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// There was no file before: sequence 1.
    Created,
    /// The entries differ from the previous file: sequence plus one.
    Updated,
    /// The entries are the same but the previous file is about to expire: sequence plus one
    /// with new times.
    Renewed,
    /// Nothing to publish: the previous file stays as it is.
    Unchanged,
}

impl Action {
    /// The name used in reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::Created => "created",
            Action::Updated => "updated",
            Action::Renewed => "renewed",
            Action::Unchanged => "unchanged",
        }
    }
}

/// One platform's file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// `any` or one of the v1 platforms.
    pub platform: String,
    /// The file name clients look for, such as `demo-linux-x64.json`.
    pub file: String,
    pub action: Action,
    pub sequence: u64,
    pub generated: Timestamp,
    pub expires: Timestamp,
    /// The bytes to sign and publish.
    pub bytes: Vec<u8>,
    /// For [`Action::Unchanged`], the signature already published for `bytes`; otherwise the
    /// file still needs signing.
    pub signature: Option<Vec<u8>>,
    /// How many entries the file lists.
    pub entries: usize,
    /// Versions listed now that were not before.
    pub added: usize,
    /// Versions listed before that are gone.
    pub removed: usize,
    /// Versions listed in both whose content differs.
    pub changed: usize,
}

/// Warning code for a version that is published again with a different SHA-256.
pub const W_HASH_CHANGED: &str = "W_HASH_CHANGED";

/// Something worth a human's attention that does not stop the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    pub code: &'static str,
    pub message: String,
}

/// The result of [`write`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    /// One file per platform, in a stable order.
    pub files: Vec<Output>,
    pub warnings: Vec<Warning>,
}

impl Written {
    /// Whether any file needs signing and publishing.
    pub fn changed(&self) -> bool {
        self.files.iter().any(|f| f.action != Action::Unchanged)
    }
}

/// Writes the index files for `confirmed`, given the files published before.
///
/// `previous` maps a platform to its published file. A platform in it that `confirmed` has no
/// entries for is refused: a vendor, a filter or an adapter that stops reporting a whole
/// platform is more likely a fault than a decision, and silently publishing without it would
/// leave its clients with nothing.
pub fn write(
    binding: &Binding,
    confirmed: &Confirmed,
    previous: &BTreeMap<String, Previous>,
    settings: &Settings,
) -> Result<Written> {
    let by_target = group(binding, confirmed)?;
    check_previous(binding, &by_target, previous)?;

    let validator = Signer::ephemeral()?;
    let mut files = Vec::with_capacity(by_target.len());
    let mut warnings = Vec::new();
    for (target, entries) in by_target {
        let platform = target.as_str();
        let output = plan(
            binding,
            platform,
            entries,
            previous.get(platform),
            settings,
            &mut warnings,
        )?;
        if output.action != Action::Unchanged {
            // The client's own loader has the last word on whether the file is acceptable.
            verify::sign_and_load(
                &validator,
                &binding.plugin,
                &output.file,
                &output.bytes,
                settings.now,
            )?;
        }
        files.push(output);
    }
    Ok(Written { files, warnings })
}

/// The index entries for each target, in order, after checking them against the binding.
fn group(binding: &Binding, confirmed: &Confirmed) -> Result<BTreeMap<Target, Vec<IndexEntry>>> {
    if confirmed.entries.is_empty() {
        return Err(Error::Invalid {
            message: format!(
                "no entries to publish for `{}`; an empty index would take every version away \
                 from its clients",
                binding.plugin
            ),
        });
    }
    let mut by_target: BTreeMap<Target, Vec<IndexEntry>> = BTreeMap::new();
    for entry in &confirmed.entries {
        check_target(binding, entry)?;
        by_target
            .entry(entry.target)
            .or_default()
            .push(index_entry(binding, entry)?);
    }
    for entries in by_target.values_mut() {
        entries.sort_by(|a, b| (&a.variant, &a.version).cmp(&(&b.variant, &b.version)));
    }
    Ok(by_target)
}

fn check_target(binding: &Binding, entry: &ConfirmedEntry) -> Result<()> {
    let describe = || {
        format!(
            "{} {} ({})",
            entry.variant.as_deref().unwrap_or("-"),
            entry.version,
            entry.target
        )
    };
    match (binding.platform_independent, entry.target) {
        (true, Target::Platform(_)) => Err(Error::Invalid {
            message: format!(
                "`{}` is platform-independent, so its index is for `any`, but {} is for a \
                 platform",
                binding.plugin,
                describe()
            ),
        }),
        (false, Target::Any) => Err(Error::Invalid {
            message: format!(
                "`{}` publishes an index for each platform, but {} is for `any`",
                binding.plugin,
                describe()
            ),
        }),
        _ => Ok(()),
    }
}

fn index_entry(binding: &Binding, entry: &ConfirmedEntry) -> Result<IndexEntry> {
    let variant = match (&entry.variant, binding.variants.is_empty()) {
        (None, true) => "default".to_owned(),
        (Some(variant), false) if binding.variants.contains(variant) => variant.clone(),
        (Some(variant), false) => {
            return Err(Error::Invalid {
                message: format!(
                    "`{}` does not publish a variant `{variant}` (version {})",
                    binding.plugin, entry.version
                ),
            });
        }
        (None, false) => {
            return Err(Error::Invalid {
                message: format!(
                    "`{}` has variants, but version {} names none",
                    binding.plugin, entry.version
                ),
            });
        }
        (Some(variant), true) => {
            return Err(Error::Invalid {
                message: format!(
                    "`{}` has no variants, but version {} names `{variant}`",
                    binding.plugin, entry.version
                ),
            });
        }
    };
    let tags: BTreeSet<String> = entry.tags.iter().cloned().collect();
    let provenance: BTreeSet<String> = entry.provenance.labels().into_iter().collect();
    Ok(IndexEntry {
        variant,
        version: entry.version.clone(),
        tags: tags.into_iter().collect(),
        url: entry.url.clone(),
        archive: entry.archive,
        size: entry.size,
        sha256: entry.sha256.clone(),
        provenance: provenance.into_iter().collect(),
    })
}

/// Checks that each previous file is the one for the platform it is filed under, and that no
/// platform disappears.
fn check_previous(
    binding: &Binding,
    by_target: &BTreeMap<Target, Vec<IndexEntry>>,
    previous: &BTreeMap<String, Previous>,
) -> Result<()> {
    for (platform, old) in previous {
        let file = file_name(&binding.plugin, platform);
        if old.index.plugin != binding.plugin || old.index.platform != *platform {
            return Err(Error::Previous {
                file: file.clone(),
                error: jtm_security::Error::IndexBinding {
                    file,
                    expected: format!("plugin `{}` on `{platform}`", binding.plugin),
                    got: format!("plugin `{}` on `{}`", old.index.plugin, old.index.platform),
                },
            });
        }
        // SPEC-QUESTION: the spec does not say what happens to a platform that stops
        // appearing. Dropping its file would leave its clients with `E_PLATFORM_UNSUPPORTED`
        // and an empty index would remove every version, so the most secure reading is to
        // refuse and let a maintainer remove the old files on purpose.
        if !by_target.keys().any(|t| t.as_str() == platform) {
            return Err(Error::Invalid {
                message: format!(
                    "{file} was published at sequence {} but this run has no entries for \
                     {platform}; if the platform is really gone, remove its files from the \
                     previous publish",
                    old.index.sequence
                ),
            });
        }
    }
    Ok(())
}

/// What to do with one platform.
fn plan(
    binding: &Binding,
    platform: &str,
    entries: Vec<IndexEntry>,
    previous: Option<&Previous>,
    settings: &Settings,
    warnings: &mut Vec<Warning>,
) -> Result<Output> {
    let file = file_name(&binding.plugin, platform);
    let now = settings.now;
    let Some(old) = previous else {
        return render(
            binding,
            platform,
            file,
            entries,
            1,
            Action::Created,
            settings,
        );
    };

    if now < old.index.generated {
        return Err(Error::Rollback {
            file,
            message: format!(
                "this run is dated {now}, before the previous publish at {}",
                old.index.generated
            ),
        });
    }
    let diff = Diff::of(&old.index.entries, &entries);
    for (variant, version) in &diff.rehashed {
        warnings.push(Warning {
            code: W_HASH_CHANGED,
            message: format!(
                "{file}: {variant} {version} has a different SHA-256 than at sequence {}; \
                 clients with a lockfile for it will refuse the new index \
                 (E_LOCK_INDEX_MISMATCH)",
                old.index.sequence
            ),
        });
    }

    // SPEC-QUESTION: section 8 says `sequence` increases by at least 1 "on every publish" but
    // not what a run that finds nothing new is. Publishing it anyway would make clients fetch
    // and re-verify a new file every day for nothing, so an unchanged index is not published;
    // it is reissued only when less than half of its validity is left, so it cannot expire.
    let same = old.index.entries == entries;
    let remaining = old.index.expires.unix() - now.unix();
    if same && remaining > settings.validity.seconds() / 2 {
        return Ok(Output {
            platform: platform.to_owned(),
            file,
            action: Action::Unchanged,
            sequence: old.index.sequence,
            generated: old.index.generated,
            expires: old.index.expires,
            bytes: old.bytes.clone(),
            signature: Some(old.signature.clone()),
            entries: entries.len(),
            added: 0,
            removed: 0,
            changed: 0,
        });
    }
    let sequence = old
        .index
        .sequence
        .checked_add(1)
        .ok_or_else(|| Error::Rollback {
            file: file.clone(),
            message: "the sequence cannot grow any further".to_owned(),
        })?;
    let action = if same {
        Action::Renewed
    } else {
        Action::Updated
    };
    let mut output = render(binding, platform, file, entries, sequence, action, settings)?;
    output.added = diff.added;
    output.removed = diff.removed;
    output.changed = diff.rehashed.len() + diff.edited;
    Ok(output)
}

fn render(
    binding: &Binding,
    platform: &str,
    file: String,
    entries: Vec<IndexEntry>,
    sequence: u64,
    action: Action,
    settings: &Settings,
) -> Result<Output> {
    let generated = settings.now;
    let expires =
        Timestamp::from_unix(generated.unix().saturating_add(settings.validity.seconds()));
    let out = FileOut {
        format: FORMAT,
        plugin: &binding.plugin,
        platform,
        sequence,
        generated: generated.to_string(),
        expires: expires.to_string(),
        entries: entries.iter().map(EntryOut::from).collect(),
    };
    let mut bytes = serde_json::to_vec_pretty(&out).map_err(|e| Error::Invalid {
        message: format!("cannot write {file}: {e}"),
    })?;
    bytes.push(b'\n');
    let count = entries.len();
    Ok(Output {
        platform: platform.to_owned(),
        file,
        action,
        sequence,
        generated,
        expires,
        bytes,
        signature: None,
        entries: count,
        added: count,
        removed: 0,
        changed: 0,
    })
}

/// How two lists of entries differ, by (variant, version).
struct Diff {
    added: usize,
    removed: usize,
    /// Versions whose SHA-256 differs.
    rehashed: Vec<(String, String)>,
    /// Versions whose SHA-256 is the same but something else differs.
    edited: usize,
}

impl Diff {
    fn of(old: &[IndexEntry], new: &[IndexEntry]) -> Diff {
        let key = |e: &IndexEntry| (e.variant.clone(), e.version.clone());
        let old_by: BTreeMap<_, _> = old.iter().map(|e| (key(e), e)).collect();
        let new_by: BTreeMap<_, _> = new.iter().map(|e| (key(e), e)).collect();
        let mut diff = Diff {
            added: 0,
            removed: 0,
            rehashed: Vec::new(),
            edited: 0,
        };
        for (k, entry) in &new_by {
            match old_by.get(k) {
                None => diff.added += 1,
                Some(before) if before.sha256 != entry.sha256 => diff.rehashed.push(k.clone()),
                Some(before) if before != entry => diff.edited += 1,
                Some(_) => {}
            }
        }
        diff.removed = old_by.keys().filter(|k| !new_by.contains_key(*k)).count();
        diff
    }
}

/// The file name clients ask for: `<plugin directory name>-<platform>.json`.
pub fn file_name(plugin: &str, platform: &str) -> String {
    format!("{}-{platform}.json", dir_name(plugin))
}

#[derive(Serialize)]
struct FileOut<'a> {
    format: u64,
    plugin: &'a str,
    platform: &'a str,
    sequence: u64,
    generated: String,
    expires: String,
    entries: Vec<EntryOut<'a>>,
}

#[derive(Serialize)]
struct EntryOut<'a> {
    variant: &'a str,
    version: &'a str,
    tags: &'a [String],
    url: &'a str,
    archive: &'static str,
    size: u64,
    sha256: &'a str,
    provenance: &'a [String],
}

impl<'a> From<&'a IndexEntry> for EntryOut<'a> {
    fn from(entry: &'a IndexEntry) -> EntryOut<'a> {
        EntryOut {
            variant: &entry.variant,
            version: &entry.version,
            tags: &entry.tags,
            url: &entry.url,
            archive: entry.archive.as_str(),
            size: entry.size,
            sha256: &entry.sha256,
            provenance: &entry.provenance,
        }
    }
}

#[cfg(test)]
mod tests;
