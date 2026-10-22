//! `jtm mirror export`: copies signed indices, their signatures and, on request, the artifacts
//! they describe into a directory that `[mirrors]` and `plugins.<name>.index_url` can point at
//! (SPEC.md sections 8 and 13).
//!
//! # Layout
//!
//! Every file sits where the URL it is served from says: `<dir>/<host>/<path of the URL>`, with
//! the path percent-decoded and a `:port` written `+port` ([`jtm_fetch::mirrors::export_path`]).
//! A signature is the file's URL plus `.minisig`, which is where jtm looks for it. So
//! `https://github.com/jtm-dev/index/releases/download/v1/java-linux-x64.json` is exported to
//! `<dir>/github.com/jtm-dev/index/releases/download/v1/java-linux-x64.json` and its signature
//! next to it, and a `[mirrors]` entry from `https://github.com/` to `<dir>/github.com/`
//! serves it, whichever prefix the entry uses.
//!
//! # What is exported
//!
//! Only bytes that were verified, exactly as signed. An index and its signature are the bytes
//! that passed signature, binding, rollback and expiry checks, never a re-serialisation. An
//! artifact is copied from the content-addressed download cache, which fetched it through
//! `[mirrors]` and checked its SHA-256 and size against the signed index, and it is hashed
//! again as it is copied. Nothing is written to the directory for a file that fails a check.
//!
//! Artifacts are written first and indices last, each atomically, so a directory that an export
//! died in never advertises an artifact it lacks. Files that already hold the right bytes are
//! left alone, which makes a repeated export a no-op.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use jtm_fetch::download::hash_reader;
use jtm_fetch::mirrors::export_path;
use jtm_security::{IndexEntry, Warning};
use serde::Serialize;

use crate::error::{JtmError, Result};
use crate::indices::{SignedCopy, expand};
use crate::platform::Platform;
use crate::plugins::Plugin;
use crate::session::Session;

/// Warning code for a platform a plugin publishes no index for, skipped when no `--platform`
/// was given.
pub const W_MIRROR_PLATFORM_SKIPPED: &str = "W_MIRROR_PLATFORM_SKIPPED";

/// What to export.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportOptions {
    /// The directory to export into. Created when missing.
    pub dir: PathBuf,
    /// Plugins to export; every available plugin when empty.
    pub plugins: Vec<String>,
    /// Platforms to export; every v1 platform when empty, skipping those a plugin has no index
    /// for. A platform named here must have one.
    pub platforms: Vec<Platform>,
    /// Also copy every artifact the indices list.
    pub artifacts: bool,
    /// Report what would be exported without writing, downloading or creating anything.
    pub dry_run: bool,
}

/// What kind of file was exported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Index,
    Signature,
    Keys,
    KeysSignature,
    Artifact,
}

/// What happened, or with a dry run would happen, to one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    Written,
    Unchanged,
    WouldWrite,
}

/// One file of the export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExportedFile {
    pub kind: FileKind,
    pub plugin: String,
    /// The platform an index or artifact is for; none for a keys file.
    pub platform: Option<String>,
    /// The URL the file is served from, and so what a mirror replaces.
    pub url: String,
    /// Where it is in the export directory.
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub status: FileStatus,
}

/// The result of an export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportReport {
    /// The export directory as an absolute path.
    pub dir: PathBuf,
    pub files: Vec<ExportedFile>,
    /// The `[mirrors]` entries that serve the export: a URL prefix per host and the directory
    /// that holds that host's files.
    pub mirrors: BTreeMap<String, String>,
    pub warnings: Vec<Warning>,
}

impl ExportReport {
    /// Whether any file was written.
    pub fn changed(&self) -> bool {
        self.files.iter().any(|f| f.status == FileStatus::Written)
    }
}

/// What a file holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Content {
    /// Bytes verified by the index loader.
    Bytes(Vec<u8>),
    /// An archive, copied from the download cache after its hash is checked.
    Artifact(IndexEntry),
}

impl Content {
    fn size(&self) -> u64 {
        match self {
            Content::Bytes(bytes) => bytes.len() as u64,
            Content::Artifact(entry) => entry.size,
        }
    }

    fn sha256(&self) -> String {
        match self {
            Content::Bytes(bytes) => jtm_security::sha256_hex(bytes),
            Content::Artifact(entry) => entry.sha256.clone(),
        }
    }

    /// Whether `other` would put the same bytes in the file. Two index entries for one archive
    /// may differ in tags or provenance and still promise the same bytes.
    fn same_bytes(&self, other: &Content) -> bool {
        match (self, other) {
            (Content::Bytes(a), Content::Bytes(b)) => a == b,
            (Content::Artifact(a), Content::Artifact(b)) => {
                a.sha256 == b.sha256 && a.size == b.size
            }
            _ => false,
        }
    }

    /// Whether the file at `path` already holds exactly this content.
    pub(crate) fn is_current(&self, path: &Path) -> Result<bool> {
        let io_err = |e| JtmError::io(path, e);
        let meta = match fs::metadata(path) {
            Ok(meta) if meta.is_file() => meta,
            Ok(_) => return Ok(false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(io_err(e)),
        };
        if meta.len() != self.size() {
            return Ok(false);
        }
        match self {
            Content::Bytes(bytes) => Ok(fs::read(path).map_err(io_err)? == *bytes),
            Content::Artifact(entry) => {
                let file = File::open(path).map_err(io_err)?;
                let (hash, _) = hash_reader(file, entry.size).map_err(io_err)?;
                Ok(hash == entry.sha256)
            }
        }
    }
}

/// One file to export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Item {
    pub(crate) kind: FileKind,
    pub(crate) plugin: String,
    pub(crate) platform: Option<String>,
    pub(crate) url: String,
    /// The path under the export directory.
    pub(crate) rel: PathBuf,
    pub(crate) content: Content,
}

/// The files of an export, by destination. Two items for one destination must agree.
#[derive(Debug, Default)]
pub(crate) struct Plan {
    items: BTreeMap<PathBuf, Item>,
}

impl Plan {
    /// Adds `item`, ignoring an exact repeat. A destination wanted with two different contents
    /// is two signed files claiming one URL, which no mirror could serve both of.
    pub(crate) fn add(&mut self, item: Item) -> Result<()> {
        match self.items.get(&item.rel) {
            None => {
                self.items.insert(item.rel.clone(), item);
                Ok(())
            }
            Some(existing) if existing.content.same_bytes(&item.content) => Ok(()),
            Some(existing) => Err(JtmError::SignedFileInvalid {
                file: existing.url.clone(),
                message: format!(
                    "{} and {} are signed with different contents for the same URL",
                    existing.plugin, item.plugin
                ),
            }),
        }
    }

    /// The items in the order they are written: artifacts, keys, signatures, indices.
    fn ordered(self) -> Vec<Item> {
        let rank = |kind: FileKind| match kind {
            FileKind::Artifact => 0,
            FileKind::Keys => 1,
            FileKind::KeysSignature | FileKind::Signature => 2,
            FileKind::Index => 3,
        };
        let mut items: Vec<Item> = self.items.into_values().collect();
        items.sort_by_key(|item| rank(item.kind));
        items
    }
}

/// Replaces `dest` with `bytes`, atomically.
pub(crate) fn write_bytes(dest: &Path, bytes: &[u8]) -> Result<()> {
    let dir = dest.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(|e| JtmError::io(dir, e))?;
    Ok(jtm_security::trust::write_atomically(dest, bytes)?)
}

/// Copies the cached archive at `source` to `dest`, atomically, after checking that it is
/// exactly what `entry` promises. Nothing is left at `dest` or beside it for a source that
/// does not match.
pub(crate) fn copy_verified(source: &Path, dest: &Path, entry: &IndexEntry) -> Result<()> {
    let input = File::open(source).map_err(|e| JtmError::io(source, e))?;
    write_through(dest, |tmp| {
        // One byte more than promised is enough to see that the source is too long.
        let tee = Tee {
            from: input,
            to: tmp,
        };
        let (actual, read) =
            hash_reader(tee, entry.size.saturating_add(1)).map_err(|e| JtmError::io(source, e))?;
        if read != entry.size || actual != entry.sha256 {
            return Err(JtmError::HashMismatch {
                url: entry.url.clone(),
                expected: entry.sha256.clone(),
                actual,
            });
        }
        Ok(())
    })
}

/// A reader that writes everything it reads to `to`, so a file is hashed as it is copied.
struct Tee<'a> {
    from: File,
    to: &'a mut File,
}

impl Read for Tee<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.from.read(buf)?;
        self.to.write_all(&buf[..n])?;
        Ok(n)
    }
}

/// Runs `fill` on a temporary file beside `dest` and renames it over `dest` only when `fill`
/// succeeded. The temporary file is removed on failure.
fn write_through(dest: &Path, fill: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
    let dir = dest.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(|e| JtmError::io(dir, e))?;
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.tmp", std::process::id()));
    let tmp = dest.with_file_name(name);
    let result = (|| {
        let mut file = File::create(&tmp).map_err(|e| JtmError::io(&tmp, e))?;
        fill(&mut file)?;
        file.sync_all().map_err(|e| JtmError::io(&tmp, e))?;
        drop(file);
        fs::rename(&tmp, dest).map_err(|e| JtmError::io(dest, e))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// `scheme://host/` of `url`, the prefix a `[mirrors]` entry for the whole host uses.
fn host_prefix(url: &str) -> Option<String> {
    let after = url.find("://")? + 3;
    let slash = url[after..].find('/')?;
    Some(url[..after + slash + 1].to_owned())
}

fn export_error(err: jtm_fetch::Error) -> JtmError {
    match err {
        jtm_fetch::Error::Scheme { url, reason } => {
            JtmError::usage(format!("cannot export {url}: {reason}"))
        }
        other => other.into(),
    }
}

/// `dir` as an absolute path with `/` separators, which TOML strings and URLs both accept.
fn slashed(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

impl Session<'_> {
    /// Exports signed indices, signatures and, with `options.artifacts`, archives.
    ///
    /// All indices are loaded and verified before anything is written, so a bad index, an
    /// untrusted key or an unknown plugin leaves the directory untouched. Indices are
    /// refreshed first when online, since a mirror is only worth as much as what it was
    /// copied from; offline, the local copies are exported. A dry run never refreshes, since
    /// that would write the index cache and the trust state.
    pub fn export_mirror(&self, options: &ExportOptions) -> Result<ExportReport> {
        // SPEC-QUESTION: section 8 says `mirror export` copies "indices, signatures and
        // optionally every artifact" and gives no layout, no default for `--plugin` and
        // `--platform`, and no word on keys files or on whether the index is refreshed. This
        // exports `<host>/<URL path>` so any `[mirrors]` prefix can serve it; every plugin and
        // every platform it publishes by default; the plugin's keys file too, since an index
        // signed by a delegated key cannot be verified without it; and a refreshed index.
        let plugins: Vec<Plugin> = if options.plugins.is_empty() {
            self.plugins()?
        } else {
            let mut names = options.plugins.clone();
            let mut seen = std::collections::BTreeSet::new();
            names.retain(|name| seen.insert(name.clone()));
            names
                .iter()
                .map(|name| self.plugin(name))
                .collect::<Result<_>>()?
        };
        let platforms_named = !options.platforms.is_empty();
        let plugins_named = !options.plugins.is_empty();
        let platforms: &[Platform] = if platforms_named {
            &options.platforms
        } else {
            Platform::ALL
        };

        // A platform a plugin has no index for is an error only when both were asked for by
        // name; otherwise it is skipped with a warning, as long as something is exported.
        let strict = platforms_named && plugins_named;
        let mut plan = Plan::default();
        let mut warnings = Vec::new();
        let mut skipped = None;
        let mut exported = false;
        for plugin in &plugins {
            match self.plan_plugin(plugin, platforms, strict, options, &mut plan, &mut warnings) {
                Ok(()) => exported = true,
                Err(err @ (JtmError::PlatformUnsupported { .. } | JtmError::Offline { .. }))
                    if !plugins_named =>
                {
                    warnings.push(Warning {
                        code: W_MIRROR_PLATFORM_SKIPPED,
                        message: format!("skipping a plugin with nothing to export: {err}"),
                    });
                    skipped.get_or_insert(err);
                }
                Err(err) => return Err(err),
            }
        }
        if let (false, Some(err)) = (exported, skipped) {
            return Err(err);
        }
        let items = plan.ordered();

        let dir = std::path::absolute(&options.dir).map_err(|e| JtmError::io(&options.dir, e))?;
        let archives = self.archives()?;
        let mut files = Vec::with_capacity(items.len());
        let mut mirrors = BTreeMap::new();
        for item in items {
            let dest = dir.join(&item.rel);
            let current = item.content.is_current(&dest)?;
            let status = match (current, options.dry_run) {
                (true, _) => FileStatus::Unchanged,
                (false, true) => FileStatus::WouldWrite,
                (false, false) => {
                    match &item.content {
                        Content::Bytes(bytes) => write_bytes(&dest, bytes)?,
                        Content::Artifact(entry) => {
                            tracing::info!(url = %entry.url, "exporting an archive");
                            let cached = archives.get(entry, &mut |_| {})?;
                            copy_verified(&cached.path, &dest, entry)?;
                        }
                    }
                    FileStatus::Written
                }
            };
            if let (Some(prefix), Some(host)) = (host_prefix(&item.url), item.rel.iter().next()) {
                mirrors.insert(
                    prefix,
                    format!("{}/{}/", slashed(&dir), host.to_string_lossy()),
                );
            }
            files.push(ExportedFile {
                kind: item.kind,
                plugin: item.plugin,
                platform: item.platform,
                url: item.url,
                path: slashed(&dest),
                size: item.content.size(),
                sha256: item.content.sha256(),
                status,
            });
        }
        Ok(ExportReport {
            dir,
            files,
            mirrors,
            warnings,
        })
    }

    /// Loads `plugin`'s indices and keys file and adds their files to `plan`.
    fn plan_plugin(
        &self,
        plugin: &Plugin,
        platforms: &[Platform],
        strict: bool,
        options: &ExportOptions,
        plan: &mut Plan,
        warnings: &mut Vec<Warning>,
    ) -> Result<()> {
        let manifest = &plugin.manifest;
        let name = manifest.name.as_str();
        // A platform-independent plugin has one index whichever platform asks for it.
        let platforms = if manifest.index.platform_independent() {
            &platforms[..platforms.len().min(1)]
        } else {
            platforms
        };
        let refresh = !options.dry_run;
        // The keys are loaded once for every platform of the plugin.
        let trust = self.plugin_trust(plugin, refresh)?;
        let mut keys = trust.keys_file.clone();
        let mut skipped: Option<JtmError> = None;
        let mut exported = false;
        for &platform in platforms {
            let index = match self.index_with_trust(plugin, platform, refresh, &trust) {
                Ok(loaded) => loaded,
                Err(err @ (JtmError::PlatformUnsupported { .. } | JtmError::Offline { .. }))
                    if !strict =>
                {
                    warnings.push(Warning {
                        code: W_MIRROR_PLATFORM_SKIPPED,
                        message: format!("skipping `{name}` for {platform}: {err}"),
                    });
                    skipped.get_or_insert(err);
                    continue;
                }
                Err(err) => return Err(err),
            };
            exported = true;
            let index_platform = manifest.index.index_platform(platform.as_str());
            let url = expand(&manifest.index.url, index_platform);
            warnings.extend(index.warnings.iter().cloned());
            self.plan_signed(
                plan,
                (FileKind::Index, FileKind::Signature),
                (name, Some(index_platform)),
                &url,
                index.copy,
            )?;
            if let (Some(keys_url), Some(keys)) = (manifest.index.keys_url.as_deref(), keys.take())
            {
                self.plan_signed(
                    plan,
                    (FileKind::Keys, FileKind::KeysSignature),
                    (name, None),
                    keys_url,
                    keys,
                )?;
            }
            if options.artifacts {
                for entry in &index.index.entries {
                    plan.add(Item {
                        kind: FileKind::Artifact,
                        plugin: name.to_owned(),
                        platform: Some(index_platform.to_owned()),
                        url: entry.url.clone(),
                        rel: export_path(&entry.url).map_err(export_error)?,
                        content: Content::Artifact(entry.clone()),
                    })?;
                }
            }
        }
        match (exported, skipped) {
            (false, Some(err)) => Err(err),
            _ => Ok(()),
        }
    }

    /// Adds a verified file and its signature to `plan`.
    fn plan_signed(
        &self,
        plan: &mut Plan,
        kinds: (FileKind, FileKind),
        (plugin, platform): (&str, Option<&str>),
        url: &str,
        copy: SignedCopy,
    ) -> Result<()> {
        let item = |kind, url: String, bytes| -> Result<Item> {
            Ok(Item {
                kind,
                plugin: plugin.to_owned(),
                platform: platform.map(str::to_owned),
                rel: export_path(&url).map_err(export_error)?,
                url,
                content: Content::Bytes(bytes),
            })
        };
        plan.add(item(kinds.0, url.to_owned(), copy.data)?)?;
        plan.add(item(kinds.1, format!("{url}.minisig"), copy.signature)?)
    }
}

#[cfg(test)]
mod tests;
