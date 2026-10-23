//! `cargo xtask embed-snapshot`: fills `crates/jtm-cli/snapshot/` with the latest signed
//! first-party indices, `keys.json` and their signatures, for `build.rs` to embed (SPEC.md
//! section 8, "Embedded snapshot").
//!
//! The files to fetch are the ones the first-party manifests name: each index URL expanded for
//! every platform (or `any`), and `keys_url`, each with its `.minisig`. They come from the
//! manifests' own URLs or from a directory laid out as a release, and are gathered in a private
//! staging directory. That directory is then checked by `jtm-index verify`'s release check,
//! which runs jtm's own loader against the manifests' root keys with expiry enforced, so a file
//! a client would refuse is never embedded. Only then is the old snapshot replaced, with the
//! listing written last.
//!
//! The check here is about usefulness, not trust: the binary verifies every embedded copy at
//! runtime exactly like any other.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use jtm_core::indices::{Fetcher, expand};
use jtm_core::{JtmError, Platform};
use jtm_security::Timestamp;
use jtm_security::index::MAX_INDEX_FILE;

#[path = "../../crates/jtm-cli/build/snapshot.rs"]
pub(crate) mod listing;

use listing::{IndexFile, KeysFile, LISTING, Listing, check_file_name, signature_file};

/// Warns when the newest index key of a plugin ends within this many days, as
/// `jtm-index verify` does by default.
const MIN_KEY_DAYS: u32 = 14;

/// What to embed and where.
pub(crate) struct Request<'a> {
    /// The first-party plugin directories, `crates/jtm-cli/plugins`.
    pub(crate) plugins: &'a Path,
    /// Where the files come from: the network, or a release directory.
    pub(crate) source: &'a dyn Fetcher,
    /// The snapshot directory, `crates/jtm-cli/snapshot`.
    pub(crate) out: &'a Path,
    pub(crate) now: Timestamp,
}

/// What was embedded.
#[derive(Debug)]
pub(crate) struct Embedded {
    pub(crate) listing: Listing,
    /// Warnings from the release check, such as an index key that expires soon.
    pub(crate) warnings: Vec<String>,
}

/// Reads a release directory by file name, whatever the URL says, as a release serves it.
#[derive(Debug)]
pub(crate) struct ReleaseDir<'a>(pub(crate) &'a Path);

impl Fetcher for ReleaseDir<'_> {
    fn fetch(&self, url: &str) -> jtm_core::Result<Option<Vec<u8>>> {
        let Ok(name) = file_name(url) else {
            return Ok(None);
        };
        let path = self.0.join(name);
        match fs::metadata(&path) {
            Ok(meta) if meta.is_file() && meta.len() <= MAX_INDEX_FILE as u64 => {}
            Ok(meta) if meta.is_file() => {
                return Err(JtmError::usage(format!(
                    "{} is larger than an index may be",
                    path.display()
                )));
            }
            Ok(_) => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(JtmError::io(&path, e)),
        }
        fs::read(&path)
            .map(Some)
            .map_err(|e| JtmError::io(&path, e))
    }
}

/// Fetches, checks and embeds the snapshot. Nothing in `req.out` changes unless every file
/// passes.
pub(crate) fn embed(req: &Request<'_>) -> Result<Embedded, String> {
    let plugin_dirs = plugin_dirs(req.plugins)?;
    let staging = tempfile::tempdir().map_err(|e| format!("cannot create a staging dir: {e}"))?;
    let mut staged: BTreeMap<String, String> = BTreeMap::new();
    let mut keys = Vec::new();

    for dir in &plugin_dirs {
        let manifest = jtm_index::plugin::read_manifest(dir).map_err(|e| e.to_string())?;
        let index = &manifest.index;
        for platform in platforms(index.platform_independent()) {
            let url = expand(&index.url, platform);
            // A platform the plugin does not publish has no file; the check below fails a
            // plugin that has none at all.
            stage(req.source, &url, staging.path(), &mut staged, false)?;
        }
        if let Some(url) = &index.keys_url {
            let file = stage(req.source, url, staging.path(), &mut staged, true)?
                .ok_or_else(|| format!("{url} was not found"))?;
            if !keys.iter().any(|k: &KeysFile| &k.url == url) {
                keys.push(KeysFile {
                    url: url.clone(),
                    file,
                });
            }
        }
    }

    let report = jtm_index::release::verify(&jtm_index::release::Request {
        published: staging.path(),
        plugin_dirs: &plugin_dirs,
        root_keys: &[],
        now: req.now,
        min_key_days: MIN_KEY_DAYS,
    })
    .map_err(|e| format!("the files would not load in jtm: {e}"))?;

    let mut indices = Vec::new();
    for (dir, plugin) in plugin_dirs.iter().zip(&report.plugins) {
        let manifest = jtm_index::plugin::read_manifest(dir).map_err(|e| e.to_string())?;
        for verified in &plugin.files {
            let file = file_name(&expand(&manifest.index.url, &verified.platform))?.to_owned();
            indices.push(IndexFile {
                plugin: plugin.plugin.clone(),
                platform: verified.platform.clone(),
                file,
            });
        }
    }
    let listing = Listing { indices, keys };
    write(staging.path(), req.out, &listing)?;
    Ok(Embedded {
        listing,
        warnings: report
            .warnings
            .iter()
            .map(|w| format!("{}: {}", w.code, w.message))
            .collect(),
    })
}

/// Removes the snapshot from `out`, so the next build embeds nothing.
pub(crate) fn clear(out: &Path) -> Result<(), String> {
    // The listing goes first: without it the files left behind are never embedded.
    remove(&out.join(LISTING))?;
    let entries = match fs::read_dir(out) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("cannot read {}: {e}", out.display())),
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // Only what `embed` writes; the README and `.gitignore` stay.
        if name.ends_with(".json") || name.ends_with(".minisig") {
            remove(&entry.path())?;
        }
    }
    Ok(())
}

/// Every directory under `plugins` with a `plugin.toml`, sorted.
fn plugin_dirs(plugins: &Path) -> Result<Vec<PathBuf>, String> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(plugins)
        .map_err(|e| format!("cannot read {}: {e}", plugins.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.join("plugin.toml").is_file())
        .collect();
    dirs.sort();
    if dirs.is_empty() {
        return Err(format!("no plugins found under {}", plugins.display()));
    }
    Ok(dirs)
}

// SPEC-QUESTION: section 8 says release builds include "the signed first-party indices"
// without saying for which platforms. Every platform is embedded, not only the build target's,
// so `jtm available --platform` and `jtm mirror export` work offline for any platform; the cost
// is binary size. Each copy is bound to its platform by its signature either way.
fn platforms(independent: bool) -> Vec<&'static str> {
    if independent {
        vec![jtm_plugin::manifest::ANY_PLATFORM]
    } else {
        Platform::ALL.iter().map(|p| p.as_str()).collect()
    }
}

/// Fetches `url` and its signature into `staging` under the URL's file name, unless it is
/// already there. `None` when the source has no such file and it is not `required`.
fn stage(
    source: &dyn Fetcher,
    url: &str,
    staging: &Path,
    staged: &mut BTreeMap<String, String>,
    required: bool,
) -> Result<Option<String>, String> {
    let name = file_name(url)?.to_owned();
    match staged.get(&name) {
        Some(seen) if seen == url => return Ok(Some(name)),
        // A release is flat, so two URLs with one file name cannot both be served from it.
        Some(seen) => return Err(format!("{seen} and {url} both name the file {name}")),
        None => {}
    }
    let fetch = |url: &str| source.fetch(url).map_err(|e| format!("{url}: {e}"));
    let Some(data) = fetch(url)? else {
        return if required {
            Err(format!("{url} was not found"))
        } else {
            Ok(None)
        };
    };
    let sig_url = signature_file(url);
    let signature = fetch(&sig_url)?.ok_or_else(|| format!("{sig_url} was not found"))?;
    for (file, bytes) in [(name.clone(), data), (signature_file(&name), signature)] {
        let path = staging.join(&file);
        fs::write(&path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    }
    staged.insert(name.clone(), url.to_owned());
    Ok(Some(name))
}

/// Replaces the snapshot in `out` with `listing`'s files from `staging`, writing the listing
/// last so an interrupted run leaves no listing rather than a partial one.
fn write(staging: &Path, out: &Path, listing: &Listing) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    clear(out)?;
    for file in listing.files() {
        for name in [file.to_owned(), signature_file(file)] {
            let (from, to) = (staging.join(&name), out.join(&name));
            fs::copy(&from, &to).map_err(|e| format!("cannot write {}: {e}", to.display()))?;
        }
    }
    let path = out.join(LISTING);
    fs::write(&path, listing.to_toml()).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn remove(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("cannot remove {}: {e}", path.display())),
    }
}

/// The last path segment of `url`, without query or fragment, when it is a plain file name.
fn file_name(url: &str) -> Result<&str, String> {
    let name = url
        .split(['?', '#'])
        .next()
        .and_then(|path| path.rsplit('/').next())
        .unwrap_or_default();
    check_file_name(name).map_err(|e| format!("{url}: {e}"))?;
    Ok(name)
}

#[cfg(test)]
mod tests;
