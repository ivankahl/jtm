//! Loading a plugin's version index from every source it may come from (SPEC.md section 8).
//!
//! The copies are the snapshot embedded in the binary, the verified copy in the cache, a
//! configured `plugins.<name>.index_url` override, and the canonical remote. Every copy is
//! verified and checked the same way, and the valid copy with the highest sequence is used. A
//! copy that came over the network is saved to the cache, and the accepted sequence is recorded
//! in `state/trust.json` for rollback protection.
//!
//! [`IndexLoader::keyring`] builds the keys an index is checked against. First-party and
//! third-party plugins go through the same steps: the manifest's `signing_keys` are the
//! plugin's trust anchors, an optional keys file at `keys_url` delegates to short-lived index
//! keys, and keys the user trusts for the plugin may re-sign its indices. The only difference is
//! that anchors in a manifest compiled into jtm ([`ManifestOrigin::Builtin`]) are pre-approved,
//! while any other manifest's anchors ([`ManifestOrigin::External`]) count only once the user
//! has trusted them.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use jtm_security::select::{IndexCopy, Selection};
use jtm_security::{
    ExpiryPolicy, IndexFile, IndexRequest, Keyring, KeysFile, SourceKind, Timestamp, TrustAnchors,
    TrustState, Warning,
};

use crate::dirs::{Dirs, dir_name};
use crate::error::{JtmError, Result};

/// Warning code when the network copy could not be fetched and a local copy was used.
pub const W_INDEX_REFRESH_FAILED: &str = "W_INDEX_REFRESH_FAILED";
/// Warning code when a plugin's keys file is unavailable or invalid, so only its anchors and
/// the user's keys can verify its indices.
pub const W_KEYS_FILE_UNAVAILABLE: &str = "W_KEYS_FILE_UNAVAILABLE";

/// Where a plugin manifest came from, which decides whether its anchors are pre-approved.
///
/// Pre-approval is provenance, never a property of a key or of a file's contents: `Builtin` is
/// only for manifests compiled into the jtm binary. The unpacked `<data>/plugins/builtin`
/// working copy, the marketplace, a project directory and the network are all `External`, so
/// their anchors count only once the user trusts them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestOrigin {
    /// Compiled into the jtm binary, as the first-party plugins are.
    Builtin,
    /// Any other manifest.
    External,
}

/// A plugin's signing keys, as its manifest's `[index]` table gives them.
#[derive(Debug, Clone, Copy)]
pub struct PluginKeys<'a> {
    pub plugin: &'a str,
    /// The trust anchors, `[index] signing_keys`.
    pub signing_keys: &'a [String],
    pub threshold: u32,
    /// `[index] keys_url`, a keys file signed by the anchors.
    pub keys_url: Option<&'a str>,
    /// Where the manifest came from. A builtin manifest's anchors are pre-approved; every other
    /// manifest's anchors must be trusted by the user.
    pub origin: ManifestOrigin,
}

/// A signed keys file compiled into the binary, identified by its URL.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedKeysFile {
    pub url: &'static str,
    pub data: &'static [u8],
    pub signature: &'static [u8],
}

/// Fetches bytes over the network. Implemented by the HTTP client; tests use an in-memory map.
pub trait Fetcher {
    /// Fetches `url`. `Ok(None)` means the server has no such file, such as an HTTP 404.
    fn fetch(&self, url: &str) -> Result<Option<Vec<u8>>>;
}

impl Fetcher for jtm_fetch::Client {
    fn fetch(&self, url: &str) -> Result<Option<Vec<u8>>> {
        // Index files are the largest thing fetched this way; keys files and signatures are
        // checked against their own, smaller limits after verification starts.
        Ok(self.get_bytes(url, jtm_security::index::MAX_INDEX_FILE as u64)?)
    }
}

/// A signed index compiled into the binary.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddedIndex {
    pub plugin: &'static str,
    pub platform: &'static str,
    pub data: &'static [u8],
    pub signature: &'static [u8],
}

/// Where one plugin's index for one platform can be found.
#[derive(Debug, Clone, Copy)]
pub struct IndexSources<'a> {
    pub plugin: &'a str,
    /// A platform such as `linux-musl-x64`. `{os}` and `{arch}` in URLs are filled from it.
    pub platform: &'a str,
    /// The canonical remote URL from the manifest's `[index] url`. Placeholders other than
    /// `{os}` and `{arch}` must already be filled.
    pub remote_url: &'a str,
    /// `plugins.<name>.index_url`, which replaces the canonical remote entirely.
    pub override_url: Option<&'a str>,
}

/// How to load.
#[derive(Debug, Clone, Copy)]
pub struct LoadOptions {
    /// Fetch from the network even when a local copy exists, as `jtm update` does.
    pub refresh: bool,
    /// Never touch the network.
    pub offline: bool,
    pub policy: ExpiryPolicy,
    pub now: Timestamp,
}

/// The index that was chosen, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginIndex {
    pub index: IndexFile,
    pub source: SourceKind,
    /// The path or URL the chosen copy was read from.
    pub origin: String,
    pub warnings: Vec<Warning>,
}

/// Loads indices for one jtm installation.
pub struct IndexLoader<'a> {
    pub dirs: &'a Dirs,
    pub embedded: &'a [EmbeddedIndex],
    pub embedded_keys: &'a [EmbeddedKeysFile],
    pub fetcher: Option<&'a dyn Fetcher>,
}

impl std::fmt::Debug for IndexLoader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexLoader")
            .field("dirs", &self.dirs)
            .field("embedded", &self.embedded.len())
            .field("embedded_keys", &self.embedded_keys.len())
            .field("fetcher", &self.fetcher.is_some())
            .finish()
    }
}

/// `<data>/state/trust.json`.
pub fn trust_path(dirs: &Dirs) -> PathBuf {
    dirs.state().join("trust.json")
}

/// `<cache>/index/<plugin>/<platform>.json`; the signature sits next to it as `.json.minisig`.
pub fn cache_path(dirs: &Dirs, plugin: &str, platform: &str) -> PathBuf {
    dirs.index_cache()
        .join(dir_name(plugin))
        .join(format!("{platform}.json"))
}

/// `<cache>/index/<plugin>/keys.json`; the signature sits next to it as `.json.minisig`.
pub fn keys_cache_path(dirs: &Dirs, plugin: &str) -> PathBuf {
    dirs.index_cache().join(dir_name(plugin)).join("keys.json")
}

impl IndexLoader<'_> {
    /// The keys that may sign `keys.plugin`'s indices, and any warnings about its keys file.
    ///
    /// Fails with `E_KEY_UNTRUSTED` when the manifest is not builtin and the user trusts fewer
    /// of its anchors than its threshold. A keys file that cannot be fetched or does not verify
    /// only removes its delegated keys, so it can never widen trust.
    pub fn keyring(
        &self,
        keys: &PluginKeys<'_>,
        options: &LoadOptions,
    ) -> Result<(Keyring, Vec<Warning>)> {
        let trust_file = trust_path(self.dirs);
        let state = TrustState::load(&trust_file)?;
        let anchors = match keys.origin {
            ManifestOrigin::Builtin => {
                TrustAnchors::preapproved(keys.plugin, keys.signing_keys, keys.threshold)?
            }
            ManifestOrigin::External => {
                TrustAnchors::confirmed(keys.plugin, keys.signing_keys, keys.threshold, &state)?
            }
        };
        let mut warnings = Vec::new();
        let keys_file = match keys.keys_url {
            Some(url) => match self.load_keys_file(url, &anchors, &state, options)? {
                Ok(file) => Some(file),
                Err(reason) => {
                    warnings.push(Warning {
                        code: W_KEYS_FILE_UNAVAILABLE,
                        message: format!(
                            "using only the signing keys in the `{}` manifest: {reason}",
                            keys.plugin
                        ),
                    });
                    None
                }
            },
            None => None,
        };
        Ok((
            jtm_security::plugin_keyring(&anchors, keys_file.as_ref(), &state),
            warnings,
        ))
    }

    /// Finds the newest valid copy of the keys file at `url`, records it and caches it. The
    /// inner error explains why no copy was usable; the outer one is a failure to write state.
    fn load_keys_file(
        &self,
        url: &str,
        anchors: &TrustAnchors,
        state: &TrustState,
        options: &LoadOptions,
    ) -> Result<std::result::Result<KeysFile, String>> {
        let plugin = anchors.plugin.as_str();
        let cache_file = keys_cache_path(self.dirs, plugin);
        let mut copies: Vec<IndexCopy> = self
            .embedded_keys
            .iter()
            .filter(|e| e.url == url)
            .map(|e| IndexCopy {
                source: SourceKind::Embedded,
                origin: "the embedded snapshot".to_owned(),
                data: e.data.to_vec(),
                signature: e.signature.to_vec(),
            })
            .collect();
        copies.extend(read_local(
            &cache_file,
            SourceKind::Cache,
            jtm_security::keys_json::MAX_KEYS_FILE,
            "the limit for a keys file",
        )?);
        let mut problems = Vec::new();
        if !options.offline
            && (options.refresh || copies.is_empty())
            && let Some(fetcher) = self.fetcher
        {
            match fetch_copy(fetcher, url, SourceKind::Remote) {
                Ok(Some(copy)) => copies.push(copy),
                Ok(None) => problems.push(format!("{url} was not found")),
                Err(err) => problems.push(err.to_string()),
            }
        }

        let mut valid: Vec<(IndexCopy, KeysFile)> = Vec::new();
        let mut conflict: Option<String> = None;
        for copy in copies {
            let loaded = match KeysFile::load(&copy.data, &copy.signature, anchors, options.now) {
                Ok(file) => file,
                Err(err) => {
                    problems.push(format!("{}: {err}", copy.origin));
                    continue;
                }
            };
            match jtm_security::check_keys_file(&loaded, plugin, state) {
                Ok(_) => valid.push((copy, loaded)),
                // The same sequence as one already seen with different content is the conflict
                // `select` refuses for an index: neither copy can be trusted, and the recorded
                // copy is not at hand to fall back on, so the whole keys file is refused.
                Err(jtm_security::Error::IndexRollback { seen, got, .. }) if seen == got => {
                    conflict = Some(format!(
                        "{}: keys.json has sequence {got}, the same as the newest copy already \
                         seen but with different content",
                        copy.origin
                    ));
                }
                Err(err) => problems.push(format!("{}: {err}", copy.origin)),
            }
        }
        if let Some(message) = conflict {
            return Ok(Err(message));
        }
        let Some(top) = valid.iter().map(|(_, file)| file.sequence).max() else {
            if problems.is_empty() {
                problems.push(format!("no copy of {url} is available"));
            }
            return Ok(Err(problems.join("; ")));
        };
        let mut best: Vec<(IndexCopy, KeysFile)> = valid
            .into_iter()
            .filter(|(_, file)| file.sequence == top)
            .collect();
        // The same rule as `select`: two valid copies that claim the same sequence with
        // different content are a rollback, and neither can be trusted.
        if best.iter().any(|(_, file)| file.sha256 != best[0].1.sha256) {
            return Ok(Err(format!(
                "copies from {} differ while claiming sequence {top}",
                best.iter()
                    .map(|(copy, _)| copy.origin.as_str())
                    .collect::<Vec<_>>()
                    .join(" and ")
            )));
        }
        let (copy, file) = best.swap_remove(0);

        TrustState::update(&trust_path(self.dirs), |state| {
            let seen = jtm_security::check_keys_file(&file, plugin, state)?;
            let changed = state.record_keys_file(plugin, seen);
            Ok(((), changed))
        })?;
        if copy.source == SourceKind::Remote {
            write_cache(&cache_file, &copy.data, &copy.signature)?;
        }
        Ok(Ok(file))
    }

    /// Gathers every available copy, verifies each against `keyring`, and returns the valid
    /// one with the highest sequence.
    pub fn load(
        &self,
        sources: &IndexSources<'_>,
        keyring: &Keyring,
        options: &LoadOptions,
    ) -> Result<PluginIndex> {
        let trust_file = trust_path(self.dirs);
        let state = TrustState::load(&trust_file)?;
        let file = format!("{}-{}.json", dir_name(sources.plugin), sources.platform);
        let cache_file = cache_path(self.dirs, sources.plugin, sources.platform);

        let mut copies: Vec<IndexCopy> = self
            .embedded
            .iter()
            .filter(|e| e.plugin == sources.plugin && e.platform == sources.platform)
            .map(|e| IndexCopy {
                source: SourceKind::Embedded,
                origin: "the embedded snapshot".to_owned(),
                data: e.data.to_vec(),
                signature: e.signature.to_vec(),
            })
            .collect();
        copies.extend(read_local(
            &cache_file,
            SourceKind::Cache,
            jtm_security::index::MAX_INDEX_FILE,
            "the limit for an index",
        )?);

        let override_url = sources.override_url.map(|u| expand(u, sources.platform));
        let local_override = override_url.as_deref().and_then(local_path);
        if let Some(path) = &local_override {
            copies.extend(read_local(
                path,
                SourceKind::Mirror,
                jtm_security::index::MAX_INDEX_FILE,
                "the limit for an index",
            )?);
        }

        // A local override is read on every load; a network location only when refreshing or
        // when no local copy exists.
        let network = match (&override_url, &local_override) {
            (Some(_), Some(_)) => None,
            (Some(url), None) => Some((url.clone(), SourceKind::Mirror)),
            (None, _) => Some((
                expand(sources.remote_url, sources.platform),
                SourceKind::Remote,
            )),
        };
        let mut not_found = false;
        let mut fetch_error = None;
        if let Some((url, source)) = network
            && !options.offline
            && (options.refresh || copies.is_empty())
            && let Some(fetcher) = self.fetcher
        {
            match fetch_copy(fetcher, &url, source) {
                Ok(Some(copy)) => copies.push(copy),
                Ok(None) => not_found = true,
                Err(err) => fetch_error = Some(err),
            }
        }

        let selection = Selection {
            request: IndexRequest {
                plugin: sources.plugin,
                platform: sources.platform,
            },
            file: &file,
            keyring,
            state: &state,
            policy: options.policy,
            now: options.now,
        };
        let selected = match jtm_security::select(copies, selection) {
            Ok(Some(selected)) => selected,
            Ok(None) => {
                return Err(match fetch_error {
                    Some(err) => err,
                    None if not_found => JtmError::PlatformUnsupported {
                        tool: sources.plugin.to_owned(),
                        platform: sources.platform.to_owned(),
                    },
                    None if options.offline => JtmError::Offline {
                        action: format!("loading the `{}` index", sources.plugin),
                    },
                    None => JtmError::internal(format!(
                        "no copy of the `{}` index for {} is available and this jtm cannot \
                         fetch one",
                        sources.plugin, sources.platform
                    )),
                });
            }
            Err(err) => return Err(err.into()),
        };

        let mut warnings = selected.warnings.clone();
        if let Some(err) = fetch_error {
            warnings.push(Warning {
                code: W_INDEX_REFRESH_FAILED,
                message: format!("could not refresh the `{}` index: {err}", sources.plugin),
            });
        }

        TrustState::update(&trust_file, |state| {
            let changed = state.record_index(
                sources.plugin,
                sources.platform,
                selected.accepted.seen.clone(),
            );
            Ok(((), changed))
        })?;
        if matches!(selected.source, SourceKind::Remote | SourceKind::Mirror) {
            write_cache(&cache_file, &selected.data, &selected.signature)?;
        }

        Ok(PluginIndex {
            index: selected.loaded.index,
            source: selected.source,
            origin: selected.origin,
            warnings,
        })
    }
}

/// Fills `{os}` and `{arch}` from a platform such as `linux-musl-x64` (`linux-musl`, `x64`).
fn expand(url: &str, platform: &str) -> String {
    let (os, arch) = platform.rsplit_once('-').unwrap_or((platform, platform));
    url.replace("{os}", os).replace("{arch}", arch)
}

/// The local path a `file://` URL or plain path names, or `None` for a network URL.
fn local_path(location: &str) -> Option<PathBuf> {
    if location.starts_with("https://") || location.starts_with("http://") {
        return None;
    }
    let Some(rest) = location.strip_prefix("file://") else {
        return Some(PathBuf::from(location));
    };
    // `file:///C:/x` names `C:/x` on Windows.
    let bytes = rest.as_bytes();
    let windows_drive = bytes.len() >= 3 && bytes[0] == b'/' && bytes[2] == b':';
    Some(PathBuf::from(if windows_drive { &rest[1..] } else { rest }))
}

fn signature_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".minisig");
    path.with_file_name(name)
}

/// Reads a copy and its signature from disk, refusing either over the limit for its format. A
/// missing file is no copy; a missing signature is a copy with an empty signature, so it is
/// reported as unsigned rather than ignored.
fn read_local(
    path: &Path,
    source: SourceKind,
    limit: usize,
    what: &str,
) -> Result<Option<IndexCopy>> {
    let data = match read_capped(path, limit, what) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(JtmError::io(path, e)),
    };
    let sig_path = signature_path(path);
    let signature = match read_capped(
        &sig_path,
        jtm_security::signature::MAX_SIGNATURE_FILE,
        "the limit for a signature file",
    ) {
        Ok(sig) => sig,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(JtmError::io(&sig_path, e)),
    };
    Ok(Some(IndexCopy {
        source,
        origin: path.display().to_string(),
        data,
        signature,
    }))
}

/// Reads a file, refusing one larger than its format's limit before reading it.
fn read_capped(path: &Path, limit: usize, what: &str) -> io::Result<Vec<u8>> {
    let len = fs::metadata(path)?.len();
    if len > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("larger than {what}"),
        ));
    }
    fs::read(path)
}

fn fetch_copy(fetcher: &dyn Fetcher, url: &str, source: SourceKind) -> Result<Option<IndexCopy>> {
    let Some(data) = fetcher.fetch(url)? else {
        return Ok(None);
    };
    let sig_url = format!("{url}.minisig");
    // A missing signature is fetched as empty and fails verification, never skipped.
    let signature = fetcher.fetch(&sig_url)?.unwrap_or_default();
    Ok(Some(IndexCopy {
        source,
        origin: url.to_owned(),
        data,
        signature,
    }))
}

/// Saves a verified copy, signature first, each replaced atomically.
fn write_cache(path: &Path, data: &[u8], signature: &[u8]) -> Result<()> {
    if fs::read(path).is_ok_and(|old| old == data) {
        return Ok(());
    }
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(|e| JtmError::io(dir, e))?;
    jtm_security::trust::write_atomically(&signature_path(path), signature)?;
    jtm_security::trust::write_atomically(path, data)?;
    Ok(())
}

#[cfg(test)]
mod tests;
