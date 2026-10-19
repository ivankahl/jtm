//! Loading a plugin's version index from every source it may come from (SPEC.md section 8).
//!
//! The copies are the snapshot embedded in the binary, the verified copy in the cache, a
//! configured `plugins.<name>.index_url` override, and the canonical remote. Every copy is
//! verified and checked the same way, and the valid copy with the highest sequence is used. A
//! copy that came over the network is saved to the cache, and the accepted sequence is recorded
//! in `state/trust.json` for rollback protection.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use jtm_security::select::{IndexCopy, Selection};
use jtm_security::{
    ExpiryPolicy, IndexFile, IndexRequest, KeyGroup, Keyring, KeysFile, PublicKey, Scope,
    SourceKind, Timestamp, TrustState, TrustedKey, Warning,
};

use crate::dirs::{Dirs, dir_name};
use crate::error::{JtmError, Result};

/// Warning code when the network copy could not be fetched and a local copy was used.
pub const W_INDEX_REFRESH_FAILED: &str = "W_INDEX_REFRESH_FAILED";

/// Fetches bytes over the network. Implemented by the HTTP client; tests use an in-memory map.
pub trait Fetcher {
    /// Fetches `url`. `Ok(None)` means the server has no such file, such as an HTTP 404.
    fn fetch(&self, url: &str) -> Result<Option<Vec<u8>>>;
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
    pub fetcher: Option<&'a dyn Fetcher>,
}

impl std::fmt::Debug for IndexLoader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexLoader")
            .field("dirs", &self.dirs)
            .field("embedded", &self.embedded.len())
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

impl IndexLoader<'_> {
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
        copies.extend(read_local(&cache_file, SourceKind::Cache)?);

        let override_url = sources.override_url.map(|u| expand(u, sources.platform));
        let local_override = override_url.as_deref().and_then(local_path);
        if let Some(path) = &local_override {
            copies.extend(read_local(path, SourceKind::Mirror)?);
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

/// The keys trusted for `plugin`'s indices, each group able to accept an index on its own:
/// the `keys.json` index keys (first-party plugins), the signing keys pinned in the plugin's
/// manifest (third-party plugins), and keys the user added with `jtm trust add`.
pub fn keyring_for(
    plugin: &str,
    manifest_keys: &[String],
    keys_json: Option<&KeysFile>,
    state: &TrustState,
) -> Result<Keyring> {
    let mut keyring = Keyring::new();
    if let Some(keys) = keys_json {
        keyring = keyring.with(keys.group());
    }
    if !manifest_keys.is_empty() {
        let scope = Scope::plugins([plugin]).map_err(JtmError::internal)?;
        let keys = manifest_keys
            .iter()
            .map(|k| {
                Ok(TrustedKey {
                    key: PublicKey::parse(k).map_err(|e| JtmError::internal(e.to_string()))?,
                    scope: scope.clone(),
                    expires: None,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        keyring = keyring.with(KeyGroup {
            origin: format!("the `{plugin}` plugin manifest"),
            keys,
            threshold: 1,
        });
    }
    Ok(keyring.with(state.user_group()))
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

/// Reads a copy and its signature from disk. A missing file is no copy; a missing signature
/// is a copy with an empty signature, so it is reported as unsigned rather than ignored.
fn read_local(path: &Path, source: SourceKind) -> Result<Option<IndexCopy>> {
    let data = match read_capped(path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_error(path, e)),
    };
    let sig_path = signature_path(path);
    let signature = match read_capped(&sig_path) {
        Ok(sig) => sig,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(io_error(&sig_path, e)),
    };
    Ok(Some(IndexCopy {
        source,
        origin: path.display().to_string(),
        data,
        signature,
    }))
}

/// Reads a file, refusing one larger than any index can be before reading it.
fn read_capped(path: &Path) -> io::Result<Vec<u8>> {
    let len = fs::metadata(path)?.len();
    if len > jtm_security::index::MAX_INDEX_FILE as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "larger than any index jtm accepts",
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
    fs::create_dir_all(dir).map_err(|e| io_error(dir, e))?;
    jtm_security::trust::write_atomically(&signature_path(path), signature)?;
    jtm_security::trust::write_atomically(path, data)?;
    Ok(())
}

fn io_error(path: &Path, source: io::Error) -> JtmError {
    jtm_security::Error::Io {
        path: path.to_path_buf(),
        source,
    }
    .into()
}

#[cfg(test)]
mod tests;
