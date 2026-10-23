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
//! keys, and company keys the user config lists for the plugin (`plugins.<name>.signing_keys`)
//! may re-sign its indices. The only difference is that anchors in a manifest compiled into jtm
//! ([`ManifestOrigin::Builtin`]) are pre-approved, while any other manifest's anchors
//! ([`ManifestOrigin::External`]) count only once the user config lists them.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use jtm_fetch::mirrors::{Location, local_path, resolve};
use jtm_security::select::{IndexCopy, Selection};
use jtm_security::{
    ExpiryPolicy, IndexFile, IndexRequest, Keyring, KeysFile, PublicKey, SourceKind, Timestamp,
    TrustAnchors, TrustState, Warning,
};

use crate::dirs::{Dirs, dir_name};
use crate::error::{JtmError, Result};

/// Warning code when the network copy could not be fetched and a local copy was used.
pub const W_INDEX_REFRESH_FAILED: &str = "W_INDEX_REFRESH_FAILED";
/// Warning code when a plugin's keys file is unavailable or invalid, so only its anchors and
/// the company keys in the user config can verify its indices.
pub const W_KEYS_FILE_UNAVAILABLE: &str = "W_KEYS_FILE_UNAVAILABLE";

/// Where a plugin manifest came from, which decides whether its anchors are pre-approved.
///
/// Pre-approval is provenance, never a property of a key or of a file's contents: `Builtin` is
/// only for manifests compiled into the jtm binary. The unpacked `<data>/plugins/builtin`
/// working copy, the marketplace, a project directory and the network are all `External`, so
/// their anchors count only once the user config lists them.
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
    /// manifest's anchors must be listed in `company_keys`.
    pub origin: ManifestOrigin,
    /// `plugins.<name>.signing_keys` from the user config: company keys that may sign this
    /// plugin's indices on their own. They count for this plugin only.
    pub company_keys: &'a [PublicKey],
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
    /// The canonical remote URL from the manifest's `[index] url`. `{os}`, `{arch}` and
    /// `{index_version}` are filled when it is used.
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

/// The exact bytes of a verified file and the detached signature that verified them. These are
/// what `jtm mirror export` copies: a mirror holds the signed bytes, never a re-serialisation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCopy {
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

/// The index that was chosen, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginIndex {
    pub index: IndexFile,
    /// The raw bytes `index` was parsed from, and their signature, after verification.
    pub copy: SignedCopy,
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
    /// `[mirrors]` prefix rewrites. They apply to the canonical URL of every index and keys
    /// file and, separately, to the URL of its `.minisig`. A `file://` or path target is read
    /// from disk even offline. A rewrite changes where bytes come from, never how they are
    /// verified.
    pub mirrors: &'a BTreeMap<String, String>,
}

impl std::fmt::Debug for IndexLoader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexLoader")
            .field("dirs", &self.dirs)
            .field("embedded", &self.embedded.len())
            .field("embedded_keys", &self.embedded_keys.len())
            .field("fetcher", &self.fetcher.is_some())
            .field("mirrors", &self.mirrors.len())
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
    /// Fails with `E_KEY_UNTRUSTED` when the manifest is not builtin and the user config lists
    /// fewer of its anchors than its threshold. A keys file that cannot be fetched or does not
    /// verify only removes its delegated keys, so it can never widen trust.
    pub fn keyring(
        &self,
        keys: &PluginKeys<'_>,
        options: &LoadOptions,
    ) -> Result<(Keyring, Vec<Warning>)> {
        let (keyring, _, warnings) = self.keyring_with_keys_file(keys, options)?;
        Ok((keyring, warnings))
    }

    /// [`IndexLoader::keyring`], and also the verified bytes of the keys file it used, if any.
    pub fn keyring_with_keys_file(
        &self,
        keys: &PluginKeys<'_>,
        options: &LoadOptions,
    ) -> Result<(Keyring, Option<SignedCopy>, Vec<Warning>)> {
        let trust_file = trust_path(self.dirs);
        let state = TrustState::load(&trust_file)?;
        let anchors = match keys.origin {
            ManifestOrigin::Builtin => {
                TrustAnchors::preapproved(keys.plugin, keys.signing_keys, keys.threshold)?
            }
            ManifestOrigin::External => TrustAnchors::confirmed(
                keys.plugin,
                keys.signing_keys,
                keys.threshold,
                keys.company_keys,
            )?,
        };
        let mut warnings = Vec::new();
        let keys_file = match keys.keys_url {
            Some(url) => match self.load_keys_file(url, &anchors, &state, options)? {
                Ok(loaded) => Some(loaded),
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
        let keyring = jtm_security::plugin_keyring(
            &anchors,
            keys_file.as_ref().map(|(file, _)| file),
            keys.company_keys,
        );
        Ok((keyring, keys_file.map(|(_, copy)| copy), warnings))
    }

    /// Finds the newest valid copy of the keys file at `url`, records it and caches it. The
    /// inner error explains why no copy was usable; the outer one is a failure to write state.
    fn load_keys_file(
        &self,
        url: &str,
        anchors: &TrustAnchors,
        state: &TrustState,
        options: &LoadOptions,
    ) -> Result<std::result::Result<(KeysFile, SignedCopy), String>> {
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
        match self.locate(url, SourceKind::Remote) {
            Err(err) => problems.push(err.to_string()),
            Ok(Located::Local(path)) => match read_local(
                &path,
                SourceKind::Mirror,
                jtm_security::keys_json::MAX_KEYS_FILE,
                "the limit for a keys file",
            )? {
                Some(copy) => copies.push(copy),
                None => problems.push(format!("{} was not found", path.display())),
            },
            Ok(Located::Remote(remote)) => {
                if !options.offline
                    && (options.refresh || copies.is_empty())
                    && let Some(fetcher) = self.fetcher
                {
                    match fetch_copy(fetcher, &remote) {
                        Ok(Some(copy)) => copies.push(copy),
                        Ok(None) => problems.push(format!("{} was not found", remote.url)),
                        Err(err) => problems.push(err.to_string()),
                    }
                }
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
        if matches!(copy.source, SourceKind::Remote | SourceKind::Mirror) {
            write_cache(&cache_file, &copy.data, &copy.signature)?;
        }
        Ok(Ok((
            file,
            SignedCopy {
                data: copy.data,
                signature: copy.signature,
            },
        )))
    }

    /// Applies `[mirrors]` to the canonical `url` of an index or keys file, and to the URL of
    /// its signature. For a network copy the signature is looked for where its own rewritten
    /// URL leads; a local file's signature is always read next to it.
    fn locate(&self, url: &str, source: SourceKind) -> Result<Located> {
        // SPEC-QUESTION: section 8 says mirrors apply to "index URLs and artifact URLs" and is
        // silent on `keys_url` and on `.minisig` files. `keys_url` is rewritten like an index
        // URL and the signature URL as a URL of its own, so a corporate network only needs
        // the approved hosts (section 13). A `plugins.<name>.index_url` override is used as
        // written and is not rewritten.
        match resolve(url, self.mirrors)? {
            Location::File { path, .. } => Ok(Located::Local(path)),
            Location::Url(rewritten) => Ok(Located::Remote(Remote {
                // Section 9 enforces expiry only for the canonical remote; a copy that came
                // through a `[mirrors]` rewrite is a mirror copy, like an `https` `index_url`.
                source: if rewritten == url {
                    source
                } else {
                    SourceKind::Mirror
                },
                sig: resolve(&format!("{url}.minisig"), self.mirrors)?,
                url: rewritten,
            })),
        }
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

        // A plugin's `index_url` replaces the canonical location entirely and is used as
        // written. Otherwise `[mirrors]` rewrite the canonical URL, and may lead to a file.
        let mut fetch_error = None;
        let located = match sources.override_url.map(|u| expand(u, sources.platform)) {
            Some(url) => Ok(match local_path(&url) {
                Some(path) => Located::Local(path),
                None => Located::Remote(Remote {
                    sig: Location::Url(format!("{url}.minisig")),
                    url,
                    source: SourceKind::Mirror,
                }),
            }),
            None => self.locate(
                &expand(sources.remote_url, sources.platform),
                SourceKind::Remote,
            ),
        };
        // A local copy is read on every load; a network location only when refreshing or
        // when no local copy exists.
        let network = match located {
            Ok(Located::Local(path)) => {
                copies.extend(read_local(
                    &path,
                    SourceKind::Mirror,
                    jtm_security::index::MAX_INDEX_FILE,
                    "the limit for an index",
                )?);
                None
            }
            Ok(Located::Remote(remote)) => Some(remote),
            Err(err) => {
                fetch_error = Some(err);
                None
            }
        };
        let mut not_found = false;
        if let Some(remote) = network
            && !options.offline
            && (options.refresh || copies.is_empty())
            && let Some(fetcher) = self.fetcher
        {
            match fetch_copy(fetcher, &remote) {
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
            copy: SignedCopy {
                data: selected.data,
                signature: selected.signature,
            },
            source: selected.source,
            origin: selected.origin,
            warnings,
        })
    }
}

/// What `{index_version}` stands for in an index URL.
///
/// There is no version to learn: the canonical remote publishes every index as an asset of its
/// newest release, which a stable `latest` location always serves (SPEC.md section 8). Rollback
/// protection rests on the signed `sequence`, not on which release a copy came from, so a
/// client never needs a release name. The placeholder stays valid so that a manifest written
/// for it still loads; it works for a host that keeps its newest index under a `latest` path
/// or tag, and a manifest that names a release in some other way should not use it.
pub const INDEX_VERSION_LATEST: &str = "latest";

/// Fills `{os}` and `{arch}` from a platform such as `linux-musl-x64` (`linux-musl`, `x64`),
/// and `{index_version}` with [`INDEX_VERSION_LATEST`].
pub fn expand(url: &str, platform: &str) -> String {
    let (os, arch) = platform.rsplit_once('-').unwrap_or((platform, platform));
    url.replace("{os}", os)
        .replace("{arch}", arch)
        .replace("{index_version}", INDEX_VERSION_LATEST)
}

/// Where a copy is read from once `[mirrors]` or an `index_url` override has been applied.
enum Located {
    /// A file on disk, with its signature next to it.
    Local(PathBuf),
    Remote(Remote),
}

/// A copy to fetch over the network, and where its signature is.
struct Remote {
    url: String,
    /// Where the `.minisig` is, rewritten separately from `url`.
    sig: Location,
    source: SourceKind,
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
    // A missing signature is empty and fails verification, never skipped.
    let signature = read_signature(&signature_path(path))?.unwrap_or_default();
    Ok(Some(IndexCopy {
        source,
        origin: path.display().to_string(),
        data,
        signature,
    }))
}

/// Reads a signature file, or `None` when it does not exist.
fn read_signature(path: &Path) -> Result<Option<Vec<u8>>> {
    match read_capped(
        path,
        jtm_security::signature::MAX_SIGNATURE_FILE,
        "the limit for a signature file",
    ) {
        Ok(sig) => Ok(Some(sig)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(JtmError::io(path, e)),
    }
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

fn fetch_copy(fetcher: &dyn Fetcher, remote: &Remote) -> Result<Option<IndexCopy>> {
    let Some(data) = fetcher.fetch(&remote.url)? else {
        return Ok(None);
    };
    let signature = match &remote.sig {
        Location::Url(url) => fetcher.fetch(url)?,
        Location::File { path, .. } => read_signature(path)?,
    };
    Ok(Some(IndexCopy {
        source: remote.source,
        origin: remote.url.clone(),
        data,
        // A missing signature is empty and fails verification, never skipped.
        signature: signature.unwrap_or_default(),
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
