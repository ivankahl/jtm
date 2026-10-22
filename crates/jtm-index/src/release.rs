//! Checking a release before it is published, the way a client will (SPEC.md sections 8 and 9).
//!
//! The generator checks each file against the signing key it was given. That cannot tell
//! whether a client will accept the file, because a client trusts the index key only if the
//! release's `keys.json`, signed by the plugin's root keys, delegates to it for this plugin and
//! the delegation has not expired. This module runs jtm's own loader over a directory laid out
//! as a release is, with the manifest's `[index] url` and `keys_url` served from that directory,
//! so the answer is the client's answer: a key the root never delegated to, a delegation for
//! another plugin, an expired key, a `keys.json` the root keys did not sign and a file name the
//! manifest does not ask for are all refused with the client's code.
//!
//! Nothing is read from the network or from the user's jtm state: the loader runs in a
//! temporary home that is removed afterwards.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use jtm_core::dirs::dir_name;
use jtm_core::indices::{
    Fetcher, IndexLoader, IndexSources, LoadOptions, ManifestOrigin, PluginKeys,
    W_KEYS_FILE_UNAVAILABLE, expand,
};
use jtm_core::{Dirs, JtmError, Os, Platform};
use jtm_security::index::MAX_INDEX_FILE;
use jtm_security::{ExpiryPolicy, KeysFile, Timestamp, TrustAnchors};
use serde::Serialize;

use crate::error::{Error, Result};
use crate::plugin::read_manifest;
use crate::writer::Warning;

/// The warning code for an index key whose delegation ends soon.
pub const W_KEY_EXPIRES_SOON: &str = "W_KEY_EXPIRES_SOON";

const DAY: i64 = 86_400;

/// What to check.
#[derive(Debug)]
pub struct Request<'a> {
    /// The directory a release is made from: index files, their `.minisig` files, `keys.json`
    /// and `keys.json.minisig`.
    pub published: &'a Path,
    /// The plugin directories whose manifests say what to expect. Only `plugin.toml` is read.
    pub plugin_dirs: &'a [PathBuf],
    /// Root keys to use instead of each manifest's `signing_keys`, for a rehearsal with
    /// throwaway keys. The manifest's threshold still applies. Empty means the manifest's.
    pub root_keys: &'a [String],
    pub now: Timestamp,
    /// A warning is raised when the newest delegated key of a plugin ends sooner than this many
    /// days from `now`.
    pub min_key_days: u32,
}

/// What was checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub published: String,
    pub plugins: Vec<PluginReport>,
    /// Reported beside the data, in the envelope's `warnings`.
    #[serde(skip)]
    pub warnings: Vec<Warning>,
}

/// One plugin's files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginReport {
    pub plugin: String,
    /// The `sequence` of the verified `keys.json`, for a plugin that has one.
    pub keys_sequence: Option<u64>,
    /// When the newest delegated key that covers the plugin stops being valid.
    pub newest_key_expires: Option<String>,
    pub files: Vec<VerifiedFile>,
}

/// One index file that a client accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedFile {
    pub file: String,
    pub platform: String,
    pub sequence: u64,
    pub generated: String,
    pub expires: String,
    pub entries: usize,
}

/// Serves the files of a release directory by file name, whatever the URL says.
struct ReleaseDir<'a>(&'a Path);

impl Fetcher for ReleaseDir<'_> {
    fn fetch(&self, url: &str) -> jtm_core::Result<Option<Vec<u8>>> {
        let name = file_name(url);
        if name.is_empty() || name == "." || name == ".." || name.contains('\\') {
            return Ok(None);
        }
        let path = self.0.join(name);
        if !path.is_file() {
            return Ok(None);
        }
        // One byte over the loader's limit is enough for it to refuse the file.
        let mut bytes = Vec::new();
        File::open(&path)
            .and_then(|file| file.take(MAX_INDEX_FILE as u64 + 1).read_to_end(&mut bytes))
            .map_err(|source| JtmError::Io { path, source })?;
        Ok(Some(bytes))
    }
}

/// The last path segment of a URL, without query or fragment.
fn file_name(url: &str) -> &str {
    url.split(['?', '#'])
        .next()
        .and_then(|path| path.rsplit('/').next())
        .unwrap_or_default()
}

/// Checks `req.published` for every plugin in `req.plugin_dirs`.
pub fn verify(req: &Request<'_>) -> Result<Report> {
    let home = tempfile::tempdir().map_err(Error::Io)?;
    let os = Os::host().ok_or_else(|| {
        Error::Client(JtmError::internal("this operating system is not supported"))
    })?;
    let dirs = Dirs::resolve(os, Some(home.path()), None, &|_| None)?;
    let fetcher = ReleaseDir(req.published);
    let loader = IndexLoader {
        dirs: &dirs,
        embedded: &[],
        embedded_keys: &[],
        fetcher: Some(&fetcher),
    };
    let options = LoadOptions {
        refresh: true,
        offline: false,
        policy: ExpiryPolicy::Enforce,
        now: req.now,
    };

    let mut plugins = Vec::new();
    let mut warnings = Vec::new();
    for dir in req.plugin_dirs {
        let manifest = read_manifest(dir)?;
        let name = manifest.name.as_str();
        let signing_keys: &[String] = if req.root_keys.is_empty() {
            &manifest.index.signing_keys
        } else {
            req.root_keys
        };
        let keys = PluginKeys {
            plugin: name,
            signing_keys,
            threshold: manifest.index.threshold(),
            keys_url: manifest.index.keys_url.as_deref(),
            // The files are checked as the first-party manifests are: their anchors are the
            // ones compiled into jtm.
            origin: ManifestOrigin::Builtin,
        };
        let (keyring, keys_warnings) = loader.keyring(&keys, &options)?;
        if let Some(warning) = keys_warnings
            .iter()
            .find(|w| w.code == W_KEYS_FILE_UNAVAILABLE)
        {
            return Err(Error::KeysFile {
                message: format!(
                    "keys.json of the release cannot be used for `{name}`: {}",
                    warning.message
                ),
            });
        }
        let horizon = match keys.keys_url {
            Some(_) => key_horizon(req, &keys)?,
            None => None,
        };

        let platforms: Vec<&str> = if manifest.index.platform_independent() {
            vec![jtm_plugin::manifest::ANY_PLATFORM]
        } else {
            Platform::ALL.iter().map(|p| p.as_str()).collect()
        };
        let mut files = Vec::new();
        for platform in platforms {
            let file = format!("{}-{platform}.json", dir_name(name));
            if !req.published.join(&file).is_file() {
                continue;
            }
            let sources = IndexSources {
                plugin: name,
                platform,
                remote_url: &manifest.index.url,
                override_url: None,
            };
            let loaded = loader
                .load(&sources, &keyring, &options)
                .map_err(|e| match e {
                    // The loader asks for the name the manifest gives, so a name that differs from
                    // the file the generator wrote is found here, not by a user's `jtm install`.
                    JtmError::PlatformUnsupported { .. } => Error::Invalid {
                        message: format!(
                            "the `{name}` manifest asks for {}, but the release holds {file}",
                            expand(&manifest.index.url, platform)
                                .rsplit('/')
                                .next()
                                .unwrap_or_default()
                        ),
                    },
                    other => Error::Client(other),
                })?;
            files.push(VerifiedFile {
                file,
                platform: platform.to_owned(),
                sequence: loaded.index.sequence,
                generated: loaded.index.generated.to_string(),
                expires: loaded.index.expires.to_string(),
                entries: loaded.index.entries.len(),
            });
        }
        if files.is_empty() {
            return Err(Error::Invalid {
                message: format!(
                    "the release holds no index file of `{name}` in {}",
                    req.published.display()
                ),
            });
        }

        if let Some((_, newest)) = horizon
            && newest.unix() - req.now.unix() < i64::from(req.min_key_days) * DAY
        {
            warnings.push(Warning {
                code: W_KEY_EXPIRES_SOON,
                message: format!(
                    "the newest index key for `{name}` is valid until {newest}, less than {} \
                     days from now; publish a new keys.json before then",
                    req.min_key_days
                ),
            });
        }
        plugins.push(PluginReport {
            plugin: name.to_owned(),
            keys_sequence: horizon.map(|(sequence, _)| sequence),
            newest_key_expires: horizon.map(|(_, newest)| newest.to_string()),
            files,
        });
    }
    Ok(Report {
        published: req.published.display().to_string(),
        plugins,
        warnings,
    })
}

/// The `sequence` of the release's keys file and the latest end of any delegation that covers
/// the plugin and has not ended yet. `None` when no listed key does, which the loader then
/// reports as an untrusted signer.
fn key_horizon(req: &Request<'_>, keys: &PluginKeys<'_>) -> Result<Option<(u64, Timestamp)>> {
    let anchors = TrustAnchors::preapproved(keys.plugin, keys.signing_keys, keys.threshold)
        .map_err(|e| Error::KeysFile {
            message: e.to_string(),
        })?;
    let read = |name: &str| {
        std::fs::read(req.published.join(name)).map_err(|source| Error::Output {
            path: req.published.join(name),
            source,
        })
    };
    // The loader fetches the file the manifest's `keys_url` names, so this reads the same one.
    let name = file_name(keys.keys_url.unwrap_or_default());
    let file = KeysFile::load(
        &read(name)?,
        &read(&format!("{name}.minisig"))?,
        &anchors,
        req.now,
    )
    .map_err(|e| Error::KeysFile {
        message: format!("{name} of the release cannot be used: {e}"),
    })?;
    let newest = file
        .keys
        .iter()
        .filter(|k| k.scope.covers(keys.plugin) && k.expires > req.now)
        .map(|k| k.expires)
        .max();
    Ok(newest.map(|newest| (file.sequence, newest)))
}

#[cfg(test)]
mod tests;
