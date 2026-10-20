//! The operations behind `jtm install`, `uninstall`, `list` and `available` (SPEC.md sections
//! 4 and 10). The CLI and, later, the MCP server call these and render what they return.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use jtm_fetch::{Client, ClientOptions, DownloadCache};
use jtm_plugin::{Candidate, ResolveError};
use jtm_security::{IndexEntry, Timestamp, Warning};
use serde::Serialize;

use crate::config::{AutoRefresh, Config, ConfigInputs, FileSource, Settings};
use crate::context::Context;
use crate::dirs::{Dirs, dir_name};
use crate::error::{JtmError, Result};
use crate::indices::{
    EmbeddedIndex, EmbeddedKeysFile, Fetcher, IndexLoader, IndexSources, LoadOptions, PluginIndex,
    PluginKeys, cache_path,
};
use crate::install::{self, Archives, InstallRequest, Progress, Receipt, Status};
use crate::platform::Platform;
use crate::plugins::{BUILTIN, Plugin, Registry};
use crate::spec::ToolSpec;

/// Warning code when uninstalling the version the user default pointed at.
pub const W_DEFAULT_CLEARED: &str = "W_DEFAULT_CLEARED";

/// The first-party indices compiled into this build.
// Embedded by T6.6; until then every index comes from the cache or the network.
const EMBEDDED_INDICES: &[EmbeddedIndex] = &[];
const EMBEDDED_KEYS: &[EmbeddedKeysFile] = &[];

/// Everything an operation needs: directories, configuration, the platform and the network.
#[derive(Debug)]
pub struct Session<'a> {
    pub ctx: &'a Context,
    pub dirs: Dirs,
    pub settings: Settings,
    pub platform: Platform,
    client: Option<Client>,
    cache: DownloadCache,
}

/// One version as install, uninstall and list report it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionItem {
    pub tool: String,
    pub variant: String,
    pub version: String,
    pub path: String,
}

/// What `install` did, or with `dry_run` would do, for one spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallItem {
    #[serde(flatten)]
    pub version: VersionItem,
    /// `installed`, `already_installed` or, for a dry run, `would_install`.
    pub status: &'static str,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    /// Whether the archive is already in the download cache.
    pub cached: bool,
}

/// One installed version, as `list` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstalledItem {
    #[serde(flatten)]
    pub version: VersionItem,
    pub platform: String,
    pub installed_at: String,
}

/// One installable version, as `available` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AvailableItem {
    pub variant: String,
    pub version: String,
    pub tags: Vec<String>,
    pub installed: bool,
}

/// What `available` reports for one tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Available {
    pub tool: String,
    pub platform: String,
    pub versions: Vec<AvailableItem>,
    /// Each alias and the version it resolves to in the default variant.
    pub aliases: BTreeMap<String, String>,
}

/// Options for [`Session::install`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InstallOptions {
    pub force: bool,
    pub dry_run: bool,
    /// Refresh the index first, so the newest versions are seen.
    pub latest: bool,
}

/// Options for [`Session::available`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AvailableOptions {
    pub variant: Option<String>,
    pub alias: Option<String>,
    /// Include every variant, not only the default.
    pub all: bool,
}

impl<'a> Session<'a> {
    /// Opens a session from the process environment.
    pub fn open(ctx: &'a Context) -> Result<Session<'a>> {
        let dirs = Dirs::for_context(ctx)?;
        let config = load_config(&dirs, &|key| std::env::var_os(key))?;
        Session::new(ctx, dirs, config.settings, Platform::detect()?)
    }

    pub fn new(
        ctx: &'a Context,
        dirs: Dirs,
        settings: Settings,
        platform: Platform,
    ) -> Result<Session<'a>> {
        let cache = DownloadCache::new(
            settings
                .download
                .cache_dir
                .clone()
                .unwrap_or_else(|| dirs.downloads()),
        );
        let client = if ctx.offline {
            None
        } else {
            Some(Client::new(ClientOptions {
                allow_http: settings.security.allow_http_mirrors,
                ..ClientOptions::new(env!("CARGO_PKG_VERSION"))
            })?)
        };
        Ok(Session {
            ctx,
            dirs,
            settings,
            platform,
            client,
            cache,
        })
    }

    pub fn registry(&self) -> Registry<'_> {
        Registry {
            dirs: &self.dirs,
            builtin: BUILTIN,
        }
    }

    pub fn plugin(&self, name: &str) -> Result<Plugin> {
        self.registry().find(name)
    }

    /// Loads and verifies `plugin`'s index for this platform. `refresh` fetches a new copy as
    /// `jtm update` does.
    pub fn index(&self, plugin: &Plugin, refresh: bool) -> Result<PluginIndex> {
        let manifest = &plugin.manifest;
        let name = manifest.name.as_str();
        let loader = IndexLoader {
            dirs: &self.dirs,
            embedded: EMBEDDED_INDICES,
            embedded_keys: EMBEDDED_KEYS,
            fetcher: self.client.as_ref().map(|c| c as &dyn Fetcher),
        };
        let options = LoadOptions {
            refresh,
            offline: self.ctx.offline,
            policy: self.settings.security.expiry.into(),
            now: Timestamp::now(),
        };
        let keys = PluginKeys {
            plugin: name,
            signing_keys: &manifest.index.signing_keys,
            threshold: manifest.index.threshold(),
            keys_url: manifest.index.keys_url.as_deref(),
            origin: plugin.origin,
        };
        let (keyring, mut warnings) = loader.keyring(&keys, &options)?;
        let override_url = self
            .settings
            .plugins
            .get(name)
            .and_then(|p| p.index_url.as_deref());
        // SPEC-QUESTION: nothing yet says what fills `{index_version}`; such a URL is only
        // usable through `plugins.<name>.index_url` or a copy already embedded or cached.
        let remote_url = jtm_fetch::mirrors::rewrite(&manifest.index.url, &self.settings.mirrors);
        let mut index = loader.load(
            &IndexSources {
                plugin: name,
                platform: self.platform.as_str(),
                remote_url: &remote_url,
                override_url,
            },
            &keyring,
            &options,
        )?;
        warnings.append(&mut index.warnings);
        index.warnings = warnings;
        Ok(index)
    }

    /// Whether a spec that local data cannot resolve may refresh the index (SPEC.md section
    /// 8): never offline, in JSON mode or under CI, and otherwise per `index.auto_refresh`,
    /// once the cached copy is older than `index.ttl_hours`.
    fn may_auto_refresh(&self, plugin: &str) -> bool {
        if self.ctx.offline || self.ctx.json || self.ctx.ci {
            return false;
        }
        let allowed = match self.settings.index.auto_refresh {
            AutoRefresh::Never => false,
            AutoRefresh::Always => true,
            AutoRefresh::Tty => self.ctx.interactive,
        };
        let ttl = Duration::from_secs(u64::from(self.settings.index.ttl_hours) * 3600);
        let stale = fs::metadata(cache_path(&self.dirs, plugin, self.platform.as_str()))
            .and_then(|m| m.modified())
            .map_or(true, |at| {
                SystemTime::now().duration_since(at).unwrap_or_default() >= ttl
            });
        allowed && stale
    }

    /// Resolves `spec` to one index entry, refreshing the index once when local data cannot
    /// resolve it and the refresh policy allows.
    pub fn resolve(
        &self,
        spec: &ToolSpec,
        plugin: &Plugin,
        refresh: bool,
    ) -> Result<(IndexEntry, PluginIndex)> {
        let index = self.index(plugin, refresh)?;
        match select(spec, plugin, &index.index.entries) {
            Ok(entry) => Ok((entry.clone(), index)),
            Err(err) if !refresh && is_not_found(&err) && self.may_auto_refresh(&spec.tool) => {
                tracing::info!(tool = %spec.tool, "refreshing the index to resolve the spec");
                let index = self.index(plugin, true)?;
                let entry = select(spec, plugin, &index.index.entries)?.clone();
                Ok((entry, index))
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Installs the version `spec` resolves to, or with `dry_run` reports what would happen.
    // SPEC-QUESTION: a dry run still verifies the index, which caches a fetched copy and
    // records its sequence; neither changes what is installed, and skipping the record would
    // weaken rollback protection.
    pub fn install(
        &self,
        spec: &ToolSpec,
        options: InstallOptions,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<(InstallItem, Vec<Warning>)> {
        let plugin = self.plugin(&spec.tool)?;
        let (entry, index) = self.resolve(spec, &plugin, options.latest)?;
        let path = install::install_path(&self.dirs, &spec.tool, &entry.variant, &entry.version)?;
        let cached = self.cache.path(&entry.sha256).is_ok_and(|p| p.is_file());
        let item = |status: &'static str, path: &Path| InstallItem {
            version: VersionItem {
                tool: spec.tool.clone(),
                variant: entry.variant.clone(),
                version: entry.version.clone(),
                path: path.display().to_string(),
            },
            status,
            url: entry.url.clone(),
            sha256: entry.sha256.clone(),
            size: entry.size,
            cached,
        };

        if options.dry_run {
            let installed =
                !options.force && Receipt::read(&path).is_some_and(|r| r.sha256 == entry.sha256);
            let status = if installed {
                "already_installed"
            } else {
                "would_install"
            };
            return Ok((item(status, &path), index.warnings));
        }

        let request = InstallRequest {
            manifest: &plugin.manifest,
            manifest_sha256: &plugin.sha256,
            entry: &entry,
            platform: self.platform,
            index_sequence: index.index.sequence,
            force: options.force,
        };
        let archives = Archives {
            cache: &self.cache,
            client: self.client.as_ref(),
            mirrors: &self.settings.mirrors,
        };
        let limits = jtm_archive::Limits {
            max_bytes: self.settings.extract.max_bytes,
            ..jtm_archive::Limits::default()
        };
        let done = install::install(&self.dirs, &archives, &request, &limits, progress)?;
        let status = match done.status {
            Status::Installed => "installed",
            Status::AlreadyInstalled => "already_installed",
        };
        let mut item = item(status, &done.path);
        item.url = done.receipt.url;
        Ok((item, index.warnings))
    }

    /// Every installed version, optionally of one tool, sorted by tool, variant and version.
    pub fn list(&self, tool: Option<&str>) -> Result<Vec<InstalledItem>> {
        let mut found = Vec::new();
        let tools = self.dirs.tools();
        let plugin_dirs: Vec<PathBuf> = match tool {
            Some(tool) => vec![tools.join(dir_name(tool))],
            None => read_dirs(&tools)?
                .into_iter()
                .filter(|p| !hidden(p))
                .collect(),
        };
        for plugin_dir in plugin_dirs {
            for dir in read_dirs(&plugin_dir)? {
                let Some(receipt) = Receipt::read(&dir) else {
                    continue;
                };
                if tool.is_some_and(|t| t != receipt.plugin) {
                    continue;
                }
                found.push(InstalledItem {
                    version: VersionItem {
                        tool: receipt.plugin,
                        variant: receipt.variant,
                        version: receipt.version,
                        path: dir.display().to_string(),
                    },
                    platform: receipt.platform,
                    installed_at: receipt.installed_at,
                });
            }
        }
        let schemes: BTreeMap<String, Option<jtm_plugin::VersionScheme>> = found
            .iter()
            .map(|i| i.version.tool.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|t| {
                let scheme = self
                    .plugin(&t)
                    .ok()
                    .and_then(|p| p.manifest.versions.scheme.builtin());
                (t, scheme)
            })
            .collect();
        found.sort_by(|a, b| {
            let (a, b) = (&a.version, &b.version);
            let scheme = schemes.get(&a.tool).copied().flatten();
            a.tool
                .cmp(&b.tool)
                .then_with(|| a.variant.cmp(&b.variant))
                .then_with(|| {
                    let parse = |v: &str| jtm_plugin::MaybeVersion::parse(scheme, v);
                    let (pa, pb) = (parse(&a.version), parse(&b.version));
                    pb.parsed()
                        .cmp(&pa.parsed())
                        .then_with(|| a.version.cmp(&b.version))
                })
        });
        Ok(found)
    }

    /// The versions of `tool` its index offers for this platform.
    pub fn available(
        &self,
        tool: &str,
        options: &AvailableOptions,
    ) -> Result<(Available, Vec<Warning>)> {
        let plugin = self.plugin(tool)?;
        let manifest = &plugin.manifest;
        let index = self.index(&plugin, false)?;
        let variant = options
            .variant
            .clone()
            .unwrap_or_else(|| manifest.default_variant().to_owned());
        if !options.all && !manifest.has_variant(&variant) {
            return Err(JtmError::VersionNotFound {
                tool: tool.to_owned(),
                spec: format!("{variant}:"),
            });
        }
        let entries = &index.index.entries;
        let scheme = manifest.versions.scheme.builtin();
        let mut chosen: Vec<&IndexEntry> = jtm_plugin::sorted_for_display(scheme, entries)
            .into_iter()
            .filter(|e| options.all || e.variant == variant)
            .collect();
        if let Some(alias) = &options.alias {
            let variants: Vec<String> = if options.all {
                let mut all: Vec<String> = entries.iter().map(|e| e.variant.clone()).collect();
                all.dedup();
                all
            } else {
                vec![variant.clone()]
            };
            let mut hits = Vec::new();
            for v in &variants {
                match jtm_plugin::resolve_alias(manifest, alias, v, entries) {
                    Ok(hit) => hits.push(hit),
                    Err(ResolveError::AliasNoMatch { .. }) => {}
                    Err(err) => return Err(err.into()),
                }
            }
            chosen.retain(|e| hits.iter().any(|h| std::ptr::eq(*h, *e)));
        }
        let versions = chosen
            .into_iter()
            .map(|e| AvailableItem {
                variant: e.variant.clone(),
                version: e.version.clone(),
                tags: e.tags.clone(),
                installed: install::install_path(&self.dirs, tool, &e.variant, &e.version)
                    .ok()
                    .and_then(|p| Receipt::read(&p))
                    .is_some_and(|r| r.sha256 == e.sha256),
            })
            .collect();
        let aliases = manifest
            .aliases
            .keys()
            .filter_map(|name| {
                jtm_plugin::resolve_alias(manifest, name, &variant, entries)
                    .ok()
                    .map(|e| (name.clone(), e.version().to_owned()))
            })
            .collect();
        Ok((
            Available {
                tool: tool.to_owned(),
                platform: self.platform.as_str().to_owned(),
                versions,
                aliases,
            },
            index.warnings,
        ))
    }

    /// The installed versions `tool@[variant:]version` names. Without a variant, the plugin's
    /// default variant, or every variant with `all_variants`.
    pub fn find_installed(
        &self,
        spec: &ToolSpec,
        all_variants: bool,
    ) -> Result<Vec<InstalledItem>> {
        let selector = spec.selector.as_ref().ok_or_else(|| {
            JtmError::usage(format!(
                "name the version to uninstall, such as `{}@<version>`",
                spec.tool
            ))
        })?;
        let variant = match (&selector.variant, all_variants) {
            (Some(variant), _) => Some(variant.clone()),
            (None, true) => None,
            (None, false) => match self.plugin(&spec.tool) {
                Ok(plugin) => Some(plugin.manifest.default_variant().to_owned()),
                // A removed plugin's installs can still be uninstalled by exact version.
                Err(err) if err.code() == "E_TOOL_UNKNOWN" => None,
                Err(err) => return Err(err),
            },
        };
        let matches: Vec<InstalledItem> = self
            .list(Some(&spec.tool))?
            .into_iter()
            .filter(|i| i.version.version == selector.value)
            .filter(|i| variant.as_ref().is_none_or(|v| *v == i.version.variant))
            .collect();
        if matches.is_empty() {
            return Err(JtmError::VersionNotFound {
                tool: spec.tool.clone(),
                spec: format!(
                    "{}{} (not installed)",
                    variant.map(|v| format!("{v}:")).unwrap_or_default(),
                    selector.value
                ),
            });
        }
        Ok(matches)
    }

    /// Removes the installed versions `spec` names, or with `dry_run` reports them. Clears a
    /// current link that pointed at a removed version, with a warning.
    pub fn uninstall(
        &self,
        spec: &ToolSpec,
        all_variants: bool,
        dry_run: bool,
    ) -> Result<(Vec<VersionItem>, Vec<Warning>)> {
        let found = self.find_installed(spec, all_variants)?;
        let mut removed = Vec::new();
        let mut warnings = Vec::new();
        for item in found {
            let v = item.version;
            if !dry_run {
                let _lock = install::lock_version(&self.dirs, &v.tool, &v.variant, &v.version)?;
                let path = PathBuf::from(&v.path);
                if self.clear_current_link(&v.tool, &path) {
                    warnings.push(Warning {
                        code: W_DEFAULT_CLEARED,
                        message: format!(
                            "{}@{}:{} was the default; no version of `{}` is the default now",
                            v.tool, v.variant, v.version, v.tool
                        ),
                    });
                }
                let trashed = install::move_to_trash(&self.dirs, &path)?;
                install::remove_trash(&trashed);
            }
            removed.push(v);
        }
        Ok((removed, warnings))
    }

    /// Removes `current/<tool>` when it points at `install_dir`. Returns whether it did.
    fn clear_current_link(&self, tool: &str, install_dir: &Path) -> bool {
        let link = self.dirs.current().join(dir_name(tool));
        let points_here = match (fs::canonicalize(&link), fs::canonicalize(install_dir)) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        };
        if !points_here {
            return false;
        }
        let removed = fs::remove_file(&link).or_else(|_| fs::remove_dir(&link));
        if let Err(err) = &removed {
            tracing::warn!(link = %link.display(), %err, "cannot clear the current link");
        }
        removed.is_ok()
    }
}

/// Loads the user config file, if any, and `JTM__*` variables.
pub fn load_config(dirs: &Dirs, env: &dyn Fn(&str) -> Option<OsString>) -> Result<Config> {
    let text = match fs::read_to_string(&dirs.config_file) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(install::io_error(&dirs.config_file, e)),
    };
    Config::load(&ConfigInputs {
        user: text.as_deref().map(|text| FileSource {
            path: &dirs.config_file,
            text,
        }),
        project: None,
        env,
        flags: &[],
    })
}

fn select<'e>(
    spec: &ToolSpec,
    plugin: &Plugin,
    entries: &'e [IndexEntry],
) -> std::result::Result<&'e IndexEntry, ResolveError> {
    let manifest = &plugin.manifest;
    match &spec.selector {
        None => jtm_plugin::resolve_default(manifest, manifest.default_variant(), entries),
        Some(selector) => {
            let variant = selector
                .variant
                .as_deref()
                .unwrap_or_else(|| manifest.default_variant());
            jtm_plugin::resolve_value(manifest, &selector.value, variant, entries)
        }
    }
}

fn is_not_found(err: &ResolveError) -> bool {
    matches!(
        err,
        ResolveError::VersionNotFound { .. } | ResolveError::AliasNoMatch { .. }
    )
}

fn hidden(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| n.to_string_lossy().starts_with('.'))
}

/// The subdirectories of `dir`; none when it does not exist.
fn read_dirs(dir: &Path) -> Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(install::io_error(dir, e)),
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    dirs.sort();
    Ok(dirs)
}
