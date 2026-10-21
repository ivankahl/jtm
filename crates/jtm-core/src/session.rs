//! The operations behind `jtm install`, `uninstall`, `list` and `available` (SPEC.md sections
//! 4 and 10). The CLI and, later, the MCP server call these and render what they return.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use jtm_fetch::{Client, ClientOptions, DownloadCache};
use jtm_plugin::{Candidate, ResolveError};
use jtm_security::{IndexEntry, Timestamp, Warning};
use serde::Serialize;

use crate::activate::{Choice, Defaults, Installed, Layers, Override, pick_installed, tool_env};
use crate::config::{AutoRefresh, Config, ConfigInputs, FileSource, Settings};
use crate::context::Context;
use crate::dirs::{Dirs, dir_name};
use crate::error::{JtmError, Result};
use crate::indices::{
    EmbeddedIndex, EmbeddedKeysFile, Fetcher, IndexLoader, IndexSources, LoadOptions, PluginIndex,
    PluginKeys, cache_path,
};
use crate::install::{self, Archives, InstallRequest, Progress, Receipt, Status, VersionId};
use crate::links;
use crate::pins::{ProjectPins, W_PIN_CONFLICT};
use crate::platform::Platform;
use crate::plugins::{Plugin, Registry};
use crate::project::PROJECT_FILE;
use crate::spec::{Selector, ToolSpec};

/// Warning code when uninstalling the version the user default pointed at.
pub const W_DEFAULT_CLEARED: &str = "W_DEFAULT_CLEARED";
/// Warning code for a session or project version that is not installed, so it does not apply.
pub const W_NOT_INSTALLED: &str = "W_NOT_INSTALLED";

/// The `PATH` list separator on this OS.
pub const PATH_SEPARATOR: char = if cfg!(windows) { ';' } else { ':' };

/// The first-party indices compiled into this build.
// Embedded by T6.6; until then every index comes from the cache or the network.
const EMBEDDED_INDICES: &[EmbeddedIndex] = &[];
const EMBEDDED_KEYS: &[EmbeddedKeysFile] = &[];

/// Everything an operation needs: directories, configuration, the platform and the network.
#[derive(Debug)]
pub struct Session<'a> {
    ctx: &'a Context,
    dirs: Dirs,
    settings: Settings,
    platform: Platform,
    /// Built on first use: setting up TLS costs more than the shell hook can spend on a prompt.
    client: std::sync::OnceLock<Option<Client>>,
    cache: DownloadCache,
}

/// One version on disk, as install, uninstall and list report it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionItem {
    #[serde(flatten)]
    pub id: VersionId,
    /// The install dir.
    pub path: String,
}

/// What `install` did, or with `dry_run` would do, for one spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InstallItem {
    #[serde(flatten)]
    pub version: VersionItem,
    pub status: Status,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    /// Whether the archive was already in the download cache.
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
    /// Each alias and the version it resolves to in `alias_variant`.
    pub aliases: BTreeMap<String, String>,
    /// The variant `aliases` resolve in: the one asked for, or the default.
    pub alias_variant: String,
}

/// Options for [`Session::install`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InstallOptions {
    pub force: bool,
    pub dry_run: bool,
    /// Refresh the index first, so the newest versions are seen.
    pub latest: bool,
}

/// Options for commands that need a version installed, such as `jtm default`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EnsureOptions {
    /// Install the version when it is missing.
    pub install: bool,
    /// Resolve against a refreshed index instead of preferring an installed match.
    pub latest: bool,
}

/// What `jtm default` set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefaultItem {
    #[serde(flatten)]
    pub version: VersionItem,
    /// The tool home the link points at.
    pub home: String,
    pub link: String,
    /// The default before, as `tool@variant:version`, when it was another version.
    pub previous: Option<String>,
    /// Whether the version was installed by this command.
    pub installed: bool,
}

/// Options for [`Session::uninstall`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UninstallOptions {
    /// Remove the version from every variant, not only the default one.
    pub all_variants: bool,
    pub dry_run: bool,
}

/// Options for [`Session::available`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AvailableOptions {
    pub variant: Option<String>,
    pub alias: Option<String>,
    /// Include every variant, not only the default.
    pub all: bool,
}

/// A spec resolved against a verified index, ready to install.
#[derive(Debug, Clone)]
pub struct Planned {
    pub(crate) plugin: Plugin,
    pub(crate) entry: IndexEntry,
    pub(crate) index_sequence: u64,
    pub(crate) warnings: Vec<Warning>,
}

/// The HTTP client options `settings` ask for.
fn client_options(settings: &Settings) -> ClientOptions {
    ClientOptions {
        allow_http: settings.security.allow_http_mirrors,
        proxy: settings.network.proxy.clone(),
        extra_ca_file: settings.network.extra_ca_file.clone(),
        ..ClientOptions::new(env!("CARGO_PKG_VERSION"))
    }
}

/// The outcome of installing one spec, and the warnings met on the way.
pub type InstallResult = Result<(InstallItem, Vec<Warning>)>;

impl<'a> Session<'a> {
    /// Opens a session from the process environment.
    pub fn open(ctx: &'a Context) -> Result<Session<'a>> {
        let dirs = Dirs::for_context(ctx)?;
        let cwd = std::env::current_dir().ok();
        let config = load_config(&dirs, cwd.as_deref(), &|key| std::env::var_os(key))?;
        // The working copy is only for reading, so failing to repair it never fails a command.
        if let Err(err) = crate::plugins::sync_working_copy(&dirs, ctx.builtin) {
            tracing::debug!(%err, "cannot update the builtin plugin working copy");
        }
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
        Ok(Session {
            ctx,
            dirs,
            settings,
            platform,
            client: std::sync::OnceLock::new(),
            cache,
        })
    }

    /// The HTTP client, or `None` offline.
    fn client(&self) -> Result<Option<&Client>> {
        if let Some(client) = self.client.get() {
            return Ok(client.as_ref());
        }
        let client = if self.ctx.offline {
            None
        } else {
            Some(Client::new(client_options(&self.settings))?)
        };
        Ok(self.client.get_or_init(|| client).as_ref())
    }

    /// Whether `jtm.lock` is honoured: false under `--no-lock`.
    pub fn uses_lockfile(&self) -> bool {
        self.ctx.use_lockfile
    }

    /// The platform jtm runs on.
    pub fn platform(&self) -> Platform {
        self.platform
    }

    pub fn registry(&self) -> Registry<'_> {
        Registry {
            dirs: &self.dirs,
            builtin: self.ctx.builtin,
        }
    }

    pub fn plugin(&self, name: &str) -> Result<Plugin> {
        self.registry().find(name)
    }

    /// Loads and verifies `plugin`'s index for `platform`. `refresh` fetches a new copy as
    /// `jtm update` does.
    pub fn index(&self, plugin: &Plugin, platform: Platform, refresh: bool) -> Result<PluginIndex> {
        let manifest = &plugin.manifest;
        let name = manifest.name.as_str();
        let loader = IndexLoader {
            dirs: &self.dirs,
            embedded: EMBEDDED_INDICES,
            embedded_keys: EMBEDDED_KEYS,
            fetcher: self.client()?.map(|c| c as &dyn Fetcher),
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
        // What fills `{index_version}` is decided with index publishing (T6.4); until then such
        // a URL is usable only through `plugins.<name>.index_url` or an embedded or cached copy.
        let remote_url = jtm_fetch::mirrors::rewrite(&manifest.index.url, &self.settings.mirrors);
        let mut index = loader.load(
            &IndexSources {
                plugin: name,
                platform: manifest.index.index_platform(platform.as_str()),
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
    fn may_auto_refresh(&self, plugin: &Plugin, platform: Platform) -> bool {
        if self.ctx.offline || self.ctx.json || self.ctx.ci {
            return false;
        }
        let allowed = match self.settings.index.auto_refresh {
            AutoRefresh::Never => false,
            AutoRefresh::Always => true,
            AutoRefresh::Tty => self.ctx.interactive,
        };
        let ttl = Duration::from_secs(u64::from(self.settings.index.ttl_hours) * 3600);
        let index = &plugin.manifest.index;
        let cached = cache_path(
            &self.dirs,
            &plugin.manifest.name,
            index.index_platform(platform.as_str()),
        );
        let stale = fs::metadata(cached)
            .and_then(|m| m.modified())
            .map_or(true, |at| {
                SystemTime::now().duration_since(at).unwrap_or_default() >= ttl
            });
        allowed && stale
    }

    /// Resolves `spec` to one entry of `platform`'s index, refreshing the index once when
    /// local data cannot resolve it and the refresh policy allows.
    pub fn resolve(
        &self,
        spec: &ToolSpec,
        plugin: &Plugin,
        platform: Platform,
        refresh: bool,
    ) -> Result<(IndexEntry, PluginIndex)> {
        let index = self.index(plugin, platform, refresh)?;
        match select(spec, plugin, &index.index.entries) {
            Ok(entry) => Ok((entry.clone(), index)),
            Err(err)
                if !refresh && is_not_found(&err) && self.may_auto_refresh(plugin, platform) =>
            {
                tracing::info!(tool = %spec.tool, "refreshing the index to resolve the spec");
                let index = self.index(plugin, platform, true)?;
                let entry = select(spec, plugin, &index.index.entries)?.clone();
                Ok((entry, index))
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Resolves `spec` for installing.
    pub fn plan(&self, spec: &ToolSpec, options: InstallOptions) -> Result<Planned> {
        let plugin = self.plugin(&spec.tool)?;
        let (entry, index) = self.resolve(spec, &plugin, self.platform, options.latest)?;
        Ok(Planned {
            plugin,
            entry,
            index_sequence: index.index.sequence,
            warnings: index.warnings,
        })
    }

    /// Installs a planned version, or with `dry_run` reports what would happen.
    pub fn execute(
        &self,
        planned: Planned,
        options: InstallOptions,
        progress: &mut dyn FnMut(Progress),
    ) -> InstallResult {
        let Planned {
            plugin,
            entry,
            index_sequence,
            warnings,
        } = planned;
        let id = VersionId::of(&plugin.manifest.name, &entry);
        let cached = self.cache.path(&entry.sha256).is_ok_and(|p| p.is_file());
        let item = |status: Status, path: &Path, url: &str| InstallItem {
            version: VersionItem {
                id: id.clone(),
                path: path.display().to_string(),
            },
            status,
            url: url.to_owned(),
            sha256: entry.sha256.clone(),
            size: entry.size,
            cached,
        };
        let archives = Archives {
            cache: &self.cache,
            client: self.client()?,
            mirrors: &self.settings.mirrors,
        };

        let dest = id.install_dir(&self.dirs)?;
        if options.dry_run {
            let installed =
                !options.force && Receipt::read(&dest).is_some_and(|r| r.sha256 == entry.sha256);
            let status = if installed {
                Status::AlreadyInstalled
            } else {
                Status::WouldInstall
            };
            return Ok((item(status, &dest, &entry.url), warnings));
        }
        let script = match plugin.manifest.hooks.post_extract {
            Some(_) => plugin.script(self.platform)?,
            None => None,
        };
        let request = InstallRequest {
            manifest: &plugin.manifest,
            manifest_sha256: &plugin.sha256,
            entry: &entry,
            platform: self.platform,
            index_sequence,
            force: options.force,
            script: script.as_ref(),
        };
        let limits = jtm_archive::Limits {
            max_bytes: self.settings.extract.max_bytes,
            max_entries: self.settings.extract.max_entries,
            max_ratio: self.settings.extract.max_ratio,
            ..jtm_archive::Limits::default()
        };
        let done = install::install(&self.dirs, &archives, &request, &limits, progress)?;
        Ok((item(done.status, &done.path, &done.receipt.url), warnings))
    }

    /// Installs the version `spec` resolves to, or with `dry_run` reports what would happen.
    pub fn install(
        &self,
        spec: &ToolSpec,
        options: InstallOptions,
        progress: &mut dyn FnMut(Progress),
    ) -> InstallResult {
        let planned = self.plan(spec, options)?;
        self.execute(planned, options, progress)
    }

    /// Installs several specs: indices are loaded and specs resolved one at a time, then up to
    /// `download.concurrency` versions download and extract in parallel. Results are in the
    /// order of `specs`; `progress` receives each spec's position.
    pub fn install_all(
        &self,
        specs: &[ToolSpec],
        options: InstallOptions,
        progress: &(dyn Fn(usize, Progress) + Sync),
    ) -> Vec<InstallResult> {
        let mut results: Vec<Option<InstallResult>> = specs.iter().map(|_| None).collect();
        let mut work = Vec::new();
        for (i, spec) in specs.iter().enumerate() {
            match self.plan(spec, options) {
                Ok(planned) => work.push((i, planned)),
                Err(err) => results[i] = Some(Err(err)),
            }
        }
        let workers = (self.settings.download.concurrency.max(1) as usize).min(work.len());
        let queue = Mutex::new(work.into_iter());
        let done = Mutex::new(Vec::new());
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    loop {
                        let next = queue.lock().map(|mut q| q.next()).ok().flatten();
                        let Some((i, planned)) = next else { break };
                        let result = self.execute(planned, options, &mut |p| progress(i, p));
                        if let Ok(mut done) = done.lock() {
                            done.push((i, result));
                        }
                    }
                });
            }
        });
        for (i, result) in done.into_inner().unwrap_or_default() {
            results[i] = Some(result);
        }
        results
            .into_iter()
            .map(|r| r.unwrap_or_else(|| Err(JtmError::internal("an install did not finish"))))
            .collect()
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
                        id: VersionId {
                            tool: receipt.plugin,
                            variant: receipt.variant,
                            version: receipt.version,
                        },
                        path: dir.display().to_string(),
                    },
                    platform: receipt.platform,
                    installed_at: receipt.installed_at,
                });
            }
        }
        let schemes: BTreeMap<String, Option<jtm_plugin::VersionScheme>> = found
            .iter()
            .map(|i| i.version.id.tool.clone())
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
            let (a, b) = (&a.version.id, &b.version.id);
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
        let index = self.index(&plugin, self.platform, false)?;
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
                installed: VersionId::of(tool, e)
                    .install_dir(&self.dirs)
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
                alias_variant: variant,
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
                Err(JtmError::ToolUnknown { .. }) => None,
                Err(err) => return Err(err),
            },
        };
        let matches: Vec<InstalledItem> = self
            .list(Some(&spec.tool))?
            .into_iter()
            .filter(|i| i.version.id.version == selector.value)
            .filter(|i| variant.as_ref().is_none_or(|v| *v == i.version.id.variant))
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
        options: UninstallOptions,
    ) -> Result<(Vec<VersionItem>, Vec<Warning>)> {
        let found = self.find_installed(spec, options.all_variants)?;
        let mut removed = Vec::new();
        let mut warnings = Vec::new();
        for item in found {
            let v = item.version;
            if !options.dry_run {
                let _lock = v.id.lock(&self.dirs)?;
                let path = PathBuf::from(&v.path);
                // Decided before the move, cleared only once it succeeded, so `E_IN_USE`
                // leaves both the install and the default as they were.
                let link = self.current_link_to(&v.id.tool, &path);
                let trashed = install::move_to_trash(&self.dirs, &path)?;
                install::remove_trash(&trashed);
                if let Some(link) = link
                    && clear_link(&link)
                {
                    let mut defaults = Defaults::load(&self.dirs.defaults_file())?;
                    if defaults.remove(&v.id.tool) {
                        defaults.save()?;
                    }
                    warnings.push(Warning {
                        code: W_DEFAULT_CLEARED,
                        message: format!(
                            "{} was the default; no version of `{}` is the default now",
                            v.id, v.id.tool
                        ),
                    });
                }
            }
            removed.push(v);
        }
        Ok((removed, warnings))
    }

    /// `current/<tool>`, when it points at `install_dir` or a directory inside it.
    fn current_link_to(&self, tool: &str, install_dir: &Path) -> Option<PathBuf> {
        let link = self.current_link(tool);
        match (fs::canonicalize(&link), fs::canonicalize(install_dir)) {
            (Ok(a), Ok(b)) if a.starts_with(&b) => Some(link),
            _ => None,
        }
    }

    /// `<data>/current/<tool>`.
    pub fn current_link(&self, tool: &str) -> PathBuf {
        self.dirs.current().join(dir_name(tool))
    }

    pub fn dirs(&self) -> &Dirs {
        &self.dirs
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Every plugin available, builtin first.
    pub fn plugins(&self) -> Result<Vec<Plugin>> {
        let registry = self.registry();
        registry
            .names()?
            .iter()
            .map(|name| registry.find(name))
            .collect()
    }

    /// The installed versions of `tool`, highest first per variant.
    pub fn installed(&self, tool: &str) -> Result<Vec<Installed>> {
        Ok(self
            .list(Some(tool))?
            .into_iter()
            .map(|item| {
                let dir = PathBuf::from(&item.version.path);
                let home = install_home(&dir);
                Installed {
                    variant: item.version.id.variant,
                    version: item.version.id.version,
                    dir,
                    home,
                }
            })
            .collect())
    }

    /// The installed version `selector` picks for `plugin`, as activation uses it.
    pub fn installed_match(
        &self,
        plugin: &Plugin,
        selector: Option<&Selector>,
    ) -> Result<Option<Installed>> {
        let installed = self.installed(&plugin.manifest.name)?;
        Ok(pick_installed(&plugin.manifest, selector, &installed).cloned())
    }

    /// The installed version `spec` picks, installing it first when `install` is set. Without
    /// `install`, a missing version fails with `E_INPUT_REQUIRED` naming `--install`.
    pub fn ensure_installed(
        &self,
        spec: &ToolSpec,
        options: EnsureOptions,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<(Installed, bool, Vec<Warning>)> {
        let plugin = self.plugin(&spec.tool)?;
        if !options.latest
            && let Some(found) = self.installed_match(&plugin, spec.selector.as_ref())?
        {
            return Ok((found, false, Vec::new()));
        }
        if !options.install {
            return Err(JtmError::InputRequired {
                action: format!("`{spec}` is not installed, and installing it"),
                resolve: "--install (or --yes)".to_owned(),
            });
        }
        let install_options = InstallOptions {
            latest: options.latest,
            ..InstallOptions::default()
        };
        let (item, warnings) = self.install(spec, install_options, progress)?;
        let dir = PathBuf::from(&item.version.path);
        let home = install_home(&dir);
        let installed = Installed {
            variant: item.version.id.variant,
            version: item.version.id.version,
            dir,
            home,
        };
        Ok((installed, item.status.changed(), warnings))
    }

    /// The tools a shell should use from real install dirs: the session and project choices
    /// in `session` and `pins`. Defaults are left to the current links. A choice with no
    /// matching install is skipped with a `W_NOT_INSTALLED` warning.
    pub fn overrides(
        &self,
        session: &BTreeMap<String, Selector>,
        pins: &ProjectPins,
        plugins: &[Plugin],
    ) -> Result<(Vec<Override>, Vec<Warning>)> {
        let defaults = Defaults::empty(self.dirs.defaults_file());
        let layers = Layers {
            exec: &[],
            session,
            project: pins,
            defaults: &defaults,
        };
        let mut overrides = Vec::new();
        let mut warnings = pin_warnings(pins);
        for plugin in plugins {
            let tool = plugin.manifest.name.as_str();
            let Some(choice) = layers.choose(tool) else {
                continue;
            };
            match self.installed_match(plugin, choice.selector.as_ref())? {
                Some(found) => overrides.push(Override {
                    tool: tool.to_owned(),
                    layer: choice.layer,
                    env: tool_env(&plugin.manifest, &found.home),
                    selector: Selector {
                        variant: Some(found.variant),
                        value: found.version,
                    },
                }),
                None => warnings.push(not_installed_warning(&choice)),
            }
        }
        Ok((overrides, warnings))
    }

    /// Makes the version `spec` picks the user default: points `current/<tool>` at it and
    /// records it in `state/defaults.toml`.
    pub fn set_default(
        &self,
        spec: &ToolSpec,
        options: EnsureOptions,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<(DefaultItem, bool, Vec<Warning>)> {
        let (found, installed, warnings) = self.ensure_installed(spec, options, progress)?;
        let tool = spec.tool.as_str();
        let link = self.current_link(tool);
        let mut defaults = Defaults::load(&self.dirs.defaults_file())?;
        let previous = defaults
            .get(tool)
            .map(|s| format!("{tool}@{s}"))
            .filter(|_| links::read(&link).is_some());
        let selector = Selector {
            variant: Some(found.variant.clone()),
            value: found.version.clone(),
        };
        // The link points at the tool home, not the install dir (SPEC.md section 5), so `{home}`
        // stays a valid home through the link for layouts like a macOS JDK's `Contents/Home`.
        let link_changed = links::set(&link, &found.home)?;
        let default_changed = defaults.set(tool, selector);
        if default_changed {
            defaults.save()?;
        }
        let id = VersionId {
            tool: tool.to_owned(),
            variant: found.variant,
            version: found.version,
        };
        let previous = previous.filter(|p| *p != id.to_string());
        let item = DefaultItem {
            version: VersionItem {
                id,
                path: found.dir.display().to_string(),
            },
            home: found.home.display().to_string(),
            link: link.display().to_string(),
            previous,
            installed,
        };
        Ok((item, link_changed || default_changed || installed, warnings))
    }
}

/// The `W_NOT_INSTALLED` warning for a `choice` with no matching install.
fn not_installed_warning(choice: &Choice) -> Warning {
    let tool = &choice.tool;
    let wanted = choice
        .selector
        .as_ref()
        .map(|s| format!("{tool}@{s}"))
        .unwrap_or_else(|| tool.clone());
    Warning {
        code: W_NOT_INSTALLED,
        message: format!(
            "{} sets `{wanted}`, which is not installed; run `jtm install {wanted}` or `jtm \
             sync`",
            choice.origin
        ),
    }
}

/// A `W_PIN_CONFLICT` warning for each conflict between pin files.
pub fn pin_warnings(pins: &ProjectPins) -> Vec<Warning> {
    pins.conflicts
        .iter()
        .map(|c| Warning {
            code: W_PIN_CONFLICT,
            message: c.message(),
        })
        .chain(pins.ignored.iter().map(|message| Warning {
            code: crate::pins::W_PIN_IGNORED,
            message: message.clone(),
        }))
        .collect()
}

/// The tool home of the install at `dir`, from its receipt, or `dir` itself without one.
pub fn install_home(dir: &Path) -> PathBuf {
    Receipt::read(dir).map_or_else(|| dir.to_path_buf(), |r| home_dir(dir, &r.home))
}

/// The tool home of an install: `dir` plus the receipt's `/`-separated `home`.
pub fn home_dir(dir: &Path, home: &str) -> PathBuf {
    home.split('/')
        .filter(|part| !part.is_empty())
        .fold(dir.to_path_buf(), |dir, part| dir.join(part))
}

/// Removes a current link. Returns whether it did.
fn clear_link(link: &Path) -> bool {
    let removed = fs::remove_file(link).or_else(|_| fs::remove_dir(link));
    if let Err(err) = &removed {
        tracing::warn!(link = %link.display(), %err, "cannot clear the current link");
    }
    removed.is_ok()
}

/// Loads the user config file, the `[settings]` of the nearest `.jtm.toml` at or above `cwd`,
/// and `JTM__*` variables.
pub fn load_config(
    dirs: &Dirs,
    cwd: Option<&Path>,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<Config> {
    let read = |path: &Path| match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(JtmError::io(path, e)),
    };
    let user = read(&dirs.config_file)?;
    let mut project = None;
    for dir in cwd.into_iter().flat_map(Path::ancestors) {
        let path = dir.join(PROJECT_FILE);
        if let Some(text) = read(&path)? {
            project = Some((path, text));
            break;
        }
    }
    Config::load(&ConfigInputs {
        user: user.as_deref().map(|text| FileSource {
            path: &dirs.config_file,
            text,
        }),
        project: project
            .as_ref()
            .map(|(path, text)| FileSource { path, text }),
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
        Err(e) => return Err(JtmError::io(dir, e)),
    };
    let mut dirs: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    dirs.sort();
    Ok(dirs)
}

#[cfg(test)]
mod tests;
