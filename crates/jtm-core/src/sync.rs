//! `jtm lock` and `jtm sync` (SPEC.md section 11): resolving a project's pins to exact
//! versions for every platform, and installing what the lock names.

use std::path::{Component, Path, PathBuf};

use jtm_security::{ArchiveKind, IndexEntry, Warning};
use serde::Serialize;

use crate::error::{JtmError, Result};
use crate::lockfile::{LOCK_FILE, LockedArtifact, LockedPlugin, LockedTool, Lockfile};
use crate::pins::{ProjectPins, discover, discover_within};
use crate::platform::Platform;
use crate::plugins::Plugin;
use crate::project::{PROJECT_FILE, ProjectFile};
use crate::session::{InstallOptions, InstallResult, Planned, Session, pin_warnings};
use crate::spec::{Selector, ToolSpec};

/// Which locked tools `jtm lock --upgrade` re-resolves.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Upgrade {
    #[default]
    None,
    All,
    Tool(String),
}

impl Upgrade {
    fn covers(&self, tool: &str) -> bool {
        match self {
            Upgrade::None => false,
            Upgrade::All => true,
            Upgrade::Tool(t) => t == tool,
        }
    }
}

/// Options for [`Session::lock`].
#[derive(Debug, Clone, Default)]
pub struct LockOptions {
    /// Lock only these platforms instead of `[lock] platforms` or every v1 platform.
    pub platforms: Option<Vec<Platform>>,
    pub upgrade: Upgrade,
    pub dry_run: bool,
}

/// What happened to one tool's lock entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LockStatus {
    Kept,
    Added,
    Updated,
    Removed,
}

/// One tool in a lock report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LockItem {
    pub tool: String,
    pub variant: String,
    pub version: String,
    pub platforms: Vec<String>,
    pub status: LockStatus,
}

/// The outcome of [`Session::lock`].
#[derive(Debug, Clone)]
pub struct LockReport {
    /// The lockfile path.
    pub file: PathBuf,
    pub tools: Vec<LockItem>,
    /// Whether the file changed, or with a dry run would change.
    pub differs: bool,
    pub lockfile: Lockfile,
    pub pins: ProjectPins,
    pub root: PathBuf,
    pub warnings: Vec<Warning>,
}

/// The project directory for `start`: the nearest directory with a `jtm.lock`, a
/// `.jtm.toml` or any pin file. The lock lives there, so a subdirectory pinned by its own
/// `.java-version`-style file gets its own lock rather than sharing an ancestor's.
pub fn project_root(start: &Path, plugins: &[Plugin]) -> Result<PathBuf> {
    let pins = discover(start, plugins)?;
    root_of(start, &pins).ok_or_else(|| {
        JtmError::usage(format!(
            "no project pins at or above {}; pin a tool first with `jtm pin <tool>@<version>`",
            start.display()
        ))
    })
}

/// The nearest directory from `start` with a `jtm.lock`, a `.jtm.toml` or one of `pins.files`.
fn root_of(start: &Path, pins: &ProjectPins) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|dir| {
            dir.join(LOCK_FILE).is_file()
                || dir.join(PROJECT_FILE).is_file()
                || pins.files.iter().any(|f| f.parent() == Some(*dir))
        })
        .map(Path::to_path_buf)
}

/// The pins `jtm lock` and `jtm sync` take for the project at `root`: those set in `root` and
/// its ancestors up to the repository root, the nearest directory holding `.git`, or only
/// those in `root` outside a repository. Pin files further up, such as a `~/.tool-versions`,
/// belong to one machine and must not reach the committed lock (SPEC.md section 5, "Nothing
/// machine-specific in tracked files").
pub fn project_pins(root: &Path, plugins: &[Plugin]) -> Result<ProjectPins> {
    let top = root
        .ancestors()
        .find(|dir| dir.join(".git").exists())
        .unwrap_or(root);
    discover_within(root, Some(top), plugins)
}

impl Session<'_> {
    /// Resolves the pins of the project around `start` for every platform, keeping each lock
    /// entry whose pin is unchanged unless `upgrade` names it, and writes `jtm.lock` unless
    /// `dry_run`.
    pub fn lock(&self, start: &Path, options: &LockOptions) -> Result<LockReport> {
        let plugins = self.plugins()?;
        let root = project_root(start, &plugins)?;
        let pins = project_pins(&root, &plugins)?;
        if let Upgrade::Tool(tool) = &options.upgrade
            && !pins.pins.contains_key(tool)
        {
            return Err(JtmError::usage(format!(
                "`{tool}` is not pinned in this project, so there is nothing to upgrade"
            )));
        }
        let existing = Lockfile::read(&root)?;
        let platforms = match &options.platforms {
            Some(platforms) => platforms.clone(),
            None => ProjectFile::read(&root)?
                .and_then(|f| f.lock_platforms())
                .unwrap_or_else(|| Platform::ALL.to_vec()),
        };

        let mut lockfile = Lockfile::new();
        let mut items = Vec::new();
        let mut warnings = pin_warnings(&pins);
        for (tool, pin) in &pins.pins {
            let plugin = plugins
                .iter()
                .find(|p| &p.manifest.name == tool)
                .ok_or_else(|| JtmError::ToolUnknown { tool: tool.clone() })?;
            let requested = pin.selector.to_string();
            let previous = existing.as_ref().and_then(|l| l.tool(tool));
            // Locked wins over newer while the entry still satisfies the pin.
            let keep = previous.filter(|p| {
                !options.upgrade.covers(tool)
                    && (p.requested == requested || locked_satisfies(plugin, p, &pin.selector))
            });
            let (variant, version) = match keep {
                Some(kept) => (kept.variant.clone(), kept.version.clone()),
                None => {
                    let entry = self.resolve_any(
                        plugin,
                        &pin.selector,
                        &platforms,
                        options.upgrade.covers(tool),
                    )?;
                    (entry.variant, entry.version)
                }
            };
            let mut artifacts = Vec::new();
            for platform in &platforms {
                if let Some(found) = keep.and_then(|k| k.artifact(platform.as_str())) {
                    artifacts.push(found.clone());
                    continue;
                }
                if let Some(entry) = self.entry_for(plugin, *platform, &variant, &version)? {
                    artifacts.push(LockedArtifact {
                        platform: platform.as_str().to_owned(),
                        url: entry.url,
                        size: entry.size,
                        sha256: entry.sha256,
                    });
                }
            }
            let locked = LockedTool {
                name: tool.clone(),
                requested,
                pin_source: relative(&root, &pin.file),
                variant: variant.clone(),
                version: version.clone(),
                artifacts,
            };
            let status = match previous {
                None => LockStatus::Added,
                Some(p) if *p == sorted(&locked) => LockStatus::Kept,
                Some(_) => LockStatus::Updated,
            };
            items.push(LockItem {
                tool: tool.clone(),
                variant,
                version,
                platforms: {
                    let mut p: Vec<String> = locked
                        .artifacts
                        .iter()
                        .map(|a| a.platform.clone())
                        .collect();
                    p.sort();
                    p
                },
                status,
            });
            if locked.artifacts.is_empty() {
                warnings.push(Warning {
                    code: W_LOCK_NO_ARTIFACTS,
                    message: format!(
                        "no locked platform publishes {tool}@{}:{}",
                        locked.variant, locked.version
                    ),
                });
            }
            lockfile.tools.push(locked);
            lockfile.plugins.push(locked_plugin(plugin));
        }
        if let Some(existing) = &existing {
            for gone in existing
                .tools
                .iter()
                .filter(|t| !pins.pins.contains_key(&t.name))
            {
                items.push(LockItem {
                    tool: gone.name.clone(),
                    variant: gone.variant.clone(),
                    version: gone.version.clone(),
                    platforms: Vec::new(),
                    status: LockStatus::Removed,
                });
            }
        }
        // Keep the old `generated_by` when nothing else changed, so a jtm upgrade alone does
        // not rewrite every lockfile.
        if let Some(existing) = &existing {
            let mut same = lockfile.clone();
            same.generated_by.clone_from(&existing.generated_by);
            if same.render() == existing.render() {
                lockfile = same;
            }
        }
        let differs = existing.as_ref().map(Lockfile::render) != Some(lockfile.render());
        if differs && !options.dry_run {
            lockfile.write(&root)?;
        }
        Ok(LockReport {
            file: root.join(LOCK_FILE),
            tools: items,
            differs,
            lockfile,
            pins,
            root,
            warnings,
        })
    }

    /// Resolves `selector` on the host platform, or on the first of `platforms` publishing a
    /// match when the host has no index for the tool.
    fn resolve_any(
        &self,
        plugin: &Plugin,
        selector: &Selector,
        platforms: &[Platform],
        refresh: bool,
    ) -> Result<IndexEntry> {
        let spec = ToolSpec {
            tool: plugin.manifest.name.clone(),
            selector: Some(selector.clone()),
        };
        let mut order = vec![self.platform()];
        order.extend(platforms.iter().copied().filter(|p| *p != self.platform()));
        let mut last = None;
        for platform in order {
            match self.resolve(&spec, plugin, platform, refresh) {
                Ok((entry, _)) => return Ok(entry),
                Err(err @ JtmError::PlatformUnsupported { .. }) => last = Some(err),
                Err(err) => return Err(err),
            }
        }
        Err(last.unwrap_or_else(|| JtmError::VersionNotFound {
            tool: spec.tool.clone(),
            spec: selector.to_string(),
        }))
    }

    /// The index entry for exactly `variant` and `version` on `platform`; `None` when the
    /// platform has no index for the tool or no such version.
    pub fn entry_for(
        &self,
        plugin: &Plugin,
        platform: Platform,
        variant: &str,
        version: &str,
    ) -> Result<Option<IndexEntry>> {
        let index = match self.index(plugin, platform, false) {
            Ok(index) => index,
            Err(JtmError::PlatformUnsupported { .. }) => return Ok(None),
            Err(err) => return Err(err),
        };
        Ok(index
            .index
            .entries
            .into_iter()
            .find(|e| e.variant == variant && e.version == version))
    }
}

/// Warning code for a locked version the index no longer lists; it installs from the locked
/// URL and hash.
pub const W_LOCK_NOT_IN_INDEX: &str = "W_LOCK_NOT_IN_INDEX";
/// Warning code for a wrapper file declaring a different SHA-256 for the same archive.
pub const W_WRAPPER_HASH_MISMATCH: &str = "W_WRAPPER_HASH_MISMATCH";

/// Options for [`Session::sync`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SyncOptions {
    pub dry_run: bool,
    /// Fail with `E_LOCK_OUTDATED` instead of changing `jtm.lock`.
    pub frozen: bool,
}

/// The outcome of [`Session::sync`].
#[derive(Debug)]
pub struct SyncReport {
    /// The lockfile, unless `--no-lock`.
    pub file: Option<PathBuf>,
    pub lock: Vec<LockItem>,
    /// Whether `jtm.lock` changed, or with a dry run would change.
    pub lock_differs: bool,
    pub results: Vec<(String, InstallResult)>,
    pub warnings: Vec<Warning>,
    /// Pin file conflicts, also reported as `W_PIN_CONFLICT` warnings.
    pub conflicts: Vec<crate::pins::Conflict>,
}

impl Session<'_> {
    /// Installs what the project around `start` pins (SPEC.md section 11). The locked version
    /// wins while its pin is unchanged; every locked artifact for this platform is checked
    /// against the signed index before anything is installed, and a hash disagreement is
    /// `E_LOCK_INDEX_MISMATCH`. With `--no-lock` the pins are resolved afresh and `jtm.lock`
    /// is neither read nor written.
    pub fn sync(&self, start: &Path, options: SyncOptions) -> Result<SyncReport> {
        let install = InstallOptions {
            dry_run: options.dry_run,
            ..InstallOptions::default()
        };
        if !self.uses_lockfile() {
            let plugins = self.plugins()?;
            let root = project_root(start, &plugins)?;
            let pins = project_pins(&root, &plugins)?;
            let mut results = Vec::new();
            for (tool, pin) in &pins.pins {
                // Prefer an installed match over a newer one (SPEC.md section 5, step 5).
                let installed = self
                    .plugin(tool)
                    .and_then(|plugin| self.installed_match(&plugin, Some(&pin.selector)));
                // Installs that cannot be read fail this tool, rather than passing for none.
                let selector = match installed {
                    Ok(Some(found)) => Selector {
                        variant: Some(found.variant),
                        value: found.version,
                    },
                    Ok(None) => pin.selector.clone(),
                    Err(err) => {
                        results.push((tool.clone(), Err(err)));
                        continue;
                    }
                };
                let spec = ToolSpec {
                    tool: tool.clone(),
                    selector: Some(selector),
                };
                let result = self
                    .plan(&spec, install)
                    .and_then(|planned| self.execute(planned, install, &mut |_| {}));
                results.push((tool.clone(), result));
            }
            return Ok(SyncReport {
                file: None,
                lock: Vec::new(),
                lock_differs: false,
                results,
                warnings: pin_warnings(&pins),
                conflicts: pins.conflicts,
            });
        }

        let report = self.lock(
            start,
            &LockOptions {
                dry_run: true,
                ..LockOptions::default()
            },
        )?;
        if options.frozen && report.differs {
            let changes: Vec<String> = report
                .tools
                .iter()
                .filter(|t| t.status != LockStatus::Kept)
                .map(|t| {
                    let status = match t.status {
                        LockStatus::Added => "would be added",
                        LockStatus::Removed => "would be removed",
                        _ => "would change",
                    };
                    format!("`{}` {status}", t.tool)
                })
                .collect();
            let detail = if changes.is_empty() {
                "it would be rewritten".to_owned()
            } else {
                changes.join(", ")
            };
            return Err(JtmError::LockOutdated {
                message: format!("{detail}; run `jtm lock` and commit {LOCK_FILE}"),
            });
        }

        let mut warnings = report.warnings.clone();
        let mut planned = Vec::new();
        let mut results = Vec::new();
        let host = self.platform();
        for locked in &report.lockfile.tools {
            let plugin = self.plugin(&locked.name)?;
            let Some(artifact) = locked.artifact(host.as_str()) else {
                results.push((
                    locked.name.clone(),
                    Err(JtmError::PlatformUnsupported {
                        tool: format!("{}@{}:{}", locked.name, locked.variant, locked.version),
                        platform: host.as_str().to_owned(),
                    }),
                ));
                continue;
            };
            let (entry, index_sequence) =
                self.locked_entry(&plugin, locked, artifact, &mut warnings)?;
            if let Some(pin) = report.pins.pins.get(&locked.name)
                && let Some(wrapper) = &pin.wrapper
                && let Some(declared) = &wrapper.sha256
                && entry.url.rsplit('/').next() == Some(wrapper.file_name.as_str())
                && !declared.eq_ignore_ascii_case(&entry.sha256)
            {
                warnings.push(Warning {
                    code: W_WRAPPER_HASH_MISMATCH,
                    message: format!(
                        "{} declares sha256 {declared} for {}, but the signed index has {}; \
                         jtm installs the signed one",
                        pin.file.display(),
                        wrapper.file_name,
                        entry.sha256
                    ),
                });
            }
            planned.push(Planned {
                plugin,
                entry,
                index_sequence,
                warnings: Vec::new(),
            });
        }

        if report.differs && !options.dry_run {
            report.lockfile.write(&report.root)?;
        }
        for plan in planned {
            let tool = plan.plugin.manifest.name.clone();
            results.push((tool, self.execute(plan, install, &mut |_| {})));
        }
        results.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(SyncReport {
            file: Some(report.file),
            lock: report.tools,
            lock_differs: report.differs,
            results,
            warnings,
            conflicts: report.pins.conflicts,
        })
    }

    /// The entry to install for a locked artifact: the signed index's entry when it lists the
    /// version, which must agree with the lock, or else the lock's own URL and hash.
    fn locked_entry(
        &self,
        plugin: &Plugin,
        locked: &LockedTool,
        artifact: &LockedArtifact,
        warnings: &mut Vec<Warning>,
    ) -> Result<(IndexEntry, u64)> {
        let host = self.platform();
        let index = match self.index(plugin, host, false) {
            Ok(index) => Some(index),
            Err(JtmError::PlatformUnsupported { .. } | JtmError::Offline { .. }) => None,
            Err(err) => return Err(err),
        };
        let found = index.as_ref().and_then(|index| {
            index
                .index
                .entries
                .iter()
                .find(|e| e.variant == locked.variant && e.version == locked.version)
                .map(|e| (e.clone(), index.index.sequence))
        });
        match found {
            Some((entry, sequence)) => {
                if !entry.sha256.eq_ignore_ascii_case(&artifact.sha256)
                    || entry.size != artifact.size
                {
                    return Err(JtmError::LockIndexMismatch {
                        tool: locked.name.clone(),
                        message: format!(
                            "{}:{} for {} is locked as sha256 {} ({} bytes), but the signed \
                             index has sha256 {} ({} bytes)",
                            locked.variant,
                            locked.version,
                            host,
                            artifact.sha256,
                            artifact.size,
                            entry.sha256,
                            entry.size
                        ),
                    });
                }
                Ok((entry, sequence))
            }
            None => {
                // The index checked these for an indexed entry; without one, the lock's own
                // strings name the install dir, so the variant must be one the plugin has.
                if !plugin.manifest.has_variant(&locked.variant) {
                    return Err(JtmError::LockOutdated {
                        message: format!(
                            "`{}` is locked to variant `{}`, which the plugin does not have; \
                             run `jtm lock` to write it again",
                            locked.name, locked.variant
                        ),
                    });
                }
                warnings.push(Warning {
                    code: W_LOCK_NOT_IN_INDEX,
                    message: format!(
                        "{}@{}:{} is not in the index; installing it from the locked URL and \
                         hash",
                        locked.name, locked.variant, locked.version
                    ),
                });
                let archive =
                    archive_kind(&artifact.url).ok_or_else(|| JtmError::LockOutdated {
                        message: format!(
                            "the archive type of {} cannot be told from its name",
                            artifact.url
                        ),
                    })?;
                Ok((
                    IndexEntry {
                        variant: locked.variant.clone(),
                        version: locked.version.clone(),
                        tags: Vec::new(),
                        url: artifact.url.clone(),
                        archive,
                        size: artifact.size,
                        sha256: artifact.sha256.clone(),
                        provenance: Vec::new(),
                    },
                    0,
                ))
            }
        }
    }
}

/// The archive type a URL's file name implies.
fn archive_kind(url: &str) -> Option<ArchiveKind> {
    let name = url.rsplit('/').next()?.to_ascii_lowercase();
    if name.ends_with(".zip") {
        Some(ArchiveKind::Zip)
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        Some(ArchiveKind::TarGz)
    } else if name.ends_with(".tar.xz") || name.ends_with(".txz") {
        Some(ArchiveKind::TarXz)
    } else {
        None
    }
}

/// Whether the locked version of `locked` is one `selector` can pick, by the plugin's own
/// prefix and alias rules.
pub fn locked_satisfies(plugin: &Plugin, locked: &LockedTool, selector: &Selector) -> bool {
    let candidate = [crate::activate::Installed {
        variant: locked.variant.clone(),
        version: locked.version.clone(),
        dir: PathBuf::new(),
        home: PathBuf::new(),
    }];
    crate::activate::pick_installed(&plugin.manifest, Some(selector), &candidate).is_some()
}

/// The pins with each one `jtm.lock` locks replaced by its exact locked version (SPEC.md
/// section 5, step 4). The lock is the nearest `jtm.lock` at or above `start`, looking no
/// further than the nearest `.jtm.toml`; an entry whose pin it no longer satisfies is ignored.
pub fn apply_lock(start: &Path, pins: &ProjectPins, plugins: &[Plugin]) -> Result<ProjectPins> {
    // The lock `jtm lock` would write for this directory, and no other.
    let lock = match root_of(start, pins) {
        Some(root) => Lockfile::read(&root)?,
        None => None,
    };
    let mut resolved = pins.clone();
    let Some(lock) = lock else {
        return Ok(resolved);
    };
    for (tool, pin) in &mut resolved.pins {
        let (Some(locked), Some(plugin)) = (
            lock.tool(tool),
            plugins.iter().find(|p| &p.manifest.name == tool),
        ) else {
            continue;
        };
        if locked.requested == pin.selector.to_string()
            || locked_satisfies(plugin, locked, &pin.selector)
        {
            pin.selector = Selector {
                variant: Some(locked.variant.clone()),
                value: locked.version.clone(),
            };
        }
    }
    Ok(resolved)
}

/// Warning code for a locked tool with no artifact on any locked platform.
pub const W_LOCK_NO_ARTIFACTS: &str = "W_LOCK_NO_ARTIFACTS";

fn sorted(tool: &LockedTool) -> LockedTool {
    let mut tool = tool.clone();
    tool.artifacts.sort_by(|a, b| a.platform.cmp(&b.platform));
    tool
}

/// The lockfile's record of `plugin`.
pub fn locked_plugin(plugin: &Plugin) -> LockedPlugin {
    let (source, rev) = match plugin.origin {
        crate::indices::ManifestOrigin::Builtin => ("builtin".to_owned(), None),
    };
    LockedPlugin {
        name: plugin.manifest.name.clone(),
        source,
        rev,
        manifest_sha256: plugin.sha256.clone(),
        signing_keys: plugin.manifest.index.signing_keys.clone(),
    }
}

/// `path` relative to `root`, with `/` separators, going up with `..` when it is outside.
fn relative(root: &Path, path: &Path) -> String {
    let root: Vec<Component<'_>> = root.components().collect();
    let path: Vec<Component<'_>> = path.components().collect();
    let common = root.iter().zip(&path).take_while(|(a, b)| a == b).count();
    let mut parts: Vec<String> =
        std::iter::repeat_n("..".to_owned(), root.len() - common).collect();
    parts.extend(
        path[common..]
            .iter()
            .map(|c| c.as_os_str().to_string_lossy().into_owned()),
    );
    parts.join("/")
}

#[cfg(test)]
mod tests;
