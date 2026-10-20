//! `jtm lock` and `jtm sync` (SPEC.md section 11): resolving a project's pins to exact
//! versions for every platform, and installing what the lock names.

use std::path::{Component, Path, PathBuf};

use jtm_security::{IndexEntry, Warning};
use serde::Serialize;

use crate::error::{JtmError, Result};
use crate::lockfile::{LOCK_FILE, LockedArtifact, LockedPlugin, LockedTool, Lockfile};
use crate::pins::{ProjectPins, discover};
use crate::platform::Platform;
use crate::plugins::Plugin;
use crate::project::{PROJECT_FILE, ProjectFile};
use crate::session::{Session, pin_warnings};
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

/// The project directory for `start`: the nearest directory with a `jtm.lock` or `.jtm.toml`,
/// or else the nearest with any pin file. The lock lives there, and pins are read from there,
/// so running from any subdirectory gives the same lock.
pub fn project_root(start: &Path, plugins: &[Plugin]) -> Result<PathBuf> {
    for dir in start.ancestors() {
        if dir.join(LOCK_FILE).is_file() || dir.join(PROJECT_FILE).is_file() {
            return Ok(dir.to_path_buf());
        }
    }
    let pins = discover(start, plugins)?;
    pins.files
        .first()
        .and_then(|f| f.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            JtmError::usage(format!(
                "no project pins at or above {}; pin a tool first with `jtm pin <tool>@<version>`",
                start.display()
            ))
        })
}

impl Session<'_> {
    /// Resolves the pins of the project around `start` for every platform, keeping each lock
    /// entry whose pin is unchanged unless `upgrade` names it, and writes `jtm.lock` unless
    /// `dry_run`.
    pub fn lock(&self, start: &Path, options: &LockOptions) -> Result<LockReport> {
        let plugins = self.plugins()?;
        let root = project_root(start, &plugins)?;
        let pins = discover(&root, &plugins)?;
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
            let keep =
                previous.filter(|p| p.requested == requested && !options.upgrade.covers(tool));
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

/// Warning code for a locked tool with no artifact on any locked platform.
pub const W_LOCK_NO_ARTIFACTS: &str = "W_LOCK_NO_ARTIFACTS";

fn sorted(tool: &LockedTool) -> LockedTool {
    let mut tool = tool.clone();
    tool.artifacts.sort_by(|a, b| a.platform.cmp(&b.platform));
    tool
}

/// The lockfile's record of `plugin`.
pub fn locked_plugin(plugin: &Plugin) -> LockedPlugin {
    // SPEC-QUESTION: where a third-party plugin came from is recorded by `jtm plugin add`
    // (T9.3). Until then an external plugin is locked by its manifest hash and the revision in
    // its directory name, with source `external`.
    let (source, rev) = match plugin.origin {
        crate::indices::ManifestOrigin::Builtin => ("builtin".to_owned(), None),
        crate::indices::ManifestOrigin::External => {
            let rev = Path::new(&plugin.location)
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .and_then(|n| n.split_once('@'))
                .map(|(_, rev)| rev.to_owned());
            ("external".to_owned(), rev)
        }
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
