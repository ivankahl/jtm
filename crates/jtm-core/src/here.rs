//! What applies in one directory and shell: the activation context behind `jtm current`,
//! `which`, `exec`, `env` and `use` (SPEC.md sections 5 and 6).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use jtm_security::Warning;
use serde::Serialize;

use crate::activate::{
    Change, Defaults, Installed, Layer, Layers, Override, plan_env, session_from_env, tool_env,
};
use crate::error::{JtmError, Result};
use crate::pins::{ProjectPins, discover};
use crate::platform::Os;
use crate::plugins::Plugin;
use crate::session::{PATH_SEPARATOR, Session, pin_warnings};
use crate::spec::Selector;
use crate::sync::apply_lock;

/// Warning code when an active tool's `[requires]` entry is not met by the active version of
/// the tool it needs, such as a build tool that needs a newer Java than the one active.
pub const W_REQUIRES_UNMET: &str = "W_REQUIRES_UNMET";

/// The plugins, pins, session versions and defaults that apply in one directory.
#[derive(Debug)]
pub struct Here<'s, 'c> {
    pub session: &'s Session<'c>,
    pub plugins: Vec<Plugin>,
    /// The pins as the files set them.
    pub pins: ProjectPins,
    /// The pins with locked versions applied, as activation uses them.
    pub resolved: ProjectPins,
    /// Session versions from `JTM_SESSION_*`.
    pub selected: BTreeMap<String, Selector>,
    /// Warnings for `JTM_SESSION_*` values that were ignored.
    pub session_warnings: Vec<Warning>,
    pub defaults: Defaults,
}

/// One tool as `jtm current` reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CurrentItem {
    pub tool: String,
    /// The winning layer; `None` when jtm does not manage the tool here.
    pub layer: Option<Layer>,
    /// What set it: `jtm exec`, a variable, a pin file or the defaults file.
    pub origin: Option<String>,
    /// The pin or spec as set, such as `temurin:21`.
    pub requested: Option<String>,
    pub variant: Option<String>,
    pub version: Option<String>,
    /// The install dir, when the version is installed.
    pub path: Option<String>,
    pub installed: bool,
}

/// What `jtm which` found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WhichItem {
    pub command: String,
    /// The tool providing it, when jtm manages it here.
    pub tool: Option<String>,
    pub layer: Option<Layer>,
    pub version: Option<String>,
    pub path: String,
}

impl<'s, 'c> Here<'s, 'c> {
    /// Reads the context for `cwd` and the environment `env`.
    pub fn read(
        session: &'s Session<'c>,
        cwd: &Path,
        env: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Here<'s, 'c>> {
        let plugins = session.plugins()?;
        let tools: Vec<String> = plugins.iter().map(|p| p.manifest.name.clone()).collect();
        let pins = discover(cwd, &plugins)?;
        let resolved = if session.uses_lockfile() {
            apply_lock(cwd, &pins, &plugins)?
        } else {
            pins.clone()
        };
        let (selected, session_warnings) = session_from_env(&tools, env);
        let defaults = Defaults::load(&session.dirs().defaults_file())?;
        Ok(Here {
            session,
            plugins,
            pins,
            resolved,
            selected,
            session_warnings,
            defaults,
        })
    }

    pub fn tools(&self) -> Vec<String> {
        self.plugins
            .iter()
            .map(|p| p.manifest.name.clone())
            .collect()
    }

    pub fn plugin(&self, tool: &str) -> Result<&Plugin> {
        self.plugins
            .iter()
            .find(|p| p.manifest.name == tool)
            .ok_or_else(|| JtmError::ToolUnknown {
                tool: tool.to_owned(),
            })
    }

    /// Pin conflicts and ignored session values as warnings.
    pub fn warnings(&self) -> Vec<Warning> {
        let mut warnings = pin_warnings(&self.pins);
        warnings.extend(self.session_warnings.iter().cloned());
        warnings
    }

    fn layers(&self) -> Layers<'_> {
        Layers {
            exec: &[],
            session: &self.selected,
            project: &self.resolved,
            defaults: &self.defaults,
        }
    }

    /// The active version of each tool, or of `only`.
    pub fn current(&self, only: Option<&str>) -> Result<Vec<CurrentItem>> {
        if let Some(tool) = only {
            self.plugin(tool)?;
        }
        let mut items = Vec::new();
        for plugin in &self.plugins {
            let tool = plugin.manifest.name.as_str();
            if only.is_some_and(|o| o != tool) {
                continue;
            }
            let Some(choice) = self.layers().choose(tool) else {
                items.push(CurrentItem {
                    tool: tool.to_owned(),
                    layer: None,
                    origin: None,
                    requested: None,
                    variant: None,
                    version: None,
                    path: None,
                    installed: false,
                });
                continue;
            };
            let found = self
                .session
                .installed_match(plugin, choice.selector.as_ref())?;
            items.push(CurrentItem {
                tool: tool.to_owned(),
                layer: Some(choice.layer),
                origin: Some(choice.origin),
                // A project pin is shown as written, not as the version the lock resolved.
                requested: match choice.layer {
                    Layer::Project => self.pins.pins.get(tool).map(|p| p.selector.to_string()),
                    _ => choice.selector.as_ref().map(ToString::to_string),
                },
                variant: found.as_ref().map(|f| f.variant.clone()),
                version: found.as_ref().map(|f| f.version.clone()),
                path: found.as_ref().map(|f| f.dir.display().to_string()),
                installed: found.is_some(),
            });
        }
        Ok(items)
    }

    /// The tools to take from real install dirs: `exec` first, then session and project
    /// choices. Defaults stay with the current links.
    pub fn overrides(&self, exec: &[(String, Installed)]) -> Result<(Vec<Override>, Vec<Warning>)> {
        let mut selected = self.selected.clone();
        for (tool, _) in exec {
            selected.remove(tool);
        }
        let mut pins = self.resolved.clone();
        for (tool, _) in exec {
            pins.pins.remove(tool);
        }
        let (mut overrides, mut warnings) =
            self.session.overrides(&selected, &pins, &self.plugins)?;
        warnings.extend(self.session_warnings.iter().cloned());
        for (tool, found) in exec.iter().rev() {
            let plugin = self.plugin(tool)?;
            overrides.insert(
                0,
                Override {
                    tool: tool.clone(),
                    layer: Layer::Exec,
                    selector: Selector {
                        variant: Some(found.variant.clone()),
                        value: found.version.clone(),
                    },
                    origin: "jtm exec".to_owned(),
                    env: tool_env(&plugin.manifest, &found.home),
                },
            );
        }
        Ok((overrides, warnings))
    }

    /// A [`W_REQUIRES_UNMET`] warning for each `[requires]` entry of an active tool that the
    /// active version of the required tool does not meet. The active versions are the
    /// `overrides`, as [`Here::overrides`] returned them, and the defaults of tools only the
    /// defaults set, so a version a pin chose but is not installed is not active, as in
    /// [`Here::current`]. A
    /// required tool jtm does not manage here is not checked, since whatever is on `PATH` may
    /// meet it. Requirements are only ever warnings; nothing is installed, and a failure to
    /// read a default's installs only skips that tool, so it never fails a command.
    pub fn requirement_warnings(&self, overrides: &[Override]) -> Vec<Warning> {
        // A default is looked up at most once, however many tools require it.
        let defaults = RefCell::new(BTreeMap::new());
        self.unmet_requirements(|tool| match overrides.iter().find(|o| o.tool == tool) {
            Some(found) => Some((found.selector.value.clone(), found.origin.clone())),
            None => defaults
                .borrow_mut()
                .entry(tool.to_owned())
                .or_insert_with(|| self.default_version(tool))
                .clone(),
        })
    }

    /// [`Here::requirement_warnings`] for the active versions `jtm current` found, which must
    /// cover every tool.
    pub fn current_requirement_warnings(&self, items: &[CurrentItem]) -> Vec<Warning> {
        self.unmet_requirements(|tool| {
            let item = items.iter().find(|i| i.tool == tool)?;
            Some((
                item.version.clone()?,
                item.origin.clone().unwrap_or_default(),
            ))
        })
    }

    /// The warnings for the active `(version, origin)` of each tool that `active` gives. It is
    /// asked only about tools that are active or required, so the lookups stay few.
    fn unmet_requirements(
        &self,
        active: impl Fn(&str) -> Option<(String, String)>,
    ) -> Vec<Warning> {
        let mut warnings = Vec::new();
        for plugin in &self.plugins {
            if plugin.manifest.requires.is_empty() {
                continue;
            }
            let tool = plugin.manifest.name.as_str();
            let Some((version, _)) = active(tool) else {
                continue;
            };
            for (needed, requirement) in &plugin.manifest.requires {
                let Ok(needed_plugin) = self.plugin(needed) else {
                    continue;
                };
                let Some((have, origin)) = active(needed) else {
                    continue;
                };
                if meets(&needed_plugin.manifest, &have, requirement) == Some(false) {
                    warnings.push(Warning {
                        code: W_REQUIRES_UNMET,
                        message: format!(
                            "`{tool}` {version} needs `{needed}` {requirement}, but the active \
                             `{needed}` is {have} (set by {origin})"
                        ),
                    });
                }
            }
        }
        warnings
    }

    /// The installed version `tool`'s default picks, with the defaults file as its origin, when
    /// no higher layer chooses `tool`.
    fn default_version(&self, tool: &str) -> Option<(String, String)> {
        let choice = self.layers().choose(tool)?;
        if choice.layer != Layer::Default {
            return None;
        }
        let selector = choice.selector?;
        let plugin = self.plugin(tool).ok()?;
        match self.session.installed_match(plugin, Some(&selector)) {
            Ok(found) => {
                found.map(|found| (found.version, self.defaults.path().display().to_string()))
            }
            Err(err) => {
                tracing::debug!(%err, tool, "cannot read the default's installs");
                None
            }
        }
    }

    /// The changes that make `env` match the overrides.
    pub fn plan(
        &self,
        env: &dyn Fn(&str) -> Option<String>,
        overrides: &[Override],
    ) -> Vec<Change> {
        plan_env(
            env,
            overrides,
            &self.tools(),
            &self.session.dirs().tools(),
            PATH_SEPARATOR,
        )
    }

    /// The executable `command` runs here: the first active install whose bin dirs hold it, so
    /// any file a tool ships maps to that tool, whatever the version calls it; anything else is
    /// looked up on `path`.
    pub fn which(&self, command: &str, os: Os, path: Option<&str>) -> Result<WhichItem> {
        for plugin in &self.plugins {
            let tool = plugin.manifest.name.as_str();
            let Some(choice) = self.layers().choose(tool) else {
                continue;
            };
            let Some(found) = self
                .session
                .installed_match(plugin, choice.selector.as_ref())?
            else {
                continue;
            };
            let env = tool_env(&plugin.manifest, &found.home);
            let Some(path) = find_in_dirs(command, &env.path, os) else {
                continue;
            };
            return Ok(WhichItem {
                command: command.to_owned(),
                tool: Some(tool.to_owned()),
                layer: Some(choice.layer),
                version: Some(format!("{}:{}", found.variant, found.version)),
                path: path.display().to_string(),
            });
        }
        let found = find_on_path(command, path, os).ok_or_else(|| JtmError::ToolUnknown {
            tool: command.to_owned(),
        })?;
        Ok(WhichItem {
            command: command.to_owned(),
            tool: None,
            layer: None,
            version: None,
            path: found.display().to_string(),
        })
    }
}

/// Whether `version` meets every clause of `requirement` under `manifest`'s scheme; `None`
/// when that cannot be decided, such as for a version the scheme cannot parse.
fn meets(manifest: &jtm_plugin::Manifest, version: &str, requirement: &str) -> Option<bool> {
    let scheme = manifest.versions.scheme.builtin()?;
    let have = scheme.parse(version).ok()?;
    for (op, wanted) in jtm_plugin::manifest::parse_requirement(requirement).ok()? {
        if !op.holds(have.cmp_precedence(&scheme.parse(&wanted).ok()?)) {
            return Some(false);
        }
    }
    Some(true)
}

/// The first file named `command` in `path`, trying Windows executable extensions on Windows.
pub fn find_on_path(command: &str, path: Option<&str>, os: Os) -> Option<PathBuf> {
    let separator = if os == Os::Windows { ';' } else { ':' };
    let dirs: Vec<PathBuf> = path?
        .split(separator)
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .collect();
    find_in_dirs(command, &dirs, os)
}

/// The first file named `command` in `dirs`, trying Windows executable extensions on Windows.
pub fn find_in_dirs(command: &str, dirs: &[PathBuf], os: Os) -> Option<PathBuf> {
    let candidates: Vec<String> = if os == Os::Windows && !command.contains('.') {
        let pathext = std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into());
        pathext
            .split(';')
            .filter(|e| !e.is_empty())
            .map(|ext| format!("{command}{}", ext.to_ascii_lowercase()))
            .chain(std::iter::once(command.to_owned()))
            .collect()
    } else {
        vec![command.to_owned()]
    };
    dirs.iter()
        .flat_map(|dir| candidates.iter().map(move |c| dir.join(c)))
        .find(|p| p.is_file())
}
