//! What applies in one directory and shell: the activation context behind `jtm current`,
//! `which`, `exec`, `env` and `use` (SPEC.md sections 5 and 6).

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
                    env: tool_env(&plugin.manifest, &found.home),
                },
            );
        }
        Ok((overrides, warnings))
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

    /// The executable `command` runs here. A command a plugin declares comes from that tool's
    /// active install; anything else is looked up on `path`.
    pub fn which(&self, command: &str, os: Os, path: Option<&str>) -> Result<WhichItem> {
        for plugin in &self.plugins {
            let tool = plugin.manifest.name.as_str();
            let Some(file) = plugin
                .manifest
                .executables
                .for_os(os.as_str())
                .iter()
                .find(|e| *e == command || file_stem(e) == command)
            else {
                continue;
            };
            let Some(choice) = self.layers().choose(tool) else {
                continue;
            };
            let found = self
                .session
                .installed_match(plugin, choice.selector.as_ref())?
                .ok_or_else(|| JtmError::VersionNotFound {
                    tool: tool.to_owned(),
                    spec: format!(
                        "{} (set by {}, not installed)",
                        choice
                            .selector
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_default(),
                        choice.origin
                    ),
                })?;
            let env = tool_env(&plugin.manifest, &found.home);
            let path = env
                .path
                .iter()
                .map(|dir| dir.join(file))
                .find(|p| p.is_file())
                .ok_or_else(|| JtmError::LayoutMismatch {
                    plugin: tool.to_owned(),
                    message: format!("`{file}` is missing from {}", found.home.display()),
                })?;
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

fn file_stem(name: &str) -> &str {
    name.rsplit_once('.').map_or(name, |(stem, _)| stem)
}

/// The first file named `command` in `path`, trying Windows executable extensions on Windows.
pub fn find_on_path(command: &str, path: Option<&str>, os: Os) -> Option<PathBuf> {
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
    let separator = if os == Os::Windows { ';' } else { ':' };
    path?
        .split(separator)
        .filter(|dir| !dir.is_empty())
        .flat_map(|dir| candidates.iter().map(move |c| Path::new(dir).join(c)))
        .find(|p| p.is_file())
}
