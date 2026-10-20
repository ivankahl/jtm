//! Which version of each tool is active (SPEC.md section 5).
//!
//! The active version comes from the first layer that sets the tool, highest first:
//!
//! 1. **Exec:** specs passed to `jtm exec`, for that process only.
//! 2. **Session:** `jtm use`, stored in the shell as `JTM_SESSION_<TOOL>`.
//! 3. **Project:** the nearest pin file (see [`crate::pins`]).
//! 4. **Default:** `jtm default`, stored in `state/defaults.toml`.
//!
//! With none, jtm does not manage the tool and whatever is on `PATH` runs.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::{JtmError, Result};
use crate::pins::ProjectPins;
use crate::project::write_atomic;
use crate::spec::{Selector, ToolSpec};

/// The layer that chose a tool's version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Exec,
    Session,
    Project,
    Default,
}

impl Layer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Layer::Exec => "exec",
            Layer::Session => "session",
            Layer::Project => "project",
            Layer::Default => "default",
        }
    }
}

/// The winning layer's choice for one tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub tool: String,
    /// `None` for a bare `jtm exec <tool>`: the plugin's default.
    pub selector: Option<Selector>,
    pub layer: Layer,
    /// What set it: `jtm exec`, the session variable, the pin file or the defaults file.
    pub origin: String,
}

/// Everything that can set a tool's version.
#[derive(Debug, Clone, Copy)]
pub struct Layers<'a> {
    pub exec: &'a [ToolSpec],
    pub session: &'a BTreeMap<String, Selector>,
    pub project: &'a ProjectPins,
    pub defaults: &'a Defaults,
}

impl Layers<'_> {
    /// The highest layer's choice for `tool`, or `None` when no layer sets it.
    pub fn choose(&self, tool: &str) -> Option<Choice> {
        let choice = |selector: Option<Selector>, layer: Layer, origin: String| Choice {
            tool: tool.to_owned(),
            selector,
            layer,
            origin,
        };
        if let Some(spec) = self.exec.iter().find(|s| s.tool == tool) {
            return Some(choice(
                spec.selector.clone(),
                Layer::Exec,
                "jtm exec".to_owned(),
            ));
        }
        if let Some(selector) = self.session.get(tool) {
            return Some(choice(
                Some(selector.clone()),
                Layer::Session,
                session_var(tool),
            ));
        }
        if let Some(pin) = self.project.pins.get(tool) {
            return Some(choice(
                Some(pin.selector.clone()),
                Layer::Project,
                pin.file.display().to_string(),
            ));
        }
        self.defaults.get(tool).map(|selector| {
            choice(
                Some(selector.clone()),
                Layer::Default,
                self.defaults.path.display().to_string(),
            )
        })
    }
}

/// The shell variable `jtm use` stores a tool's session version in. Plugin names never contain
/// `_` or `--`, so writing `-` as `_` and `/` as `__` gives every tool its own name.
pub fn session_var(tool: &str) -> String {
    let name: String = tool
        .chars()
        .map(|c| match c {
            '/' => "__".to_owned(),
            '-' => "_".to_owned(),
            c => c.to_ascii_uppercase().to_string(),
        })
        .collect();
    format!("JTM_SESSION_{name}")
}

/// The session versions of `tools` set in the environment. An empty variable is unset.
pub fn session_from_env(
    tools: &[String],
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Result<BTreeMap<String, Selector>> {
    let mut session = BTreeMap::new();
    for tool in tools {
        let name = session_var(tool);
        let Some(raw) = env(&name).filter(|v| !v.is_empty()) else {
            continue;
        };
        let text = raw
            .into_string()
            .map_err(|_| JtmError::usage(format!("{name} is not valid UTF-8")))?;
        let selector = Selector::parse(&text).map_err(|e| {
            JtmError::usage(format!(
                "{name} is `{text}`, which is not a version: {e}; run `jtm use {tool} --unset`"
            ))
        })?;
        session.insert(tool.clone(), selector);
    }
    Ok(session)
}

/// One installed version of a tool, as activation sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub variant: String,
    pub version: String,
    /// The install dir.
    pub dir: PathBuf,
}

impl jtm_plugin::Candidate for Installed {
    fn variant(&self) -> &str {
        &self.variant
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn tags(&self) -> &[String] {
        &[]
    }
}

/// The installed version `selector` picks, by the plugin's own rules: an alias it can resolve
/// without index tags, or the highest version matching a prefix. `None` for the plugin default.
/// Preferring an install over a newer remote version keeps runs offline-friendly (SPEC.md
/// section 5, step 5).
pub fn pick_installed<'i>(
    manifest: &jtm_plugin::Manifest,
    selector: Option<&Selector>,
    installed: &'i [Installed],
) -> Option<&'i Installed> {
    match selector {
        None => jtm_plugin::resolve_default(manifest, manifest.default_variant(), installed).ok(),
        Some(selector) => {
            let variant = selector
                .variant
                .as_deref()
                .unwrap_or_else(|| manifest.default_variant());
            jtm_plugin::resolve_value(manifest, &selector.value, variant, installed).ok()
        }
    }
}

/// What activating one install changes: `[env]` variables and `PATH` entries.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ToolEnv {
    /// Variables by name, with `{home}` and `{bin}` filled in.
    pub vars: Vec<(String, String)>,
    /// The tool's bin directories, to put ahead of the rest of `PATH`.
    pub path: Vec<PathBuf>,
}

/// The environment for a tool whose home is `home`: the install dir plus the receipt's `home`,
/// or a current link. `{bin}` is the first of `layout.bin_dirs`.
pub fn tool_env(manifest: &jtm_plugin::Manifest, home: &Path) -> ToolEnv {
    let join = |relative: &str| {
        relative
            .split('/')
            .filter(|part| !part.is_empty() && *part != ".")
            .fold(home.to_path_buf(), |dir, part| dir.join(part))
    };
    let path: Vec<PathBuf> = manifest.layout.bin_dirs.iter().map(|d| join(d)).collect();
    let home_text = home.display().to_string();
    let bin_text = path
        .first()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| home_text.clone());
    let vars = manifest
        .env
        .iter()
        .map(|(name, value)| {
            let value = value
                .replace("{home}", &home_text)
                .replace("{bin}", &bin_text);
            (name.clone(), value)
        })
        .collect();
    ToolEnv { vars, path }
}

/// User defaults set by `jtm default`, kept in `state/defaults.toml` as exact versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Defaults {
    path: PathBuf,
    tools: BTreeMap<String, Selector>,
}

impl Defaults {
    pub fn empty(path: PathBuf) -> Defaults {
        Defaults {
            path,
            tools: BTreeMap::new(),
        }
    }

    /// Reads the defaults file; a missing file has no defaults. A file that does not parse is
    /// an error rather than a silent reset.
    pub fn load(path: &Path) -> Result<Defaults> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Ok(Defaults::empty(path.to_path_buf()));
            }
            Err(e) => return Err(JtmError::io(path, e)),
        };
        let corrupt = |message: String| JtmError::Config {
            origin: format!("defaults file {}", path.display()),
            key: String::new(),
            message: format!("{message}; fix it, or remove it to clear every default"),
        };
        let table: toml::Table = toml::from_str(&text).map_err(|e| corrupt(e.to_string()))?;
        let mut tools = BTreeMap::new();
        if let Some(defaults) = table.get("defaults") {
            let defaults = defaults
                .as_table()
                .ok_or_else(|| corrupt("`defaults` is not a table".to_owned()))?;
            for (tool, value) in defaults {
                let text = value
                    .as_str()
                    .ok_or_else(|| corrupt(format!("`{tool}` is not a string")))?;
                let selector = Selector::parse(text).map_err(|e| corrupt(e.to_string()))?;
                tools.insert(tool.clone(), selector);
            }
        }
        Ok(Defaults {
            path: path.to_path_buf(),
            tools,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn get(&self, tool: &str) -> Option<&Selector> {
        self.tools.get(tool)
    }

    /// Every default, by tool.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Selector)> {
        self.tools.iter().map(|(t, s)| (t.as_str(), s))
    }

    /// Sets `tool`'s default. Returns whether it changed.
    pub fn set(&mut self, tool: &str, selector: Selector) -> bool {
        self.tools.insert(tool.to_owned(), selector.clone()) != Some(selector)
    }

    /// Clears `tool`'s default. Returns whether it had one.
    pub fn remove(&mut self, tool: &str) -> bool {
        self.tools.remove(tool).is_some()
    }

    /// Writes the file atomically.
    pub fn save(&self) -> Result<()> {
        let mut text = String::from("[defaults]\n");
        for (tool, selector) in &self.tools {
            let key = toml_edit::Key::new(tool.as_str()).to_string();
            let value = toml_edit::Value::from(selector.to_string()).to_string();
            text.push_str(&format!("{key} = {}\n", value.trim()));
        }
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).map_err(|e| JtmError::io(dir, e))?;
        }
        write_atomic(&self.path, text.as_bytes())
    }
}

#[cfg(test)]
mod tests;
