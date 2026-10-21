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

use jtm_security::Warning;
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
    format!("JTM_SESSION_{}", var_suffix(tool))
}

/// The shell variable the hook records a tool's applied project pin in.
pub fn project_var(tool: &str) -> String {
    format!("JTM_PROJECT_{}", var_suffix(tool))
}

fn var_suffix(tool: &str) -> String {
    tool.chars()
        .map(|c| match c {
            '/' => "__".to_owned(),
            '-' => "_".to_owned(),
            c => c.to_ascii_uppercase().to_string(),
        })
        .collect()
}

/// The variable holding the values `[env]` variables had before jtm overrode them, as a JSON
/// object of name to value, `null` for unset.
pub const SAVED_VAR: &str = "JTM_SAVED";

/// A tool the shell should use from a real install dir rather than its current link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Override {
    pub tool: String,
    /// `Session` or `Project`.
    pub layer: Layer,
    /// The exact version, as `variant:version`.
    pub selector: Selector,
    /// What set it: `jtm exec`, the session variable or the pin file.
    pub origin: String,
    pub env: ToolEnv,
}

/// One change to a shell's environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Change {
    Set { name: String, value: String },
    Unset { name: String },
}

impl Change {
    pub fn name(&self) -> &str {
        match self {
            Change::Set { name, .. } | Change::Unset { name } => name,
        }
    }
}

/// The changes that turn the environment `env` into one where exactly `overrides` apply.
///
/// `PATH` entries under `tools_dir` are always jtm's, so they are dropped and the overrides'
/// bin directories put first. `[env]` variables are set for the overrides; one jtm set before
/// that no override sets now goes back to the value saved in [`SAVED_VAR`]. The session and
/// project variables of `tools` record which layer applied each tool. The plan is empty when
/// nothing would change, so applying it twice is a no-op.
pub fn plan_env(
    env: &dyn Fn(&str) -> Option<String>,
    overrides: &[Override],
    tools: &[String],
    tools_dir: &Path,
    path_separator: char,
) -> Vec<Change> {
    let saved_before: BTreeMap<String, Option<String>> = env(SAVED_VAR)
        .and_then(|json| serde_json::from_str(&json).ok())
        .unwrap_or_default();
    let mut desired: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut saved = BTreeMap::new();
    for o in overrides {
        for (name, value) in &o.env.vars {
            desired.insert(name.clone(), Some(value.clone()));
            let original = match saved_before.get(name) {
                Some(original) => original.clone(),
                None => env(name),
            };
            saved.insert(name.clone(), original);
        }
    }
    for (name, original) in &saved_before {
        desired
            .entry(name.clone())
            .or_insert_with(|| original.clone());
    }

    let current_path = env("PATH");
    let mut entries: Vec<String> = overrides
        .iter()
        .flat_map(|o| o.env.path.iter().map(|p| p.display().to_string()))
        .collect();
    if let Some(path) = &current_path {
        entries.extend(
            path.split(path_separator)
                .filter(|entry| !Path::new(entry).starts_with(tools_dir))
                .map(str::to_owned),
        );
    }
    if current_path.is_some() || !entries.is_empty() {
        desired.insert(
            "PATH".to_owned(),
            Some(entries.join(&path_separator.to_string())),
        );
    }

    desired.insert(
        SAVED_VAR.to_owned(),
        (!saved.is_empty()).then(|| serde_json::to_string(&saved).unwrap_or_default()),
    );
    let mut all_tools: Vec<&str> = tools.iter().map(String::as_str).collect();
    all_tools.extend(overrides.iter().map(|o| o.tool.as_str()));
    for tool in all_tools {
        let applied = |layer: Layer| {
            overrides
                .iter()
                .find(|o| o.tool == tool && o.layer == layer)
                .map(|o| o.selector.to_string())
        };
        desired.insert(session_var(tool), applied(Layer::Session));
        desired.insert(project_var(tool), applied(Layer::Project));
    }

    desired
        .into_iter()
        .filter(|(name, want)| env(name) != *want)
        .map(|(name, want)| match want {
            Some(value) => Change::Set { name, value },
            None => Change::Unset { name },
        })
        .collect()
}

/// Warning code for a `JTM_SESSION_*` value that is not a version and so is ignored.
pub const W_SESSION_INVALID: &str = "W_SESSION_INVALID";

/// The session versions of `tools` set in the environment. An empty variable is unset. A value
/// that is not a version is skipped with a warning rather than failing, so the shell hook keeps
/// working and clears it, and `jtm use <tool> --unset` can still run.
pub fn session_from_env(
    tools: &[String],
    env: &dyn Fn(&str) -> Option<OsString>,
) -> (BTreeMap<String, Selector>, Vec<Warning>) {
    let mut session = BTreeMap::new();
    let mut warnings = Vec::new();
    for tool in tools {
        let name = session_var(tool);
        let Some(raw) = env(&name).filter(|v| !v.is_empty()) else {
            continue;
        };
        let parsed = raw
            .into_string()
            .map_err(|_| "it is not valid UTF-8".to_owned())
            .and_then(|text| {
                Selector::parse(&text).map_err(|e| format!("`{text}` is not a version: {e}"))
            });
        match parsed {
            Ok(selector) => {
                session.insert(tool.clone(), selector);
            }
            Err(reason) => warnings.push(Warning {
                code: W_SESSION_INVALID,
                message: format!("{name} is ignored because {reason}"),
            }),
        }
    }
    (session, warnings)
}

/// One installed version of a tool, as activation sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub variant: String,
    pub version: String,
    /// The install dir.
    pub dir: PathBuf,
    /// The tool home: the install dir plus the receipt's `home`.
    pub home: PathBuf,
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
