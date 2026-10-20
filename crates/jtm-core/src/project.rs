//! The native pin file, `.jtm.toml` (SPEC.md section 6).
//!
//! The file is edited with `toml_edit`, so `jtm pin` and `jtm unpin` keep the user's comments,
//! ordering and formatting. Parsing validates every table jtm reads: `[tools]` pins,
//! `[plugins]` entries and `[lock]`. `[settings]` is validated by configuration loading, which
//! refuses the keys a project must not set.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use jtm_plugin::names::check_plugin_name;
use toml_edit::{DocumentMut, Item, Table, Value};

use crate::error::{JtmError, Result};
use crate::platform::Platform;
use crate::spec::Selector;

/// The native pin file's name.
pub const PROJECT_FILE: &str = ".jtm.toml";

/// The top-level tables a `.jtm.toml` may hold.
const TABLES: &[&str] = &["tools", "plugins", "settings", "lock"];

/// A parsed `.jtm.toml`.
#[derive(Debug, Clone)]
pub struct ProjectFile {
    path: PathBuf,
    doc: DocumentMut,
}

/// One `[plugins]` entry: a third-party plugin the project needs, pinned to a revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectPlugin {
    pub name: String,
    pub source: String,
    pub rev: String,
}

impl ProjectFile {
    /// An empty file at `path`, for `jtm pin` in a project without one.
    pub fn empty(path: &Path) -> ProjectFile {
        ProjectFile {
            path: path.to_path_buf(),
            doc: DocumentMut::new(),
        }
    }

    /// Parses and validates the text of the file at `path`.
    pub fn parse(path: &Path, text: &str) -> Result<ProjectFile> {
        let doc: DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| {
            let line = e
                .span()
                .map(|s| text[..s.start.min(text.len())].matches('\n').count() + 1);
            let message = e.message().trim().to_owned();
            let message = match line {
                Some(line) => format!("line {line}: {message}"),
                None => message,
            };
            error(path, "", message)
        })?;
        let file = ProjectFile {
            path: path.to_path_buf(),
            doc,
        };
        file.validate()?;
        Ok(file)
    }

    /// Reads `dir/.jtm.toml`, or `None` when there is none.
    pub fn read(dir: &Path) -> Result<Option<ProjectFile>> {
        let path = dir.join(PROJECT_FILE);
        match fs::read_to_string(&path) {
            Ok(text) => ProjectFile::parse(&path, &text).map(Some),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(JtmError::io(&path, e)),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The `[tools]` pins, in file order.
    pub fn tools(&self) -> Vec<(String, Selector)> {
        let Some(tools) = self.doc.get("tools").and_then(Item::as_table_like) else {
            return Vec::new();
        };
        tools
            .iter()
            .filter_map(|(tool, item)| {
                let selector = Selector::parse(item.as_str()?).ok()?;
                Some((tool.to_owned(), selector))
            })
            .collect()
    }

    /// The pin for `tool`, if the file sets one.
    pub fn tool(&self, tool: &str) -> Option<Selector> {
        self.tools()
            .into_iter()
            .find(|(name, _)| name == tool)
            .map(|(_, selector)| selector)
    }

    /// Pins `tool` to `selector`, keeping the line's comments when it already exists. Returns
    /// whether the file changed.
    pub fn set_tool(&mut self, tool: &str, selector: &Selector) -> bool {
        let text = selector.to_string();
        if self.tool(tool).is_some_and(|s| s.to_string() == text) {
            return false;
        }
        let Some(tools) = self.tools_table() else {
            return false;
        };
        match tools.get_mut(tool).and_then(Item::as_value_mut) {
            Some(value) => {
                // Keep the comment and spacing around the old value.
                let decor = value.decor().clone();
                *value = Value::from(text);
                *value.decor_mut() = decor;
            }
            None => {
                tools.insert(tool, toml_edit::value(text));
            }
        }
        true
    }

    /// Removes the pin for `tool`. Returns whether the file changed.
    pub fn remove_tool(&mut self, tool: &str) -> bool {
        self.doc
            .get_mut("tools")
            .and_then(Item::as_table_like_mut)
            .and_then(|tools| tools.remove(tool))
            .is_some()
    }

    /// The `[plugins]` entries, in file order.
    pub fn plugins(&self) -> Vec<ProjectPlugin> {
        let Some(plugins) = self.doc.get("plugins").and_then(Item::as_table_like) else {
            return Vec::new();
        };
        plugins
            .iter()
            .filter_map(|(name, item)| {
                let entry = item.as_table_like()?;
                Some(ProjectPlugin {
                    name: name.to_owned(),
                    source: entry.get("source")?.as_str()?.to_owned(),
                    rev: entry.get("rev")?.as_str()?.to_owned(),
                })
            })
            .collect()
    }

    /// `[lock] platforms`, the platforms `jtm.lock` covers, when the file narrows them.
    pub fn lock_platforms(&self) -> Option<Vec<Platform>> {
        let platforms = self.doc.get("lock")?.get("platforms")?.as_array()?;
        Some(
            platforms
                .iter()
                .filter_map(|v| v.as_str()?.parse().ok())
                .collect(),
        )
    }

    /// The file's text.
    pub fn render(&self) -> String {
        self.doc.to_string()
    }

    /// Writes the file, replacing it atomically so a reader never sees half of it.
    pub fn write(&self) -> Result<()> {
        write_atomic(&self.path, self.render().as_bytes())
    }

    /// `[tools]`, appended to the file when missing.
    fn tools_table(&mut self) -> Option<&mut dyn toml_edit::TableLike> {
        if !self.doc.contains_key("tools") {
            let mut table = Table::new();
            if !self.doc.as_table().is_empty() {
                table.decor_mut().set_prefix("\n");
            }
            self.doc.insert("tools", Item::Table(table));
        }
        // Validation guarantees `tools` is a table when present.
        self.doc.get_mut("tools").and_then(Item::as_table_like_mut)
    }

    fn validate(&self) -> Result<()> {
        let path = &self.path;
        for (key, item) in self.doc.iter() {
            if !TABLES.contains(&key) {
                return Err(error(
                    path,
                    key,
                    format!("unknown table; a .jtm.toml holds {}", list(TABLES)),
                ));
            }
            if item.as_table_like().is_none() {
                return Err(error(
                    path,
                    key,
                    format!("expected a table such as `[{key}]`"),
                ));
            }
        }
        if let Some(tools) = self.doc.get("tools").and_then(Item::as_table_like) {
            for (tool, item) in tools.iter() {
                let key = format!("tools.{tool}");
                check_plugin_name(tool).map_err(|(_, message)| error(path, &key, message))?;
                let text = item.as_str().ok_or_else(|| {
                    error(
                        path,
                        &key,
                        "expected a version, alias or `variant:version` string such as \"21\"",
                    )
                })?;
                Selector::parse(text).map_err(|e| error(path, &key, e.to_string()))?;
            }
        }
        if let Some(plugins) = self.doc.get("plugins").and_then(Item::as_table_like) {
            for (name, item) in plugins.iter() {
                let key = format!("plugins.{name}");
                check_plugin_name(name).map_err(|(_, message)| error(path, &key, message))?;
                let entry = item.as_table_like().ok_or_else(|| {
                    error(
                        path,
                        &key,
                        "expected `{ source = \"<url>\", rev = \"<commit>\" }`",
                    )
                })?;
                for (field, value) in entry.iter() {
                    if !matches!(field, "source" | "rev") {
                        return Err(error(
                            path,
                            &format!("{key}.{field}"),
                            "unknown key; a plugin entry has `source` and `rev`",
                        ));
                    }
                    if value.as_str().is_none_or(|s| s.trim().is_empty()) {
                        return Err(error(
                            path,
                            &format!("{key}.{field}"),
                            "expected a non-empty string",
                        ));
                    }
                }
                for field in ["source", "rev"] {
                    if !entry.contains_key(field) {
                        return Err(error(
                            path,
                            &format!("{key}.{field}"),
                            "missing; a project plugin is pinned by `source` and `rev`",
                        ));
                    }
                }
            }
        }
        if let Some(lock) = self.doc.get("lock").and_then(Item::as_table_like) {
            for (field, item) in lock.iter() {
                let key = format!("lock.{field}");
                if field != "platforms" {
                    return Err(error(path, &key, "unknown key; `[lock]` has `platforms`"));
                }
                let platforms = item
                    .as_array()
                    .ok_or_else(|| error(path, &key, "expected a list such as [\"linux-x64\"]"))?;
                for value in platforms.iter() {
                    let known = value
                        .as_str()
                        .is_some_and(|s| s.parse::<Platform>().is_ok());
                    if !known {
                        let names: Vec<&str> = Platform::ALL.iter().map(|p| p.as_str()).collect();
                        return Err(error(
                            path,
                            &key,
                            format!("expected platforms from {}", list(&names)),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

fn list(items: &[&str]) -> String {
    items
        .iter()
        .map(|i| format!("`{i}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn error(path: &Path, key: &str, message: impl Into<String>) -> JtmError {
    JtmError::Config {
        origin: format!("project file {}", path.display()),
        key: key.to_owned(),
        message: message.into(),
    }
}

/// Writes `bytes` to `path` through a temporary file in the same directory and a rename.
///
/// A symlink is followed, so the file it points at is replaced and the link kept (a dotfiles
/// manager's link stays a link). The replaced file's permissions are kept; a new file gets
/// the usual permissions for the user's umask rather than the temporary file's owner-only ones.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let target = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            std::fs::canonicalize(path).map_err(|e| JtmError::io(path, e))?
        }
        _ => path.to_path_buf(),
    };
    let existing = match std::fs::metadata(&target) {
        Ok(meta) => Some(meta.permissions()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(JtmError::io(&target, e)),
    };
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Subject to the umask, as a file created with `open` would be.
        builder.permissions(std::fs::Permissions::from_mode(0o666));
    }
    let mut tmp = builder.tempfile_in(dir).map_err(|e| JtmError::io(dir, e))?;
    io::Write::write_all(&mut tmp, bytes).map_err(|e| JtmError::io(tmp.path(), e))?;
    if let Some(permissions) = existing {
        std::fs::set_permissions(tmp.path(), permissions)
            .map_err(|e| JtmError::io(tmp.path(), e))?;
    }
    tmp.persist(&target)
        .map_err(|e| JtmError::io(&target, e.error))?;
    Ok(())
}

#[cfg(test)]
mod tests;
