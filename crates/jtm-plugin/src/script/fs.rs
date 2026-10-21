//! `jtm.fs`: the file operations `post_extract` may use, confined to the install dir.
//!
//! Paths are relative and `/`-separated, as in `bin/tool` or `.` for the install dir itself.
//! Absolute paths, `..`, backslashes, colons and control characters are refused, as the
//! archive rules refuse them, and so is any path whose parent directories include a link, so
//! no operation can reach outside the install dir. Operations act on links themselves, never
//! on their targets, and `chmod` refuses links. Moving a link can change where it points, so
//! once the hook returns, [`check_links`] fails it if any link points outside, or if any
//! directory cannot be read, since a link could hide in it.
//!
//! - `exists(path)` and `is_dir(path)`, without following links.
//! - `list(dir)`: the sorted names in a directory.
//! - `rename(from, to)`, also named `move`: `to` must not exist yet.
//! - `remove(path)`: a file, a link or a whole directory.
//! - `chmod(path, mode)`: permission bits from `0` to `0o777`; a no-op on Windows. A
//!   directory keeps at least `0o700`, so jtm can still check, move and remove it.
//!
//! Failed operations, such as a missing file, raise ordinary errors the script may catch. A
//! path that leaves the install dir is recorded as a limit breach and fails the hook even if
//! the script catches it.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use mlua::{Lua, Table};

use super::sandbox::refuse;
use super::{Limit, Shared};

/// The highest mode `chmod` accepts: permission bits only, never setuid, setgid or sticky.
const MAX_MODE: u32 = 0o777;
/// The bits a directory's mode must keep: read, write and search for its owner.
const DIR_MODE: u32 = 0o700;

/// A directory the script may change, and nothing outside it.
#[derive(Debug, Clone)]
struct Root {
    dir: PathBuf,
    shared: Arc<Shared>,
}

impl Root {
    /// The absolute path for `rel`, refusing anything that could leave the root.
    fn resolve(&self, rel: &str) -> mlua::Result<PathBuf> {
        if self.shared.cancelled() {
            return Err(refuse(&self.shared, Limit::Time(self.shared.limits.time)));
        }
        let escape = |reason: &str| {
            refuse(
                &self.shared,
                Limit::Path {
                    path: rel.to_owned(),
                    reason: reason.to_owned(),
                },
            )
        };
        if rel.is_empty() {
            return Err(escape("is empty"));
        }
        if rel.starts_with('/') || rel.contains(['\\', ':']) {
            return Err(escape("is not a relative `/`-separated path"));
        }
        if rel.chars().any(char::is_control) {
            return Err(escape("contains control characters"));
        }
        let mut path = self.dir.clone();
        let parts: Vec<&str> = rel
            .split('/')
            .filter(|p| !p.is_empty() && *p != ".")
            .collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == ".." {
                return Err(escape("contains `..`"));
            }
            path.push(part);
            let is_parent = i + 1 < parts.len();
            if is_parent && fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
                return Err(escape("goes through a link"));
            }
        }
        Ok(path)
    }

    /// Like [`Root::resolve`], refusing the root itself.
    fn resolve_entry(&self, rel: &str) -> mlua::Result<PathBuf> {
        let path = self.resolve(rel)?;
        if path == self.dir {
            return Err(mlua::Error::runtime(
                "this cannot be done to the install dir itself",
            ));
        }
        Ok(path)
    }
}

/// Builds the read-only `jtm.fs` table for `dir`, which must be canonical.
pub(super) fn api(lua: &Lua, dir: PathBuf, shared: Arc<Shared>) -> mlua::Result<Table> {
    let root = Root { dir, shared };
    let t = lua.create_table()?;

    let r = root.clone();
    t.raw_set(
        "exists",
        lua.create_function(move |_, path: String| {
            Ok(fs::symlink_metadata(r.resolve(&path)?).is_ok())
        })?,
    )?;
    let r = root.clone();
    t.raw_set(
        "is_dir",
        lua.create_function(move |_, path: String| {
            Ok(fs::symlink_metadata(r.resolve(&path)?).is_ok_and(|m| m.is_dir()))
        })?,
    )?;
    let r = root.clone();
    t.raw_set(
        "list",
        lua.create_function(move |lua, path: String| {
            let dir = r.resolve(&path)?;
            if !fs::symlink_metadata(&dir).is_ok_and(|m| m.is_dir()) {
                return Err(mlua::Error::runtime(format!("`{path}` is not a directory")));
            }
            let mut names = Vec::new();
            for entry in fs::read_dir(&dir).map_err(|e| io_error(&path, &e))? {
                let entry = entry.map_err(|e| io_error(&path, &e))?;
                names.push(entry.file_name().to_string_lossy().into_owned());
            }
            names.sort();
            lua.create_sequence_from(names)
        })?,
    )?;
    let r = root.clone();
    let rename = lua.create_function(move |_, (from, to): (String, String)| {
        let (source, dest) = (r.resolve_entry(&from)?, r.resolve_entry(&to)?);
        fs::symlink_metadata(&source).map_err(|e| io_error(&from, &e))?;
        if fs::symlink_metadata(&dest).is_ok() {
            return Err(mlua::Error::runtime(format!("`{to}` already exists")));
        }
        if dest.starts_with(&source) {
            return Err(mlua::Error::runtime(format!(
                "`{from}` cannot move into itself"
            )));
        }
        fs::rename(&source, &dest).map_err(|e| io_error(&from, &e))
    })?;
    t.raw_set("rename", rename.clone())?;
    t.raw_set("move", rename)?;
    let r = root.clone();
    t.raw_set(
        "remove",
        lua.create_function(move |_, path: String| {
            let target = r.resolve_entry(&path)?;
            let meta = fs::symlink_metadata(&target).map_err(|e| io_error(&path, &e))?;
            let removed = if meta.is_dir() {
                fs::remove_dir_all(&target)
            } else {
                remove_file_or_link(&target)
            };
            removed.map_err(|e| io_error(&path, &e))
        })?,
    )?;
    let r = root;
    t.raw_set(
        "chmod",
        lua.create_function(move |_, (path, mode): (String, u32)| {
            if mode > MAX_MODE {
                return Err(mlua::Error::runtime(format!(
                    "mode {mode:#o} is above 0o777; setuid, setgid and sticky bits are not allowed"
                )));
            }
            let target = r.resolve(&path)?;
            let meta = fs::symlink_metadata(&target).map_err(|e| io_error(&path, &e))?;
            if meta.file_type().is_symlink() {
                return Err(mlua::Error::runtime(format!(
                    "`{path}` is a link; chmod does not follow links"
                )));
            }
            if meta.is_dir() && mode & DIR_MODE != DIR_MODE {
                return Err(mlua::Error::runtime(format!(
                    "mode {mode:#o} would lock jtm out of the directory `{path}`; a directory \
                     keeps at least 0o700"
                )));
            }
            set_mode(&target, mode).map_err(|e| io_error(&path, &e))
        })?,
    )?;
    t.set_readonly(true);
    Ok(t)
}

/// Checks that every link under `root` still points inside it. A directory or entry that
/// cannot be read fails the check, since a link the check cannot see could point anywhere.
pub(super) fn check_links(root: &Path) -> Result<(), Limit> {
    let relative = |path: &Path| {
        path.strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/")
    };
    let unreadable = |path: &Path, e: io::Error| Limit::Path {
        path: relative(path),
        reason: format!("cannot be read to check its links: {e}"),
    };
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).map_err(|e| unreadable(&dir, e))? {
            let entry = entry.map_err(|e| unreadable(&dir, e))?;
            let path = entry.path();
            let kind = entry.file_type().map_err(|e| unreadable(&path, e))?;
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_symlink() {
                let rel = relative(&path);
                let target = fs::read_link(&path).map_err(|e| Limit::Path {
                    path: rel.clone(),
                    reason: format!("is a link that cannot be read: {e}"),
                })?;
                let parent = path.parent().unwrap_or(root);
                if !stays_inside(root, parent, &target) {
                    return Err(Limit::Path {
                        path: rel,
                        reason: format!(
                            "is a link to `{}`, outside the install dir",
                            target.display()
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Whether the link `target`, in the real directory `from` under `root`, resolves inside
/// `root` at every step. Links met on the way are followed through the file system, so a link
/// to `.` followed by `..` is caught; a target that cannot be resolved counts as outside.
fn stays_inside(root: &Path, from: &Path, target: &Path) -> bool {
    let mut current = from.to_path_buf();
    for part in target.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                if !current.pop() {
                    return false;
                }
            }
            Component::Normal(name) => {
                current.push(name);
                if fs::symlink_metadata(&current).is_ok_and(|m| m.file_type().is_symlink()) {
                    match fs::canonicalize(&current) {
                        Ok(real) => current = real,
                        Err(_) => return false,
                    }
                }
            }
            Component::RootDir | Component::Prefix(_) => return false,
        }
        if !current.starts_with(root) {
            return false;
        }
    }
    true
}

fn remove_file_or_link(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        // A Windows link to a directory is removed as a directory.
        Err(e) if cfg!(windows) => fs::remove_dir(path).map_err(|_| e),
        other => other,
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

fn io_error(path: &str, error: &io::Error) -> mlua::Error {
    mlua::Error::runtime(format!("`{path}`: {error}"))
}
