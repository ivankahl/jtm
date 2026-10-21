//! `jtm.fs`: the file operations `post_extract` may use, confined to the install dir.
//!
//! Paths are relative and `/`-separated, as in `bin/tool` or `.` for the install dir itself.
//! Absolute paths, `..`, backslashes, colons and control characters are refused, as the
//! archive rules refuse them, and so is any path whose parent directories include a link, so
//! no operation can reach outside the install dir. Operations act on links themselves, never
//! on their targets, and `chmod` refuses links. Moving a link can change where it points, so
//! once the hook returns, [`check_links`] fails it if any link points outside. A directory the
//! check cannot read fails it too, since a link could hide in it, but as a host I/O error
//! rather than a limit breach.
//!
//! - `exists(path)` and `is_dir(path)`, without following links.
//! - `list(dir)`: the sorted names in a directory.
//! - `rename(from, to)`, also named `move`: `to` must not exist yet.
//! - `remove(path)`: a file, a link or a whole directory.
//! - `chmod(path, mode)`: permission bits from `0` to `0o777`. A file keeps at least `0o400`,
//!   so jtm can still read it. A directory may take any mode during the hook, and once the
//!   hook returns, even with an error, [`restore_dirs`] gives every directory back `0o700`
//!   for its owner, so jtm can still check, move and remove it. The mode is checked on every
//!   OS, so a hook fails the same way everywhere, and only applying it is skipped on Windows.
//!
//! Failed operations, such as a missing file, raise ordinary errors the script may catch. A
//! path that leaves the install dir, or a file mode jtm could not read, is recorded as a
//! limit breach and fails the hook even if the script catches it.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use jtm_archive::tree::{self, ReadError, display_rel};
use mlua::{Lua, Table};

use super::sandbox::refuse;
use super::{Limit, Shared};

/// The highest mode `chmod` accepts: permission bits only, never setuid, setgid or sticky.
const MAX_MODE: u32 = 0o777;
/// The bits a file's mode must keep: read for its owner.
const FILE_MODE: u32 = 0o400;
/// The bits every directory gets back after the hook: read, write and search for its owner.
#[cfg(unix)]
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
            if !meta.is_dir() && mode & FILE_MODE != FILE_MODE {
                return Err(refuse(&r.shared, Limit::Mode { path, mode }));
            }
            set_mode(&target, mode).map_err(|e| io_error(&path, &e))
        })?,
    )?;
    t.set_readonly(true);
    Ok(t)
}

/// Why a check after the hook failed.
#[derive(Debug)]
pub(super) enum Failure {
    /// A link points outside the install dir.
    Limit(Limit),
    /// The install dir could not be read or changed, which is the host's problem.
    Io { path: PathBuf, source: io::Error },
}

impl From<ReadError> for Failure {
    fn from(e: ReadError) -> Self {
        Failure::Io {
            path: e.path,
            source: e.source,
        }
    }
}

/// Gives every directory under `root`, and `root` itself, read, write and search for its
/// owner, whatever mode the hook left it with. Each directory is fixed before it is read, so
/// a locked directory inside another is reached too.
#[cfg(unix)]
pub(super) fn restore_dirs(root: &Path) -> Result<(), Failure> {
    use std::os::unix::fs::PermissionsExt as _;
    let restore = |path: &Path| {
        let failed = |source| Failure::Io {
            path: path.to_path_buf(),
            source,
        };
        let mode = fs::symlink_metadata(path)
            .map_err(failed)?
            .permissions()
            .mode()
            & 0o7777;
        if mode & DIR_MODE == DIR_MODE {
            return Ok(());
        }
        set_mode(path, mode | DIR_MODE).map_err(failed)
    };
    restore(root)?;
    tree::walk(root, |entry| {
        if entry.kind.is_dir() {
            restore(&entry.path)?;
        }
        Ok(())
    })
}

/// Windows ignores the modes a hook sets, so there is nothing to restore.
#[cfg(not(unix))]
pub(super) fn restore_dirs(_root: &Path) -> Result<(), Failure> {
    Ok(())
}

/// Checks that every link under `root` still points inside it. A directory or entry that
/// cannot be read fails the check, since a link the check cannot see could point anywhere.
pub(super) fn check_links(root: &Path) -> Result<(), Failure> {
    tree::walk(root, |entry| {
        if !entry.kind.is_symlink() {
            return Ok(());
        }
        let path = &entry.path;
        let target = fs::read_link(path).map_err(|source| Failure::Io {
            path: path.clone(),
            source,
        })?;
        let parent = path.parent().unwrap_or(root);
        if stays_inside(root, parent, &target) {
            return Ok(());
        }
        Err(Failure::Limit(Limit::Path {
            path: display_rel(root, path),
            reason: format!(
                "is a link to `{}`, outside the install dir",
                target.display()
            ),
        }))
    })
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
