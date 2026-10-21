//! Finding the tool home inside an extracted archive (SPEC.md section 10, step 8) and checking
//! that its bin dirs hold files (step 10).
//!
//! `strip_components = <n>` is applied while extracting; `"auto"` strips a single top-level
//! directory afterwards, when the archive has exactly one. The per-OS `home_subdir` then names
//! the tool home inside what remains, such as a macOS app bundle's `Contents/Home`, or lists
//! candidates for vendors that ship different shapes: the first that is a directory inside
//! the archive whose bin dirs hold files wins. The whole tree is kept, so links from the home
//! to elsewhere in the archive keep working.

use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

use jtm_plugin::manifest::{Layout, StripComponents};

use crate::error::{JtmError, Result};
use crate::platform::Os;

/// Where the install is inside the extraction directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placed {
    /// The directory that becomes the install dir.
    pub root: PathBuf,
    /// The tool home relative to `root`, empty when it is `root` itself.
    pub home: PathBuf,
}

impl Placed {
    /// The absolute tool home.
    pub fn home_dir(&self) -> PathBuf {
        self.root.join(&self.home)
    }
}

/// The number of leading components the extractor strips for `layout`.
pub fn extract_strip(layout: &Layout) -> u32 {
    match layout.strip_components {
        StripComponents::Count(n) => n,
        StripComponents::Auto => 0,
    }
}

/// Applies `layout` to the archive extracted, already stripped by [`extract_strip`], into
/// `extracted`.
pub fn apply(plugin: &str, extracted: &Path, layout: &Layout, os: Os) -> Result<Placed> {
    let mismatch = |message: String| JtmError::LayoutMismatch {
        plugin: plugin.to_owned(),
        message,
    };

    let mut root = extracted.to_path_buf();
    if layout.strip_components == StripComponents::Auto {
        let mut entries = fs::read_dir(extracted)
            .map_err(|e| JtmError::io(extracted, e))?
            .collect::<io::Result<Vec<_>>>()
            .map_err(|e| JtmError::io(extracted, e))?;
        if entries.len() == 1 {
            let only = entries.remove(0);
            let kind = only.file_type().map_err(|e| JtmError::io(only.path(), e))?;
            if kind.is_dir() {
                root = only.path();
            }
        }
    }
    if fs::read_dir(&root)
        .map_err(|e| JtmError::io(&root, e))?
        .next()
        .is_none()
    {
        return Err(mismatch("the archive is empty".to_owned()));
    }

    let candidates = layout.home_subdir_for(os.as_str());
    if candidates.is_empty() {
        return Ok(Placed {
            root,
            home: PathBuf::new(),
        });
    }
    // A lone home only has to exist: its bin dirs are checked after `post_extract`, which may
    // fill them. Choosing between candidates needs the bin dirs to hold files already.
    if let [only] = candidates {
        return match find_home(&root, only, None)? {
            Some(home) => Ok(Placed { root, home }),
            None => Err(mismatch(format!(
                "home `{only}` is not a directory inside the archive"
            ))),
        };
    }
    for candidate in candidates {
        if let Some(home) = find_home(&root, candidate, Some(&layout.bin_dirs))? {
            return Ok(Placed { root, home });
        }
    }
    let tried: Vec<String> = candidates.iter().map(|c| format!("`{c}`")).collect();
    Err(mismatch(format!(
        "no home candidate is a directory inside the archive whose bin dirs hold files; tried {}",
        tried.join(", ")
    )))
}

/// The home `candidate` names inside `root`, relative to it, when it is a directory inside
/// `root` whose `bin_dirs`, if given, hold files. A `*` segment matches any one real
/// directory, never a link, and the candidate matches only when exactly one directory fits it.
fn find_home(root: &Path, candidate: &str, bin_dirs: Option<&[String]>) -> Result<Option<PathBuf>> {
    let Some(rel) = relative(candidate) else {
        return Ok(None);
    };
    let mut paths = vec![PathBuf::new()];
    for part in rel.components() {
        let Component::Normal(part) = part else {
            continue;
        };
        if part != "*" {
            for path in &mut paths {
                path.push(part);
            }
            continue;
        }
        let mut next = Vec::new();
        for path in &paths {
            let dir = root.join(path);
            // Never list a directory a link leads to outside the archive.
            if !inside(root, &dir)? {
                continue;
            }
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                // `DirEntry::file_type` does not follow links.
                if entry.file_type().is_ok_and(|t| t.is_dir()) {
                    next.push(path.join(entry.file_name()));
                }
            }
        }
        paths = next;
    }
    let mut homes = Vec::new();
    for path in paths {
        let dir = root.join(&path);
        if dir.is_dir() && inside(root, &dir)? {
            homes.push(path);
        }
    }
    match <[PathBuf; 1]>::try_from(homes) {
        Ok([home])
            if bin_dirs
                .is_none_or(|bins| missing_bin_dir(root, &root.join(&home), bins).is_none()) =>
        {
            Ok(Some(home))
        }
        _ => Ok(None),
    }
}

/// Checks that every bin dir is a directory inside the install holding at least one file, so a
/// wrong `strip_components` or `home_subdir` fails the install instead of committing a tool
/// with nothing to run. Plugins name no executables, so a vendor can rename or add commands in
/// any version; whatever is in the bin dirs goes on `PATH`. Nothing is executed.
pub fn check_bin_dirs(plugin: &str, placed: &Placed, layout: &Layout) -> Result<()> {
    match missing_bin_dir(&placed.root, &placed.home_dir(), &layout.bin_dirs) {
        None => Ok(()),
        Some(bin) => Err(JtmError::LayoutMismatch {
            plugin: plugin.to_owned(),
            message: format!("bin dir `{bin}` is missing or has no files"),
        }),
    }
}

/// The first of `bin_dirs` under `home` that is not a directory inside `root` holding a file.
fn missing_bin_dir<'a>(root: &Path, home: &Path, bin_dirs: &'a [String]) -> Option<&'a str> {
    bin_dirs
        .iter()
        .find(|bin| {
            let dir = relative(bin).map(|bin| home.join(bin));
            !dir.as_ref().is_some_and(|dir| {
                inside(root, dir).unwrap_or(false)
                    && fs::read_dir(dir).is_ok_and(|entries| {
                        entries.flatten().any(|e| {
                            let path = e.path();
                            fs::metadata(&path).is_ok_and(|m| m.is_file())
                                && inside(root, &path).unwrap_or(false)
                        })
                    })
            })
        })
        .map(String::as_str)
}

/// `path` as a relative path of normal components, or `None`.
fn relative(path: &str) -> Option<PathBuf> {
    let p = Path::new(path);
    p.components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
        .then(|| p.to_path_buf())
}

/// Whether `path` exists and, with links resolved, is inside `root`.
fn inside(root: &Path, path: &Path) -> Result<bool> {
    let real_root = fs::canonicalize(root).map_err(|e| JtmError::io(root, e))?;
    Ok(fs::canonicalize(path).is_ok_and(|real| real.starts_with(&real_root)))
}

#[cfg(test)]
mod tests;
