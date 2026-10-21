//! Finding the tool home inside an extracted archive (SPEC.md section 10, step 8) and checking
//! that its bin dirs hold files (step 10).
//!
//! `strip_components = <n>` is applied while extracting; `"auto"` strips a single top-level
//! directory afterwards, when the archive has exactly one. The per-OS `home_subdir` then names
//! the tool home inside what remains, such as a macOS app bundle's `Contents/Home`. The whole tree is
//! kept, so links from the home to elsewhere in the archive keep working.

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

    let home = match layout.home_subdir_for(os.as_str()) {
        None => PathBuf::new(),
        Some(sub) => {
            let sub =
                relative(sub).ok_or_else(|| mismatch(format!("`{sub}` is not a relative path")))?;
            let dir = root.join(&sub);
            if !inside(&root, &dir)? || !dir.is_dir() {
                return Err(mismatch(format!(
                    "home `{}` is not a directory inside the archive",
                    sub.display()
                )));
            }
            sub
        }
    };
    Ok(Placed { root, home })
}

/// Checks that every bin dir is a directory inside the install holding at least one file, so a
/// wrong `strip_components` or `home_subdir` fails the install instead of committing a tool
/// with nothing to run. Plugins name no executables, so a vendor can rename or add commands in
/// any version; whatever is in the bin dirs goes on `PATH`. Nothing is executed.
pub fn check_bin_dirs(plugin: &str, placed: &Placed, layout: &Layout) -> Result<()> {
    let home = placed.home_dir();
    for bin in &layout.bin_dirs {
        let dir = relative(bin).map(|bin| home.join(bin));
        let has_file = dir.as_ref().is_some_and(|dir| {
            inside(&placed.root, dir).unwrap_or(false)
                && fs::read_dir(dir).is_ok_and(|entries| {
                    entries.flatten().any(|e| {
                        let path = e.path();
                        fs::metadata(&path).is_ok_and(|m| m.is_file())
                            && inside(&placed.root, &path).unwrap_or(false)
                    })
                })
        });
        if !has_file {
            return Err(JtmError::LayoutMismatch {
                plugin: plugin.to_owned(),
                message: format!("bin dir `{bin}` is missing or has no files"),
            });
        }
    }
    Ok(())
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
