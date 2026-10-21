//! Finding the tool home inside an extracted archive (SPEC.md section 10, step 8) and checking
//! that its bin dirs hold files (step 10).
//!
//! `strip_components = <n>` is applied while extracting; `"auto"` strips a single top-level
//! directory afterwards, when the archive has exactly one. The per-OS `home_subdir` then names
//! the tool home inside what remains, such as a macOS app bundle's `Contents/Home`, or lists
//! candidates for vendors that ship different shapes: the first that is a directory inside
//! the archive wins. The whole tree is kept, so links from the home to elsewhere in the
//! archive keep working.

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
    // Validation rejects these; never let one quietly hand the choice to another candidate,
    // whatever the archive holds.
    if let Some(bad) = candidates.iter().find(|c| relative(c).is_none()) {
        return Err(mismatch(format!("`{bad}` is not a relative path")));
    }
    // The first candidate that exists wins. Its bin dirs are checked after `post_extract`,
    // which may fill them.
    for candidate in candidates {
        if let Some(home) = find_home(plugin, &root, candidate)? {
            return Ok(Placed { root, home });
        }
    }
    let tried: Vec<String> = candidates.iter().map(|c| format!("`{c}`")).collect();
    let star = if candidates.iter().any(|c| c.contains('*')) {
        " (a `*` must match exactly one directory)"
    } else {
        ""
    };
    Err(mismatch(format!(
        "no home candidate is a directory inside the archive{star}; tried {}",
        tried.join(", ")
    )))
}

/// The home `candidate` names inside `root`, relative to it, when it is a directory inside
/// `root`, or `None` when it is not. A `*` segment matches any one real directory, never a
/// link. When two or more directories fit the whole path the candidate is ambiguous, and a
/// directory `*` matched must have a [safe name](is_safe_name): both are errors, never a
/// reason to try the next candidate.
fn find_home(plugin: &str, root: &Path, candidate: &str) -> Result<Option<PathBuf>> {
    let mismatch = |message: String| JtmError::LayoutMismatch {
        plugin: plugin.to_owned(),
        message,
    };
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
            // Never list a directory a link leads to outside the archive. A path that is not
            // a directory simply has no matches; any other failure to read one is an error,
            // never a reason to pick another candidate.
            if !dir.is_dir() || !inside(root, &dir)? {
                continue;
            }
            for entry in fs::read_dir(&dir).map_err(|e| JtmError::io(&dir, e))? {
                let entry = entry.map_err(|e| JtmError::io(&dir, e))?;
                // `DirEntry::file_type` does not follow links.
                let kind = entry
                    .file_type()
                    .map_err(|e| JtmError::io(entry.path(), e))?;
                if kind.is_dir() {
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
    let home = match <[PathBuf; 1]>::try_from(homes) {
        Ok([home]) => home,
        Err(homes) if homes.is_empty() => return Ok(None),
        Err(mut homes) => {
            homes.sort();
            let found: Vec<String> = homes
                .iter()
                .map(|h| {
                    // `/` on every OS, as in the manifest.
                    let parts: Vec<_> = h.iter().map(|p| p.to_string_lossy()).collect();
                    format!("`{}`", parts.join("/"))
                })
                .collect();
            return Err(mismatch(format!(
                "home candidate `{candidate}` is ambiguous: it matches {}",
                found.join(", ")
            )));
        }
    };
    // The names `*` matched come from the archive, not the signed manifest, and end up in
    // the receipt, `{home}` and shell output.
    let stars = rel
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .map(|c| c.as_os_str() == "*");
    for (is_star, name) in stars.zip(home.components()) {
        if is_star && !name.as_os_str().to_str().is_some_and(is_safe_name) {
            return Err(mismatch(format!(
                "home candidate `{candidate}` matches `{}`, whose name may hold only ASCII \
                 letters, digits, `.`, `_`, `+` and `-` and may not start with `.` or `-`",
                name.as_os_str().to_string_lossy()
            )));
        }
    }
    Ok(Some(home))
}

/// Whether a directory name a `*` matched is safe to record as part of a tool home: ASCII
/// letters, digits, `.`, `_`, `+` and `-`, not starting with `.` or `-`.
fn is_safe_name(name: &str) -> bool {
    !name.starts_with(['.', '-'])
        && !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
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
