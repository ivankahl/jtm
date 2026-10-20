//! Current links (SPEC.md section 5): `<data>/current/<tool>` points at the default install.
//!
//! A link is a symlink on macOS and Linux and a directory junction on Windows, which needs no
//! admin rights or Developer Mode. Retargeting never leaves the link missing on Unix: a new
//! symlink is created beside the old one and renamed over it. A Windows junction cannot be
//! renamed over another, so the new junction is created under a temporary name, the old one
//! removed and the new one renamed into place, retrying while a scanner holds it. A real
//! directory at the link path is never removed.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::{JtmError, Result};

/// The target `link` points at, or `None` when it is not a link.
pub fn read(link: &Path) -> Option<PathBuf> {
    if !is_link(link) {
        return None;
    }
    #[cfg(windows)]
    if junction::exists(link).unwrap_or(false) {
        return junction::get_target(link).ok();
    }
    fs::read_link(link).ok()
}

/// Points `link` at `target`, creating its parent directory. Returns whether anything changed.
pub fn set(link: &Path, target: &Path) -> Result<bool> {
    if read(link).as_deref() == Some(target) {
        return Ok(false);
    }
    refuse_non_link(link)?;
    let dir = link
        .parent()
        .ok_or_else(|| JtmError::internal(format!("{} has no parent", link.display())))?;
    fs::create_dir_all(dir).map_err(|e| JtmError::io(dir, e))?;
    let name = link
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = dir.join(format!(".{name}.new-{}", std::process::id()));
    // A leftover from a killed run would make creation fail.
    let _ = remove_raw(&tmp);
    create(target, &tmp).map_err(|e| JtmError::io(&tmp, e))?;
    if let Err(err) = replace(&tmp, link) {
        let _ = remove_raw(&tmp);
        return Err(err);
    }
    Ok(true)
}

/// Removes `link`, leaving its target alone. Returns whether there was a link.
pub fn remove(link: &Path) -> Result<bool> {
    if fs::symlink_metadata(link).is_err() {
        return Ok(false);
    }
    refuse_non_link(link)?;
    remove_raw(link).map_err(|e| JtmError::io(link, e))?;
    Ok(true)
}

fn is_link(path: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    if junction::exists(path).unwrap_or(false) {
        return true;
    }
    false
}

/// Refuses to touch something at `link` that is not a link, such as a real directory.
fn refuse_non_link(link: &Path) -> Result<()> {
    if fs::symlink_metadata(link).is_ok() && !is_link(link) {
        return Err(JtmError::usage(format!(
            "{} is not a link jtm made; move it away and run the command again",
            link.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn create(target: &Path, at: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

#[cfg(windows)]
fn create(target: &Path, at: &Path) -> io::Result<()> {
    junction::create(target, at)
}

#[cfg(unix)]
fn replace(tmp: &Path, link: &Path) -> Result<()> {
    fs::rename(tmp, link).map_err(|e| JtmError::io(link, e))
}

#[cfg(windows)]
fn replace(tmp: &Path, link: &Path) -> Result<()> {
    use std::time::{Duration, Instant};
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if fs::symlink_metadata(link).is_ok()
            && let Err(e) = remove_raw(link)
        {
            if Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            return Err(JtmError::io(link, e));
        }
        match fs::rename(tmp, link) {
            Ok(()) => return Ok(()),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(JtmError::io(link, e)),
        }
    }
}

/// Removes a link itself: a symlink on Unix, a junction or directory symlink on Windows.
fn remove_raw(link: &Path) -> io::Result<()> {
    fs::remove_file(link).or_else(|_| fs::remove_dir(link))
}

#[cfg(test)]
mod tests;
