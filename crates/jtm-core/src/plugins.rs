//! Finding plugin manifests (SPEC.md sections 7 and 14).
//!
//! First-party manifests are compiled into the binary and are the only ones whose anchors are
//! pre-approved. Every other manifest lives at `<data>/plugins/<name>@<rev>/plugin.toml`, where
//! `<name>` is the plugin name with `/` written as `--`, and its anchors count only once the
//! user trusts them. The unpacked `<data>/plugins/builtin` working copy is never read here.

use std::fs;
use std::io;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use jtm_plugin::Manifest;
use jtm_plugin::script::{Host, Script};

use crate::dirs::{Dirs, dir_name};
use crate::error::{JtmError, Result};
use crate::indices::ManifestOrigin;
use crate::platform::Platform;

/// The name prefix of the files the working copy repair writes in `<data>/plugins`.
const TEMP_PREFIX: &str = ".jtm-builtin-";
/// How old a repair's temporary file must be before the sync takes it for one a killed process
/// left behind. A repair writes for well under a second.
const TEMP_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(600);

/// The working copy files of one builtin plugin, as `(file name, bytes)`.
fn working_files(found: &BuiltinManifest) -> Vec<(&'static str, &'static [u8])> {
    let mut files = vec![("plugin.toml", found.text.as_bytes())];
    if let Some(script) = found.script {
        files.push(("plugin.lua", script.as_bytes()));
    }
    files
}

/// Makes the `<data>/plugins/builtin` working copy match `builtin` byte for byte (SPEC.md
/// sections 9 and 14): one directory per plugin holding its `plugin.toml` and any
/// `plugin.lua`. A file that differs, or is a link or a directory, is replaced; anything else
/// in the working copy is removed, and links are removed, never followed. Returns the paths it
/// repaired, so `jtm doctor` can report them.
///
/// The working copy is for people and tools to read. jtm never reads it, so a modified copy
/// cannot change a trust decision; [`Registry`] reads only the compiled-in manifests.
///
/// Several jtm processes may repair the copy at once, such as two shells' prompt hooks. New
/// files are written in `<data>/plugins`, outside the copy, and renamed into place, so one
/// process never takes another's half-written file for an unknown entry and removes it.
/// Without any `builtin` manifests, such as from a context that embeds none, there is nothing
/// to compare against, so the copy is left alone.
pub fn sync_working_copy(dirs: &Dirs, builtin: &[BuiltinManifest]) -> Result<Vec<PathBuf>> {
    if builtin.is_empty() {
        return Ok(Vec::new());
    }
    let root = dirs.builtin_plugins();
    let scratch = dirs.plugins();
    let mut repaired = Vec::new();
    ensure_dir(&root, &mut repaired)?;
    sweep_temp_files(&scratch);
    let wanted: Vec<(String, &BuiltinManifest)> =
        builtin.iter().map(|b| (dir_name(b.name), b)).collect();
    for entry in read_entries(&root)? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !wanted.iter().any(|(dir, _)| *dir == name) {
            remove_entry(&entry.path())?;
            repaired.push(entry.path());
        }
    }
    for (dir, found) in &wanted {
        let dir = root.join(dir);
        ensure_dir(&dir, &mut repaired)?;
        let files = working_files(found);
        for entry in read_entries(&dir)? {
            let name = entry.file_name();
            if !files.iter().any(|(file, _)| name == *file) {
                remove_entry(&entry.path())?;
                repaired.push(entry.path());
            }
        }
        for (file, bytes) in files {
            let path = dir.join(file);
            let current = match fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_file() => fs::read(&path).ok(),
                Ok(meta) if meta.is_dir() => {
                    remove_entry(&path)?;
                    None
                }
                // A link is replaced by the rename below, never followed.
                _ => None,
            };
            if current.as_deref() != Some(bytes) {
                write_replacing(&scratch, &path, bytes)?;
                repaired.push(path);
            }
        }
    }
    if !repaired.is_empty() {
        tracing::debug!(
            count = repaired.len(),
            "repaired the builtin plugin working copy"
        );
    }
    Ok(repaired)
}

/// Writes `bytes` to a new file in `scratch`, on the same file system, and renames it over
/// `path`. A rename replaces a link rather than writing through it, so a link planted in the
/// working copy is never followed.
fn write_replacing(scratch: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = tempfile::Builder::new()
        .prefix(TEMP_PREFIX)
        .tempfile_in(scratch)
        .map_err(|e| JtmError::io(scratch, e))?;
    io::Write::write_all(&mut file, bytes).map_err(|e| JtmError::io(file.path(), e))?;
    file.persist(path)
        .map_err(|e| JtmError::io(path, e.error))?;
    Ok(())
}

/// Removes the repair's temporary files in `scratch` older than [`TEMP_MAX_AGE`], which a
/// process killed mid-repair left behind. Failures are ignored; the next sync tries again.
fn sweep_temp_files(scratch: &Path) {
    let Ok(entries) = fs::read_dir(scratch) else {
        return;
    };
    for entry in entries.flatten() {
        let ours = entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX);
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > TEMP_MAX_AGE);
        if ours && stale && entry.file_type().is_ok_and(|t| t.is_file()) {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Makes `dir` a real directory, replacing a file or link in its place.
fn ensure_dir(dir: &Path, repaired: &mut Vec<PathBuf>) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => {
            remove_entry(dir)?;
            repaired.push(dir.to_path_buf());
        }
        Err(_) => {}
    }
    fs::create_dir_all(dir).map_err(|e| JtmError::io(dir, e))
}

fn read_entries(dir: &Path) -> Result<Vec<fs::DirEntry>> {
    fs::read_dir(dir)
        .and_then(Iterator::collect::<io::Result<Vec<_>>>)
        .map_err(|e| JtmError::io(dir, e))
}

/// Removes a file, a link (not its target) or a whole directory.
fn remove_entry(path: &Path) -> Result<()> {
    let removed = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path).or_else(|e| {
            // A Windows link to a directory is removed as a directory.
            if cfg!(windows) {
                fs::remove_dir(path)
            } else {
                Err(e)
            }
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    };
    removed.map_err(|e| JtmError::io(path, e))
}

/// A manifest compiled into jtm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinManifest {
    pub name: &'static str,
    pub text: &'static str,
    /// The plugin's `plugin.lua`, if it has one.
    pub script: Option<&'static str>,
}

/// A parsed plugin manifest and where it came from.
#[derive(Debug, Clone)]
pub struct Plugin {
    pub manifest: Manifest,
    /// Lowercase hex SHA-256 of the manifest bytes.
    pub sha256: String,
    pub origin: ManifestOrigin,
    /// Where the manifest was read: `builtin` or a file path.
    pub location: String,
    /// The manifest text, which hooks see as `jtm.manifest`.
    pub text: String,
    /// The `plugin.lua` source, when a hook needs it. It always matches the manifest's
    /// `hooks.script_sha256`, so the manifest hash covers it too.
    pub script: Option<String>,
}

/// The largest `plugin.lua` jtm reads.
const MAX_SCRIPT_BYTES: u64 = 1024 * 1024;

impl Plugin {
    /// The plugin's `plugin.lua` prepared to run hooks on `platform`, if it has one.
    pub fn script(&self, platform: Platform) -> Result<Option<Script>> {
        let Some(source) = &self.script else {
            return Ok(None);
        };
        let host = Host {
            platform: platform.as_str().to_owned(),
            os: platform.os().as_str().to_owned(),
            arch: platform.arch().as_str().to_owned(),
        };
        let name = &self.manifest.name;
        Script::new(
            name,
            source,
            &self.text,
            self.manifest.versions.scheme.builtin(),
            host,
        )
        .map(Some)
        .map_err(|e| JtmError::script(name, e))
    }
}

/// Plugin manifests for one jtm installation.
#[derive(Debug, Clone, Copy)]
pub struct Registry<'a> {
    pub dirs: &'a Dirs,
    pub builtin: &'a [BuiltinManifest],
}

impl Registry<'_> {
    /// The plugin named `name`. Builtin manifests win over any file of the same name.
    pub fn find(&self, name: &str) -> Result<Plugin> {
        if let Some(found) = self.builtin.iter().find(|b| b.name == name) {
            return parse(
                found.text.as_bytes(),
                found.script.map(str::to_owned),
                ManifestOrigin::Builtin,
                "builtin",
                name,
            );
        }
        let dirs = self.external_dirs(name)?;
        match dirs.as_slice() {
            [] => Err(JtmError::ToolUnknown {
                tool: name.to_owned(),
            }),
            [dir] => {
                let path = dir.join("plugin.toml");
                let bytes = fs::read(&path).map_err(|e| JtmError::io(&path, e))?;
                let script = read_script(&dir.join("plugin.lua"))?;
                parse(
                    &bytes,
                    script,
                    ManifestOrigin::External,
                    &path.display().to_string(),
                    name,
                )
            }
            // Which revision is active is recorded by `jtm plugin add` (T9.3); until then several
            // revisions of one plugin are refused rather than guessed.
            _ => Err(JtmError::usage(format!(
                "several revisions of plugin `{name}` are installed under {}; remove all but one",
                self.dirs.plugins().display()
            ))),
        }
    }

    /// The names of every plugin available, builtin first, each once.
    pub fn names(&self) -> Result<Vec<String>> {
        let mut names: Vec<String> = self.builtin.iter().map(|b| b.name.to_owned()).collect();
        for (dir_name, _) in self.external_entries()? {
            let name = dir_name.replace("--", "/");
            if !names.contains(&name) {
                names.push(name);
            }
        }
        Ok(names)
    }

    fn external_dirs(&self, name: &str) -> Result<Vec<PathBuf>> {
        let wanted = dir_name(name);
        Ok(self
            .external_entries()?
            .into_iter()
            .filter(|(dir, _)| *dir == wanted)
            .map(|(_, path)| path)
            .collect())
    }

    /// `(<name with -->, path)` for each `<name>@<rev>` directory with a `plugin.toml`.
    fn external_entries(&self) -> Result<Vec<(String, PathBuf)>> {
        let root = self.dirs.plugins();
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(JtmError::io(&root, e)),
        };
        let mut found = Vec::new();
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            let Some((name, rev)) = file_name.split_once('@') else {
                continue;
            };
            if rev.is_empty() || !entry.path().join("plugin.toml").is_file() {
                continue;
            }
            found.push((name.to_owned(), entry.path()));
        }
        found.sort();
        Ok(found)
    }
}

/// The script at `path`, if there is one. One that is too large or not UTF-8 makes the plugin
/// invalid.
fn read_script(path: &Path) -> Result<Option<String>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(JtmError::io(path, e)),
    };
    let mut bytes = Vec::new();
    io::Read::take(file, MAX_SCRIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| JtmError::io(path, e))?;
    let problem = if bytes.len() as u64 > MAX_SCRIPT_BYTES {
        format!("is larger than {MAX_SCRIPT_BYTES} bytes")
    } else {
        match String::from_utf8(bytes) {
            Ok(text) => return Ok(Some(text)),
            Err(_) => "is not UTF-8".to_owned(),
        }
    };
    Err(JtmError::InvalidManifest {
        origin: path.display().to_string(),
        error: jtm_plugin::ManifestError {
            problems: vec![jtm_plugin::manifest::Problem {
                path: String::new(),
                message: format!("plugin.lua {problem}"),
                line: None,
            }],
        },
    })
}

fn parse(
    bytes: &[u8],
    script: Option<String>,
    origin: ManifestOrigin,
    location: &str,
    name: &str,
) -> Result<Plugin> {
    let invalid = |message: String| JtmError::InvalidManifest {
        origin: location.to_owned(),
        error: jtm_plugin::ManifestError {
            problems: vec![jtm_plugin::manifest::Problem {
                path: String::new(),
                message,
                line: None,
            }],
        },
    };
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("is not UTF-8".to_owned()))?;
    let manifest = Manifest::parse(text).map_err(|error| JtmError::InvalidManifest {
        origin: location.to_owned(),
        error,
    })?;
    if manifest.name != name {
        return Err(invalid(format!(
            "declares plugin `{}`, not `{name}`",
            manifest.name
        )));
    }
    // Validation guarantees `script_sha256` exactly when a hook is named. A script no hook
    // uses is never loaded.
    let script = match (&manifest.hooks.script_sha256, script) {
        (None, _) => None,
        (Some(_), None) => {
            let hook = first_hook(&manifest).unwrap_or("a hook");
            return Err(invalid(format!(
                "names the hook `{hook}`, but the plugin has no plugin.lua"
            )));
        }
        (Some(expected), Some(source)) => {
            let actual = jtm_security::sha256_hex(source.as_bytes());
            if actual != *expected {
                return Err(invalid(format!(
                    "plugin.lua has SHA-256 {actual}, but `hooks.script_sha256` is {expected}"
                )));
            }
            Some(source)
        }
    };
    Ok(Plugin {
        manifest,
        sha256: jtm_security::sha256_hex(bytes),
        origin,
        location: location.to_owned(),
        text: text.to_owned(),
        script,
    })
}

/// The first `[hooks]` entry the manifest sets, by its key.
fn first_hook(manifest: &Manifest) -> Option<&'static str> {
    manifest
        .hooks
        .named()
        .into_iter()
        .find_map(|(key, function)| function.is_some().then_some(key))
}

#[cfg(test)]
mod tests;
