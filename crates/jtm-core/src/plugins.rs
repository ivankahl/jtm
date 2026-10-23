//! Finding plugin manifests (SPEC.md sections 7 and 14).
//!
//! First-party manifests are compiled into the binary and are the only ones whose anchors are
//! pre-approved. Every other manifest lives at `<data>/plugins/<name>@<rev>/plugin.toml`, where
//! `<name>` is the plugin name with `/` written as `--`, and its anchors count only once the
//! user trusts them.

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

/// The working copy of the builtin manifests that older jtm versions unpacked, under
/// `<data>/plugins`. Nothing reads or writes it any more.
const OLD_WORKING_COPY: &str = "builtin";

/// Removes the `<data>/plugins/builtin` working copy older jtm versions kept, with the lock and
/// any temporary files of its repair. It is best effort: a failure is logged and tried again by
/// the next command, and never fails this one. When there is no copy, which is every run after
/// the first, it costs one `stat`, so the shell hook can run it at every prompt.
pub fn remove_old_working_copy(dirs: &Dirs) {
    let plugins = dirs.plugins();
    let copy = plugins.join(OLD_WORKING_COPY);
    if fs::symlink_metadata(&copy).is_err() {
        return;
    }
    if let Err(err) = remove_entry(&copy) {
        tracing::debug!(%err, "cannot remove the old builtin plugin working copy");
        return;
    }
    // What the copy's repair left behind: its lock, and the files a killed repair left beside
    // the copy.
    let _ = fs::remove_file(dirs.locks().join(".builtin-working-copy.lock"));
    if let Ok(entries) = fs::read_dir(&plugins) {
        for entry in entries.flatten() {
            let ours = entry
                .file_name()
                .to_string_lossy()
                .starts_with(".jtm-builtin-");
            if ours && entry.file_type().is_ok_and(|t| t.is_file()) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    // Only succeeds when nothing else is left in it.
    let _ = fs::remove_dir(&plugins);
    tracing::debug!(path = %copy.display(), "removed the old builtin plugin working copy");
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
                || Ok(found.script.map(str::to_owned)),
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
                parse(
                    &bytes,
                    || read_script(&dir.join("plugin.lua")),
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

/// Parses the manifest `bytes`, reading the plugin's script through `script` only when the
/// manifest names a hook.
fn parse(
    bytes: &[u8],
    script: impl FnOnce() -> Result<Option<String>>,
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
    // uses is never read.
    let script = match &manifest.hooks.script_sha256 {
        None => None,
        Some(expected) => {
            let Some(source) = script()? else {
                let hook = first_hook(&manifest).unwrap_or("a hook");
                return Err(invalid(format!(
                    "names the hook `{hook}`, but the plugin has no plugin.lua"
                )));
            };
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
