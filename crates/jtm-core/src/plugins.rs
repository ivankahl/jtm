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

/// A manifest compiled into jtm.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinManifest {
    pub name: &'static str,
    pub text: &'static str,
    /// The plugin's `plugin.lua`, if it has one.
    pub script: Option<&'static str>,
}

/// The first-party manifests compiled into this build.
// The first-party manifests are embedded by T5.4; until then every plugin is external.
pub const BUILTIN: &[BuiltinManifest] = &[];

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
    /// The `plugin.lua` source, when the plugin has one.
    // SPEC-QUESTION: section 7 records only the manifest hash, so a changed `plugin.lua` at
    // the same plugin revision is not detected. The revision pins both files until T9.3
    // decides whether the script hash is recorded too.
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

/// The script at `path`, if there is one.
fn read_script(path: &Path) -> Result<Option<String>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(JtmError::io(path, e)),
    };
    let mut text = String::new();
    let read = io::Read::take(file, MAX_SCRIPT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| JtmError::io(path, e))?;
    if read as u64 > MAX_SCRIPT_BYTES {
        return Err(JtmError::io(
            path,
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("plugin.lua is larger than {MAX_SCRIPT_BYTES} bytes"),
            ),
        ));
    }
    Ok(Some(text))
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
    if script.is_none()
        && let Some(hook) = first_hook(&manifest)
    {
        return Err(invalid(format!(
            "names the hook `{hook}`, but the plugin has no plugin.lua"
        )));
    }
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
    let hooks = &manifest.hooks;
    [
        ("resolve_alias", &hooks.resolve_alias),
        ("parse_interop", &hooks.parse_interop),
        ("format_interop", &hooks.format_interop),
        ("compare_versions", &hooks.compare_versions),
        ("post_extract", &hooks.post_extract),
    ]
    .into_iter()
    .find_map(|(key, value)| value.is_some().then_some(key))
}

#[cfg(test)]
mod tests;
