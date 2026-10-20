//! Finding plugin manifests (SPEC.md sections 7 and 14).
//!
//! First-party manifests are compiled into the binary and are the only ones whose anchors are
//! pre-approved. Every other manifest lives at `<data>/plugins/<name>@<rev>/plugin.toml`, where
//! `<name>` is the plugin name with `/` written as `--`, and its anchors count only once the
//! user trusts them. The unpacked `<data>/plugins/builtin` working copy is never read here.

use std::fs;
use std::io;
use std::path::PathBuf;

use jtm_plugin::Manifest;

use crate::dirs::{Dirs, dir_name};
use crate::error::{JtmError, Result};
use crate::indices::ManifestOrigin;

/// A manifest compiled into jtm.
#[derive(Debug, Clone, Copy)]
pub struct BuiltinManifest {
    pub name: &'static str,
    pub text: &'static str,
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

fn parse(bytes: &[u8], origin: ManifestOrigin, location: &str, name: &str) -> Result<Plugin> {
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
    Ok(Plugin {
        manifest,
        sha256: jtm_security::sha256_hex(bytes),
        origin,
        location: location.to_owned(),
    })
}

#[cfg(test)]
mod tests;
