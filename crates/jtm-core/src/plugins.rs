//! Finding plugin manifests (SPEC.md sections 7 and 14).
//!
//! Every plugin manifest is compiled into the binary; jtm never loads one from disk
//! (ADR 0002).

use std::fs;
use std::io;
use std::path::Path;

use jtm_plugin::Manifest;

use crate::dirs::Dirs;
use crate::error::{JtmError, Result};
use crate::indices::ManifestOrigin;

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
}

/// `builtin`, and with the `test-plugins` feature also the `demo` plugin of jtm-cli's
/// end-to-end tests. That feature is enabled only by jtm-cli's dev-dependencies, so a release
/// binary embeds exactly `builtin`.
pub fn embedded(builtin: &'static [BuiltinManifest]) -> &'static [BuiltinManifest] {
    #[cfg(feature = "test-plugins")]
    {
        const DEMO: BuiltinManifest = BuiltinManifest {
            name: "demo",
            text: include_str!("../test-plugins/demo.toml"),
        };
        let mut all = builtin.to_vec();
        all.push(DEMO);
        Box::leak(all.into_boxed_slice())
    }
    #[cfg(not(feature = "test-plugins"))]
    builtin
}

/// A parsed plugin manifest and where it came from.
#[derive(Debug, Clone)]
pub struct Plugin {
    pub manifest: Manifest,
    /// Lowercase hex SHA-256 of the manifest bytes.
    pub sha256: String,
    pub origin: ManifestOrigin,
    /// Where the manifest was read: always `builtin`.
    pub location: String,
    /// The manifest text.
    pub text: String,
}

/// The plugin manifests compiled into this jtm. No manifest is ever read from disk, a project,
/// a mirror or the network (ADR 0002).
#[derive(Debug, Clone, Copy)]
pub struct Registry<'a> {
    pub builtin: &'a [BuiltinManifest],
}

impl Registry<'_> {
    /// The plugin named `name`.
    pub fn find(&self, name: &str) -> Result<Plugin> {
        let found = self
            .builtin
            .iter()
            .find(|b| b.name == name)
            .ok_or_else(|| JtmError::ToolUnknown {
                tool: name.to_owned(),
            })?;
        parse(found.text, name)
    }

    /// The names of every plugin available, in the order they were compiled in.
    pub fn names(&self) -> Vec<String> {
        self.builtin.iter().map(|b| b.name.to_owned()).collect()
    }
}

/// Parses the builtin manifest `text`, which must declare the plugin `name`.
fn parse(text: &str, name: &str) -> Result<Plugin> {
    let location = "builtin";
    let manifest = Manifest::parse(text).map_err(|error| JtmError::InvalidManifest {
        origin: location.to_owned(),
        error,
    })?;
    if manifest.name != name {
        return Err(JtmError::InvalidManifest {
            origin: location.to_owned(),
            error: jtm_plugin::ManifestError {
                problems: vec![jtm_plugin::manifest::Problem {
                    path: String::new(),
                    message: format!("declares plugin `{}`, not `{name}`", manifest.name),
                    line: None,
                }],
            },
        });
    }
    Ok(Plugin {
        manifest,
        sha256: jtm_security::sha256_hex(text.as_bytes()),
        origin: ManifestOrigin::Builtin,
        location: location.to_owned(),
        text: text.to_owned(),
    })
}

#[cfg(test)]
mod tests;
