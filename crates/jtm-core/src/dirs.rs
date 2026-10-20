//! Where jtm keeps its data, config and cache on each OS (SPEC.md section 14).
//!
//! | | Windows | macOS and Linux |
//! | --- | --- | --- |
//! | Data | `%LOCALAPPDATA%\jtm` | `$XDG_DATA_HOME/jtm` or `~/.local/share/jtm` |
//! | Config | `%APPDATA%\jtm\config.toml` | `$XDG_CONFIG_HOME/jtm/config.toml` or `~/.config/jtm/config.toml` |
//! | Cache | `%LOCALAPPDATA%\jtm\cache` | `$XDG_CACHE_HOME/jtm` or `~/.cache/jtm` |
//!
//! `JTM_HOME` collapses data, config and cache into one directory. `JTM_CONFIG` or `--config`
//! picks the user config file.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::context::Context;
use crate::error::{JtmError, Result};
use crate::platform::Os;

/// The directories jtm uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dirs {
    /// Installs, current links, plugins, state and locks.
    pub data: PathBuf,
    /// Cached indices and downloaded archives.
    pub cache: PathBuf,
    /// The user config file. It may not exist.
    pub config_file: PathBuf,
}

const APP: &str = "jtm";
const CONFIG_FILE: &str = "config.toml";

impl Dirs {
    /// Resolves the directories for the running OS from the process environment and `ctx`.
    pub fn for_context(ctx: &Context) -> Result<Dirs> {
        let os = Os::host().ok_or_else(|| JtmError::HostUnsupported {
            host: std::env::consts::OS.to_owned(),
        })?;
        Dirs::resolve(
            os,
            ctx.home.as_deref(),
            ctx.config_path.as_deref(),
            &|key| std::env::var_os(key),
        )
    }

    /// Resolves the directories for `os`. `home` is `JTM_HOME`, `config` an explicit user
    /// config file, and `env` looks up the OS variables, so every OS can be tested anywhere.
    pub fn resolve(
        os: Os,
        home: Option<&Path>,
        config: Option<&Path>,
        env: &dyn Fn(&str) -> Option<OsString>,
    ) -> Result<Dirs> {
        let var = |name: &str| env(name).filter(|v| !v.is_empty()).map(PathBuf::from);

        let (data, cache, default_config) = match home {
            Some(home) => {
                let home = require_absolute(os, "JTM_HOME", home.to_path_buf())?;
                (home.clone(), home.join("cache"), home.join(CONFIG_FILE))
            }
            None => match os {
                Os::Windows => {
                    let profile = || {
                        var("USERPROFILE")
                            .filter(|p| is_absolute(os, p))
                            .map(|p| p.join("AppData"))
                    };
                    let local = var("LOCALAPPDATA")
                        .filter(|p| is_absolute(os, p))
                        .or_else(|| profile().map(|p| p.join("Local")))
                        .ok_or_else(|| missing(os))?
                        .join(APP);
                    let roaming = var("APPDATA")
                        .filter(|p| is_absolute(os, p))
                        .or_else(|| profile().map(|p| p.join("Roaming")))
                        .ok_or_else(|| missing(os))?
                        .join(APP);
                    (
                        local.clone(),
                        local.join("cache"),
                        roaming.join(CONFIG_FILE),
                    )
                }
                Os::Macos | Os::Linux => {
                    // Relative XDG values are ignored, as the XDG Base Directory spec requires.
                    let xdg = |name: &str, fallback: &[&str]| -> Result<PathBuf> {
                        match var(name).filter(|p| is_absolute(os, p)) {
                            Some(dir) => Ok(dir),
                            None => {
                                let home = var("HOME")
                                    .filter(|p| is_absolute(os, p))
                                    .ok_or_else(|| missing(os))?;
                                Ok(fallback.iter().fold(home, |dir, part| dir.join(part)))
                            }
                        }
                    };
                    (
                        xdg("XDG_DATA_HOME", &[".local", "share"])?.join(APP),
                        xdg("XDG_CACHE_HOME", &[".cache"])?.join(APP),
                        xdg("XDG_CONFIG_HOME", &[".config"])?
                            .join(APP)
                            .join(CONFIG_FILE),
                    )
                }
            },
        };

        Ok(Dirs {
            data,
            cache,
            config_file: config.map_or(default_config, Path::to_path_buf),
        })
    }

    /// `<data>/current`, holding one link per tool to its default install.
    pub fn current(&self) -> PathBuf {
        self.data.join("current")
    }

    /// `<data>/tools`, holding one directory per plugin.
    pub fn tools(&self) -> PathBuf {
        self.data.join("tools")
    }

    /// `<data>/tools/<plugin>/<variant>-<version>`, the install dir for one version.
    pub fn install_dir(&self, plugin: &str, variant: &str, version: &str) -> PathBuf {
        self.tools()
            .join(dir_name(plugin))
            .join(format!("{variant}-{version}"))
    }

    /// `<data>/tools/.tmp`, where installs are extracted before their atomic rename.
    pub fn tools_tmp(&self) -> PathBuf {
        self.tools().join(".tmp")
    }

    /// `<data>/tools/.trash`, where uninstalls move directories before deleting them.
    pub fn tools_trash(&self) -> PathBuf {
        self.tools().join(".trash")
    }

    /// `<data>/plugins`.
    pub fn plugins(&self) -> PathBuf {
        self.data.join("plugins")
    }

    /// `<data>/plugins/builtin`, first-party manifests unpacked from the binary.
    ///
    /// A working copy for display and hooks only: the compiled-in manifests are authoritative,
    /// trust decisions never read this directory, and a mismatch is repaired from the binary
    /// and reported by `jtm doctor`.
    pub fn builtin_plugins(&self) -> PathBuf {
        self.plugins().join("builtin")
    }

    /// `<data>/state`: trust store, defaults and the shell hook cache.
    pub fn state(&self) -> PathBuf {
        self.data.join("state")
    }

    /// `<data>/state/defaults.toml`, the user defaults set by `jtm default`.
    pub fn defaults_file(&self) -> PathBuf {
        self.state().join("defaults.toml")
    }

    /// `<data>/locks`, for per-install file locks.
    pub fn locks(&self) -> PathBuf {
        self.data.join("locks")
    }

    /// `<cache>/index`, verified copies of version indices.
    pub fn index_cache(&self) -> PathBuf {
        self.cache.join("index")
    }

    /// `<cache>/downloads`, archives named by their SHA-256.
    pub fn downloads(&self) -> PathBuf {
        self.cache.join("downloads")
    }
}

/// The directory name for a plugin. Third-party names contain `/`, which would nest
/// directories, so it becomes `--`, which plugin names cannot otherwise contain.
pub fn dir_name(plugin: &str) -> String {
    plugin.replace('/', "--")
}

/// Whether `path` is absolute on `os`, independent of the OS jtm is running on.
fn is_absolute(os: Os, path: &Path) -> bool {
    let text = path.to_string_lossy();
    match os {
        Os::Windows => {
            let bytes = text.as_bytes();
            let drive = bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && matches!(bytes[2], b'\\' | b'/');
            drive || text.starts_with(r"\\")
        }
        Os::Macos | Os::Linux => text.starts_with('/'),
    }
}

fn require_absolute(os: Os, name: &str, path: PathBuf) -> Result<PathBuf> {
    if is_absolute(os, &path) {
        Ok(path)
    } else {
        Err(JtmError::usage(format!(
            "{name} must be an absolute path, not `{}`",
            path.display()
        )))
    }
}

fn missing(os: Os) -> JtmError {
    JtmError::usage(match os {
        Os::Windows => {
            "cannot find the user profile: LOCALAPPDATA, APPDATA and USERPROFILE are unset; \
             set JTM_HOME"
        }
        Os::Macos | Os::Linux => "cannot find the home directory: HOME is unset; set JTM_HOME",
    })
}

#[cfg(test)]
mod tests;
