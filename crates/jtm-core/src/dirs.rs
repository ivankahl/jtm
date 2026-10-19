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
    pub fn builtin_plugins(&self) -> PathBuf {
        self.plugins().join("builtin")
    }

    /// `<data>/state`: trust store, defaults and the shell hook cache.
    pub fn state(&self) -> PathBuf {
        self.data.join("state")
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
mod tests {
    use super::*;

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |key| {
            vars.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| OsString::from(v))
        }
    }

    fn resolve(os: Os, vars: &[(&str, &str)]) -> Result<Dirs> {
        Dirs::resolve(os, None, None, &env(vars))
    }

    fn p(base: &str, parts: &[&str]) -> PathBuf {
        parts
            .iter()
            .fold(PathBuf::from(base), |dir, part| dir.join(part))
    }

    const WINDOWS: &[(&str, &str)] = &[
        ("LOCALAPPDATA", r"C:\Users\u\AppData\Local"),
        ("APPDATA", r"C:\Users\u\AppData\Roaming"),
        ("USERPROFILE", r"C:\Users\u"),
    ];

    #[test]
    fn windows_paths() {
        let dirs = resolve(Os::Windows, WINDOWS).unwrap();
        assert_eq!(dirs.data, p(r"C:\Users\u\AppData\Local", &["jtm"]));
        assert_eq!(
            dirs.cache,
            p(r"C:\Users\u\AppData\Local", &["jtm", "cache"])
        );
        assert_eq!(
            dirs.config_file,
            p(r"C:\Users\u\AppData\Roaming", &["jtm", "config.toml"])
        );
    }

    #[test]
    fn windows_falls_back_to_the_profile() {
        let dirs = resolve(Os::Windows, &[("USERPROFILE", r"C:\Users\u")]).unwrap();
        assert_eq!(dirs.data, p(r"C:\Users\u", &["AppData", "Local", "jtm"]));
        assert_eq!(
            dirs.config_file,
            p(r"C:\Users\u", &["AppData", "Roaming", "jtm", "config.toml"])
        );
        assert_eq!(resolve(Os::Windows, &[]).unwrap_err().code(), "E_USAGE");
    }

    #[test]
    fn unix_paths_default_under_home() {
        for os in [Os::Macos, Os::Linux] {
            let dirs = resolve(os, &[("HOME", "/home/u")]).unwrap();
            assert_eq!(dirs.data, p("/home/u", &[".local", "share", "jtm"]), "{os}");
            assert_eq!(dirs.cache, p("/home/u", &[".cache", "jtm"]), "{os}");
            assert_eq!(
                dirs.config_file,
                p("/home/u", &[".config", "jtm", "config.toml"]),
                "{os}"
            );
        }
    }

    #[test]
    fn unix_honours_absolute_xdg_variables() {
        let dirs = resolve(
            Os::Linux,
            &[
                ("HOME", "/home/u"),
                ("XDG_DATA_HOME", "/xdg/data"),
                ("XDG_CACHE_HOME", "/xdg/cache"),
                ("XDG_CONFIG_HOME", "/xdg/config"),
            ],
        )
        .unwrap();
        assert_eq!(dirs.data, p("/xdg/data", &["jtm"]));
        assert_eq!(dirs.cache, p("/xdg/cache", &["jtm"]));
        assert_eq!(dirs.config_file, p("/xdg/config", &["jtm", "config.toml"]));

        let dirs = resolve(
            Os::Macos,
            &[("HOME", "/Users/u"), ("XDG_DATA_HOME", "relative/data")],
        )
        .unwrap();
        assert_eq!(dirs.data, p("/Users/u", &[".local", "share", "jtm"]));
    }

    #[test]
    fn unix_without_home_is_an_error_unless_xdg_covers_everything() {
        assert_eq!(resolve(Os::Linux, &[]).unwrap_err().code(), "E_USAGE");
        assert_eq!(
            resolve(Os::Linux, &[("HOME", "relative")])
                .unwrap_err()
                .code(),
            "E_USAGE"
        );
        let dirs = resolve(
            Os::Linux,
            &[
                ("XDG_DATA_HOME", "/d"),
                ("XDG_CACHE_HOME", "/c"),
                ("XDG_CONFIG_HOME", "/f"),
            ],
        )
        .unwrap();
        assert_eq!(dirs.data, p("/d", &["jtm"]));
    }

    #[test]
    fn jtm_home_collapses_data_config_and_cache() {
        for (os, home, vars) in [
            (Os::Windows, r"E:\portable\jtm", WINDOWS),
            (Os::Linux, "/opt/jtm", &[("HOME", "/home/u")][..]),
            (Os::Macos, "/opt/jtm", &[][..]),
        ] {
            let dirs = Dirs::resolve(os, Some(Path::new(home)), None, &env(vars)).unwrap();
            assert_eq!(dirs.data, PathBuf::from(home), "{os}");
            assert_eq!(dirs.cache, p(home, &["cache"]), "{os}");
            assert_eq!(dirs.config_file, p(home, &["config.toml"]), "{os}");
            assert_eq!(dirs.index_cache(), p(home, &["cache", "index"]), "{os}");
            assert_eq!(dirs.tools(), p(home, &["tools"]), "{os}");
            assert_eq!(dirs.state(), p(home, &["state"]), "{os}");
        }
    }

    #[test]
    fn jtm_home_must_be_absolute() {
        let err = Dirs::resolve(Os::Linux, Some(Path::new("jtm")), None, &env(&[])).unwrap_err();
        assert_eq!(err.code(), "E_USAGE");
        assert!(err.to_string().contains("JTM_HOME"));
        let err =
            Dirs::resolve(Os::Windows, Some(Path::new("/opt/jtm")), None, &env(&[])).unwrap_err();
        assert_eq!(
            err.code(),
            "E_USAGE",
            "a Unix path is not absolute on Windows"
        );
        Dirs::resolve(
            Os::Windows,
            Some(Path::new(r"\\server\share\jtm")),
            None,
            &env(&[]),
        )
        .unwrap();
    }

    #[test]
    fn an_explicit_config_file_wins() {
        let dirs = Dirs::resolve(
            Os::Linux,
            Some(Path::new("/opt/jtm")),
            Some(Path::new("/srv/ci/jtm.toml")),
            &env(&[]),
        )
        .unwrap();
        assert_eq!(dirs.config_file, PathBuf::from("/srv/ci/jtm.toml"));
        assert_eq!(dirs.data, PathBuf::from("/opt/jtm"));
    }

    #[test]
    fn data_layout_matches_section_14() {
        let dirs = resolve(Os::Linux, &[("HOME", "/h")]).unwrap();
        let data = p("/h", &[".local", "share", "jtm"]);
        let cache = p("/h", &[".cache", "jtm"]);
        assert_eq!(dirs.current(), data.join("current"));
        assert_eq!(
            dirs.install_dir("example", "default", "21.0.5+11"),
            data.join("tools").join("example").join("default-21.0.5+11")
        );
        assert_eq!(
            dirs.install_dir("acme/flyway", "default", "10.1"),
            data.join("tools").join("acme--flyway").join("default-10.1")
        );
        assert_eq!(dirs.tools_tmp(), data.join("tools").join(".tmp"));
        assert_eq!(dirs.tools_trash(), data.join("tools").join(".trash"));
        assert_eq!(dirs.builtin_plugins(), data.join("plugins").join("builtin"));
        assert_eq!(dirs.locks(), data.join("locks"));
        assert_eq!(dirs.downloads(), cache.join("downloads"));
    }

    #[test]
    fn resolves_for_the_running_os() {
        let ctx = Context::resolve(
            &crate::context::GlobalFlags::default(),
            |_| None,
            crate::context::Terminal::default(),
        )
        .unwrap();
        let host_home = if cfg!(windows) {
            r"C:\jtm-test"
        } else {
            "/jtm-test"
        };
        let ctx = Context {
            home: Some(PathBuf::from(host_home)),
            ..ctx
        };
        let dirs = Dirs::for_context(&ctx).unwrap();
        assert_eq!(dirs.data, PathBuf::from(host_home));
    }
}
