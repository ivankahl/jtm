//! Global flags and environment variables resolved into a [`Context`] (SPEC.md section 4).
//!
//! Precedence, highest first: command-line flag, `JTM_*` variable, `CI`, terminal detection,
//! built-in default.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::{JtmError, Result};

/// The global flags as typed on the command line, before any environment is consulted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GlobalFlags {
    pub json: bool,
    pub progress: bool,
    pub offline: bool,
    pub quiet: bool,
    pub verbose: bool,
    pub no_input: bool,
    pub yes: bool,
    pub config: Option<PathBuf>,
    /// `None` when `--color` was not passed.
    pub color: Option<ColorChoice>,
    pub no_lock: bool,
}

/// The value of `--color`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorChoice {
    Auto,
    Always,
    Never,
}

/// Which standard streams are attached to a terminal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Terminal {
    pub stdin: bool,
    pub stderr: bool,
}

/// How much diagnostic output to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verbosity {
    Quiet,
    Normal,
    Verbose,
}

/// Everything a command needs to know about how it was invoked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// Write one JSON envelope to stdout.
    pub json: bool,
    /// With `json`, stream newline-delimited progress events to stderr.
    pub progress: bool,
    /// Never touch the network.
    pub offline: bool,
    /// Prompts are allowed. False under `--no-input`, `--json`, `CI` or without a terminal.
    pub interactive: bool,
    /// Accept routine confirmations. Never accepts trust changes.
    pub assume_yes: bool,
    /// Use ANSI colour on stderr.
    pub color: bool,
    pub verbosity: Verbosity,
    /// A `tracing` filter directive for diagnostic logs.
    pub log_filter: String,
    /// Explicit user config file, from `--config` or `JTM_CONFIG`.
    pub config_path: Option<PathBuf>,
    /// Single directory for all state, from `JTM_HOME`.
    pub home: Option<PathBuf>,
    /// Honour `jtm.lock`. False under `--no-lock`.
    pub use_lockfile: bool,
    /// Running under CI, from the `CI` variable.
    pub ci: bool,
}

const DEFAULT_LOG_FILTER: &str = "warn";

impl Context {
    /// Resolves `flags` against the environment. `env` looks up one variable, so tests can pass
    /// a fake environment instead of the process one.
    pub fn resolve(
        flags: &GlobalFlags,
        env: impl Fn(&str) -> Option<OsString>,
        terminal: Terminal,
    ) -> Result<Context> {
        let ci = ci_detected(env("CI"));
        let offline = flags.offline || env_flag("JTM_OFFLINE", env("JTM_OFFLINE"))?;
        let no_input = flags.no_input || env_flag("JTM_NO_INPUT", env("JTM_NO_INPUT"))?;
        let interactive = !no_input && !ci && !flags.json && terminal.stdin && terminal.stderr;

        let color = match flags.color.unwrap_or(ColorChoice::Auto) {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => {
                !ci && !flags.json && terminal.stderr && non_empty(env("NO_COLOR")).is_none()
            }
        };

        let verbosity = match (flags.quiet, flags.verbose) {
            (true, true) => {
                return Err(JtmError::usage(
                    "--quiet and --verbose cannot be used together",
                ));
            }
            (true, false) => Verbosity::Quiet,
            (false, true) => Verbosity::Verbose,
            (false, false) => Verbosity::Normal,
        };
        let log_filter = match verbosity {
            Verbosity::Quiet => "error".to_owned(),
            Verbosity::Verbose => "debug".to_owned(),
            Verbosity::Normal => match non_empty(env("JTM_LOG")) {
                Some(value) => value
                    .into_string()
                    .map_err(|_| JtmError::usage("JTM_LOG is not valid UTF-8"))?,
                None => DEFAULT_LOG_FILTER.to_owned(),
            },
        };

        Ok(Context {
            json: flags.json,
            progress: flags.json && flags.progress,
            offline,
            interactive,
            assume_yes: flags.yes,
            color,
            verbosity,
            log_filter,
            config_path: flags
                .config
                .clone()
                .or_else(|| non_empty(env("JTM_CONFIG")).map(PathBuf::from)),
            home: non_empty(env("JTM_HOME")).map(PathBuf::from),
            use_lockfile: !flags.no_lock,
            ci,
        })
    }
}

fn non_empty(value: Option<OsString>) -> Option<OsString> {
    value.filter(|v| !v.is_empty())
}

/// Parses a boolean `JTM_*` variable. Unset or empty means false; anything unrecognised is a
/// usage error rather than a guess.
fn env_flag(name: &str, value: Option<OsString>) -> Result<bool> {
    let Some(value) = non_empty(value) else {
        return Ok(false);
    };
    match value.to_str().map(str::to_ascii_lowercase).as_deref() {
        Some("1" | "true" | "yes" | "on") => Ok(true),
        Some("0" | "false" | "no" | "off") => Ok(false),
        _ => Err(JtmError::usage(format!(
            "{name} must be 1, true, yes, on, 0, false, no or off, got {value:?}"
        ))),
    }
}

/// CI systems disagree on the value of `CI` (`true`, `1`, a vendor name), so any non-empty value
/// other than an explicit false counts. Erring towards CI only ever turns prompts off.
fn ci_detected(value: Option<OsString>) -> bool {
    match non_empty(value) {
        None => false,
        Some(value) => !matches!(
            value.to_str().map(str::to_ascii_lowercase).as_deref(),
            Some("0" | "false" | "no" | "off")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const TTY: Terminal = Terminal {
        stdin: true,
        stderr: true,
    };

    fn resolve(flags: GlobalFlags, vars: &[(&str, &str)], terminal: Terminal) -> Result<Context> {
        let vars: HashMap<String, OsString> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        Context::resolve(&flags, |key| vars.get(key).cloned(), terminal)
    }

    fn ok(flags: GlobalFlags, vars: &[(&str, &str)]) -> Context {
        resolve(flags, vars, TTY).unwrap()
    }

    #[test]
    fn defaults_in_a_terminal() {
        let ctx = ok(GlobalFlags::default(), &[]);
        assert!(!ctx.json);
        assert!(!ctx.offline);
        assert!(ctx.interactive);
        assert!(!ctx.assume_yes);
        assert!(ctx.color);
        assert_eq!(ctx.verbosity, Verbosity::Normal);
        assert_eq!(ctx.log_filter, "warn");
        assert_eq!(ctx.config_path, None);
        assert_eq!(ctx.home, None);
        assert!(ctx.use_lockfile);
        assert!(!ctx.ci);
    }

    #[test]
    fn env_vars_apply_when_no_flag_is_given() {
        let ctx = ok(
            GlobalFlags::default(),
            &[
                ("JTM_OFFLINE", "1"),
                ("JTM_NO_INPUT", "true"),
                ("JTM_CONFIG", "/env/config.toml"),
                ("JTM_HOME", "/env/home"),
                ("JTM_LOG", "jtm_core=trace"),
            ],
        );
        assert!(ctx.offline);
        assert!(!ctx.interactive);
        assert_eq!(ctx.config_path, Some(PathBuf::from("/env/config.toml")));
        assert_eq!(ctx.home, Some(PathBuf::from("/env/home")));
        assert_eq!(ctx.log_filter, "jtm_core=trace");
    }

    #[test]
    fn config_flag_beats_jtm_config() {
        let flags = GlobalFlags {
            config: Some(PathBuf::from("/flag/config.toml")),
            ..GlobalFlags::default()
        };
        let ctx = ok(flags, &[("JTM_CONFIG", "/env/config.toml")]);
        assert_eq!(ctx.config_path, Some(PathBuf::from("/flag/config.toml")));
    }

    #[test]
    fn verbosity_flags_beat_jtm_log() {
        let vars = [("JTM_LOG", "trace")];
        let verbose = GlobalFlags {
            verbose: true,
            ..GlobalFlags::default()
        };
        assert_eq!(ok(verbose, &vars).log_filter, "debug");
        let quiet = GlobalFlags {
            quiet: true,
            ..GlobalFlags::default()
        };
        assert_eq!(ok(quiet, &vars).log_filter, "error");
    }

    #[test]
    fn offline_flag_beats_jtm_offline_off() {
        let flags = GlobalFlags {
            offline: true,
            ..GlobalFlags::default()
        };
        assert!(ok(flags, &[("JTM_OFFLINE", "0")]).offline);
    }

    #[test]
    fn no_input_flag_beats_jtm_no_input_off() {
        let flags = GlobalFlags {
            no_input: true,
            ..GlobalFlags::default()
        };
        assert!(!ok(flags, &[("JTM_NO_INPUT", "false")]).interactive);
    }

    #[test]
    fn color_flag_beats_ci_and_no_color() {
        let always = GlobalFlags {
            color: Some(ColorChoice::Always),
            ..GlobalFlags::default()
        };
        assert!(ok(always, &[("CI", "true"), ("NO_COLOR", "1")]).color);
        let never = GlobalFlags {
            color: Some(ColorChoice::Never),
            ..GlobalFlags::default()
        };
        assert!(!ok(never, &[]).color);
    }

    #[test]
    fn ci_implies_no_input_and_no_colour() {
        for value in ["true", "1", "github-actions"] {
            let ctx = ok(GlobalFlags::default(), &[("CI", value)]);
            assert!(ctx.ci, "CI={value}");
            assert!(!ctx.interactive, "CI={value}");
            assert!(!ctx.color, "CI={value}");
        }
        for value in ["false", "0", ""] {
            let ctx = ok(GlobalFlags::default(), &[("CI", value)]);
            assert!(!ctx.ci, "CI={value}");
            assert!(ctx.interactive, "CI={value}");
        }
    }

    #[test]
    fn json_is_never_interactive() {
        let flags = GlobalFlags {
            json: true,
            ..GlobalFlags::default()
        };
        let ctx = ok(flags, &[]);
        assert!(!ctx.interactive);
        assert!(!ctx.color);
    }

    #[test]
    fn no_terminal_is_never_interactive() {
        for terminal in [
            Terminal {
                stdin: false,
                stderr: true,
            },
            Terminal {
                stdin: true,
                stderr: false,
            },
        ] {
            let ctx = resolve(GlobalFlags::default(), &[], terminal).unwrap();
            assert!(!ctx.interactive, "{terminal:?}");
        }
    }

    #[test]
    fn progress_only_applies_with_json() {
        let progress = GlobalFlags {
            progress: true,
            ..GlobalFlags::default()
        };
        assert!(!ok(progress.clone(), &[]).progress);
        let json = GlobalFlags {
            json: true,
            ..progress
        };
        assert!(ok(json, &[]).progress);
    }

    #[test]
    fn yes_and_no_lock_flags_are_carried_through() {
        let flags = GlobalFlags {
            yes: true,
            no_lock: true,
            ..GlobalFlags::default()
        };
        let ctx = ok(flags, &[]);
        assert!(ctx.assume_yes);
        assert!(!ctx.use_lockfile);
    }

    #[test]
    fn empty_env_values_count_as_unset() {
        let ctx = ok(
            GlobalFlags::default(),
            &[
                ("JTM_HOME", ""),
                ("JTM_CONFIG", ""),
                ("JTM_OFFLINE", ""),
                ("JTM_LOG", ""),
            ],
        );
        assert_eq!(ctx.home, None);
        assert_eq!(ctx.config_path, None);
        assert!(!ctx.offline);
        assert_eq!(ctx.log_filter, "warn");
    }

    #[test]
    fn unrecognised_boolean_env_value_is_a_usage_error() {
        let err = resolve(GlobalFlags::default(), &[("JTM_OFFLINE", "maybe")], TTY).unwrap_err();
        assert_eq!(err.code(), "E_USAGE");
        assert!(err.to_string().contains("JTM_OFFLINE"));
    }

    #[test]
    fn quiet_and_verbose_together_is_a_usage_error() {
        let flags = GlobalFlags {
            quiet: true,
            verbose: true,
            ..GlobalFlags::default()
        };
        let err = resolve(flags, &[], TTY).unwrap_err();
        assert_eq!(err.code(), "E_USAGE");
    }
}
