//! Global flags and environment variables resolved into a [`Context`] (SPEC.md section 4).
//!
//! Precedence, highest first: command-line flag, `JTM_*` variable, `CI`, terminal detection,
//! built-in default.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::error::{JtmError, Result};
use crate::plugins::BuiltinManifest;

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
    /// The plugin manifests compiled into this binary. Only these have pre-approved anchors;
    /// [`Context::resolve`] leaves it empty, and the binary sets it.
    pub builtin: &'static [BuiltinManifest],
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
            builtin: &[],
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
mod tests;
