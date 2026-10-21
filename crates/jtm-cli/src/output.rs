//! The output envelope (SPEC.md section 12) and its human and JSON renderers.
//!
//! In JSON mode stdout carries exactly one envelope per run and everything else goes to stderr.
//! In human mode results go to stdout and warnings and errors to stderr.

use std::error::Error as _;
use std::io::{self, Write};

use jtm_core::JtmError;
use serde::Serialize;
use serde_json::{Map, Value};

/// The version of jtm reported in every envelope.
pub(crate) const JTM_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How results are written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    Human,
    Json,
}

/// A non-fatal problem reported alongside a result, successful or not.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct Warning {
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) details: Map<String, Value>,
}

/// Command data that can also be shown to a human.
pub(crate) trait Human {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()>;
}

/// The successful result of a command.
#[derive(Debug)]
pub(crate) struct Outcome<T> {
    pub(crate) command: &'static str,
    /// Whether the command changed any state; re-running an idempotent command reports `false`.
    pub(crate) changed: bool,
    pub(crate) data: T,
    pub(crate) warnings: Vec<Warning>,
}

#[derive(Serialize)]
struct SuccessEnvelope<'a, T> {
    ok: bool,
    command: &'a str,
    changed: bool,
    data: &'a T,
    warnings: &'a [Warning],
    jtm_version: &'static str,
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    ok: bool,
    command: &'a str,
    error: ErrorBody,
    warnings: &'a [Warning],
    jtm_version: &'static str,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
    retryable: bool,
    details: Map<String, Value>,
}

/// Writes outcomes and failures to a pair of streams in the chosen format.
pub(crate) struct Renderer<O, E> {
    format: Format,
    stdout: O,
    stderr: E,
}

impl Renderer<io::Stdout, io::Stderr> {
    pub(crate) fn stdio(format: Format) -> Self {
        Renderer::new(format, io::stdout(), io::stderr())
    }
}

impl<O: Write, E: Write> Renderer<O, E> {
    pub(crate) fn new(format: Format, stdout: O, stderr: E) -> Self {
        Renderer {
            format,
            stdout,
            stderr,
        }
    }

    pub(crate) fn success<T: Serialize + Human>(&mut self, outcome: &Outcome<T>) -> io::Result<()> {
        match self.format {
            Format::Json => {
                let envelope = SuccessEnvelope {
                    ok: true,
                    command: outcome.command,
                    changed: outcome.changed,
                    data: &outcome.data,
                    warnings: &outcome.warnings,
                    jtm_version: JTM_VERSION,
                };
                self.write_json(&envelope)
            }
            Format::Human => {
                for warning in &outcome.warnings {
                    writeln!(
                        self.stderr,
                        "warning[{}]: {}",
                        warning.code, warning.message
                    )?;
                }
                outcome.data.render_human(&mut self.stdout)?;
                self.stdout.flush()
            }
        }
    }

    pub(crate) fn failure(&mut self, command: &str, error: &JtmError) -> io::Result<()> {
        self.failure_with(command, error, Map::new(), &[])
    }

    /// A failure whose `details` also carry `extra`, reported with the `warnings` the command
    /// collected before it failed.
    pub(crate) fn failure_with(
        &mut self,
        command: &str,
        error: &JtmError,
        extra: Map<String, Value>,
        warnings: &[Warning],
    ) -> io::Result<()> {
        match self.format {
            Format::Json => {
                let mut details = error.details();
                details.extend(extra);
                let envelope = ErrorEnvelope {
                    ok: false,
                    command,
                    error: ErrorBody {
                        code: error.code(),
                        message: error.to_string(),
                        retryable: error.retryable(),
                        details,
                    },
                    warnings,
                    jtm_version: JTM_VERSION,
                };
                self.write_json(&envelope)
            }
            Format::Human => {
                for warning in warnings {
                    writeln!(
                        self.stderr,
                        "warning[{}]: {}",
                        warning.code, warning.message
                    )?;
                }
                writeln!(self.stderr, "error[{}]: {error}", error.code())?;
                let mut source = error.source();
                while let Some(cause) = source {
                    writeln!(self.stderr, "  caused by: {cause}")?;
                    source = cause.source();
                }
                self.stderr.flush()
            }
        }
    }

    fn write_json<T: Serialize>(&mut self, value: &T) -> io::Result<()> {
        serde_json::to_writer(&mut self.stdout, value)?;
        writeln!(self.stdout)?;
        self.stdout.flush()
    }
}

#[cfg(test)]
mod tests;
