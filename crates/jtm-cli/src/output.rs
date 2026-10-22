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

/// A non-fatal problem reported alongside a successful result.
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
    jtm_version: &'static str,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
    retryable: bool,
    details: Map<String, Value>,
}

/// A failure found by a command that reports on many things, such as `jtm doctor`, with the
/// code and message of the finding that decides the exit code.
#[derive(Debug)]
pub(crate) struct Diagnosis<'a> {
    pub(crate) code: &'static str,
    pub(crate) message: &'a str,
    pub(crate) retryable: bool,
    pub(crate) details: Map<String, Value>,
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
        self.failure_with(command, error, Map::new())
    }

    /// A failure whose `details` also carry `extra`.
    pub(crate) fn failure_with(
        &mut self,
        command: &str,
        error: &JtmError,
        extra: Map<String, Value>,
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
                    jtm_version: JTM_VERSION,
                };
                self.write_json(&envelope)
            }
            Format::Human => {
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

    /// A failure that comes with a full report, as `jtm doctor` produces. In JSON mode the
    /// report is in `error.details.report`; for a human it is written to stdout first, then the
    /// error to stderr.
    pub(crate) fn report_failure<T: Serialize + Human>(
        &mut self,
        command: &str,
        failure: &Diagnosis<'_>,
        report: &T,
    ) -> io::Result<()> {
        match self.format {
            Format::Json => {
                let mut details = failure.details.clone();
                details.insert(
                    "report".to_owned(),
                    serde_json::to_value(report).unwrap_or_default(),
                );
                let envelope = ErrorEnvelope {
                    ok: false,
                    command,
                    error: ErrorBody {
                        code: failure.code,
                        message: failure.message.to_owned(),
                        retryable: failure.retryable,
                        details,
                    },
                    jtm_version: JTM_VERSION,
                };
                self.write_json(&envelope)
            }
            Format::Human => {
                report.render_human(&mut self.stdout)?;
                self.stdout.flush()?;
                writeln!(self.stderr, "error[{}]: {}", failure.code, failure.message)?;
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
