//! `jtm doctor` (SPEC.md sections 9, 13, 14 and 16): finds what keeps jtm from working and says
//! exactly what and how to fix it.
//!
//! A [`Report`] holds one [`Check`] per area, in a fixed order: `PATH`, current links, the
//! shell hook, the proxy, TLS and the trust store. A check holds the
//! [`Finding`]s it made, each with a stable code, a specific message and a hint. An error
//! finding carries one of the `E_` codes of section 12 and decides the exit code; a warning
//! finding carries a `W_` code and never changes it. The first error in check order wins, so
//! the envelope's `error.code` is always the code of a finding in the report.
//!
//! Doctor only reads. It never repairs, prompts or refreshes anything, and a network
//! connection is made only for the TLS check, and only when jtm is not offline. Everything it
//! prints about a proxy is redacted. It finds the plugins' tool names, environment variables
//! and `bin` directories in their manifests, never in this code.

mod links;
mod network;
mod trust;

use jtm_fetch::Client;
use jtm_security::Timestamp;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::config::Settings;
use crate::dirs::Dirs;
use crate::error::{ErrorCode, ExitCode, JtmError};
use crate::plugins::Registry;

/// Warning code for a current-link `bin` directory missing from `PATH`.
pub const W_PATH_MISSING: &str = "W_PATH_MISSING";
/// Warning code for a shell hook that is not loaded where it should be.
pub const W_SHELL_HOOK_MISSING: &str = "W_SHELL_HOOK_MISSING";
/// Warning code for a pinned project used in a shell where the hook is not active.
pub const W_SHELL_HOOK_INACTIVE: &str = "W_SHELL_HOOK_INACTIVE";
/// Warning code for a proxy setting jtm found but cannot honour, such as a PAC file.
pub const W_PROXY_UNSUPPORTED: &str = "W_PROXY_UNSUPPORTED";
/// Warning code for an expired index key while another key still signs for the plugin.
pub const W_INDEX_KEY_EXPIRED: &str = "W_INDEX_KEY_EXPIRED";

/// How a check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    /// Only warning findings.
    Warning,
    /// At least one error finding.
    Failed,
    /// The check could not run; its summary says why.
    Skipped,
}

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Warning,
    Error,
}

/// One problem a check found.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// An `E_` code from section 12 for an error, a `W_` code for a warning.
    pub code: &'static str,
    pub message: String,
    /// What to do about it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    pub details: Map<String, Value>,
    #[serde(skip)]
    error: Option<ErrorCode>,
}

impl Finding {
    /// An error finding with the code `code` stands for.
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Finding {
        Finding {
            severity: Severity::Error,
            code: code.as_str(),
            message: message.into(),
            hint: None,
            details: Map::new(),
            error: Some(code),
        }
    }

    /// A warning finding with a `W_` code.
    pub fn warning(code: &'static str, message: impl Into<String>) -> Finding {
        Finding {
            severity: Severity::Warning,
            code,
            message: message.into(),
            hint: None,
            details: Map::new(),
            error: None,
        }
    }

    /// An error finding for `err`, with its code and details.
    pub fn from_error(err: &JtmError) -> Finding {
        let mut finding = Finding::error(err.kind(), err.to_string());
        finding.details = err.details();
        finding
    }

    #[must_use]
    pub fn hint(mut self, hint: impl Into<String>) -> Finding {
        self.hint = Some(hint.into());
        self
    }

    #[must_use]
    pub fn detail(mut self, key: &str, value: impl Into<Value>) -> Finding {
        self.details.insert(key.to_owned(), value.into());
        self
    }

    /// The exit code this finding stands for: success for a warning.
    pub fn exit_code(&self) -> ExitCode {
        self.error.map_or(ExitCode::Success, ErrorCode::exit_code)
    }

    /// Whether running the same command again might succeed.
    pub fn retryable(&self) -> bool {
        self.error.is_some_and(ErrorCode::retryable)
    }
}

/// The result of one check.
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub status: Status,
    /// What was found, or why the check did not run.
    pub summary: String,
    /// Things worth knowing that are not problems, such as a part of the check that was skipped.
    pub notes: Vec<String>,
    pub findings: Vec<Finding>,
    /// What was inspected, for machines.
    pub details: Map<String, Value>,
}

impl Check {
    /// A check that found nothing wrong.
    pub fn pass(id: &'static str, summary: impl Into<String>) -> Check {
        Check {
            id,
            status: Status::Ok,
            summary: summary.into(),
            notes: Vec::new(),
            findings: Vec::new(),
            details: Map::new(),
        }
    }

    /// A check that could not run.
    pub fn skipped(id: &'static str, reason: impl Into<String>) -> Check {
        Check {
            status: Status::Skipped,
            ..Check::pass(id, reason)
        }
    }

    /// Adds a finding and moves the status to match, an error outranking a warning.
    pub fn push(&mut self, finding: Finding) {
        self.status = match (self.status, finding.severity) {
            (_, Severity::Error) | (Status::Failed, _) => Status::Failed,
            _ => Status::Warning,
        };
        self.findings.push(finding);
    }

    #[must_use]
    pub fn note(mut self, note: impl Into<String>) -> Check {
        self.notes.push(note.into());
        self
    }

    #[must_use]
    pub fn detail(mut self, key: &str, value: impl Into<Value>) -> Check {
        self.details.insert(key.to_owned(), value.into());
        self
    }
}

/// Everything doctor found, one [`Check`] per area.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    /// The first error finding in check order, which decides the exit code.
    pub fn first_error(&self) -> Option<&Finding> {
        self.findings()
            .find(|finding| finding.severity == Severity::Error)
    }

    /// Every warning finding, in check order.
    pub fn warnings(&self) -> impl Iterator<Item = &Finding> {
        self.findings()
            .filter(|finding| finding.severity == Severity::Warning)
    }

    fn findings(&self) -> impl Iterator<Item = &Finding> {
        self.checks.iter().flat_map(|check| check.findings.iter())
    }

    /// The process exit code: success unless a check found an error.
    pub fn exit_code(&self) -> ExitCode {
        self.first_error()
            .map_or(ExitCode::Success, Finding::exit_code)
    }
}

/// Opens a connection to a URL, to find out whether TLS and the network work.
pub trait Prober: Sync {
    /// Succeeds when the host answered at all; see [`Client::probe`].
    fn probe(&self, url: &str) -> jtm_fetch::Result<()>;
}

impl Prober for Client {
    fn probe(&self, url: &str) -> jtm_fetch::Result<()> {
        Client::probe(self, url)
    }
}

/// What doctor looks at.
#[derive(Clone, Copy)]
pub struct Inputs<'a> {
    pub dirs: &'a Dirs,
    pub settings: &'a Settings,
    pub registry: Registry<'a>,
    /// Never touch the network: the connection test is skipped.
    pub offline: bool,
    /// Looks up an environment variable: `PATH` and the proxy variables.
    pub env: &'a dyn Fn(&str) -> Option<String>,
    pub now: Timestamp,
    /// Makes the TLS connection test. `None` builds the HTTP client from `settings`.
    pub prober: Option<&'a dyn Prober>,
}

impl std::fmt::Debug for Inputs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Inputs")
            .field("dirs", &self.dirs)
            .field("offline", &self.offline)
            .field("prober", &self.prober.is_some())
            .finish_non_exhaustive()
    }
}

/// Runs every check. `shell_hook` is the result of the shell hook check, which needs the shell
/// setup code of the command-line crate and goes third.
pub fn run(inputs: &Inputs<'_>, shell_hook: Check) -> Report {
    let (proxy, tls) = network::checks(inputs);
    Report {
        checks: vec![
            links::path(inputs),
            links::current(inputs),
            shell_hook,
            proxy,
            tls,
            trust::check(inputs),
        ],
    }
}

/// Replaces the secrets `secrets` name in `text` with `***`.
fn scrub(text: &str, secrets: &[String]) -> String {
    secrets
        .iter()
        .filter(|secret| !secret.is_empty())
        .fold(text.to_owned(), |text, secret| text.replace(secret, "***"))
}

/// A summary of `entries` for a message: `a, b and c`.
fn list(entries: &[String]) -> String {
    match entries {
        [] => String::new(),
        [only] => only.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

#[cfg(test)]
mod tests;
