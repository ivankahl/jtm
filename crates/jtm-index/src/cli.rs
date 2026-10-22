//! The `jtm-index` command line (SPEC.md sections 12 and 18).
//!
//! `jtm-index generate` runs the whole pipeline for one plugin: query the sources in
//! `sources.toml`, confirm every hash, write the index files, sign them and check the result
//! with the client's loader. It is meant for CI, so it never prompts: the signing key and
//! its password come from files or environment variables (a CI secret), never from the
//! command line, and a missing one is an error.
//!
//! `jtm-index verify` checks a directory laid out as a release is with the client's own loader,
//! including the delegation of the signing key in `keys.json`, before anything is published.
//!
//! With `--json`, stdout carries exactly one envelope of the shape SPEC.md section 12
//! describes and everything else goes to stderr.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
use jtm_core::{ErrorCode, ExitCode};
use jtm_fetch::{Client, ClientOptions};
use jtm_security::{PublicKey, Timestamp};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::confirm::{Confirmed, DEFAULT_MAX_ARTIFACT_BYTES, Options};
use crate::confirmed_file;
use crate::context::Context;
use crate::error::{Error, Result};
use crate::plugin::Plugin;
use crate::publish::{Report, Request, publish};
use crate::release;
use crate::signing::Signer;
use crate::writer::{DEFAULT_VALIDITY_DAYS, Settings, Validity, Warning};

/// The version reported in every envelope.
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The largest key or password file read.
const MAX_SECRET_FILE: u64 = 64 * 1024;
/// The environment variable that holds the token for the GitHub API.
const GITHUB_TOKEN: &str = "GITHUB_TOKEN";

/// Generates, signs and publishes jtm version indices. Runs in CI only.
#[derive(Debug, Parser)]
#[command(name = "jtm-index", version, about)]
pub struct Cli {
    /// Print one JSON envelope on stdout; logs go to stderr.
    #[arg(long, global = true)]
    pub json: bool,

    /// Log more to stderr: once for progress, twice for detail.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Query the sources, confirm the hashes, then write and sign the index files of a plugin.
    Generate(Box<GenerateArgs>),
    /// Check a release directory the way a client will, before it is published.
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// The directory a release is made from: index files, their `.minisig` files, `keys.json`
    /// and `keys.json.minisig`.
    #[arg(long)]
    pub published: PathBuf,

    /// A plugin directory; only its `plugin.toml` is read. Repeat for every plugin in the
    /// release.
    #[arg(long = "plugin-dir", value_name = "DIR", required = true)]
    pub plugin_dirs: Vec<PathBuf>,

    /// A root key (`RW...`) to trust in place of every manifest's `signing_keys`, for a
    /// rehearsal with throwaway keys. The manifests' thresholds still apply. Repeatable.
    #[arg(long = "root-key", value_name = "KEY")]
    pub root_keys: Vec<String>,

    /// Treat this UTC time (`2026-10-19T03:00:00Z`) as now.
    #[arg(long, value_name = "TIME")]
    pub now: Option<String>,

    /// Warn when the newest index key of a plugin is valid for fewer days than this.
    #[arg(long, value_name = "DAYS", default_value_t = 14)]
    pub min_key_days: u32,
}

#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// The plugin directory holding `plugin.toml` and `sources.toml`.
    #[arg(long)]
    pub plugin_dir: PathBuf,

    /// Where to write the index files and their `.minisig` files.
    #[arg(long)]
    pub out: PathBuf,

    /// The directory of the previous publish. Sequences continue from its files, and an index
    /// that has not changed is left as it is. Leave it out only for a first publish.
    #[arg(long)]
    pub previous: Option<PathBuf>,

    /// A public key (`RW...`, or a `.pub` file) besides the signing key that the previous
    /// publish may be signed with, such as the key from before a rotation. Repeatable.
    #[arg(long = "previous-key", value_name = "KEY")]
    pub previous_keys: Vec<String>,

    /// The minisign secret key file to sign with.
    #[arg(long, value_name = "FILE", conflicts_with = "secret_key_env")]
    pub secret_key: Option<PathBuf>,

    /// The environment variable holding the contents of the minisign secret key file, as a
    /// CI secret does.
    #[arg(long, value_name = "VAR")]
    pub secret_key_env: Option<String>,

    /// A file holding the password of the secret key.
    #[arg(long, value_name = "FILE", conflicts_with = "password_env")]
    pub password_file: Option<PathBuf>,

    /// The environment variable holding the password of the secret key.
    #[arg(long, value_name = "VAR")]
    pub password_env: Option<String>,

    /// How long a new index is valid, between 1 and 90 days.
    #[arg(long, value_name = "DAYS", default_value_t = DEFAULT_VALIDITY_DAYS)]
    pub validity_days: u32,

    /// Treat this UTC time (`2026-10-19T03:00:00Z`) as the time of the run, for a
    /// reproducible run. It can never be earlier than the previous publish.
    #[arg(long, value_name = "TIME")]
    pub now: Option<String>,

    /// Do everything except write files. No key is needed, but with one it is checked.
    #[arg(long)]
    pub dry_run: bool,

    /// Save the confirmed entries to this file (also in a dry run): normalised JSON that a
    /// person can review and `--use-confirmed` can sign later.
    #[arg(long, value_name = "FILE", conflicts_with = "use_confirmed")]
    pub write_confirmed: Option<PathBuf>,

    /// Take the entries from a file written by `--write-confirmed` instead of asking the
    /// sources, so what was reviewed is exactly what is signed. Nothing is downloaded.
    #[arg(long, value_name = "FILE")]
    pub use_confirmed: Option<PathBuf>,

    /// The most bytes of one artifact downloaded to compute its hash.
    #[arg(long, value_name = "BYTES", default_value_t = DEFAULT_MAX_ARTIFACT_BYTES)]
    pub max_artifact_bytes: u64,

    /// Send requests for URLs starting with FROM to TO instead (`FROM=TO`), for a proxy cache
    /// in CI. Index entries keep the URLs the vendors report. Repeatable.
    #[arg(long = "mirror", value_name = "FROM=TO")]
    pub mirrors: Vec<String>,
}

/// Runs the command line against the network and the process environment, and returns the
/// process exit status.
pub fn run(cli: &Cli, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let env = |name: &str| std::env::var(name).ok();
    let Command::Generate(args) = &cli.command else {
        return execute_verify(cli, stdout, stderr);
    };
    let acquire = |plugin: &Plugin| -> Result<Confirmed> {
        let ctx = context(args, &env)?;
        let discovery = plugin.discover(&ctx)?;
        plugin.confirm(
            &ctx,
            discovery,
            Options {
                max_artifact_bytes: args.max_artifact_bytes,
            },
        )
    };
    execute(cli, &env, &acquire, stdout, stderr)
}

/// Runs the command line with `env` for variables and `acquire` for turning a plugin into
/// confirmed entries (which is where the network is used), and renders the outcome.
pub fn execute(
    cli: &Cli,
    env: &dyn Fn(&str) -> Option<String>,
    acquire: &dyn Fn(&Plugin) -> Result<Confirmed>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let Command::Generate(args) = &cli.command else {
        return execute_verify(cli, stdout, stderr);
    };
    let result = generate(args, env, acquire);
    render(cli.json, "generate", &result, stdout, stderr)
}

/// Runs `verify`, which never touches the network or the sources.
fn execute_verify(cli: &Cli, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let Command::Verify(args) = &cli.command else {
        return ExitCode::Usage.as_u8();
    };
    match check_release(args) {
        Ok(report) => {
            let written = if cli.json {
                let envelope = json!({
                    "ok": true,
                    "command": "verify",
                    "changed": false,
                    "data": report,
                    "warnings": warnings_out(&report.warnings),
                    "jtm_version": VERSION,
                });
                writeln!(stdout, "{envelope}")
            } else {
                human_release(&report, stdout, stderr)
            };
            let _ = written;
            ExitCode::Success.as_u8()
        }
        Err(error) => render_error(cli.json, "verify", &error, stdout, stderr),
    }
}

fn check_release(args: &VerifyArgs) -> Result<release::Report> {
    let now = match &args.now {
        Some(text) => Timestamp::parse(text).ok_or_else(|| Error::Usage {
            message: format!("--now `{text}` is not a UTC time like 2026-10-19T03:00:00Z"),
        })?,
        None => Timestamp::now(),
    };
    for key in &args.root_keys {
        PublicKey::parse(key).map_err(|_| Error::Usage {
            message: "--root-key must be a minisign public key (RW...)".to_owned(),
        })?;
    }
    release::verify(&release::Request {
        published: &args.published,
        plugin_dirs: &args.plugin_dirs,
        root_keys: &args.root_keys,
        now,
        min_key_days: args.min_key_days,
    })
}

fn human_release(
    report: &release::Report,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> std::io::Result<()> {
    for warning in &report.warnings {
        writeln!(stderr, "warning[{}]: {}", warning.code, warning.message)?;
    }
    for plugin in &report.plugins {
        for file in &plugin.files {
            writeln!(
                stdout,
                "ok {} (sequence {}, {} entries, expires {})",
                file.file, file.sequence, file.entries, file.expires
            )?;
        }
        if let Some(sequence) = plugin.keys_sequence {
            writeln!(
                stdout,
                "ok keys.json (sequence {sequence}) for {}",
                plugin.plugin
            )?;
        }
    }
    Ok(())
}

fn generate(
    args: &GenerateArgs,
    env: &dyn Fn(&str) -> Option<String>,
    acquire: &dyn Fn(&Plugin) -> Result<Confirmed>,
) -> Result<Report> {
    // Everything that can be checked without the network is checked first, so a bad key or a
    // typo does not cost a long run of downloads.
    let validity = Validity::days(args.validity_days)?;
    let now = match &args.now {
        Some(text) => Timestamp::parse(text).ok_or_else(|| Error::Usage {
            message: format!("--now `{text}` is not a UTC time like 2026-10-19T03:00:00Z"),
        })?,
        None => Timestamp::now(),
    };
    let signer = load_signer(args, env)?;
    if signer.is_none() && !args.dry_run {
        return Err(Error::Usage {
            message: "a signing key is required: give --secret-key or --secret-key-env, or use \
                      --dry-run"
                .to_owned(),
        });
    }
    let previous_keys = args
        .previous_keys
        .iter()
        .map(|value| public_key(value))
        .collect::<Result<Vec<_>>>()?;
    // The previous publish is read only after the sources have been queried, so what can be
    // known about it now is checked now rather than after a long run of downloads.
    if let Some(dir) = &args.previous {
        if !dir.is_dir() {
            return Err(Error::Usage {
                message: format!("the previous publish {} is not a directory", dir.display()),
            });
        }
        if signer.is_none() && previous_keys.is_empty() {
            return Err(Error::Usage {
                message: "the previous publish can only be checked with a key: give the signing \
                          key or --previous-key"
                    .to_owned(),
            });
        }
    }
    let plugin = Plugin::load(&args.plugin_dir)?;

    let confirmed = match &args.use_confirmed {
        Some(path) => confirmed_file::parse(&plugin.binding.plugin, &read_confirmed(path)?)?,
        None => acquire(&plugin)?,
    };
    if let Some(path) = &args.write_confirmed {
        write_confirmed(path, &plugin.binding.plugin, &confirmed)?;
    }
    publish(&Request {
        binding: &plugin.binding,
        confirmed: &confirmed,
        previous_dir: args.previous.as_deref(),
        previous_keys: &previous_keys,
        out_dir: &args.out,
        signer: signer.as_ref(),
        settings: Settings { now, validity },
        dry_run: args.dry_run,
    })
}

/// Reads a confirmed file, refusing anything larger than the limit before reading it.
fn read_confirmed(path: &Path) -> Result<Vec<u8>> {
    let usage = |why: String| Error::Usage {
        message: format!("cannot read {}: {why}", path.display()),
    };
    let size = std::fs::metadata(path)
        .map_err(|e| usage(e.to_string()))?
        .len();
    if size > confirmed_file::MAX_CONFIRMED_FILE as u64 {
        return Err(usage(format!(
            "larger than {} bytes",
            confirmed_file::MAX_CONFIRMED_FILE
        )));
    }
    std::fs::read(path).map_err(|e| usage(e.to_string()))
}

/// Saves `confirmed` as a confirmed file, replacing the file atomically.
fn write_confirmed(path: &Path, plugin: &str, confirmed: &Confirmed) -> Result<()> {
    let text = confirmed_file::render(plugin, confirmed)?;
    let io = |source| Error::Output {
        path: path.to_path_buf(),
        source,
    };
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    jtm_security::trust::write_atomically(path, text.as_bytes()).map_err(|error| match error {
        jtm_security::Error::Io { path, source } => Error::Output { path, source },
        other => Error::Invalid {
            message: other.to_string(),
        },
    })
}

/// The signer, if a key was named. Neither the key nor the password is ever printed.
fn load_signer(
    args: &GenerateArgs,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Option<Signer>> {
    // A password has no line ending of its own; a file or a secret set with `echo` adds one.
    let password = match (&args.password_file, &args.password_env) {
        (Some(path), _) => Some(read_secret_file(path)?),
        (None, Some(name)) => Some(read_env(env, name)?),
        (None, None) => None,
    }
    .map(|password| password.trim_end_matches(['\n', '\r']).to_owned());
    let text = match (&args.secret_key, &args.secret_key_env) {
        (Some(path), _) => read_secret_file(path)?,
        (None, Some(name)) => read_env(env, name)?,
        (None, None) => {
            if password.is_some() {
                return Err(Error::Usage {
                    message: "a password was given without a key: add --secret-key or \
                              --secret-key-env"
                        .to_owned(),
                });
            }
            return Ok(None);
        }
    };
    Signer::from_secret_key(&text, password).map(Some)
}

fn read_env(env: &dyn Fn(&str) -> Option<String>, name: &str) -> Result<String> {
    env(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| Error::Usage {
            message: format!("the environment variable {name} is not set or is empty"),
        })
}

fn read_secret_file(path: &Path) -> Result<String> {
    let usage = |why: String| Error::Usage {
        message: format!("cannot read {}: {why}", path.display()),
    };
    let size = std::fs::metadata(path)
        .map_err(|e| usage(e.to_string()))?
        .len();
    if size > MAX_SECRET_FILE {
        return Err(usage(format!("larger than {MAX_SECRET_FILE} bytes")));
    }
    std::fs::read_to_string(path).map_err(|e| usage(e.to_string()))
}

/// A public key given as its `RW...` line or as a `.pub` file.
fn public_key(value: &str) -> Result<PublicKey> {
    let not_a_key = || Error::Usage {
        message: "--previous-key must be a minisign public key (RW...) or the path of a .pub \
                  file"
            .to_owned(),
    };
    if let Ok(key) = PublicKey::parse(value) {
        return Ok(key);
    }
    let path = Path::new(value);
    if !path.is_file() {
        return Err(not_a_key());
    }
    let text = read_secret_file(path)?;
    let line = text
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .ok_or_else(not_a_key)?;
    PublicKey::parse(line).map_err(|_| not_a_key())
}

/// The context for the sources: an HTTPS client, prefix rewrites and the GitHub token.
fn context(args: &GenerateArgs, env: &dyn Fn(&str) -> Option<String>) -> Result<Context> {
    let mut mirrors = BTreeMap::new();
    for mirror in &args.mirrors {
        let (from, to) = mirror
            .split_once('=')
            .filter(|(from, to)| !from.is_empty() && !to.is_empty())
            .ok_or_else(|| Error::Usage {
                message: format!("--mirror `{mirror}` must look like FROM=TO"),
            })?;
        mirrors.insert(from.to_owned(), to.to_owned());
    }
    let client = Client::new(ClientOptions::new(VERSION)).map_err(|error| Error::Fetch {
        source_id: "http client".to_owned(),
        error,
    })?;
    Ok(Context::new(client)
        .with_mirrors(mirrors)
        .with_github_token(env(GITHUB_TOKEN)))
}

// ---------------------------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------------------------

#[derive(Serialize)]
struct WarningOut<'a> {
    code: &'a str,
    message: &'a str,
    details: Map<String, Value>,
}

fn warnings_out(warnings: &[Warning]) -> Vec<WarningOut<'_>> {
    warnings
        .iter()
        .map(|w| WarningOut {
            code: w.code,
            message: &w.message,
            details: Map::new(),
        })
        .collect()
}

/// The envelope of a failure (SPEC.md section 12).
fn error_envelope(
    command: &str,
    code: ErrorCode,
    message: &str,
    details: Map<String, Value>,
) -> Value {
    json!({
        "ok": false,
        "command": command,
        "error": {
            "code": code.as_str(),
            "message": message,
            "retryable": code.retryable(),
            "details": details,
        },
        "jtm_version": VERSION,
    })
}

/// The envelope for a command line that does not parse, and the exit status that goes with it.
pub fn usage_failure(message: &str) -> (Value, u8) {
    (
        error_envelope("jtm-index", ErrorCode::Usage, message, Map::new()),
        ExitCode::Usage.as_u8(),
    )
}

/// Writes the result and returns the exit status.
fn render(
    json: bool,
    command: &str,
    result: &Result<Report>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    match result {
        Ok(report) => {
            let written = if json {
                let envelope = json!({
                    "ok": true,
                    "command": command,
                    // Whether the run changed anything on disk; a dry run never does.
                    "changed": report.changed && !report.dry_run,
                    "data": report,
                    "warnings": warnings_out(&report.warnings),
                    "jtm_version": VERSION,
                });
                writeln!(stdout, "{envelope}")
            } else {
                human(report, stdout, stderr)
            };
            // A closed pipe is the reader's business; the files are already written.
            let _ = written;
            ExitCode::Success.as_u8()
        }
        Err(error) => render_error(json, command, error, stdout, stderr),
    }
}

/// Writes a failure and returns the exit status that goes with it.
fn render_error(
    json: bool,
    command: &str,
    error: &Error,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> u8 {
    let code = error.code();
    if json {
        let mut details = Map::new();
        if let Error::Rejected { rejections } = error {
            details.insert(
                "rejections".to_owned(),
                rejections.iter().map(ToString::to_string).collect(),
            );
        }
        let envelope = error_envelope(command, code, &error.to_string(), details);
        let _ = writeln!(stdout, "{envelope}");
    } else {
        let _ = writeln!(stderr, "error[{}]: {error}", code.as_str());
    }
    code.exit_code().as_u8()
}

fn human(report: &Report, stdout: &mut dyn Write, stderr: &mut dyn Write) -> std::io::Result<()> {
    for warning in &report.warnings {
        writeln!(stderr, "warning[{}]: {}", warning.code, warning.message)?;
    }
    for file in &report.files {
        writeln!(
            stdout,
            "{} {} (sequence {}, {} entries, expires {})",
            file.action.as_str(),
            file.file,
            file.sequence,
            file.entries,
            file.expires
        )?;
    }
    if !report.changed {
        writeln!(stdout, "nothing to publish: every index is unchanged")?;
    } else if report.dry_run {
        writeln!(stdout, "dry run: nothing was written")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
