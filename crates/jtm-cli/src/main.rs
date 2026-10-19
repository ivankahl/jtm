//! The `jtm` command-line interface.

mod logging;
mod output;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind;
use jtm_core::{ExitCode as JtmExitCode, JtmError};
use serde::Serialize;

use crate::output::{Format, Human, JTM_VERSION, Outcome, Renderer};

/// Runtime manager for the JVM ecosystem.
#[derive(Debug, Parser)]
#[command(
    name = "jtm",
    disable_version_flag = true,
    arg_required_else_help = true
)]
struct Cli {
    /// Print the jtm version.
    #[arg(short = 'V', long)]
    version: bool,

    /// Write one JSON envelope to stdout; logs go to stderr.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Debug, Serialize)]
struct VersionData {
    version: &'static str,
}

impl Human for VersionData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out, "jtm {}", self.version)
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();
    // Decide the format before parsing so that usage errors honour `--json` too.
    let format = if wants_json(&args) {
        Format::Json
    } else {
        Format::Human
    };
    logging::init(format);
    let mut renderer = Renderer::stdio(format);

    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(err) if format == Format::Human || is_informational(err.kind()) => {
            let _ = err.print();
            return ExitCode::from(err.exit_code().clamp(0, 255) as u8);
        }
        Err(err) => return fail(&mut renderer, "jtm", &usage_error(&err)),
    };

    if cli.version {
        let outcome = Outcome {
            command: "version",
            changed: false,
            data: VersionData {
                version: JTM_VERSION,
            },
            warnings: Vec::new(),
        };
        let _ = renderer.success(&outcome);
        return JtmExitCode::Success.into();
    }
    fail(
        &mut renderer,
        "jtm",
        &JtmError::usage("no command given; see `jtm --help`"),
    )
}

fn fail<O: Write, E: Write>(
    renderer: &mut Renderer<O, E>,
    command: &str,
    err: &JtmError,
) -> ExitCode {
    let _ = renderer.failure(command, err);
    err.exit_code().into()
}

/// Whether `--json` appears before any `--` separator.
fn wants_json(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "--json")
}

fn is_informational(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::DisplayHelp | ErrorKind::DisplayVersion)
}

fn usage_error(err: &clap::Error) -> JtmError {
    let rendered = err.render().to_string();
    let first_line = rendered.lines().next().unwrap_or_default();
    JtmError::usage(
        first_line
            .strip_prefix("error: ")
            .unwrap_or(first_line)
            .trim(),
    )
}
