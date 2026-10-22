//! Generates, signs and publishes jtm version indices. Runs in CI only.
//!
//! `keys build` and `keys verify` support the root key ceremony (`docs/key-ceremony.md`): they
//! assemble the unsigned first-party `keys.json` and check the signed result with the same
//! loader the client uses. They never sign and never see a secret key.

use std::io;
use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind;
use jtm_index::cli::{Cli, run, usage_failure};
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().collect();
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        // Usage errors honour `--json` even though parsing failed.
        Err(err) if wants_json(&args) && !is_informational(err.kind()) => {
            let (envelope, status) = usage_failure(err.render().to_string().trim());
            println!("{envelope}");
            return ExitCode::from(status);
        }
        Err(err) => {
            let _ = err.print();
            return ExitCode::from(u8::try_from(err.exit_code()).unwrap_or(2));
        }
    };

    let filter = match cli.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("warn")))
        .with_writer(io::stderr)
        .with_target(false)
        .without_time()
        .try_init();

    ExitCode::from(run(&cli, &mut io::stdout(), &mut io::stderr()))
}

fn wants_json(args: &[std::ffi::OsString]) -> bool {
    args.iter().any(|a| a == "--json")
}

fn is_informational(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::DisplayHelp | ErrorKind::DisplayVersion)
}
