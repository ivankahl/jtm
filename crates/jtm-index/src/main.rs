//! Generates, signs and publishes jtm version indices. Runs in CI only.
//!
//! `keys build` and `keys verify` support the root key ceremony (`docs/key-ceremony.md`): they
//! assemble the unsigned first-party `keys.json` and check the signed result with the same
//! loader the client uses. They never sign and never see a secret key.

// A CI tool reports to the terminal; errors go to stderr and `--json` keeps stdout to one object.
#![allow(clippy::print_stderr)]

mod keys_file;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use jtm_security::Timestamp;

use keys_file::{BuildSpec, Failure, VerifySpec};

#[derive(Debug, Parser)]
#[command(name = "jtm-index", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// The first-party `keys.json` and the root key ceremony.
    #[command(subcommand)]
    Keys(KeysCommand),
}

#[derive(Debug, Subcommand)]
enum KeysCommand {
    /// Write the unsigned `keys.json` that the root key holders sign offline.
    Build(BuildArgs),
    /// Check a signed `keys.json` with the client's loader, against the first-party manifests.
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
struct Common {
    /// Directory holding the first-party `<plugin>/plugin.toml` manifests.
    #[arg(long, default_value = "crates/jtm-cli/plugins")]
    plugins: PathBuf,
    /// The sequence of the `keys.json` published now; the new file must exceed it.
    #[arg(long)]
    previous_sequence: Option<u64>,
    /// Act as if it were this UTC time (`2026-10-19T03:00:00Z`) instead of now.
    #[arg(long, value_parser = parse_time)]
    now: Option<Timestamp>,
    /// Print one JSON object on stdout instead of text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct BuildArgs {
    /// Sequence of the new file; at least 1 and higher than the published one.
    #[arg(long)]
    sequence: u64,
    /// How many of the listed index keys must sign each index.
    #[arg(long, default_value_t = 1)]
    threshold: u32,
    /// An index key and its expiry, `RW...@2027-01-17T00:00:00Z`. Repeat during an overlap.
    #[arg(long = "index-key", required = true, value_name = "KEY@EXPIRES", value_parser = parse_index_key)]
    index_keys: Vec<(String, Timestamp)>,
    /// Plugins the keys may sign for, comma-separated. Default: every first-party plugin.
    #[arg(long, value_delimiter = ',')]
    scope: Option<Vec<String>>,
    /// Where to write the unsigned file.
    #[arg(long, default_value = "keys.json")]
    out: PathBuf,
    #[command(flatten)]
    common: Common,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// The signed file.
    #[arg(long, default_value = "keys.json")]
    file: PathBuf,
    /// Its signatures. Default: the file name plus `.minisig`.
    #[arg(long)]
    sig: Option<PathBuf>,
    /// Check against these root keys instead of the manifests', such as the new roots of a
    /// rotation or throwaway keys in a rehearsal. Repeat for each key.
    #[arg(long = "root-key", requires = "root_threshold")]
    root_keys: Vec<String>,
    /// How many of the `--root-key` keys must sign.
    #[arg(long, requires = "root_keys")]
    root_threshold: Option<u32>,
    #[command(flatten)]
    common: Common,
}

fn parse_time(text: &str) -> Result<Timestamp, String> {
    Timestamp::parse(text)
        .ok_or_else(|| format!("`{text}` is not a UTC time like 2026-10-19T03:00:00Z"))
}

fn parse_index_key(text: &str) -> Result<(String, Timestamp), String> {
    let (key, expires) = text
        .split_once('@')
        .ok_or("expected KEY@EXPIRES, like RW...@2027-01-17T00:00:00Z")?;
    Ok((key.to_owned(), parse_time(expires)?))
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Command::Keys(command) = cli.command;
    let (json, result) = match command {
        KeysCommand::Build(args) => (args.common.json, build(&args)),
        KeysCommand::Verify(args) => (args.common.json, verify(&args)),
    };
    match result {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(failure) => {
            if json {
                let error = serde_json::json!({
                    "ok": false,
                    "error": { "code": failure.code(), "message": failure.to_string() },
                });
                println!("{error}");
            }
            eprintln!("error: {failure}");
            ExitCode::from(failure.exit_code())
        }
    }
}

fn now(common: &Common) -> Timestamp {
    common.now.unwrap_or_else(Timestamp::now)
}

fn read(path: &Path) -> Result<Vec<u8>, Failure> {
    std::fs::read(path).map_err(|e| Failure::Io(format!("cannot read {}: {e}", path.display())))
}

fn build(args: &BuildArgs) -> Result<String, Failure> {
    let first_party = keys_file::load_first_party(&args.common.plugins)?;
    let spec = BuildSpec {
        sequence: args.sequence,
        threshold: args.threshold,
        keys: args.index_keys.clone(),
        scope: args.scope.clone(),
        previous_sequence: args.common.previous_sequence,
    };
    let bytes = keys_file::build(&spec, &first_party, now(&args.common))?;
    std::fs::write(&args.out, &bytes)
        .map_err(|e| Failure::Io(format!("cannot write {}: {e}", args.out.display())))?;
    let sha256 = jtm_security::sha256_hex(&bytes);
    if args.common.json {
        return Ok(serde_json::json!({
            "ok": true,
            "file": args.out,
            "sequence": args.sequence,
            "keys": args.index_keys.len(),
            "sha256": sha256,
        })
        .to_string());
    }
    Ok(format!(
        "wrote {} (sequence {}, {} index key(s), sha256 {sha256})\n\
         sign it offline with {} root keys, then run `jtm-index keys verify`",
        args.out.display(),
        args.sequence,
        args.index_keys.len(),
        first_party.first().map_or(0, |f| f.threshold),
    ))
}

fn verify(args: &VerifyArgs) -> Result<String, Failure> {
    let first_party = keys_file::load_first_party(&args.common.plugins)?;
    let sig_path = args.sig.clone().unwrap_or_else(|| {
        let mut name = args.file.clone().into_os_string();
        name.push(".minisig");
        PathBuf::from(name)
    });
    let data = read(&args.file)?;
    let signatures = read(&sig_path)?;
    let mut spec = VerifySpec::new(first_party);
    if let Some(threshold) = args.root_threshold {
        spec.roots = Some((args.root_keys.clone(), threshold));
    }
    spec.previous_sequence = args.common.previous_sequence;
    let report = keys_file::verify(&data, &signatures, &spec, now(&args.common))?;

    if args.common.json {
        let mut value = serde_json::to_value(&report)
            .map_err(|e| Failure::Io(format!("cannot encode the report: {e}")))?;
        value["ok"] = true.into();
        return Ok(value.to_string());
    }
    let mut out = format!(
        "{} verifies for {} first-party plugins ({}), signed by root key(s) {}\n\
         sequence {}, threshold {}, sha256 {}",
        args.file.display(),
        report.plugins.len(),
        report.plugins.join(", "),
        report.signers.join(", "),
        report.sequence,
        report.threshold,
        report.sha256,
    );
    for key in &report.keys {
        out.push_str(&format!(
            "\nindex key {} ({}): scope {}, expires {} ({} days left)",
            key.id,
            key.key,
            key.scope.join(","),
            key.expires,
            key.days_left
        ));
    }
    for warning in &report.warnings {
        out.push_str(&format!("\nwarning: {warning}"));
    }
    Ok(out)
}
