//! Build helpers, run with `cargo xtask <task>`.
//!
//! - `check-tool-names`: fails when a library crate's source names a first-party tool (SPEC.md
//!   section 15: no line of core code may mention a specific tool).
//! - `embed-snapshot [--from <dir> | --clear]`: fills `crates/jtm-cli/snapshot/` with the
//!   latest signed first-party indices and `keys.json`, which release builds embed (SPEC.md
//!   section 8).

// A build helper reports to the terminal; there is no JSON mode to keep clean.
#![allow(clippy::print_stderr)]

mod snapshot;
mod tool_names;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask check-tool-names\n       \
                     cargo xtask embed-snapshot [--from <dir> | --clear]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["check-tool-names"] => tool_names::run(&root),
        ["embed-snapshot"] => embed_snapshot(&root, None),
        ["embed-snapshot", "--from", dir] => embed_snapshot(&root, Some(PathBuf::from(dir))),
        ["embed-snapshot", "--clear"] => {
            let out = root.join("crates/jtm-cli/snapshot");
            match snapshot::clear(&out) {
                Ok(()) => {
                    eprintln!("cleared the index snapshot in {}", out.display());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Embeds the snapshot from the manifests' URLs, or from the release directory `from`.
fn embed_snapshot(root: &Path, from: Option<PathBuf>) -> ExitCode {
    let client;
    let dir;
    let source: &dyn jtm_core::indices::Fetcher = match &from {
        Some(path) => {
            dir = snapshot::ReleaseDir(path);
            &dir
        }
        None => {
            match jtm_fetch::Client::new(jtm_fetch::ClientOptions::new(env!("CARGO_PKG_VERSION"))) {
                Ok(c) => {
                    client = c;
                    &client
                }
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            }
        }
    };
    let out = root.join("crates/jtm-cli/snapshot");
    let req = snapshot::Request {
        plugins: &root.join("crates/jtm-cli/plugins"),
        source,
        out: &out,
        now: jtm_security::Timestamp::now(),
    };
    match snapshot::embed(&req) {
        Ok(embedded) => {
            for warning in &embedded.warnings {
                eprintln!("warning: {warning}");
            }
            eprintln!(
                "embedded {} index files and {} keys files in {}",
                embedded.listing.indices.len(),
                embedded.listing.keys.len(),
                out.display()
            );
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
