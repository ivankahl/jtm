//! Build helpers, run with `cargo xtask <task>`.
//!
//! - `check-tool-names`: fails when a library crate's source names a first-party tool (SPEC.md
//!   section 15: no line of core code may mention a specific tool).

// A build helper reports to the terminal; there is no JSON mode to keep clean.
#![allow(clippy::print_stderr)]

mod tool_names;

use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let task = std::env::args().nth(1);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();
    match task.as_deref() {
        Some("check-tool-names") => tool_names::run(&root),
        _ => {
            eprintln!("usage: cargo xtask check-tool-names");
            ExitCode::from(2)
        }
    }
}
