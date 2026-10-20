//! Confirmation prompts. jtm only asks when [`Context::interactive`] is set, which is never
//! true under `--json`, `--no-input`, `CI` or without a terminal.

use std::io::{self, BufRead, Write};

use jtm_core::{Context, JtmError, Result};

/// Asks `question` on stderr and reads a yes or no from stdin. `--yes` answers yes without
/// asking; without a terminal the answer is no.
pub(crate) fn confirm(ctx: &Context, question: &str) -> Result<bool> {
    if ctx.assume_yes {
        return Ok(true);
    }
    if !ctx.interactive {
        return Ok(false);
    }
    let mut stderr = io::stderr().lock();
    write!(stderr, "{question} [y/N] ").map_err(|e| JtmError::io("stderr", e))?;
    stderr.flush().map_err(|e| JtmError::io("stderr", e))?;
    let mut answer = String::new();
    io::stdin()
        .lock()
        .read_line(&mut answer)
        .map_err(|e| JtmError::io("stdin", e))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
