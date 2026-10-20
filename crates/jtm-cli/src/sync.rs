//! `jtm lock`.

use std::io::{self, Write};
use std::path::PathBuf;

use jtm_core::session::Session;
use jtm_core::sync::{LockItem, LockOptions, LockStatus, Upgrade};
use jtm_core::{Context, JtmError, Platform, Result};
use serde::Serialize;

use crate::output::{Human, Outcome};
use crate::tools::warnings;

#[derive(Debug, Serialize)]
pub(crate) struct LockData {
    file: PathBuf,
    dry_run: bool,
    tools: Vec<LockItem>,
}

impl Human for LockData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        for item in &self.tools {
            let status = match item.status {
                LockStatus::Kept => "kept",
                LockStatus::Added => "added",
                LockStatus::Updated => "updated",
                LockStatus::Removed => "removed",
            };
            writeln!(
                out,
                "{status} {}@{}:{} ({})",
                item.tool,
                item.variant,
                item.version,
                item.platforms.join(", ")
            )?;
        }
        let verb = if self.dry_run { "would write" } else { "wrote" };
        writeln!(out, "{verb} {}", self.file.display())
    }
}

pub(crate) fn lock(
    ctx: &Context,
    platforms: &[String],
    upgrade: Option<&str>,
    dry_run: bool,
) -> Result<Outcome<LockData>> {
    let platforms = if platforms.is_empty() {
        None
    } else {
        Some(
            platforms
                .iter()
                .map(|p| p.parse::<Platform>())
                .collect::<Result<Vec<_>>>()?,
        )
    };
    let upgrade = match upgrade {
        None => Upgrade::None,
        Some("") => Upgrade::All,
        Some(tool) => Upgrade::Tool(tool.to_owned()),
    };
    let session = Session::open(ctx)?;
    let cwd = std::env::current_dir().map_err(|e| JtmError::io(".", e))?;
    let report = session.lock(
        &cwd,
        &LockOptions {
            platforms,
            upgrade,
            dry_run,
        },
    )?;
    Ok(Outcome {
        command: "lock",
        changed: report.differs && !dry_run,
        data: LockData {
            file: report.file,
            dry_run,
            tools: report.tools,
        },
        warnings: warnings(report.warnings),
    })
}
