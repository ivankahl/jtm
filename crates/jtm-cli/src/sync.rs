//! `jtm lock` and `jtm sync`.

use std::io::{self, Write};
use std::path::PathBuf;

use jtm_core::install::Status;
use jtm_core::session::{InstallItem, Session};
use jtm_core::sync::{LockItem, LockOptions, LockStatus, SyncOptions, Upgrade};
use jtm_core::{Context, ExitCode, JtmError, Platform, Result};
use serde::Serialize;

use crate::output::{Human, Outcome};
use crate::tools::{Failure, InstallFailure, warnings};

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

#[derive(Debug, Serialize)]
pub(crate) struct SyncData {
    file: Option<PathBuf>,
    dry_run: bool,
    frozen: bool,
    lock: Vec<LockItem>,
    installed: Vec<InstallItem>,
    failed: Vec<Failure>,
}

impl Human for SyncData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        for item in &self.installed {
            let id = &item.version.id;
            match item.status {
                Status::Installed => writeln!(out, "installed {id}")?,
                Status::AlreadyInstalled => writeln!(out, "{id} is installed")?,
                Status::WouldInstall => writeln!(out, "would install {id}")?,
            }
        }
        for failure in &self.failed {
            failure.render_human(out)?;
        }
        Ok(())
    }
}

pub(crate) fn sync(
    ctx: &Context,
    dry_run: bool,
    frozen: bool,
) -> std::result::Result<(Outcome<SyncData>, ExitCode), InstallFailure> {
    let session = Session::open(ctx)?;
    let cwd = std::env::current_dir().map_err(|e| JtmError::io(".", e))?;
    let report = session.sync(&cwd, SyncOptions { dry_run, frozen })?;
    let mut found = report.warnings;
    let mut installed = Vec::new();
    let mut failed: Vec<(String, JtmError)> = Vec::new();
    for (tool, result) in report.results {
        match result {
            Ok((item, mut w)) => {
                found.append(&mut w);
                installed.push(item);
            }
            Err(err) => failed.push((tool, err)),
        }
    }
    let failures: Vec<Failure> = failed
        .iter()
        .map(|(tool, err)| Failure::new(tool.clone(), err))
        .collect();
    if installed.is_empty() && !failed.is_empty() {
        return Err(InstallFailure {
            error: failed.swap_remove(0).1,
            failed: failures,
        });
    }
    let code = if failures.is_empty() {
        ExitCode::Success
    } else {
        ExitCode::Partial
    };
    let changed = !dry_run && (report.lock_differs || installed.iter().any(|i| i.status.changed()));
    Ok((
        Outcome {
            command: "sync",
            changed,
            data: SyncData {
                file: report.file,
                dry_run,
                frozen,
                lock: report.lock,
                installed,
                failed: failures,
            },
            warnings: warnings(found),
        },
        code,
    ))
}
