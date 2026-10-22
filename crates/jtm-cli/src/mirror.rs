//! `jtm mirror export`.

use std::io::{self, Write};
use std::path::PathBuf;

use jtm_core::export::{ExportOptions, ExportedFile, FileKind, FileStatus};
use jtm_core::session::Session;
use jtm_core::{Context, Platform, Result};
use serde::Serialize;
use std::collections::BTreeMap;

use crate::output::{Human, Outcome};
use crate::tools::warnings;

/// The flags of `jtm mirror export`.
#[derive(Debug)]
pub(crate) struct ExportArgs {
    pub(crate) dir: PathBuf,
    pub(crate) plugins: Vec<String>,
    pub(crate) platforms: Vec<String>,
    pub(crate) artifacts: bool,
    pub(crate) dry_run: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct ExportData {
    dir: PathBuf,
    dry_run: bool,
    artifacts: bool,
    files: Vec<ExportedFile>,
    /// `[mirrors]` entries that serve the export.
    mirrors: BTreeMap<String, String>,
}

impl Human for ExportData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        let count = |status: FileStatus| self.files.iter().filter(|f| f.status == status).count();
        let artifacts = self
            .files
            .iter()
            .filter(|f| f.kind == FileKind::Artifact)
            .count();
        let (written, unchanged, would) = (
            count(FileStatus::Written),
            count(FileStatus::Unchanged),
            count(FileStatus::WouldWrite),
        );
        if self.dry_run {
            writeln!(
                out,
                "would export {would} of {} files ({artifacts} archives) to {}; {unchanged} are \
                 already there",
                self.files.len(),
                self.dir.display()
            )?;
        } else {
            writeln!(
                out,
                "exported {written} files to {} ({unchanged} already there, {artifacts} \
                 archives)",
                self.dir.display()
            )?;
        }
        if !self.mirrors.is_empty() {
            writeln!(
                out,
                "\nTo use it, add this to your jtm config:\n\n[mirrors]"
            )?;
            for (prefix, target) in &self.mirrors {
                writeln!(out, "\"{prefix}\" = \"{target}\"")?;
            }
        }
        Ok(())
    }
}

pub(crate) fn export(ctx: &Context, args: ExportArgs) -> Result<Outcome<ExportData>> {
    let platforms = args
        .platforms
        .iter()
        .map(|p| p.parse::<Platform>())
        .collect::<Result<Vec<_>>>()?;
    let session = Session::open(ctx)?;
    let report = session.export_mirror(&ExportOptions {
        dir: args.dir,
        plugins: args.plugins,
        platforms,
        artifacts: args.artifacts,
        dry_run: args.dry_run,
    })?;
    Ok(Outcome {
        command: "mirror export",
        changed: report.changed(),
        data: ExportData {
            dir: report.dir,
            dry_run: args.dry_run,
            artifacts: args.artifacts,
            files: report.files,
            mirrors: report.mirrors,
        },
        warnings: warnings(report.warnings),
    })
}

#[cfg(test)]
mod tests;
