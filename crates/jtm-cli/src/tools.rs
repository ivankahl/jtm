//! `jtm install`, `uninstall`, `list` and `available`.

use std::io::{self, Write};
use std::sync::Mutex;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use jtm_core::install::{Progress, Status};
use jtm_core::session::{
    Available, AvailableOptions, InstallItem, InstallOptions, InstalledItem, Session,
    UninstallOptions, VersionItem,
};
use jtm_core::{Context, ExitCode, JtmError, Result, ToolSpec, Verbosity};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::output::{Human, Outcome, Warning};

#[derive(Debug, Serialize)]
pub(crate) struct Failure {
    spec: String,
    code: &'static str,
    message: String,
    details: Map<String, Value>,
}

impl Failure {
    fn new(spec: String, err: &JtmError) -> Failure {
        Failure {
            spec,
            code: err.code(),
            message: err.to_string(),
            details: err.details(),
        }
    }
}

/// Every spec of an install failed: the first error, and all of them for `details.failed`.
#[derive(Debug)]
pub(crate) struct InstallFailure {
    pub(crate) error: JtmError,
    pub(crate) failed: Vec<Failure>,
}

impl From<JtmError> for InstallFailure {
    fn from(error: JtmError) -> Self {
        InstallFailure {
            error,
            failed: Vec::new(),
        }
    }
}

impl InstallFailure {
    /// Extra error details: every failure, when there was more than one spec.
    pub(crate) fn details(&self) -> Map<String, Value> {
        let mut details = Map::new();
        if self.failed.len() > 1 {
            details.insert(
                "failed".to_owned(),
                serde_json::to_value(&self.failed).unwrap_or_default(),
            );
        }
        details
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct InstallData {
    dry_run: bool,
    installed: Vec<InstallItem>,
    failed: Vec<Failure>,
}

impl Human for InstallData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        for item in &self.installed {
            let (id, path) = (&item.version.id, &item.version.path);
            let cached = if item.cached { ", cached" } else { "" };
            match item.status {
                Status::Installed => writeln!(out, "installed {id} in {path}")?,
                Status::AlreadyInstalled => writeln!(out, "{id} is already installed in {path}")?,
                Status::WouldInstall => writeln!(
                    out,
                    "would install {id} from {} ({} bytes{cached})",
                    item.url, item.size
                )?,
                Status::Downloaded => {
                    writeln!(out, "downloaded {id} for {} to {path}", item.platform)?;
                }
                Status::AlreadyDownloaded => writeln!(
                    out,
                    "{id} for {} is already downloaded to {path}",
                    item.platform
                )?,
                Status::WouldDownload => writeln!(
                    out,
                    "would download {id} for {} from {} ({} bytes)",
                    item.platform, item.url, item.size
                )?,
            }
        }
        for failure in &self.failed {
            writeln!(
                out,
                "failed {}: [{}] {}",
                failure.spec, failure.code, failure.message
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct UninstallData {
    dry_run: bool,
    removed: Vec<VersionItem>,
}

impl Human for UninstallData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        let verb = if self.dry_run {
            "would remove"
        } else {
            "removed"
        };
        for v in &self.removed {
            writeln!(out, "{verb} {} from {}", v.id, v.path)?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ListData {
    installed: Vec<InstalledItem>,
}

impl Human for ListData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        if self.installed.is_empty() {
            return writeln!(
                out,
                "nothing is installed; install a version with `jtm install <spec>`"
            );
        }
        for item in &self.installed {
            writeln!(out, "{}  {}", item.version.id, item.version.path)?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct AvailableData {
    #[serde(flatten)]
    available: Available,
}

impl Human for AvailableData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        let a = &self.available;
        if a.versions.is_empty() {
            return writeln!(
                out,
                "no matching version of `{}` for {}",
                a.tool, a.platform
            );
        }
        for item in &a.versions {
            let mut line = format!("{}:{}", item.variant, item.version);
            let aliases: Vec<&str> = a
                .aliases
                .iter()
                .filter(|(_, version)| **version == item.version)
                .map(|(name, _)| name.as_str())
                .collect();
            if !item.tags.is_empty() {
                line.push_str(&format!("  [{}]", item.tags.join(", ")));
            }
            if !aliases.is_empty() {
                line.push_str(&format!("  ({})", aliases.join(", ")));
            }
            if item.installed {
                line.push_str("  installed");
            }
            writeln!(out, "{line}")?;
        }
        Ok(())
    }
}

/// Reports install progress: newline-delimited JSON events on stderr with `--json
/// --progress`, progress bars on a terminal, or nothing.
struct Reporter {
    tools: Vec<String>,
    mode: Mode,
}

enum Mode {
    Quiet,
    Events(Mutex<Vec<Option<u64>>>),
    Bars(MultiProgress, Mutex<Vec<Option<ProgressBar>>>),
}

impl Reporter {
    fn new(ctx: &Context, specs: &[ToolSpec]) -> Reporter {
        let mode = if ctx.progress {
            Mode::Events(Mutex::new(vec![None; specs.len()]))
        } else if !ctx.json && ctx.interactive && ctx.verbosity != Verbosity::Quiet {
            Mode::Bars(MultiProgress::new(), Mutex::new(vec![None; specs.len()]))
        } else {
            Mode::Quiet
        };
        Reporter {
            tools: specs.iter().map(|s| s.tool.clone()).collect(),
            mode,
        }
    }

    fn emit(&self, event: &str, mut fields: Value) {
        if !matches!(self.mode, Mode::Events(_)) {
            return;
        }
        if let Value::Object(map) = &mut fields {
            map.insert("event".to_owned(), event.into());
        }
        let mut stderr = io::stderr().lock();
        let _ = serde_json::to_writer(&mut stderr, &fields);
        let _ = writeln!(stderr);
    }

    fn progress(&self, i: usize, progress: Progress) {
        let tool = &self.tools[i];
        match &self.mode {
            Mode::Quiet => {}
            Mode::Events(last) => match progress {
                Progress::Download { done, total } => {
                    // At most one event per percent, plus the first and last.
                    let percent = done.saturating_mul(100).checked_div(total).unwrap_or(100);
                    let Ok(mut last) = last.lock() else { return };
                    if last[i] == Some(percent) {
                        return;
                    }
                    last[i] = Some(percent);
                    drop(last);
                    self.emit(
                        "download_progress",
                        json!({ "tool": tool, "done": done, "total": total }),
                    );
                }
                Progress::Verified => self.emit("verified", json!({ "tool": tool })),
                Progress::Extracted => self.emit("extracted", json!({ "tool": tool })),
            },
            Mode::Bars(multi, bars) => {
                let Ok(mut bars) = bars.lock() else { return };
                let bar = bars[i].get_or_insert_with(|| {
                    let bar = multi.add(ProgressBar::new(0));
                    bar.set_style(
                        ProgressStyle::with_template(
                            "{prefix:>12} {bar:30} {bytes}/{total_bytes} {msg}",
                        )
                        .unwrap_or_else(|_| ProgressStyle::default_bar()),
                    );
                    bar.set_prefix(tool.clone());
                    bar
                });
                match progress {
                    Progress::Download { done, total } => {
                        bar.set_length(total);
                        bar.set_position(done);
                    }
                    Progress::Verified => bar.set_message("verified, extracting"),
                    Progress::Extracted => bar.finish_with_message("extracted"),
                }
            }
        }
    }

    fn finish(&self) {
        if let Mode::Bars(multi, _) = &self.mode {
            let _ = multi.clear();
        }
    }
}

fn warnings(found: Vec<jtm_security::Warning>) -> Vec<Warning> {
    let mut out: Vec<Warning> = Vec::new();
    for w in found {
        if !out
            .iter()
            .any(|o| o.code == w.code && o.message == w.message)
        {
            out.push(Warning {
                code: w.code,
                message: w.message,
                details: Map::new(),
            });
        }
    }
    out
}

pub(crate) fn install(
    ctx: &Context,
    specs: &[String],
    options: InstallOptions,
) -> std::result::Result<(Outcome<InstallData>, ExitCode), InstallFailure> {
    let parsed = specs
        .iter()
        .map(|s| ToolSpec::parse(s))
        .collect::<Result<Vec<_>>>()?;
    let session = Session::open(ctx)?;
    let reporter = Reporter::new(ctx, &parsed);
    for (text, spec) in specs.iter().zip(&parsed) {
        reporter.emit("resolve", json!({ "tool": spec.tool, "spec": text }));
    }
    let results = session.install_all(&parsed, options, &|i, p| reporter.progress(i, p));
    reporter.finish();

    let mut installed = Vec::new();
    let mut failed: Vec<(String, JtmError)> = Vec::new();
    let mut found_warnings = Vec::new();
    for (text, result) in specs.iter().zip(results) {
        match result {
            Ok((item, mut w)) => {
                reporter.emit(
                    "installed",
                    json!({
                        "tool": item.version.id.tool,
                        "variant": item.version.id.variant,
                        "version": item.version.id.version,
                        "status": item.status,
                    }),
                );
                found_warnings.append(&mut w);
                installed.push(item);
            }
            Err(err) => failed.push((text.clone(), err)),
        }
    }
    let failures: Vec<Failure> = failed
        .iter()
        .map(|(spec, err)| Failure::new(spec.clone(), err))
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
    let changed = installed.iter().any(|i| i.status.changed());
    Ok((
        Outcome {
            command: "install",
            changed,
            data: InstallData {
                dry_run: options.dry_run,
                installed,
                failed: failures,
            },
            warnings: warnings(found_warnings),
        },
        code,
    ))
}

pub(crate) fn uninstall(
    ctx: &Context,
    spec: &str,
    options: UninstallOptions,
) -> Result<Outcome<UninstallData>> {
    let spec = ToolSpec::parse(spec)?;
    let session = Session::open(ctx)?;
    let (removed, found_warnings) = session.uninstall(&spec, options)?;
    Ok(Outcome {
        command: "uninstall",
        changed: !options.dry_run && !removed.is_empty(),
        data: UninstallData {
            dry_run: options.dry_run,
            removed,
        },
        warnings: warnings(found_warnings),
    })
}

pub(crate) fn list(ctx: &Context, tool: Option<&str>) -> Result<Outcome<ListData>> {
    if let Some(tool) = tool {
        tool_name(tool)?;
    }
    let session = Session::open(ctx)?;
    Ok(Outcome {
        command: "list",
        changed: false,
        data: ListData {
            installed: session.list(tool)?,
        },
        warnings: Vec::new(),
    })
}

pub(crate) fn available(
    ctx: &Context,
    tool: &str,
    options: &AvailableOptions,
) -> Result<Outcome<AvailableData>> {
    tool_name(tool)?;
    let session = Session::open(ctx)?;
    let (available, found_warnings) = session.available(tool, options)?;
    Ok(Outcome {
        command: "available",
        changed: false,
        data: AvailableData { available },
        warnings: warnings(found_warnings),
    })
}

/// Checks a bare tool name, refusing a version after `@`.
fn tool_name(tool: &str) -> Result<()> {
    if ToolSpec::parse(tool)?.selector.is_some() {
        return Err(JtmError::usage(format!(
            "`{tool}` names a version; give only the tool name"
        )));
    }
    Ok(())
}
