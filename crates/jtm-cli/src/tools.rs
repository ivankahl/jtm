//! `jtm install`, `uninstall`, `list` and `available`.

use std::io::{self, Write};

use jtm_core::install::Progress;
use jtm_core::session::{
    Available, AvailableOptions, InstallItem, InstallOptions, InstalledItem, Session, VersionItem,
};
use jtm_core::{Context, ExitCode, JtmError, Result, ToolSpec};
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

#[derive(Debug, Serialize)]
pub(crate) struct InstallData {
    dry_run: bool,
    installed: Vec<InstallItem>,
    failed: Vec<Failure>,
}

impl Human for InstallData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        for item in &self.installed {
            let v = &item.version;
            let name = format!("{}@{}:{}", v.tool, v.variant, v.version);
            match item.status {
                "installed" => writeln!(out, "installed {name} in {}", v.path)?,
                "already_installed" => writeln!(out, "{name} is already installed in {}", v.path)?,
                _ => writeln!(
                    out,
                    "would install {name} from {} ({} bytes{})",
                    item.url,
                    item.size,
                    if item.cached { ", cached" } else { "" }
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
            writeln!(
                out,
                "{verb} {}@{}:{} from {}",
                v.tool, v.variant, v.version, v.path
            )?;
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
            let v = &item.version;
            writeln!(out, "{}@{}:{}  {}", v.tool, v.variant, v.version, v.path)?;
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

/// Writes `--json --progress` events, one JSON object per line, to stderr.
struct Events {
    enabled: bool,
    last_percent: Option<u64>,
}

impl Events {
    fn emit(&mut self, event: &str, mut fields: Value) {
        if !self.enabled {
            return;
        }
        if let Value::Object(map) = &mut fields {
            map.insert("event".to_owned(), event.into());
        }
        let mut stderr = io::stderr().lock();
        let _ = serde_json::to_writer(&mut stderr, &fields);
        let _ = writeln!(stderr);
    }

    fn progress(&mut self, tool: &str, progress: Progress) {
        match progress {
            Progress::Download { done, total } => {
                // At most one event per percent, plus the first and last.
                let percent = done.saturating_mul(100).checked_div(total).unwrap_or(100);
                if self.last_percent == Some(percent) {
                    return;
                }
                self.last_percent = Some(percent);
                self.emit(
                    "download_progress",
                    json!({ "tool": tool, "done": done, "total": total }),
                );
            }
            Progress::Verified => self.emit("verified", json!({ "tool": tool })),
            Progress::Extracted => self.emit("extracted", json!({ "tool": tool })),
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
) -> Result<(Outcome<InstallData>, ExitCode)> {
    let parsed = specs
        .iter()
        .map(|s| ToolSpec::parse(s))
        .collect::<Result<Vec<_>>>()?;
    let session = Session::open(ctx)?;
    let mut events = Events {
        enabled: ctx.progress,
        last_percent: None,
    };
    let mut installed = Vec::new();
    let mut failed: Vec<(String, JtmError)> = Vec::new();
    let mut found_warnings = Vec::new();
    for (text, spec) in specs.iter().zip(&parsed) {
        events.emit("resolve", json!({ "tool": spec.tool, "spec": text }));
        events.last_percent = None;
        let result = session.install(spec, options, &mut |p| events.progress(&spec.tool, p));
        match result {
            Ok((item, mut w)) => {
                events.emit(
                    "installed",
                    json!({
                        "tool": item.version.tool,
                        "variant": item.version.variant,
                        "version": item.version.version,
                        "status": item.status,
                    }),
                );
                found_warnings.append(&mut w);
                installed.push(item);
            }
            Err(err) => failed.push((text.clone(), err)),
        }
    }
    if installed.is_empty() && !failed.is_empty() {
        return Err(failed.swap_remove(0).1);
    }
    let code = if failed.is_empty() {
        ExitCode::Success
    } else {
        ExitCode::Partial
    };
    let changed = installed.iter().any(|i| i.status == "installed");
    Ok((
        Outcome {
            command: "install",
            changed,
            data: InstallData {
                dry_run: options.dry_run,
                installed,
                failed: failed
                    .into_iter()
                    .map(|(spec, err)| Failure {
                        spec,
                        code: err.code(),
                        message: err.to_string(),
                        details: err.details(),
                    })
                    .collect(),
            },
            warnings: warnings(found_warnings),
        },
        code,
    ))
}

pub(crate) fn uninstall(
    ctx: &Context,
    spec: &str,
    all_variants: bool,
    dry_run: bool,
) -> Result<Outcome<UninstallData>> {
    let spec = ToolSpec::parse(spec)?;
    let session = Session::open(ctx)?;
    let (removed, found_warnings) = session.uninstall(&spec, all_variants, dry_run)?;
    Ok(Outcome {
        command: "uninstall",
        changed: !dry_run && !removed.is_empty(),
        data: UninstallData { dry_run, removed },
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
