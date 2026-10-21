//! `jtm pin`, `unpin`, `current`, `which` and `exec`.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use jtm_core::activate::Change;
use jtm_core::here::{CurrentItem, Here, WhichItem, find_on_path};
use jtm_core::lockfile::LOCK_FILE;
use jtm_core::pins::{PinWrite, remove_pins, write_pin};
use jtm_core::project::PROJECT_FILE;
use jtm_core::session::{EnsureOptions, Session};
use jtm_core::{Context, JtmError, Result, Selector, ToolSpec};
use serde::Serialize;

use crate::activate::{here, with_install_prompt};
use crate::output::{Human, Outcome};
use crate::tools::{warnings, warnings_with};

#[derive(Debug, Serialize)]
pub(crate) struct PinData {
    #[serde(flatten)]
    pin: PinWrite,
    dry_run: bool,
}

impl Human for PinData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        let p = &self.pin;
        let verb = match (self.dry_run, p.changed) {
            (_, false) => "already pins",
            (true, true) => "would pin",
            (false, true) => "pinned",
        };
        writeln!(out, "{} {verb} {} = {}", p.file.display(), p.tool, p.value)
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct UnpinData {
    tool: String,
    removed: Vec<PathBuf>,
}

impl Human for UnpinData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        if self.removed.is_empty() {
            return writeln!(out, "no pin for `{}` here", self.tool);
        }
        for file in &self.removed {
            writeln!(out, "removed `{}` from {}", self.tool, file.display())?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct CurrentData {
    tools: Vec<CurrentItem>,
}

impl Human for CurrentData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        for item in &self.tools {
            match (&item.layer, &item.version) {
                (None, _) => writeln!(out, "{}  not managed by jtm", item.tool)?,
                (Some(layer), Some(version)) => writeln!(
                    out,
                    "{}  {}:{version}  ({} from {})",
                    item.tool,
                    item.variant.as_deref().unwrap_or_default(),
                    layer.as_str(),
                    item.origin.as_deref().unwrap_or_default()
                )?,
                (Some(layer), None) => writeln!(
                    out,
                    "{}  {} is not installed  ({} from {})",
                    item.tool,
                    item.requested.as_deref().unwrap_or_default(),
                    layer.as_str(),
                    item.origin.as_deref().unwrap_or_default()
                )?,
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct WhichData {
    #[serde(flatten)]
    item: WhichItem,
}

impl Human for WhichData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        let item = &self.item;
        match (&item.tool, &item.layer) {
            (Some(tool), Some(layer)) => writeln!(
                out,
                "{}  ({tool} {}, {})",
                item.path,
                item.version.as_deref().unwrap_or_default(),
                layer.as_str()
            ),
            _ => writeln!(out, "{}  (not managed by jtm)", item.path),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ExecData {
    command: Vec<String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
}

impl Human for ExecData {
    fn render_human(&self, _out: &mut dyn Write) -> io::Result<()> {
        Ok(())
    }
}

fn cwd() -> Result<PathBuf> {
    std::env::current_dir().map_err(|e| JtmError::io(".", e))
}

pub(crate) fn pin(
    ctx: &Context,
    spec: &str,
    format: Option<&str>,
    exact: bool,
    dry_run: bool,
) -> Result<Outcome<PinData>> {
    let spec = ToolSpec::parse(spec)?;
    let session = Session::open(ctx)?;
    let plugin = session.plugin(&spec.tool)?;
    let selector = if exact {
        match session.installed_match(&plugin, spec.selector.as_ref())? {
            Some(found) => Selector {
                variant: Some(found.variant),
                value: found.version,
            },
            None => {
                let (entry, _) = session.resolve(&spec, &plugin, session.platform(), false)?;
                Selector {
                    variant: Some(entry.variant),
                    value: entry.version,
                }
            }
        }
    } else {
        spec.selector.clone().ok_or_else(|| {
            JtmError::usage(format!(
                "name a version, such as `jtm pin {0}@<version>`, or pass --exact to pin the \
                 version `{0}` resolves to",
                spec.tool
            ))
        })?
    };
    let format = format.map_or_else(
        || session.settings().pin.default_format.clone(),
        str::to_owned,
    );
    // The project's directory: the nearest with `.jtm.toml` or `jtm.lock`, so pinning from a
    // subdirectory does not start a nested project; otherwise the working directory.
    let cwd = cwd()?;
    let dir = cwd
        .ancestors()
        .find(|d| d.join(PROJECT_FILE).is_file() || d.join(LOCK_FILE).is_file())
        .unwrap_or(&cwd);
    let pin = write_pin(dir, &plugin, &format, &selector, dry_run)?;
    Ok(Outcome {
        command: "pin",
        changed: pin.changed && !dry_run,
        data: PinData { pin, dry_run },
        warnings: Vec::new(),
    })
}

pub(crate) fn unpin(ctx: &Context, tool: &str, format: Option<&str>) -> Result<Outcome<UnpinData>> {
    let session = Session::open(ctx)?;
    let here = here(&session)?;
    let plugin = here.plugin(tool)?;
    let removed = remove_pins(&here.pins, plugin, format, false)?;
    Ok(Outcome {
        command: "unpin",
        changed: !removed.is_empty(),
        data: UnpinData {
            tool: tool.to_owned(),
            removed,
        },
        warnings: Vec::new(),
    })
}

pub(crate) fn current(ctx: &Context, tool: Option<&str>) -> Result<Outcome<CurrentData>> {
    let session = Session::open(ctx)?;
    let here = here(&session)?;
    let (tools, unreadable) = here.current(tool)?;
    let mut found = here.warnings();
    found.extend(unreadable);
    found.extend(here.requirement_warnings(&[], &tools)?);
    Ok(Outcome {
        command: "current",
        changed: false,
        data: CurrentData { tools },
        warnings: warnings_with(found, &here.pins.conflicts),
    })
}

pub(crate) fn which(ctx: &Context, command: &str) -> Result<Outcome<WhichData>> {
    let session = Session::open(ctx)?;
    let here = here(&session)?;
    let path = std::env::var("PATH").ok();
    let item = here.which(command, session.platform().os(), path.as_deref())?;
    Ok(Outcome {
        command: "which",
        changed: false,
        data: WhichData { item },
        warnings: warnings_with(here.warnings(), &here.pins.conflicts),
    })
}

/// Runs `command` with `specs` applied, plus the session and project versions for every other
/// tool. With `--json` the output is captured into the envelope and jtm exits 0; otherwise the
/// command inherits the terminal and its exit code becomes jtm's.
pub(crate) fn exec(
    ctx: &Context,
    specs: &[String],
    command: &[String],
    install: bool,
    latest: bool,
) -> Result<(Outcome<ExecData>, i32)> {
    let specs = specs
        .iter()
        .map(|s| ToolSpec::parse(s))
        .collect::<Result<Vec<_>>>()?;
    let session = Session::open(ctx)?;
    let here = here(&session)?;
    let mut exec = Vec::new();
    for spec in &specs {
        let options = EnsureOptions {
            install: install || ctx.assume_yes,
            latest,
        };
        let (found, _, _) = with_install_prompt(ctx, spec, options, |options| {
            session.ensure_installed(spec, options, &mut |_| {})
        })?;
        exec.push((spec.tool.clone(), found));
    }
    let (overrides, mut found) = here.overrides(&exec)?;
    found.extend(here.requirement_warnings(&exec, &[])?);
    let changes = here.plan(&|key| std::env::var(key).ok(), &overrides);
    let mut child = build_command(&here, command, &changes)?;
    let outcome = |exit_code: i32, stdout: String, stderr: String| Outcome {
        command: "exec",
        changed: false,
        data: ExecData {
            command: command.to_vec(),
            exit_code,
            stdout,
            stderr,
        },
        warnings: warnings(found.clone()),
    };
    if ctx.json {
        let output = child
            .stdin(Stdio::null())
            .output()
            .map_err(|e| JtmError::io(&command[0], e))?;
        let code = exit_code(output.status);
        Ok((
            outcome(
                code,
                String::from_utf8_lossy(&output.stdout).into_owned(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            ),
            0,
        ))
    } else {
        // Nothing is rendered after the child runs, so warnings go to stderr first.
        let mut stderr = io::stderr().lock();
        for warning in warnings(found.clone()) {
            let _ = writeln!(stderr, "warning[{}]: {}", warning.code, warning.message);
        }
        drop(stderr);
        let status = child.status().map_err(|e| JtmError::io(&command[0], e))?;
        let code = exit_code(status);
        Ok((outcome(code, String::new(), String::new()), code))
    }
}

/// The exit code to pass on for a child's `status`: its own code, or for a child killed by a
/// signal, 128 plus the signal number as shells report it.
pub(crate) fn exit_code(status: std::process::ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    status.code().unwrap_or(1)
}

fn build_command(here: &Here<'_, '_>, command: &[String], changes: &[Change]) -> Result<Command> {
    let Some((program, args)) = command.split_first() else {
        return Err(JtmError::usage("name a command after `--`"));
    };
    let path = changes
        .iter()
        .find_map(|c| match c {
            Change::Set { name, value } if name == "PATH" => Some(value.clone()),
            _ => None,
        })
        .or_else(|| std::env::var("PATH").ok());
    let os = here.session.platform().os();
    // Look the program up on the new PATH, which the OS would not do for us.
    let resolved = if Path::new(program).components().count() > 1 {
        PathBuf::from(program)
    } else {
        find_on_path(program, path.as_deref(), os).ok_or_else(|| JtmError::ToolUnknown {
            tool: program.clone(),
        })?
    };
    let mut cmd = Command::new(resolved);
    cmd.args(args);
    for change in changes {
        match change {
            Change::Set { name, value } => {
                cmd.env(name, value);
            }
            Change::Unset { name } => {
                cmd.env_remove(name);
            }
        }
    }
    Ok(cmd)
}
