//! `jtm default`, `use`, `env` and `shell-init`.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;

use jtm_core::activate::{Change, plan_env, session_from_env};
use jtm_core::pins::{ProjectPins, discover};
use jtm_core::plugins::Plugin;
use jtm_core::session::{DefaultItem, EnsureOptions, PATH_SEPARATOR, Session, VersionItem};
use jtm_core::{Context, JtmError, Result, Selector, ToolSpec};
use serde::Serialize;

use crate::output::{Human, Outcome};
use crate::prompt::confirm;
use crate::shell::{self, Shell};
use crate::tools::warnings;

#[derive(Debug, Serialize)]
pub(crate) struct DefaultData {
    #[serde(flatten)]
    item: DefaultItem,
}

impl Human for DefaultData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        let item = &self.item;
        writeln!(
            out,
            "{} is the default; {} points at {}",
            item.version.id, item.link, item.home
        )
    }
}

pub(crate) fn default(
    ctx: &Context,
    spec: &str,
    install: bool,
    latest: bool,
) -> Result<Outcome<DefaultData>> {
    let spec = ToolSpec::parse(spec)?;
    let session = Session::open(ctx)?;
    let options = EnsureOptions {
        install: install || ctx.assume_yes,
        latest,
    };
    let (item, changed, found) = with_install_prompt(ctx, &spec, options, |options| {
        session.set_default(&spec, options, &mut |_| {})
    })?;
    Ok(Outcome {
        command: "default",
        changed,
        data: DefaultData { item },
        warnings: warnings(found),
    })
}

/// Runs `op`, and when it needs a missing version installed, asks and runs it again with
/// `install` set.
fn with_install_prompt<T>(
    ctx: &Context,
    spec: &ToolSpec,
    options: EnsureOptions,
    op: impl Fn(EnsureOptions) -> Result<T>,
) -> Result<T> {
    match op(options) {
        Err(JtmError::InputRequired { .. })
            if confirm(ctx, &format!("`{spec}` is not installed. Install it?"))? =>
        {
            op(EnsureOptions {
                install: true,
                ..options
            })
        }
        other => other,
    }
}

/// Shell code for a human, or the changes alone for `--json`.
#[derive(Debug, Serialize)]
pub(crate) struct EnvData {
    shell: Option<&'static str>,
    changes: Vec<Change>,
    #[serde(skip)]
    script: String,
}

impl Human for EnvData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        out.write_all(self.script.as_bytes())
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct UseData {
    tool: String,
    /// The version now in use; absent after `--unset`.
    #[serde(flatten)]
    version: Option<VersionItem>,
    unset: bool,
    #[serde(flatten)]
    env: EnvData,
}

impl Human for UseData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        self.env.render_human(out)
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ShellInitData {
    shell: &'static str,
    script: String,
}

impl Human for ShellInitData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        out.write_all(self.script.as_bytes())
    }
}

/// Everything activation reads from the process: plugins, pins and session versions.
struct Here<'s, 'c> {
    session: &'s Session<'c>,
    plugins: Vec<Plugin>,
    tools: Vec<String>,
    pins: ProjectPins,
    selected: BTreeMap<String, Selector>,
}

impl<'s, 'c> Here<'s, 'c> {
    fn read(session: &'s Session<'c>) -> Result<Here<'s, 'c>> {
        let plugins = session.plugins()?;
        let tools: Vec<String> = plugins.iter().map(|p| p.manifest.name.clone()).collect();
        let cwd = std::env::current_dir().map_err(|e| JtmError::io(".", e))?;
        let pins = discover(&cwd, &plugins)?;
        let selected = session_from_env(&tools, &|key| std::env::var_os(key))?;
        Ok(Here {
            session,
            plugins,
            tools,
            pins,
            selected,
        })
    }

    /// The changes that make the shell match the session and project choices, rendered for
    /// `shell`, and any warnings.
    fn env(&self, shell: Option<Shell>) -> Result<(EnvData, Vec<jtm_security::Warning>)> {
        let (overrides, found) =
            self.session
                .overrides(&self.selected, &self.pins, &self.plugins)?;
        let tools_dir = self.session.dirs().tools();
        let changes = plan_env(
            &|key| std::env::var(key).ok(),
            &overrides,
            &self.tools,
            &tools_dir,
            PATH_SEPARATOR,
        );
        let script = match shell {
            Some(shell) => shell::render(shell, &changes, PATH_SEPARATOR)?,
            None => String::new(),
        };
        Ok((
            EnvData {
                shell: shell.map(Shell::name),
                changes,
                script,
            },
            found,
        ))
    }
}

pub(crate) fn env(ctx: &Context, shell: Option<&str>) -> Result<Outcome<EnvData>> {
    let shell = match shell {
        Some(name) => Some(Shell::parse(name)?),
        None if ctx.json => None,
        None => Some(Shell::host_default()),
    };
    let session = Session::open(ctx)?;
    let here = Here::read(&session)?;
    let (data, found) = here.env(shell)?;
    Ok(Outcome {
        command: "env",
        changed: false,
        data,
        warnings: warnings(found),
    })
}

/// Options for [`use_version`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct UseOptions<'a> {
    pub(crate) unset: bool,
    pub(crate) install: bool,
    pub(crate) latest: bool,
    pub(crate) shell: Option<&'a str>,
}

pub(crate) fn use_version(
    ctx: &Context,
    spec: &str,
    options: UseOptions<'_>,
) -> Result<Outcome<UseData>> {
    let shell = options.shell.map(Shell::parse).transpose()?;
    if shell.is_none() && !ctx.json {
        return Err(JtmError::usage(
            "`jtm use` changes the current shell through the shell hook; add `eval \
             \"$(jtm shell-init bash)\"` (or zsh, fish, pwsh) to your shell's startup file, \
             or run a command with `jtm exec <spec> -- <command>`",
        ));
    }
    let spec = ToolSpec::parse(spec)?;
    let session = Session::open(ctx)?;
    let mut here = Here::read(&session)?;
    let version = if options.unset {
        if spec.selector.is_some() {
            return Err(JtmError::usage(format!(
                "`--unset` takes a tool name, such as `jtm use {} --unset`",
                spec.tool
            )));
        }
        session.plugin(&spec.tool)?;
        here.selected.remove(&spec.tool);
        None
    } else {
        let ensure = EnsureOptions {
            install: options.install || ctx.assume_yes,
            latest: options.latest,
        };
        let (found, _, _) = with_install_prompt(ctx, &spec, ensure, |ensure| {
            session.ensure_installed(&spec, ensure, &mut |_| {})
        })?;
        here.selected.insert(
            spec.tool.clone(),
            Selector {
                variant: Some(found.variant.clone()),
                value: found.version.clone(),
            },
        );
        Some(VersionItem {
            id: jtm_core::install::VersionId {
                tool: spec.tool.clone(),
                variant: found.variant,
                version: found.version,
            },
            path: found.dir.display().to_string(),
        })
    };
    let (env, found) = here.env(shell)?;
    Ok(Outcome {
        command: "use",
        changed: !env.changes.is_empty(),
        data: UseData {
            tool: spec.tool,
            version,
            unset: options.unset,
            env,
        },
        warnings: warnings(found),
    })
}

pub(crate) fn shell_init(shell: &str) -> Result<Outcome<ShellInitData>> {
    let shell = Shell::parse(shell)?;
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .unwrap_or_else(|| PathBuf::from("jtm"));
    let script = shell::init(shell, &exe.display().to_string())?;
    Ok(Outcome {
        command: "shell-init",
        changed: false,
        data: ShellInitData {
            shell: shell.name(),
            script,
        },
        warnings: Vec::new(),
    })
}
