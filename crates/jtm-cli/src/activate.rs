//! `jtm default`, `use`, `env` and `shell-init`.

use std::io::{self, Write};

use jtm_core::activate::Change;
use jtm_core::here::Here;
use jtm_core::session::{DefaultItem, EnsureOptions, PATH_SEPARATOR, Session, VersionItem};
use jtm_core::{Context, JtmError, Result, Selector, ToolSpec};
use serde::Serialize;

use crate::output::{Human, Outcome};
use crate::prompt::confirm;
use crate::shell::{self, Shell};
use crate::tools::{warnings, warnings_with};

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
    // Keep the user environment `jtm self setup` set up in step with the defaults.
    crate::setup::refresh(&session)?;
    Ok(Outcome {
        command: "default",
        changed,
        data: DefaultData { item },
        warnings: warnings(found),
    })
}

/// Runs `op`, and when it needs a missing version installed, asks and runs it again with
/// `install` set.
pub(crate) fn with_install_prompt<T>(
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

/// The changes that make this shell match the session and project choices in `here`,
/// rendered for `shell`, and any warnings.
pub(crate) fn env_data(
    here: &Here<'_, '_>,
    shell: Option<Shell>,
) -> Result<(EnvData, Vec<jtm_security::Warning>)> {
    let (overrides, found) = here.overrides(&[])?;
    let changes = here.plan(&|key| std::env::var(key).ok(), &overrides);
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

/// Reads the activation context for the working directory and process environment.
pub(crate) fn here<'s, 'c>(session: &'s Session<'c>) -> Result<Here<'s, 'c>> {
    let cwd = std::env::current_dir().map_err(|e| JtmError::io(".", e))?;
    Here::read(session, &cwd, &|key| std::env::var_os(key))
}

pub(crate) fn env(ctx: &Context, shell: Option<&str>) -> Result<Outcome<EnvData>> {
    let shell = match shell {
        Some(name) => Some(Shell::parse(name)?),
        None if ctx.json => None,
        None => Some(Shell::host_default()),
    };
    let session = Session::open(ctx)?;
    let here = here(&session)?;
    let (data, mut found) = env_data(&here, shell)?;
    found.extend(here.requirement_warnings(&[]));
    Ok(Outcome {
        command: "env",
        changed: false,
        data,
        warnings: warnings_with(found, &here.pins.conflicts),
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
    let mut here = here(&session)?;
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
    let (env, mut found) = env_data(&here, shell)?;
    found.extend(here.requirement_warnings(&[]));
    Ok(Outcome {
        command: "use",
        changed: !env.changes.is_empty(),
        data: UseData {
            tool: spec.tool,
            version,
            unset: options.unset,
            env,
        },
        warnings: warnings_with(found, &here.pins.conflicts),
    })
}

pub(crate) fn shell_init(shell: &str) -> Result<Outcome<ShellInitData>> {
    let shell = Shell::parse(shell)?;
    let script = shell::init(shell, &shell::jtm_exe())?;
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

/// The variable the hook keeps the last directory in, to notice directory changes.
const HOOK_DIR_VAR: &str = "JTM_HOOK_DIR";

/// The shell hook's work on every prompt (SPEC.md section 5): apply the project pins of the
/// working directory and undo those of the last one. On a directory change, a session version
/// of a tool the new directory pins is dropped, so the pin takes over. Prints nothing when
/// nothing changes; warnings are shown only on a directory change.
pub(crate) fn hook_env(ctx: &Context, shell: &str) -> Result<Outcome<EnvData>> {
    let shell = Shell::parse(shell)?;
    let session = Session::open(ctx)?;
    let mut here = here(&session)?;
    let cwd = std::env::current_dir()
        .map_err(|e| JtmError::io(".", e))?
        .display()
        .to_string();
    let moved = std::env::var(HOOK_DIR_VAR).ok().as_deref() != Some(cwd.as_str());
    if moved {
        let pinned: Vec<String> = here.pins.pins.keys().cloned().collect();
        for tool in pinned {
            here.selected.remove(&tool);
        }
    }
    let (overrides, found) = here.overrides(&[])?;
    let mut changes = here.plan(&|key| std::env::var(key).ok(), &overrides);
    if moved {
        changes.push(Change::Set {
            name: HOOK_DIR_VAR.to_owned(),
            value: cwd,
        });
    }
    let script = shell::render(shell, &changes, PATH_SEPARATOR)?;
    Ok(Outcome {
        command: "hook-env",
        changed: !changes.is_empty(),
        data: EnvData {
            shell: Some(shell.name()),
            changes,
            script,
        },
        // Shown once per directory, not at every prompt.
        warnings: if moved {
            let mut found = found;
            found.extend(here.requirement_warnings(&[]));
            warnings_with(found, &here.pins.conflicts)
        } else {
            Vec::new()
        },
    })
}
