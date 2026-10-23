//! The `jtm` command-line interface.

mod activate;
mod builtin;
mod cli;
mod doctor;
mod ide;
mod logging;
mod mirror;
mod output;
mod project;
mod prompt;
mod setup;
mod shell;
mod snapshot;
mod sync;
mod tools;
mod trust;
mod uninstall;

use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use clap::Parser;
use clap::error::ErrorKind;
use jtm_core::{Context, ExitCode as JtmExitCode, GlobalFlags, JtmError, Terminal};
use serde::Serialize;

use crate::cli::{Cli, Command, IdeCommand, MirrorCommand, SelfCommand};
use crate::output::{Diagnosis, Format, Human, JTM_VERSION, Outcome, Renderer};
use crate::trust::TrustOutcome;

#[derive(Debug, Serialize)]
struct VersionData {
    version: &'static str,
}

impl Human for VersionData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(out, "jtm {}", self.version)
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();

    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        // Usage errors honour `--json` even though parsing failed.
        Err(err) if wants_json(&args) && !is_informational(err.kind()) => {
            return fail(
                &mut Renderer::stdio(Format::Json),
                "jtm",
                &usage_error(&err),
            );
        }
        Err(err) => {
            let _ = err.print();
            return ExitCode::from(u8::try_from(err.exit_code()).unwrap_or(1));
        }
    };

    let flags = GlobalFlags::from(&cli.global);
    let format = if flags.json {
        Format::Json
    } else {
        Format::Human
    };
    let mut renderer = Renderer::stdio(format);
    let terminal = Terminal {
        stdin: io::stdin().is_terminal(),
        stderr: io::stderr().is_terminal(),
    };
    let ctx = match Context::resolve(&flags, |key| std::env::var_os(key), terminal) {
        Ok(ctx) => Context {
            builtin: builtin::MANIFESTS,
            snapshot: snapshot::SNAPSHOT,
            ..ctx
        },
        Err(err) => return fail(&mut renderer, "jtm", &err),
    };
    logging::init(&ctx);
    tracing::debug!(?ctx, "resolved context");

    if cli.version {
        let outcome = Outcome {
            command: "version",
            changed: false,
            data: VersionData {
                version: JTM_VERSION,
            },
            warnings: Vec::new(),
        };
        let _ = renderer.success(&outcome);
        return JtmExitCode::Success.into();
    }
    match cli.command {
        Some(Command::Install {
            specs,
            dry_run,
            force,
            latest,
        }) => {
            let options = jtm_core::session::InstallOptions {
                force,
                dry_run,
                latest,
            };
            match tools::install(&ctx, &specs, options) {
                Ok((outcome, code)) => {
                    let _ = renderer.success(&outcome);
                    code.into()
                }
                Err(failure) => {
                    let _ = renderer.failure_with("install", &failure.error, failure.details());
                    failure.error.exit_code().into()
                }
            }
        }
        Some(Command::Uninstall {
            spec,
            all_variants,
            dry_run,
        }) => render(
            &mut renderer,
            "uninstall",
            tools::uninstall(
                &ctx,
                &spec,
                jtm_core::session::UninstallOptions {
                    all_variants,
                    dry_run,
                },
            ),
        ),
        Some(Command::List { tool }) => {
            render(&mut renderer, "list", tools::list(&ctx, tool.as_deref()))
        }
        Some(Command::Available {
            tool,
            variant,
            alias,
            all,
        }) => {
            let options = jtm_core::session::AvailableOptions {
                variant,
                alias,
                all,
            };
            render(
                &mut renderer,
                "available",
                tools::available(&ctx, &tool, &options),
            )
        }
        Some(Command::Default {
            spec,
            install,
            latest,
        }) => render(
            &mut renderer,
            "default",
            activate::default(&ctx, &spec, install, latest),
        ),
        Some(Command::Use {
            spec,
            unset,
            install,
            latest,
            shell,
        }) => render(
            &mut renderer,
            "use",
            activate::use_version(
                &ctx,
                &spec,
                activate::UseOptions {
                    unset,
                    install,
                    latest,
                    shell: shell.as_deref(),
                },
            ),
        ),
        Some(Command::Env { shell }) => {
            render(&mut renderer, "env", activate::env(&ctx, shell.as_deref()))
        }
        Some(Command::ShellInit { shell }) => {
            render(&mut renderer, "shell-init", activate::shell_init(&shell))
        }
        Some(Command::Pin {
            spec,
            format,
            exact,
            dry_run,
        }) => render(
            &mut renderer,
            "pin",
            project::pin(&ctx, &spec, format.as_deref(), exact, dry_run),
        ),
        Some(Command::Unpin { tool, format }) => render(
            &mut renderer,
            "unpin",
            project::unpin(&ctx, &tool, format.as_deref()),
        ),
        Some(Command::Current { tool }) => render(
            &mut renderer,
            "current",
            project::current(&ctx, tool.as_deref()),
        ),
        Some(Command::Which { command }) => {
            render(&mut renderer, "which", project::which(&ctx, &command))
        }
        Some(Command::Exec {
            specs,
            install,
            latest,
            command,
        }) => match project::exec(&ctx, &specs, &command, install, latest) {
            Ok((outcome, code)) => {
                if ctx.json {
                    let _ = renderer.success(&outcome);
                    JtmExitCode::Success.into()
                } else {
                    // Pass the child's code on whole: `ExitCode` holds only 0 to 255, which
                    // would lose a Windows code such as 0xC000013A for Ctrl+C.
                    std::process::exit(code)
                }
            }
            Err(err) => fail(&mut renderer, "exec", &err),
        },
        Some(Command::Sync { dry_run, frozen }) => match sync::sync(&ctx, dry_run, frozen) {
            Ok((outcome, code)) => {
                let _ = renderer.success(&outcome);
                code.into()
            }
            Err(failure) => {
                let _ = renderer.failure_with("sync", &failure.error, failure.details());
                failure.error.exit_code().into()
            }
        },
        Some(Command::Lock {
            platform,
            upgrade,
            dry_run,
        }) => render(
            &mut renderer,
            "lock",
            sync::lock(&ctx, &platform, upgrade.as_deref(), dry_run),
        ),
        Some(Command::HookEnv { shell }) => {
            render(&mut renderer, "hook-env", activate::hook_env(&ctx, &shell))
        }
        Some(Command::Ide(IdeCommand::Sync {
            dry_run,
            maven_only,
            gradle_only,
        })) => render(
            &mut renderer,
            "ide sync",
            ide::sync(
                &ctx,
                ide::IdeOptions {
                    dry_run,
                    maven: !gradle_only,
                    gradle: !maven_only,
                },
            ),
        ),
        Some(Command::SelfCmd(SelfCommand::Setup { dry_run, no_hook })) => render(
            &mut renderer,
            "self setup",
            setup::setup(&ctx, setup::SetupOptions { dry_run, no_hook }),
        ),
        Some(Command::SelfCmd(SelfCommand::Uninstall { dry_run, purge })) => render(
            &mut renderer,
            "self uninstall",
            uninstall::uninstall(&ctx, uninstall::UninstallOptions { dry_run, purge }),
        ),
        Some(Command::Doctor) => match doctor::doctor(&ctx) {
            Ok(report) => match report.first_error() {
                None => {
                    let _ = renderer.success(&doctor::outcome(report, ctx.json));
                    JtmExitCode::Success.into()
                }
                Some(finding) => {
                    let diagnosis = Diagnosis {
                        code: finding.code,
                        message: &finding.message,
                        retryable: finding.retryable(),
                        details: finding.details.clone(),
                    };
                    let _ = renderer.report_failure("doctor", &diagnosis, &report);
                    report.exit_code().into()
                }
            },
            Err(err) => fail(&mut renderer, "doctor", &err),
        },
        Some(Command::Mirror(MirrorCommand::Export {
            dir,
            plugin,
            platform,
            artifacts,
            dry_run,
        })) => render(
            &mut renderer,
            "mirror export",
            mirror::export(
                &ctx,
                mirror::ExportArgs {
                    dir,
                    plugins: plugin,
                    platforms: platform,
                    artifacts,
                    dry_run,
                },
            ),
        ),
        Some(Command::Trust(cmd)) => {
            let name = trust::command_name(&cmd);
            let _ = match trust::run(&ctx, cmd) {
                Ok(TrustOutcome::Add(outcome)) => renderer.success(&outcome),
                Ok(TrustOutcome::Remove(outcome)) => renderer.success(&outcome),
                Ok(TrustOutcome::List(outcome)) => renderer.success(&outcome),
                Err(err) => return fail(&mut renderer, name, &err),
            };
            JtmExitCode::Success.into()
        }
        None => fail(
            &mut renderer,
            "jtm",
            &JtmError::usage("no command given; see `jtm --help`"),
        ),
    }
}

fn render<O: Write, E: Write, T: Serialize + Human>(
    renderer: &mut Renderer<O, E>,
    command: &str,
    result: jtm_core::Result<Outcome<T>>,
) -> ExitCode {
    match result {
        Ok(outcome) => {
            let _ = renderer.success(&outcome);
            JtmExitCode::Success.into()
        }
        Err(err) => fail(renderer, command, &err),
    }
}

fn fail<O: Write, E: Write>(
    renderer: &mut Renderer<O, E>,
    command: &str,
    err: &JtmError,
) -> ExitCode {
    let _ = renderer.failure(command, err);
    err.exit_code().into()
}

/// Whether `--json` appears before any `--` separator.
fn wants_json(args: &[OsString]) -> bool {
    args.iter()
        .skip(1)
        .take_while(|arg| *arg != "--")
        .any(|arg| arg == "--json")
}

fn is_informational(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::DisplayHelp | ErrorKind::DisplayVersion)
}

fn usage_error(err: &clap::Error) -> JtmError {
    let rendered = err.render().to_string();
    let first_line = rendered.lines().next().unwrap_or_default();
    JtmError::usage(
        first_line
            .strip_prefix("error: ")
            .unwrap_or(first_line)
            .trim(),
    )
}
