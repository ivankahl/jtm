//! `jtm doctor` (SPEC.md sections 4, 13 and 14): runs the checks of `jtm_core::doctor`, adds
//! the shell hook check, which needs the shell setup code of this crate, and renders the
//! report.
//!
//! Doctor only reads. It does not open a [`Session`](jtm_core::session::Session), because
//! opening one repairs the builtin plugin working copy, and it never prompts. Exit codes follow
//! the first failed check (SPEC.md section 12); warnings never change the exit code.

use std::io::{self, Write};
use std::path::PathBuf;

use jtm_core::doctor::{
    Check, Finding, Inputs, Report, Severity, Status, W_SHELL_HOOK_INACTIVE, W_SHELL_HOOK_MISSING,
    run,
};
use jtm_core::plugins::Registry;
use jtm_core::session::load_config;
use jtm_core::{Context, Dirs, Os, Result};
use jtm_security::Timestamp;

use crate::activate::HOOK_DIR_VAR;
use crate::output::{Human, Outcome, Warning};
use crate::setup::{END, START, powershell_profile, rc_file, read_existing};
use crate::shell::Shell;

/// What the shell hook check looks at.
#[derive(Debug)]
pub(crate) struct Hook<'a> {
    /// The rc file or profile that should load the hook and the shell it is for; `None` when
    /// it cannot be located.
    pub(crate) rc: Option<(PathBuf, Option<Shell>)>,
    /// The tools the working directory pins.
    pub(crate) pinned: &'a [String],
    /// Whether the hook has run in this shell.
    pub(crate) active: bool,
}

/// Whether the shell hook is loaded where `jtm self setup` puts it, and active in this shell.
pub(crate) fn hook_check(hook: &Hook<'_>) -> Check {
    const ID: &str = "shell_hook";
    let Some((rc, shell)) = &hook.rc else {
        return Check::skipped(
            ID,
            "the file that should load the shell hook could not be located (HOME is not set, \
             or no PowerShell was found)",
        );
    };
    let mut check = Check::pass(ID, "");
    if shell.is_none() {
        check.summary = "jtm has no shell hook for the login shell".to_owned();
        check.push(
            Finding::warning(
                W_SHELL_HOOK_MISSING,
                "jtm has no shell hook for your login shell, so project pins and `jtm use` do \
                 not apply in it",
            )
            .hint("use bash, zsh, fish or pwsh, or run commands through `jtm exec`"),
        );
        return check;
    }
    let text = match read_existing(rc) {
        Ok(text) => text,
        Err(err) => {
            check.summary = "the shell rc file cannot be read".to_owned();
            check.push(Finding::from_error(&err).hint(format!(
                "fix the permissions of {}, or load the hook by hand with `jtm shell-init`",
                rc.display()
            )));
            return check;
        }
    };
    // `--no-hook` leaves the block without the `jtm shell-init` line.
    let loaded = text.is_some_and(|text| {
        text.find(START)
            .and_then(|start| text[start..].split(END).next())
            .is_some_and(|block| block.contains("shell-init"))
    });
    if !loaded {
        check.summary = format!("the shell hook is not loaded from {}", rc.display());
        check.push(
            Finding::warning(
                W_SHELL_HOOK_MISSING,
                format!(
                    "the shell hook is not loaded from {}, so project pins and `jtm use` do \
                     not apply in new shells",
                    rc.display()
                ),
            )
            .hint("run `jtm self setup` (without --no-hook), then open a new terminal")
            .detail("path", rc.display().to_string()),
        );
        return check;
    }
    check.summary = format!("the shell hook is loaded from {}", rc.display());
    if hook.active {
        check.summary.push_str(" and active in this shell");
    } else if hook.pinned.is_empty() {
        check
            .notes
            .push("the hook is not active in this shell; open a new terminal".to_owned());
    } else {
        let tools: Vec<String> = hook.pinned.iter().map(|t| format!("`{t}`")).collect();
        check.push(
            Finding::warning(
                W_SHELL_HOOK_INACTIVE,
                format!(
                    "this project pins {}, but the shell hook is not active in this shell, so \
                     the pins do not apply here",
                    tools.join(", ")
                ),
            )
            .hint(
                "open a new terminal so the rc file loads the hook, or use \
                 `jtm exec <specs> -- <command>`",
            )
            .detail("pinned", hook.pinned.to_vec()),
        );
    }
    check
}

/// Runs every check against the real environment.
pub(crate) fn doctor(ctx: &Context) -> Result<Report> {
    let dirs = Dirs::for_context(ctx)?;
    let cwd = std::env::current_dir().ok();
    let config = load_config(&dirs, cwd.as_deref(), &|key| std::env::var_os(key))?;
    let registry = Registry {
        dirs: &dirs,
        builtin: ctx.builtin,
    };
    let env = |key: &str| std::env::var_os(key).map(|v| v.to_string_lossy().into_owned());
    let hook = hook_check(&Hook {
        rc: rc_target(&env),
        pinned: &pinned_tools(&registry, cwd.as_deref()),
        active: std::env::var_os(HOOK_DIR_VAR).is_some_and(|v| !v.is_empty()),
    });
    let inputs = Inputs {
        dirs: &dirs,
        settings: &config.settings,
        registry,
        offline: ctx.offline,
        env: &env,
        now: Timestamp::now(),
        prober: None,
        // SPEC-QUESTION: section 16 says doctor reads `marketplace.json` when it can fetch it.
        // The signed marketplace client arrives with T9.2, so until then the yanked check is
        // skipped and says so rather than guessing.
        marketplace: None,
    };
    Ok(run(&inputs, hook))
}

/// The rc file or profile `jtm self setup` writes the hook to, and its shell.
fn rc_target(env: &dyn Fn(&str) -> Option<String>) -> Option<(PathBuf, Option<Shell>)> {
    let os = Os::host()?;
    if os == Os::Windows {
        return powershell_profile().map(|profile| (profile, Some(Shell::Pwsh)));
    }
    let home = env("HOME").filter(|h| h.starts_with('/'))?;
    Some(rc_file(std::path::Path::new(&home), os, env))
}

/// The tools the pin files at or above `cwd` pin. A project that cannot be read pins nothing
/// here; other commands report that.
fn pinned_tools(registry: &Registry<'_>, cwd: Option<&std::path::Path>) -> Vec<String> {
    let Some(cwd) = cwd else {
        return Vec::new();
    };
    let plugins: Vec<_> = registry
        .names()
        .unwrap_or_default()
        .iter()
        .filter_map(|name| registry.find(name).ok())
        .collect();
    jtm_core::pins::discover(cwd, &plugins)
        .map(|pins| pins.pins.keys().cloned().collect())
        .unwrap_or_default()
}

/// The successful result of `jtm doctor`: the report, with each warning in the envelope.
pub(crate) fn outcome(report: Report, json: bool) -> Outcome<Report> {
    // For a human the report already shows every warning, so the renderer must not repeat them.
    let warnings = report
        .warnings()
        .filter(|_| json)
        .map(|finding| {
            let mut details = finding.details.clone();
            if let Some(hint) = &finding.hint {
                details.insert("hint".to_owned(), hint.clone().into());
            }
            Warning {
                code: finding.code,
                message: finding.message.clone(),
                details,
            }
        })
        .collect();
    Outcome {
        command: "doctor",
        changed: false,
        data: report,
        warnings,
    }
}

impl Human for Report {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        for check in &self.checks {
            let status = match check.status {
                Status::Ok => "ok",
                Status::Warning => "warning",
                Status::Failed => "FAILED",
                Status::Skipped => "skipped",
            };
            writeln!(out, "[{status}] {}: {}", check.id, check.summary)?;
            for finding in &check.findings {
                let kind = match finding.severity {
                    Severity::Warning => "warning",
                    Severity::Error => "error",
                };
                writeln!(out, "    {kind}[{}]: {}", finding.code, finding.message)?;
                if let Some(hint) = &finding.hint {
                    writeln!(out, "      hint: {hint}")?;
                }
            }
            for note in &check.notes {
                writeln!(out, "    note: {note}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
