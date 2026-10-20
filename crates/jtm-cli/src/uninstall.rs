//! `jtm self uninstall`: takes jtm back out of the user environment, undoing `jtm self setup`
//! and `jtm default`.
//!
//! It removes jtm's marked block from every rc file and the PowerShell profile, jtm's
//! `env.sh` and `env.fish`, the `HKCU\Environment` values `self setup` recorded, the current
//! links and the defaults. Installed versions, plugins, trust and the cache stay unless
//! `--purge` is given, which also deletes what jtm keeps in its data and cache directories:
//! only the entries jtm makes there, then each directory once it is empty. The user config
//! file and the jtm binary are never touched; the output says where they are.
//!
//! Everything it would remove is shown first and removed only after confirmation or with
//! `--yes`, so the command never deletes anything unattended without being told to.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use jtm_core::{Context, Dirs, JtmError, Result, links};
use serde::Serialize;

use crate::output::{Human, Outcome};
use crate::prompt::confirm;
use crate::setup::{SETUP_MARKER, START, read_existing, update_rc};
use crate::shell::jtm_exe;

/// Options for [`uninstall`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct UninstallOptions {
    pub(crate) dry_run: bool,
    /// Also delete the data and cache directories: installs, plugins, trust and downloads.
    pub(crate) purge: bool,
}

/// One thing `self uninstall` removes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// Rewrite a file without jtm's block.
    Edit { path: PathBuf, text: String },
    /// Delete a file jtm wrote.
    File(PathBuf),
    /// Remove a current link, leaving its target alone.
    Link(PathBuf),
    /// Delete a directory jtm made, with everything in it.
    Dir(PathBuf),
    /// Remove a directory if it is empty, keeping it otherwise.
    Empty(PathBuf),
    /// Remove what `self setup` put in `HKCU\Environment`.
    #[cfg_attr(not(windows), allow(dead_code))]
    Registry(String),
}

impl Step {
    fn path(&self) -> String {
        match self {
            Step::Edit { path, .. }
            | Step::File(path)
            | Step::Link(path)
            | Step::Dir(path)
            | Step::Empty(path) => path.display().to_string(),
            Step::Registry(name) => name.clone(),
        }
    }

    fn action(&self) -> &'static str {
        match self {
            Step::Edit { .. } => "remove the jtm block from",
            Step::File(_) => "delete",
            Step::Link(_) => "remove the link",
            Step::Dir(_) => "delete the directory",
            Step::Empty(_) => "remove if empty",
            Step::Registry(_) => "remove",
        }
    }

    /// [`Step::action`] once done, for people.
    fn done(&self) -> &'static str {
        match self {
            Step::Edit { .. } => "removed the jtm block from",
            Step::File(_) => "deleted",
            Step::Link(_) => "removed the link",
            Step::Dir(_) => "deleted the directory",
            Step::Empty(_) => "removed, if it was empty,",
            Step::Registry(_) => "removed",
        }
    }
}

/// One thing removed, or with `--dry-run` that would be.
#[derive(Debug, Serialize)]
pub(crate) struct Removed {
    path: String,
    action: &'static str,
    #[serde(skip)]
    done: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct UninstallData {
    dry_run: bool,
    purge: bool,
    removed: Vec<Removed>,
    /// What stays: the config file, and without `--purge` the data and cache directories.
    kept: Vec<String>,
    /// The jtm binary, which the user deletes to finish.
    binary: String,
}

impl Human for UninstallData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        if self.removed.is_empty() {
            writeln!(out, "jtm has nothing set up in your environment")?;
        }
        for item in &self.removed {
            if self.dry_run {
                writeln!(out, "would {} {}", item.action, item.path)?;
            } else {
                writeln!(out, "{} {}", item.done, item.path)?;
            }
        }
        for path in &self.kept {
            writeln!(out, "kept {path}")?;
        }
        if !self.dry_run {
            writeln!(
                out,
                "jtm itself is still at {}; delete it to finish, and open a new terminal",
                self.binary
            )?;
        }
        Ok(())
    }
}

/// The rc files `self setup` may have written to, whichever shell was the login shell then:
/// all of them are checked, since the user may have switched shells since.
fn rc_files(env: &dyn Fn(&str) -> Option<String>) -> Vec<PathBuf> {
    let absolute = |key: &str| env(key).filter(|d| Path::new(d).is_absolute());
    let Some(home) = absolute("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let zdotdir = absolute("ZDOTDIR").map_or_else(|| home.clone(), PathBuf::from);
    let config = absolute("XDG_CONFIG_HOME").map_or_else(|| home.join(".config"), PathBuf::from);
    vec![
        home.join(".bashrc"),
        home.join(".bash_profile"),
        home.join(".profile"),
        zdotdir.join(".zshrc"),
        config.join("fish").join("conf.d").join("jtm.fish"),
    ]
}

/// The step that takes jtm's block out of `path`, if it has one. A file left holding nothing
/// but white space is jtm's own, such as fish's `conf.d/jtm.fish`, and is deleted.
fn rc_step(path: &Path) -> Result<Option<Step>> {
    let Some(text) = read_existing(path)? else {
        return Ok(None);
    };
    if !text.contains(START) {
        return Ok(None);
    }
    let Some(mut rest) = update_rc(Some(&text), "") else {
        return Ok(None);
    };
    // `self setup` puts a blank line before a block it appends; that goes with it.
    let at = text.find(START).unwrap_or_default();
    if text[..at].ends_with("\n\n") {
        rest.remove(at - 1);
    }
    Ok(Some(
        if rest.trim_start_matches('\u{feff}').trim().is_empty() {
            Step::File(path.to_path_buf())
        } else {
            Step::Edit {
                path: path.to_path_buf(),
                text: rest,
            }
        },
    ))
}

/// Refuses to purge in `dir` when the entries jtm makes there could be someone else's: the
/// file system root, or the home directory or one of its parents (`JTM_HOME=~`).
fn check_purge(dir: &Path, home: Option<&Path>) -> Result<()> {
    let refuse = |why: &str| {
        Err(JtmError::usage(format!(
            "refusing to purge {}: {why}; remove jtm's directories in it by hand",
            dir.display()
        )))
    };
    if dir.parent().is_none() {
        return refuse("it is the root of the file system");
    }
    if home.is_some_and(|home| home.starts_with(dir)) {
        return refuse("it holds your home directory");
    }
    Ok(())
}

/// Everything `self uninstall` would remove, in the order it removes it.
fn plan(dirs: &Dirs, options: UninstallOptions) -> Result<(Vec<Step>, Vec<String>)> {
    let env = |key: &str| std::env::var(key).ok();
    let mut steps = Vec::new();
    let mut kept = Vec::new();

    let mut rcs = rc_files(&env);
    if cfg!(windows)
        && let Some(profile) = crate::setup::powershell_profile()
    {
        rcs.push(profile);
    }
    for rc in rcs {
        steps.extend(rc_step(&rc)?);
    }

    #[cfg(windows)]
    if let Some(previous) = crate::setup::applied(dirs)? {
        let targets =
            crate::setup::windows::apply(&crate::setup::SetupPlan::default(), &previous, true)?;
        steps.extend(
            targets
                .into_iter()
                .filter(|t| t.changed)
                .map(|t| Step::Registry(t.path)),
        );
    }

    if let Ok(entries) = std::fs::read_dir(dirs.current()) {
        for entry in entries.flatten() {
            let path = entry.path();
            if links::read(&path).is_some() {
                steps.push(Step::Link(path));
            } else if !options.purge {
                kept.push(path.display().to_string());
            }
        }
    }
    for file in [
        dirs.data.join("env.sh"),
        dirs.data.join("env.fish"),
        dirs.state().join(SETUP_MARKER),
        dirs.defaults_file(),
    ] {
        if file.is_file() {
            steps.push(Step::File(file));
        }
    }

    if options.purge {
        let home = env("HOME")
            .or_else(|| env("USERPROFILE"))
            .map(PathBuf::from);
        check_purge(&dirs.data, home.as_deref())?;
        check_purge(&dirs.cache, home.as_deref())?;
        // What jtm makes, as `Dirs` lays it out. The cache may sit inside the data directory.
        let made = [
            dirs.tools(),
            dirs.current(),
            dirs.plugins(),
            dirs.state(),
            dirs.locks(),
            dirs.index_cache(),
            dirs.downloads(),
        ];
        steps.extend(made.into_iter().filter(|d| d.is_dir()).map(Step::Dir));
        for dir in [&dirs.cache, &dirs.data] {
            if dir.is_dir() && !steps.contains(&Step::Empty(dir.clone())) {
                steps.push(Step::Empty(dir.clone()));
            }
        }
    } else {
        for dir in [&dirs.data, &dirs.cache] {
            if dir.is_dir() && !kept.contains(&dir.display().to_string()) {
                kept.push(dir.display().to_string());
            }
        }
    }
    if dirs.config_file.is_file() {
        kept.push(dirs.config_file.display().to_string());
    }
    Ok((steps, kept))
}

fn run(step: &Step, dirs: &Dirs) -> Result<()> {
    let io_err = |path: &Path| {
        let path = path.to_path_buf();
        move |e| JtmError::io(path, e)
    };
    match step {
        Step::Edit { path, text } => jtm_core::project::write_atomic(path, text.as_bytes()),
        Step::File(path) => match std::fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(JtmError::io(path, e)),
            _ => Ok(()),
        },
        Step::Link(path) => links::remove(path).map(drop),
        Step::Dir(path) => {
            if path.is_dir() {
                std::fs::remove_dir_all(path).map_err(io_err(path))?;
            }
            Ok(())
        }
        Step::Empty(path) => {
            // Fails when something else is in it, such as the config file under JTM_HOME.
            let _ = std::fs::remove_dir(path);
            Ok(())
        }
        Step::Registry(_) => {
            #[cfg(windows)]
            if let Some(previous) = crate::setup::applied(dirs)? {
                crate::setup::windows::apply(
                    &crate::setup::SetupPlan::default(),
                    &previous,
                    false,
                )?;
            }
            let _ = dirs;
            Ok(())
        }
    }
}

pub(crate) fn uninstall(
    ctx: &Context,
    options: UninstallOptions,
) -> Result<Outcome<UninstallData>> {
    let dirs = Dirs::for_context(ctx)?;
    let (steps, kept) = plan(&dirs, options)?;
    if !options.dry_run && !steps.is_empty() {
        let list: Vec<String> = steps
            .iter()
            .map(|s| format!("  {} {}", s.action(), s.path()))
            .collect();
        let question = format!("Uninstall jtm? This will:\n{}\n", list.join("\n"));
        if !confirm(ctx, &question)? {
            return Err(JtmError::InputRequired {
                action: "uninstalling jtm".to_owned(),
                resolve: "--yes".to_owned(),
            });
        }
        // The registry values are removed in one go; the rest step by step.
        let mut registry_done = false;
        for step in &steps {
            if matches!(step, Step::Registry(_)) {
                if registry_done {
                    continue;
                }
                registry_done = true;
            }
            run(step, &dirs)?;
        }
        let current = dirs.current();
        if current.is_dir() {
            // Only goes when empty, so anything left in it is kept.
            let _ = std::fs::remove_dir(&current);
        }
    }
    Ok(Outcome {
        command: "self uninstall",
        changed: !options.dry_run && !steps.is_empty(),
        data: UninstallData {
            dry_run: options.dry_run,
            purge: options.purge,
            removed: steps
                .iter()
                .map(|s| Removed {
                    path: s.path(),
                    action: s.action(),
                    done: s.done(),
                })
                .collect(),
            kept,
            binary: jtm_exe(),
        },
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod tests;
