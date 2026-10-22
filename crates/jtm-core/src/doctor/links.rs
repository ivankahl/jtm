//! The `PATH` and current link checks (SPEC.md sections 5 and 14).
//!
//! Both look at the tools that have a default in `state/defaults.toml`, and take each tool's
//! `bin` directories from its plugin manifest.

use std::fs;
use std::io;
use std::path::PathBuf;

use crate::activate::{Defaults, tool_env};
use crate::dirs::dir_name;
use crate::error::{ErrorCode, JtmError};
use crate::links;
use crate::plugins::Plugin;
use crate::session::PATH_SEPARATOR;

use super::{Check, Finding, Inputs, W_PATH_MISSING, list};

/// A tool with a default, and its plugin if one is installed.
struct Default {
    tool: String,
    /// The default as `jtm default` takes it: `tool@selector`.
    spec: String,
    plugin: Option<Plugin>,
    link: PathBuf,
}

fn defaults(inputs: &Inputs<'_>) -> Result<Vec<Default>, JtmError> {
    let loaded = Defaults::load(&inputs.dirs.defaults_file())?;
    Ok(loaded
        .iter()
        .map(|(tool, selector)| Default {
            tool: tool.to_owned(),
            spec: format!("{tool}@{selector}"),
            plugin: inputs.registry.find(tool).ok(),
            link: inputs.dirs.current().join(dir_name(tool)),
        })
        .collect())
}

/// How `PATH` entries are compared: a trailing separator never matters, and Windows ignores
/// case.
fn normal(entry: &str) -> String {
    let entry = entry.trim_end_matches(['/', '\\']);
    if cfg!(windows) {
        entry.to_lowercase()
    } else {
        entry.to_owned()
    }
}

/// Every default tool's current link `bin` directories are on `PATH`.
pub(super) fn path(inputs: &Inputs<'_>) -> Check {
    const ID: &str = "path";
    let defaults = match defaults(inputs) {
        Ok(defaults) => defaults,
        Err(err) => return failed(ID, &err),
    };
    if defaults.is_empty() {
        return Check::pass(ID, "no defaults are set, so nothing needs to be on PATH");
    }
    let on_path: Vec<String> = (inputs.env)("PATH")
        .unwrap_or_default()
        .split(PATH_SEPARATOR)
        .map(normal)
        .collect();
    let mut found = Vec::new();
    let mut check = Check::pass(ID, "");
    for default in &defaults {
        let Some(plugin) = &default.plugin else {
            continue;
        };
        for dir in tool_env(&plugin.manifest, &default.link).path {
            let text = dir.display().to_string();
            if on_path.contains(&normal(&text)) {
                found.push(text);
            } else {
                check.push(
                    Finding::warning(
                        W_PATH_MISSING,
                        format!(
                            "{text} is not on PATH, so `{}` is not found from a new terminal",
                            default.tool
                        ),
                    )
                    .hint(
                        "run `jtm self setup` and open a new terminal; on Windows a terminal \
                         started before the change keeps its old PATH",
                    )
                    .detail("tool", default.tool.as_str())
                    .detail("dir", text),
                );
            }
        }
    }
    check.summary = if found.is_empty() {
        "no current link bin directory is on PATH".to_owned()
    } else {
        format!(
            "{} current link bin director{} on PATH",
            found.len(),
            if found.len() == 1 { "y is" } else { "ies are" }
        )
    };
    check.detail("on_path", found)
}

/// Every default tool has a current link that points at an install with its `bin` directories.
pub(super) fn current(inputs: &Inputs<'_>) -> Check {
    const ID: &str = "current_links";
    let defaults = match defaults(inputs) {
        Ok(defaults) => defaults,
        Err(err) => return failed(ID, &err),
    };
    if defaults.is_empty() {
        return Check::pass(ID, "no defaults are set, so there are no current links");
    }
    let mut check = Check::pass(ID, "");
    let mut fine = Vec::new();
    for default in &defaults {
        match inspect(default) {
            Ok(()) => fine.push(default.tool.clone()),
            Err(finding) => check.push(*finding),
        }
    }
    check.summary = if fine.len() == defaults.len() {
        format!("{} point at installed versions", list(&fine))
    } else {
        format!(
            "{} of {} current links are fine",
            fine.len(),
            defaults.len()
        )
    };
    check
}

fn failed(id: &'static str, err: &JtmError) -> Check {
    let mut check = Check::pass(id, "the defaults could not be read");
    check.push(
        Finding::from_error(err)
            .hint("fix or remove state/defaults.toml in the jtm data directory"),
    );
    check
}

/// Why the current link of `default` is not usable, if it is not.
fn inspect(default: &Default) -> Result<(), Box<Finding>> {
    let Some(plugin) = &default.plugin else {
        return Err(Box::new(
            Finding::error(
                ErrorCode::ToolUnknown,
                format!(
                    "a default is set for `{}`, but no plugin `{}` is installed",
                    default.tool, default.tool
                ),
            )
            .hint(format!(
                "add the plugin, or remove `{}` from state/defaults.toml",
                default.tool
            ))
            .detail("tool", default.tool.as_str()),
        ));
    };
    let link = &default.link;
    let problem = |code: ErrorCode, message: String, hint: String| {
        Err(Box::new(
            Finding::error(code, message)
                .hint(hint)
                .detail("tool", default.tool.as_str())
                .detail("path", link.display().to_string()),
        ))
    };
    let recreate = format!(
        "run `jtm default {}` to point it at the install again",
        default.spec
    );
    match fs::symlink_metadata(link) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return problem(
                ErrorCode::Io,
                format!(
                    "the current link {} for `{}` is missing",
                    link.display(),
                    default.tool
                ),
                recreate,
            );
        }
        Err(e) => return Err(Box::new(Finding::from_error(&JtmError::io(link, e)))),
        Ok(_) => {}
    }
    let Some(target) = links::read(link) else {
        return problem(
            ErrorCode::Io,
            format!(
                "{} is not a link jtm made, so it cannot be the current link for `{}`",
                link.display(),
                default.tool
            ),
            format!("move it away, then {recreate}"),
        );
    };
    match fs::metadata(link) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return problem(
                ErrorCode::Io,
                format!(
                    "the current link {} for `{}` points at {}, which does not exist",
                    link.display(),
                    default.tool,
                    target.display()
                ),
                format!(
                    "the install was removed outside jtm; run `jtm install {}` and then \
                     `jtm default {}`, or choose another version with `jtm default`",
                    default.spec, default.spec
                ),
            );
        }
        Err(e) => return Err(Box::new(Finding::from_error(&JtmError::io(link, e)))),
        Ok(_) => {}
    }
    let bin_dirs = &plugin.manifest.layout.bin_dirs;
    for (bin, dir) in bin_dirs.iter().zip(tool_env(&plugin.manifest, link).path) {
        if !dir.is_dir() {
            return problem(
                ErrorCode::Io,
                format!(
                    "the current link for `{}` points at {}, which has no `{bin}` directory",
                    default.tool,
                    target.display()
                ),
                format!(
                    "the install looks incomplete; reinstall it with `jtm install {} --force` \
                     and run `jtm default {}`",
                    default.spec, default.spec
                ),
            );
        }
    }
    Ok(())
}
