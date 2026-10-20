//! Finding a project's pins (SPEC.md sections 5 and 6).
//!
//! Walking up from the working directory, the nearest directory with any pin file setting a
//! tool decides that tool. Within one directory `.jtm.toml` comes first, then the interop files
//! plugins declare, in parser order (`keyvalue`, `tool-versions`, `single-line`, which is
//! `.sdkmanrc`, `.tool-versions`, `.java-version` for the first-party plugins) and then by file
//! name. The first file setting a tool wins, and any other file in that directory setting a
//! different value is reported as a conflict. Wrapper files count only when no pin file in any
//! directory sets the tool.
//!
//! A pin file further up is read only for tools no nearer directory decides, so a broken or
//! unmappable value in, say, `~/.sdkmanrc` does not break a project that pins the tool itself.
//! A `.jtm.toml` above the nearest one that names a tool with no plugin is skipped with a
//! warning instead of failing.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use jtm_plugin::interop::{self, InteropError};
use jtm_plugin::manifest::{Interop, InteropParser};
use serde::Serialize;

use crate::error::{JtmError, Result};
use crate::plugins::Plugin;
use crate::project::{PROJECT_FILE, ProjectFile};
use crate::spec::Selector;

/// Warning code for two pin files in one directory setting different values for a tool.
pub const W_PIN_CONFLICT: &str = "W_PIN_CONFLICT";

/// Warning code for a pin in an ancestor `.jtm.toml` naming a tool with no plugin.
pub const W_PIN_IGNORED: &str = "W_PIN_IGNORED";

/// What kind of file a pin came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PinKind {
    /// `.jtm.toml`.
    Native,
    /// A plugin's `[[interop]]` file.
    Interop,
    /// A read-only wrapper properties file.
    Wrapper,
}

/// One tool's project pin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    pub tool: String,
    pub selector: Selector,
    /// The pin file.
    pub file: PathBuf,
    pub kind: PinKind,
    /// For wrapper pins, what the wrapper declares.
    pub wrapper: Option<interop::WrapperPin>,
}

/// A file and the value it sets, as conflicts report them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PinValue {
    pub file: PathBuf,
    /// The pin as `variant:value`, with the default variant filled in.
    pub value: String,
}

/// Pin files in one directory that disagree about a tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Conflict {
    pub tool: String,
    pub winner: PinValue,
    pub others: Vec<PinValue>,
}

impl Conflict {
    /// The conflict as a warning message.
    pub fn message(&self) -> String {
        let others: Vec<String> = self
            .others
            .iter()
            .map(|o| format!("{} sets `{}`", o.file.display(), o.value))
            .collect();
        format!(
            "{} sets `{}` = `{}`, which wins, but {}",
            self.winner.file.display(),
            self.tool,
            self.winner.value,
            others.join(" and ")
        )
    }
}

/// Every pin found from a directory up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectPins {
    /// The winning pin per tool.
    pub pins: BTreeMap<String, Pin>,
    pub conflicts: Vec<Conflict>,
    /// Pins skipped because no plugin provides the tool, as warning messages.
    pub ignored: Vec<String>,
    /// Every pin file read, nearest first.
    pub files: Vec<PathBuf>,
}

/// A plugin's interop entry and its position in the read order.
struct Source<'p> {
    plugin: &'p Plugin,
    interop: &'p Interop,
}

/// Finds the pins that apply in `start`, reading the interop files `plugins` declare.
pub fn discover(start: &Path, plugins: &[Plugin]) -> Result<ProjectPins> {
    discover_within(start, None, plugins)
}

/// [`discover`], reading no directory above `top` when it is given.
pub fn discover_within(
    start: &Path,
    top: Option<&Path>,
    plugins: &[Plugin],
) -> Result<ProjectPins> {
    let mut sources: Vec<Source<'_>> = plugins
        .iter()
        .flat_map(|plugin| {
            plugin
                .manifest
                .interop
                .iter()
                .map(move |interop| Source { plugin, interop })
        })
        .collect();
    sources.sort_by(|a, b| {
        parser_rank(a.interop.parser)
            .cmp(&parser_rank(b.interop.parser))
            .then_with(|| a.interop.file.cmp(&b.interop.file))
    });
    let (wrappers, files): (Vec<Source<'_>>, Vec<Source<'_>>) = sources
        .into_iter()
        .partition(|s| s.interop.parser == InteropParser::Wrapper);
    let dirs = search_dirs(start, top);

    let mut found = ProjectPins::default();
    let mut seen_project_file = false;
    for &dir in &dirs {
        let mut here = Candidates::new();
        if let Some(file) = ProjectFile::read(dir)? {
            native_pins(&file, plugins, seen_project_file, &mut found, &mut here)?;
            seen_project_file = true;
        }
        interop_pins(dir, &files, &mut found, &mut here)?;
        settle(here, plugins, &mut found);
    }
    for source in &wrappers {
        wrapper_pin(source, &dirs, &mut found)?;
    }
    Ok(found)
}

/// Every pin one directory sets, per tool, in read order.
type Candidates = BTreeMap<String, Vec<(PathBuf, Selector, PinKind)>>;

/// The directories to read, nearest first: `start` and its ancestors up to `top`.
fn search_dirs<'a>(start: &'a Path, top: Option<&Path>) -> Vec<&'a Path> {
    let mut dirs = Vec::new();
    for dir in start.ancestors() {
        dirs.push(dir);
        if Some(dir) == top {
            break;
        }
    }
    dirs
}

/// Adds the `[tools]` of `file` to `here`, for tools no nearer directory decided. An unknown
/// tool is an error in the nearest `.jtm.toml`, and a warning in one further up.
fn native_pins(
    file: &ProjectFile,
    plugins: &[Plugin],
    nearer_project_file: bool,
    found: &mut ProjectPins,
    here: &mut Candidates,
) -> Result<()> {
    found.files.push(file.path().to_path_buf());
    for (tool, selector) in file.tools() {
        if found.pins.contains_key(&tool) {
            continue;
        }
        if !plugins.iter().any(|p| p.manifest.name == tool) {
            if nearer_project_file {
                found.ignored.push(format!(
                    "{} pins `{tool}`, which no plugin provides, so it is ignored",
                    file.path().display()
                ));
                continue;
            }
            return Err(JtmError::PinToolUnknown {
                tool,
                file: file.path().to_path_buf(),
            });
        }
        here.entry(tool)
            .or_default()
            .push((file.path().to_path_buf(), selector, PinKind::Native));
    }
    Ok(())
}

/// Adds what the interop files in `dir` set to `here`, for tools no nearer directory decided.
fn interop_pins(
    dir: &Path,
    sources: &[Source<'_>],
    found: &mut ProjectPins,
    here: &mut Candidates,
) -> Result<()> {
    let mut texts: BTreeMap<PathBuf, Option<String>> = BTreeMap::new();
    for source in sources {
        let tool = &source.plugin.manifest.name;
        // A nearer directory already decided this tool.
        if found.pins.contains_key(tool) {
            continue;
        }
        let path = dir.join(&source.interop.file);
        let text = match texts.get(&path) {
            Some(text) => text.clone(),
            None => {
                let text = read_optional(&path)?;
                if text.is_some() {
                    found.files.push(path.clone());
                }
                texts.insert(path.clone(), text.clone());
                text
            }
        };
        let Some(text) = text else { continue };
        let value = interop::read(&source.plugin.manifest, source.interop, &text)
            .map_err(|e| interop_error(tool, &path, &e))?;
        if let Some(value) = value {
            let selector = Selector {
                variant: value.variant,
                value: value.value,
            };
            here.entry(tool.clone())
                .or_default()
                .push((path, selector, PinKind::Interop));
        }
    }
    Ok(())
}

/// Takes the first pin per tool in `here` as the winner, reporting the others that disagree.
fn settle(here: Candidates, plugins: &[Plugin], found: &mut ProjectPins) {
    for (tool, values) in here {
        if found.pins.contains_key(&tool) {
            continue;
        }
        let default = plugins
            .iter()
            .find(|p| p.manifest.name == tool)
            .map(|p| p.manifest.default_variant().to_owned())
            .unwrap_or_default();
        let full =
            |s: &Selector| format!("{}:{}", s.variant.as_deref().unwrap_or(&default), s.value);
        let mut values = values.into_iter();
        let Some((file, selector, kind)) = values.next() else {
            continue;
        };
        let winner = full(&selector);
        let others: Vec<PinValue> = values
            .filter(|(_, s, _)| full(s) != winner)
            .map(|(file, s, _)| PinValue {
                file,
                value: full(&s),
            })
            .collect();
        if !others.is_empty() {
            found.conflicts.push(Conflict {
                tool: tool.clone(),
                winner: PinValue {
                    file: file.clone(),
                    value: winner,
                },
                others,
            });
        }
        found.pins.insert(
            tool.clone(),
            Pin {
                tool,
                selector,
                file,
                kind,
                wrapper: None,
            },
        );
    }
}

/// Pins the tool of the wrapper `source` from the nearest wrapper file in `dirs`, when no pin
/// file set it.
fn wrapper_pin(source: &Source<'_>, dirs: &[&Path], found: &mut ProjectPins) -> Result<()> {
    let tool = &source.plugin.manifest.name;
    if found.pins.contains_key(tool) {
        return Ok(());
    }
    for &dir in dirs {
        let path = dir.join(&source.interop.file);
        let Some(text) = read_optional(&path)? else {
            continue;
        };
        found.files.push(path.clone());
        let wrapper = interop::read_wrapper(source.interop, &text)
            .map_err(|e| interop_error(tool, &path, &e))?;
        if let Some(wrapper) = wrapper {
            found.pins.insert(
                tool.clone(),
                Pin {
                    tool: tool.clone(),
                    selector: Selector {
                        variant: None,
                        value: wrapper.version.clone(),
                    },
                    file: path,
                    kind: PinKind::Wrapper,
                    wrapper: Some(wrapper),
                },
            );
            break;
        }
    }
    Ok(())
}

/// The position of a parser in the read order within one directory.
fn parser_rank(parser: InteropParser) -> u8 {
    match parser {
        InteropParser::Keyvalue => 0,
        InteropParser::ToolVersions => 1,
        InteropParser::SingleLine => 2,
        InteropParser::Wrapper => 3,
    }
}

/// The interop file name `pin --format` and `pin.default_format` use: its file name without
/// the leading dot, such as `sdkmanrc` for `.sdkmanrc`.
pub fn format_name(interop: &Interop) -> &str {
    interop.file.trim_start_matches('.')
}

fn read_optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        Err(e) => Err(JtmError::io(path, e)),
    }
}

fn interop_error(tool: &str, path: &Path, err: &InteropError) -> JtmError {
    JtmError::Config {
        origin: format!("pin file {}", path.display()),
        key: tool.to_owned(),
        message: format!(
            "{err}; pin it in {PROJECT_FILE} instead, such as `[tools] {tool} = \
             \"<variant>:<version>\"`"
        ),
    }
}

/// The formats `plugin` can be pinned in: `native` and its writable interop files.
pub fn formats(plugin: &Plugin) -> Vec<&str> {
    std::iter::once(NATIVE)
        .chain(
            plugin
                .manifest
                .interop
                .iter()
                .filter(|i| i.parser != InteropParser::Wrapper)
                .map(format_name),
        )
        .collect()
}

/// The format name of `.jtm.toml`.
pub const NATIVE: &str = "native";

/// What [`write_pin`] wrote, or with `dry_run` would write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PinWrite {
    pub tool: String,
    pub file: PathBuf,
    pub format: String,
    /// The value as the file holds it, such as `temurin:21` or `21-tem`.
    pub value: String,
    pub changed: bool,
}

/// Pins `selector` for `plugin` in `dir`, in `format`, keeping the rest of the file.
pub fn write_pin(
    dir: &Path,
    plugin: &Plugin,
    format: &str,
    selector: &Selector,
    dry_run: bool,
) -> Result<PinWrite> {
    let tool = plugin.manifest.name.clone();
    if let Some(variant) = &selector.variant
        && !plugin.manifest.has_variant(variant)
    {
        return Err(JtmError::VersionNotFound {
            tool,
            spec: format!("{selector} (no variant `{variant}`)"),
        });
    }
    if format == NATIVE {
        let path = dir.join(PROJECT_FILE);
        let mut file = ProjectFile::read(dir)?.unwrap_or_else(|| ProjectFile::empty(&path));
        let changed = file.set_tool(&tool, selector);
        if changed && !dry_run {
            file.write()?;
        }
        return Ok(PinWrite {
            tool,
            file: path,
            format: NATIVE.to_owned(),
            value: selector.to_string(),
            changed,
        });
    }
    let interop = find_interop(plugin, format)?;
    let path = dir.join(&interop.file);
    let raw = interop::format(
        &plugin.manifest,
        interop,
        selector.variant.as_deref(),
        &selector.value,
    )
    .map_err(|e| interop_error(&tool, &path, &e))?;
    let existing = read_optional(&path)?;
    let text = interop::write(interop, existing.as_deref(), &raw)
        .map_err(|e| interop_error(&tool, &path, &e))?;
    let changed = existing.as_deref() != Some(text.as_str());
    if changed && !dry_run {
        crate::project::write_atomic(&path, text.as_bytes())?;
    }
    Ok(PinWrite {
        tool,
        file: path,
        format: format.to_owned(),
        value: raw,
        changed,
    })
}

/// Removes `plugin`'s pins from every file in the directory of its winning pin in `pins`,
/// only from files in `format` when given. Returns the files changed, or with `dry_run` the
/// files that would change. A single-line file left empty is deleted.
pub fn remove_pins(
    pins: &ProjectPins,
    plugin: &Plugin,
    format: Option<&str>,
    dry_run: bool,
) -> Result<Vec<PathBuf>> {
    let tool = &plugin.manifest.name;
    let Some(pin) = pins.pins.get(tool) else {
        return Ok(Vec::new());
    };
    if pin.kind == PinKind::Wrapper {
        return Err(JtmError::usage(format!(
            "`{tool}` is pinned by the wrapper file {}, which jtm never edits",
            pin.file.display()
        )));
    }
    let Some(dir) = pin.file.parent() else {
        return Ok(Vec::new());
    };
    let mut removed = Vec::new();
    if format.is_none_or(|f| f == NATIVE)
        && let Some(mut file) = ProjectFile::read(dir)?
        && file.remove_tool(tool)
    {
        if !dry_run {
            file.write()?;
        }
        removed.push(file.path().to_path_buf());
    }
    for interop in plugin.manifest.interop.iter().filter(|i| {
        i.parser != InteropParser::Wrapper && format.is_none_or(|f| f == format_name(i))
    }) {
        let path = dir.join(&interop.file);
        let Some(text) = read_optional(&path)? else {
            continue;
        };
        let Some(rest) = interop::remove(interop, &text) else {
            continue;
        };
        if !dry_run {
            if rest.trim().is_empty() && interop.parser == InteropParser::SingleLine {
                fs::remove_file(&path).map_err(|e| JtmError::io(&path, e))?;
            } else {
                crate::project::write_atomic(&path, rest.as_bytes())?;
            }
        }
        removed.push(path);
    }
    Ok(removed)
}

fn find_interop<'p>(plugin: &'p Plugin, format: &str) -> Result<&'p Interop> {
    plugin
        .manifest
        .interop
        .iter()
        .find(|i| i.parser != InteropParser::Wrapper && format_name(i) == format)
        .ok_or_else(|| {
            JtmError::usage(format!(
                "`{}` cannot be pinned in format `{format}`; it supports {}",
                plugin.manifest.name,
                formats(plugin)
                    .iter()
                    .map(|f| format!("`{f}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

#[cfg(test)]
mod tests;
