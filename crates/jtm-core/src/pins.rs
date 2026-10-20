//! Finding a project's pins (SPEC.md sections 5 and 6).
//!
//! Walking up from the working directory, the nearest directory with any pin file setting a
//! tool decides that tool. Within one directory `.jtm.toml` comes first, then the interop files
//! plugins declare, in parser order (`keyvalue`, `tool-versions`, `single-line`, which is
//! `.sdkmanrc`, `.tool-versions`, `.java-version` for the first-party plugins) and then by file
//! name. The first file setting a tool wins, and any other file in that directory setting a
//! different value is reported as a conflict. Wrapper files count only when no pin file in any
//! directory sets the tool.

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
    let default_variant = |tool: &str| {
        plugins
            .iter()
            .find(|p| p.manifest.name == tool)
            .map(|p| p.manifest.default_variant().to_owned())
            .unwrap_or_default()
    };

    let mut found = ProjectPins::default();
    for dir in start.ancestors() {
        // Every pin this directory sets, per tool, in read order.
        let mut here: BTreeMap<String, Vec<(PathBuf, Selector, PinKind)>> = BTreeMap::new();
        if let Some(file) = ProjectFile::read(dir)? {
            found.files.push(file.path().to_path_buf());
            for (tool, selector) in file.tools() {
                if !plugins.iter().any(|p| p.manifest.name == tool) {
                    return Err(JtmError::PinToolUnknown {
                        tool,
                        file: file.path().to_path_buf(),
                    });
                }
                here.entry(tool).or_default().push((
                    file.path().to_path_buf(),
                    selector,
                    PinKind::Native,
                ));
            }
        }
        let mut texts: BTreeMap<PathBuf, Option<String>> = BTreeMap::new();
        for source in sources
            .iter()
            .filter(|s| s.interop.parser != InteropParser::Wrapper)
        {
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
            let tool = &source.plugin.manifest.name;
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
        for (tool, values) in here {
            if found.pins.contains_key(&tool) {
                continue;
            }
            let default = default_variant(&tool);
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

    for source in sources
        .iter()
        .filter(|s| s.interop.parser == InteropParser::Wrapper)
    {
        let tool = &source.plugin.manifest.name;
        if found.pins.contains_key(tool) {
            continue;
        }
        for dir in start.ancestors() {
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
    }
    Ok(found)
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

#[cfg(test)]
mod tests;
