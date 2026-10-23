//! Interop pin files declared by `[[interop]]` (SPEC.md section 6).
//!
//! The core finds the files; this module reads a tool's value out of one, maps it to a variant
//! and version, and formats and writes values back. Where the variant sits depends on the
//! parser:
//!
//! - `keyvalue` (`.sdkmanrc`): `key=<version>-<suffix>`, where `mapping` turns the suffix into
//!   a variant, as in `java=21.0.5-tem`. A plugin with a mapping needs a known suffix.
//! - `tool-versions` and `single-line`: `[<variant>-]<version>`, where the prefix is a variant
//!   name or a `mapping` key, as in `temurin-21.0.5+11`.
//! - `wrapper`: read-only; the version comes from the distribution file name.
//!
//! A value that cannot be mapped is an error, never a guess.

use std::fmt;

use crate::manifest::{Interop, InteropParser, Manifest};
use crate::names::{check_name_segment, check_version_or_alias};
use crate::properties;

/// A value read from an interop file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteropValue {
    /// `None` means the plugin's default variant.
    pub variant: Option<String>,
    /// A version, version prefix or alias.
    pub value: String,
}

/// What a wrapper properties file pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrapperPin {
    pub version: String,
    /// The distribution URL, unescaped. jtm never downloads from it.
    pub url: String,
    /// The last path segment of `url`.
    pub file_name: String,
    /// The value under the entry's `sha256_key`, when it declares one and the file sets it.
    pub sha256: Option<String>,
}

/// Why an interop value could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteropError {
    /// The value cannot be mapped to a variant and version, or a variant to a value.
    Unmappable {
        file: String,
        value: String,
        message: String,
    },
    /// Wrapper files are never written, and are read with [`read_wrapper`].
    ReadOnly { file: String },
}

impl fmt::Display for InteropError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InteropError::Unmappable {
                file,
                value,
                message,
            } => write!(f, "{file}: `{value}` {message}"),
            InteropError::ReadOnly { file } => {
                write!(f, "{file}: jtm reads wrapper files but never writes them")
            }
        }
    }
}

impl std::error::Error for InteropError {}

/// Reads and maps the value `interop` declares from a pin file's `text`. `None` when the file
/// does not set the tool.
pub fn read(
    manifest: &Manifest,
    interop: &Interop,
    text: &str,
) -> Result<Option<InteropValue>, InteropError> {
    if interop.parser == InteropParser::Wrapper {
        return read_only(interop);
    }
    let Some(raw) = raw_value(interop, text) else {
        return Ok(None);
    };
    let unmappable = |message: String| InteropError::Unmappable {
        file: interop.file.clone(),
        value: raw.clone(),
        message,
    };
    let (variant, value) = match interop.parser {
        InteropParser::Keyvalue if interop.mapping.is_empty() => (None, raw.clone()),
        InteropParser::Keyvalue => {
            let found = interop
                .mapping
                .iter()
                .filter_map(|(suffix, variant)| {
                    let version = raw.strip_suffix(suffix.as_str())?.strip_suffix('-')?;
                    (!version.is_empty()).then_some((suffix.len(), variant, version))
                })
                .max_by_key(|(len, _, _)| *len);
            match found {
                Some((_, variant, version)) => (Some(variant.clone()), version.to_owned()),
                None => {
                    return Err(unmappable(format!(
                        "has no known suffix; expected `<version>-<suffix>` with a suffix \
                         from {}",
                        known(interop.mapping.keys())
                    )));
                }
            }
        }
        InteropParser::ToolVersions | InteropParser::SingleLine => {
            let names = interop
                .mapping
                .iter()
                .map(|(from, to)| (from.as_str(), to.as_str()))
                .chain(
                    manifest
                        .versions
                        .variants
                        .iter()
                        .map(|v| (v.as_str(), v.as_str())),
                );
            let found = names
                .filter_map(|(prefix, variant)| {
                    let version = raw.strip_prefix(prefix)?.strip_prefix('-')?;
                    (!version.is_empty()).then_some((prefix.len(), variant, version))
                })
                .max_by_key(|(len, _, _)| *len);
            match found {
                Some((_, variant, version)) => (Some(variant.to_owned()), version.to_owned()),
                None => {
                    let looks_prefixed =
                        raw.contains('-') && raw.starts_with(|c: char| c.is_ascii_alphabetic());
                    if looks_prefixed && !manifest.versions.variants.is_empty() {
                        let mut variants: Vec<&String> =
                            manifest.versions.variants.iter().collect();
                        variants.extend(interop.mapping.keys());
                        return Err(unmappable(format!(
                            "does not start with a known variant; expected \
                             `[<variant>-]<version>` with a variant from {}",
                            known(variants)
                        )));
                    }
                    (None, raw.clone())
                }
            }
        }
        InteropParser::Wrapper => read_only(interop)?,
    };
    if let Err((_, message)) = check_version_or_alias(&value) {
        return Err(unmappable(format!("is not a version: {message}")));
    }
    if let Some(variant) = &variant
        && let Err((_, message)) = check_name_segment(variant, "variant")
    {
        return Err(unmappable(message));
    }
    Ok(Some(InteropValue { variant, value }))
}

/// Formats `value` in `variant` (the default when `None`) as `interop`'s file writes it.
pub fn format(
    manifest: &Manifest,
    interop: &Interop,
    variant: Option<&str>,
    value: &str,
) -> Result<String, InteropError> {
    let variant = variant.unwrap_or_else(|| manifest.default_variant());
    let unmappable = |message: String| InteropError::Unmappable {
        file: interop.file.clone(),
        value: format!("{variant}:{value}"),
        message,
    };
    let reverse = interop
        .mapping
        .iter()
        .find(|(_, to)| to.as_str() == variant)
        .map(|(from, _)| from.as_str());
    match interop.parser {
        InteropParser::Keyvalue if interop.mapping.is_empty() => {
            if variant == manifest.default_variant() {
                Ok(value.to_owned())
            } else {
                Err(unmappable(format!(
                    "cannot be written: {} only holds the default variant",
                    interop.file
                )))
            }
        }
        InteropParser::Keyvalue => match reverse {
            Some(suffix) => Ok(format!("{value}-{suffix}")),
            None => Err(unmappable(format!(
                "cannot be written: no suffix maps to variant `{variant}`"
            ))),
        },
        InteropParser::ToolVersions | InteropParser::SingleLine => {
            if manifest.versions.variants.is_empty() {
                Ok(value.to_owned())
            } else {
                Ok(format!("{}-{value}", reverse.unwrap_or(variant)))
            }
        }
        InteropParser::Wrapper => read_only(interop),
    }
}

/// The file's new text with `raw` as the tool's value, keeping every other line. `existing` is
/// the current text, if the file exists.
pub fn write(interop: &Interop, existing: Option<&str>, raw: &str) -> Result<String, InteropError> {
    let line = match interop.parser {
        InteropParser::Keyvalue => format!("{}={raw}", key(interop)),
        InteropParser::ToolVersions => format!("{} {raw}", key(interop)),
        InteropParser::SingleLine => return Ok(format!("{raw}\n")),
        InteropParser::Wrapper => return read_only(interop),
    };
    let existing = existing.unwrap_or_default();
    let mut out = String::new();
    let mut replaced = false;
    for current in existing.split_inclusive('\n') {
        if !replaced && line_key(interop, current).is_some() {
            out.push_str(&line);
            out.push_str(line_ending(current));
            replaced = true;
        } else {
            out.push_str(current);
        }
    }
    if !replaced {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&line);
        out.push('\n');
    }
    Ok(out)
}

/// The file's text without the tool's value, or `None` when it does not set the tool. A
/// `single-line` file becomes empty.
pub fn remove(interop: &Interop, text: &str) -> Option<String> {
    if interop.parser == InteropParser::SingleLine {
        return raw_value(interop, text).map(|_| String::new());
    }
    let mut removed = false;
    let kept: String = text
        .split_inclusive('\n')
        .filter(|line| {
            let matches = line_key(interop, line).is_some();
            removed |= matches;
            !matches
        })
        .collect();
    removed.then_some(kept)
}

/// Reads a wrapper properties file: the version from the distribution file name, the URL, and
/// the declared SHA-256. `None` when the file has no distribution URL.
pub fn read_wrapper(interop: &Interop, text: &str) -> Result<Option<WrapperPin>, InteropError> {
    let (Some(url_key), Some(pattern)) = (&interop.key, &interop.pattern) else {
        return Err(InteropError::Unmappable {
            file: interop.file.clone(),
            value: String::new(),
            message: "is not declared as a wrapper file".to_owned(),
        });
    };
    let Some(url) = properties::get(text, url_key) else {
        return Ok(None);
    };
    let file_name = url.rsplit('/').next().unwrap_or_default().to_owned();
    let Some(version) = match_pattern(pattern, &file_name) else {
        return Err(InteropError::Unmappable {
            file: interop.file.clone(),
            value: file_name,
            message: format!("does not match `{pattern}`"),
        });
    };
    let sha256 = interop
        .sha256_key
        .as_ref()
        .and_then(|key| properties::get(text, key));
    Ok(Some(WrapperPin {
        version,
        url,
        file_name,
        sha256,
    }))
}

fn read_only<T>(interop: &Interop) -> Result<T, InteropError> {
    Err(InteropError::ReadOnly {
        file: interop.file.clone(),
    })
}

fn key(interop: &Interop) -> &str {
    interop.key.as_deref().unwrap_or_default()
}

/// The raw value the tool has in `text`.
fn raw_value(interop: &Interop, text: &str) -> Option<String> {
    match interop.parser {
        InteropParser::SingleLine => text
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#'))
            .map(str::to_owned),
        _ => text
            .split_inclusive('\n')
            .find_map(|line| line_key(interop, line)),
    }
}

/// The tool's raw value when `line` sets it.
fn line_key(interop: &Interop, line: &str) -> Option<String> {
    let line = line.trim();
    if line.starts_with('#') {
        return None;
    }
    match interop.parser {
        InteropParser::Keyvalue => {
            let (k, v) = line.split_once('=')?;
            (k.trim() == key(interop)).then(|| v.trim().to_owned())
        }
        InteropParser::ToolVersions => {
            let line = line.split('#').next().unwrap_or_default();
            let mut words = line.split_whitespace();
            (words.next()? == key(interop)).then(|| words.next().map(str::to_owned))?
        }
        InteropParser::SingleLine | InteropParser::Wrapper => None,
    }
}

fn line_ending(line: &str) -> &'static str {
    if line.ends_with("\r\n") {
        "\r\n"
    } else if line.ends_with('\n') {
        "\n"
    } else {
        ""
    }
}

fn known<'a>(names: impl IntoIterator<Item = &'a String>) -> String {
    names
        .into_iter()
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The version `name` holds in `pattern`'s `{version}` place. When several split points match,
/// the longest valid version wins, so `tool-8.11-rc-1-bin.zip` against `tool-{version}-*.zip`
/// reads `8.11-rc-1`.
fn match_pattern(pattern: &str, name: &str) -> Option<String> {
    let (before, after) = pattern.split_once("{version}")?;
    let mut best: Option<&str> = None;
    for start in 0..=name.len() {
        if !name.is_char_boundary(start) || !glob(before, &name[..start]) {
            continue;
        }
        for end in (start + 1)..=name.len() {
            if !name.is_char_boundary(end) || !glob(after, &name[end..]) {
                continue;
            }
            let version = &name[start..end];
            if check_version_or_alias(version).is_ok()
                && version.starts_with(|c: char| c.is_ascii_digit())
                && best.is_none_or(|b| version.len() > b.len())
            {
                best = Some(version);
            }
        }
    }
    best.map(str::to_owned)
}

/// Whether `text` matches `pattern`, where `*` matches any run of characters.
fn glob(pattern: &str, text: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == text,
        Some((head, tail)) => {
            let Some(rest) = text.strip_prefix(head) else {
                return false;
            };
            (0..=rest.len()).any(|i| rest.is_char_boundary(i) && glob(tail, &rest[i..]))
        }
    }
}

#[cfg(test)]
mod tests;
