//! Parsing of `<tool>[@[<variant>:]<version-or-alias>]` specs (SPEC.md section 4).
//!
//! Parsing only checks syntax. Whether the value is an alias or a version, and whether the
//! variant exists, depends on the plugin and is decided during resolution.

use std::fmt;
use std::str::FromStr;

use jtm_plugin::names::{NameError, check_name_segment, check_plugin_name, check_version_or_alias};

use crate::error::{JtmError, Result};

/// A spec as typed on the command line, such as `java@temurin:21` or `maven`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ToolSpec {
    /// The plugin name, such as `java` or `acme/flyway`.
    pub tool: String,
    /// What follows `@`; `None` means the plugin's default, as `resolve_default` resolves it.
    pub selector: Option<Selector>,
}

/// The part of a spec after `@`, also the value of a pin, such as `temurin:21`, `lts` or `3.9`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Selector {
    /// `None` means the plugin's `default_variant`.
    pub variant: Option<String>,
    /// A version, a version prefix or an alias.
    pub value: String,
}

impl ToolSpec {
    /// Parses a full spec. Errors are `E_USAGE` with the 1-based column of the problem.
    pub fn parse(input: &str) -> Result<ToolSpec> {
        let (tool, rest) = match input.split_once('@') {
            Some((tool, rest)) => (tool, Some(rest)),
            None => (input, None),
        };
        if tool.is_empty() {
            return Err(spec_error(input, 0, "expected a tool name"));
        }
        check_plugin_name(tool).map_err(|e| at(input, 0, e))?;
        let selector = match rest {
            Some(rest) => Some(Selector::parse_within(input, tool.len() + 1, rest)?),
            None => None,
        };
        Ok(ToolSpec {
            tool: tool.to_owned(),
            selector,
        })
    }
}

impl Selector {
    /// Parses a selector on its own, such as a `.jtm.toml` pin value.
    pub fn parse(input: &str) -> Result<Selector> {
        Selector::parse_within(input, 0, input)
    }

    /// Parses `text`, which starts at byte `offset` of `input`, reporting errors against `input`.
    fn parse_within(input: &str, offset: usize, text: &str) -> Result<Selector> {
        if text.is_empty() {
            let message = if offset == 0 {
                "expected a version or alias, such as `21` or `lts`"
            } else {
                "expected a version or alias after `@`, such as `21` or `lts`"
            };
            return Err(spec_error(input, offset, message));
        }
        let (variant, value, value_offset) = match text.split_once(':') {
            Some((variant, value)) => {
                if variant.is_empty() {
                    return Err(spec_error(input, offset, "expected a variant before `:`"));
                }
                check_name_segment(variant, "variant").map_err(|e| at(input, offset, e))?;
                (Some(variant), value, offset + variant.len() + 1)
            }
            None => (None, text, offset),
        };
        if value.is_empty() {
            return Err(spec_error(
                input,
                value_offset,
                "expected a version or alias after `:`, such as `21`",
            ));
        }
        check_version_or_alias(value).map_err(|e| at(input, value_offset, e))?;
        Ok(Selector {
            variant: variant.map(str::to_owned),
            value: value.to_owned(),
        })
    }
}

/// Maps a [`NameError`] at byte `offset` of `input` to a spec error.
fn at(input: &str, offset: usize, (inner, message): NameError) -> JtmError {
    spec_error(input, offset + inner, &message)
}

fn spec_error(input: &str, byte_offset: usize, message: &str) -> JtmError {
    let end = byte_offset.min(input.len());
    // Count characters, not bytes, so the column lines up with what the user typed. A byte
    // offset inside a multi-byte character counts that character.
    let column = input.char_indices().take_while(|(i, _)| *i < end).count() + 1;
    JtmError::InvalidSpec {
        input: input.to_owned(),
        column,
        message: message.to_owned(),
    }
}

impl FromStr for ToolSpec {
    type Err = JtmError;

    fn from_str(s: &str) -> Result<ToolSpec> {
        ToolSpec::parse(s)
    }
}

impl FromStr for Selector {
    type Err = JtmError;

    fn from_str(s: &str) -> Result<Selector> {
        Selector::parse(s)
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(variant) = &self.variant {
            write!(f, "{variant}:")?;
        }
        f.write_str(&self.value)
    }
}

impl fmt::Display for ToolSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.tool)?;
        if let Some(selector) = &self.selector {
            write!(f, "@{selector}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
