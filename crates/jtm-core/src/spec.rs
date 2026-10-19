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
    /// What follows `@`; `None` means the plugin's `default_alias`.
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
mod tests {
    use super::*;

    fn spec(tool: &str, variant: Option<&str>, value: Option<&str>) -> ToolSpec {
        ToolSpec {
            tool: tool.to_owned(),
            selector: value.map(|value| Selector {
                variant: variant.map(str::to_owned),
                value: value.to_owned(),
            }),
        }
    }

    #[test]
    fn valid_specs() {
        let cases = [
            ("java", spec("java", None, None)),
            ("java@21", spec("java", None, Some("21"))),
            ("java@temurin:21", spec("java", Some("temurin"), Some("21"))),
            ("java@lts", spec("java", None, Some("lts"))),
            (
                "java@temurin:lts",
                spec("java", Some("temurin"), Some("lts")),
            ),
            (
                "java@temurin:21.0.5+11",
                spec("java", Some("temurin"), Some("21.0.5+11")),
            ),
            (
                "java@graalvm-community:21",
                spec("java", Some("graalvm-community"), Some("21")),
            ),
            ("maven@3.9.9", spec("maven", None, Some("3.9.9"))),
            ("gradle@8.11-rc-1", spec("gradle", None, Some("8.11-rc-1"))),
            (
                "spring-boot-cli@3",
                spec("spring-boot-cli", None, Some("3")),
            ),
            ("acme/flyway@10.1", spec("acme/flyway", None, Some("10.1"))),
        ];
        for (input, expected) in cases {
            let parsed = ToolSpec::parse(input).unwrap();
            assert_eq!(parsed, expected, "{input}");
            assert_eq!(parsed.to_string(), input, "round trip");
            assert_eq!(input.parse::<ToolSpec>().unwrap(), expected);
        }
    }

    /// Each case is the input, the 1-based column of the problem, and a message fragment.
    #[test]
    fn invalid_specs_report_usage_with_column() {
        let cases = [
            ("", 1, "expected a tool name"),
            ("@21", 1, "expected a tool name"),
            ("Java@21", 1, "lowercase letter"),
            ("jaVa", 3, "must be lowercase"),
            ("1java", 1, "start with a lowercase letter"),
            ("java_8", 5, "lowercase letters, digits and `-`"),
            ("java-@21", 5, "cannot end with `-`"),
            (" java", 1, "lowercase letter"),
            ("java ", 5, "lowercase letters, digits and `-`"),
            ("java@", 6, "expected a version or alias after `@`"),
            ("java@@21", 6, "start with a letter or digit"),
            ("java@:21", 6, "expected a variant before `:`"),
            ("java@temurin:", 14, "expected a version or alias after `:`"),
            ("java@Temurin:21", 6, "lowercase letter"),
            ("java@temurin:21:1", 16, "`:` is not allowed"),
            ("java@temurin::21", 14, "start with a letter or digit"),
            ("java@21@22", 8, "`@` is not allowed"),
            ("java@21 ", 8, "` ` is not allowed"),
            ("java@.21", 6, "start with a letter or digit"),
            ("java@21/../x", 8, "`/` is not allowed"),
            ("acme//flyway", 6, "start with a lowercase letter"),
            ("acme/", 6, "cannot be empty"),
            ("jäva@21", 2, "lowercase letters, digits and `-`"),
            ("jäva@2ü", 2, "lowercase letters, digits and `-`"),
            ("java@2ü", 7, "is not allowed"),
        ];
        for (input, column, fragment) in cases {
            let err = ToolSpec::parse(input).unwrap_err();
            assert_eq!(err.code(), "E_USAGE", "{input}");
            let JtmError::InvalidSpec {
                column: got,
                ref message,
                ..
            } = err
            else {
                panic!("{input}: expected InvalidSpec, got {err:?}");
            };
            assert_eq!(got, column, "{input}: {message}");
            assert!(
                message.contains(fragment),
                "{input}: `{message}` should contain `{fragment}`"
            );
            assert_eq!(err.details()["column"], column, "{input}");
            assert_eq!(err.details()["input"], input, "{input}");
        }
    }

    #[test]
    fn overlong_values_are_rejected() {
        let long = format!("java@{}", "1".repeat(200));
        assert_eq!(ToolSpec::parse(&long).unwrap_err().code(), "E_USAGE");
        let long = format!("{}@1", "a".repeat(100));
        assert_eq!(ToolSpec::parse(&long).unwrap_err().code(), "E_USAGE");
    }

    #[test]
    fn error_message_names_input_and_column() {
        let err = ToolSpec::parse("java@").unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid spec `java@` at column 6: expected a version or alias after `@`, \
             such as `21` or `lts`"
        );
    }

    #[test]
    fn selectors_parse_on_their_own() {
        let selector = Selector::parse("temurin:21").unwrap();
        assert_eq!(selector.variant.as_deref(), Some("temurin"));
        assert_eq!(selector.value, "21");
        assert_eq!(selector.to_string(), "temurin:21");
        assert_eq!(Selector::parse("lts").unwrap().variant, None);

        let err = Selector::parse("").unwrap_err();
        assert_eq!(err.code(), "E_USAGE");
        let err = Selector::parse("temurin:").unwrap_err();
        assert_eq!(err.details()["column"], 9);
    }
}
