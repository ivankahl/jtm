//! Naming rules for plugins, variants and aliases (SPEC.md sections 4 and 16).

use crate::version::{MAX_VERSION_LEN, is_version_char};

/// The longest plugin name segment or variant name.
pub const MAX_NAME_LEN: usize = 64;

/// Why a name was rejected: the byte offset of the problem within the name, and a message.
pub type NameError = (usize, String);

/// Checks one name segment: lowercase ASCII letters and digits in hyphen-separated words,
/// starting with a letter, such as `temurin` or `graalvm-community`.
pub fn check_name_segment(name: &str, what: &str) -> Result<(), NameError> {
    let bytes = name.as_bytes();
    let Some(&first) = bytes.first() else {
        return Err((0, format!("a {what} cannot be empty")));
    };
    if name.len() > MAX_NAME_LEN {
        return Err((
            MAX_NAME_LEN,
            format!("a {what} is at most {MAX_NAME_LEN} characters"),
        ));
    }
    if !first.is_ascii_lowercase() {
        return Err((0, format!("a {what} must start with a lowercase letter")));
    }
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'a'..=b'z' | b'0'..=b'9' => {}
            b'-' if bytes.get(i + 1).is_some_and(|n| *n != b'-') => {}
            b'-' => {
                return Err((i, format!("a {what} cannot end with `-` or contain `--`")));
            }
            b'A'..=b'Z' => return Err((i, format!("a {what} must be lowercase"))),
            _ => {
                return Err((
                    i,
                    format!("a {what} may only contain lowercase letters, digits and `-`"),
                ));
            }
        }
    }
    Ok(())
}

/// Checks a plugin name: a bare first-party name such as `java`, or `<namespace>/<name>` for
/// third-party plugins.
pub fn check_plugin_name(name: &str) -> Result<(), NameError> {
    match name.split_once('/') {
        None => check_name_segment(name, "plugin name"),
        Some((namespace, rest)) => {
            check_name_segment(namespace, "plugin namespace")?;
            let offset = namespace.len() + 1;
            check_name_segment(rest, "plugin name").map_err(|(at, msg)| (offset + at, msg))
        }
    }
}

/// Checks a version or alias as typed in a spec, such as `21`, `lts` or `21.0.5+11`. It must
/// start with a letter or digit and use only characters a version may contain.
pub fn check_version_or_alias(value: &str) -> Result<(), NameError> {
    let Some(first) = value.chars().next() else {
        return Err((0, "expected a version or alias".to_owned()));
    };
    if value.len() > MAX_VERSION_LEN {
        return Err((
            MAX_VERSION_LEN,
            format!("a version or alias is at most {MAX_VERSION_LEN} characters"),
        ));
    }
    if !first.is_ascii_alphanumeric() {
        return Err((
            0,
            "a version or alias must start with a letter or digit".to_owned(),
        ));
    }
    match value.char_indices().find(|(_, c)| !is_version_char(*c)) {
        Some((i, c)) => Err((
            i,
            format!(
                "`{}` is not allowed in a version or alias; use letters, digits, `.`, `-`, `+` \
                 and `_`",
                c.escape_debug()
            ),
        )),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests;
