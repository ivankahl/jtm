//! Version schemes: parsing, total ordering and segment-prefix matching (SPEC.md section 7).
//!
//! A plugin picks one scheme for all of its versions. Versions from different schemes are never
//! compared in practice; [`Version`]'s ordering still sorts them by scheme first so it stays
//! total.

mod java;
mod loose;
mod maven;

use std::cmp::Ordering;
use std::fmt;

/// The longest version string jtm accepts.
pub const MAX_VERSION_LEN: usize = 128;

/// A built-in version ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VersionScheme {
    /// JEP 223 Java versions, such as `21.0.5+11` or `24-ea+3`.
    Java,
    /// Maven's `ComparableVersion` rules, such as `3.9.9` or `4.0.0-rc-2`.
    Maven,
    /// Dotted numbers with an optional pre-release, such as `8.10` or `8.11-rc-1`.
    SemverLoose,
}

impl VersionScheme {
    pub const ALL: &[VersionScheme] = &[
        VersionScheme::Java,
        VersionScheme::Maven,
        VersionScheme::SemverLoose,
    ];

    /// The name used in `plugin.toml`, such as `semver-loose`.
    pub const fn as_str(self) -> &'static str {
        match self {
            VersionScheme::Java => "java",
            VersionScheme::Maven => "maven",
            VersionScheme::SemverLoose => "semver-loose",
        }
    }

    /// Parses `input` as a version under this scheme.
    pub fn parse(self, input: &str) -> Result<Version, VersionError> {
        let fail = |reason: String| VersionError {
            scheme: self,
            input: input.to_owned(),
            reason,
        };
        if input.is_empty() {
            return Err(fail("a version cannot be empty".to_owned()));
        }
        if input.len() > MAX_VERSION_LEN {
            return Err(fail(format!(
                "a version is at most {MAX_VERSION_LEN} characters"
            )));
        }
        if let Some(c) = input.chars().find(|c| !is_version_char(*c)) {
            return Err(fail(format!(
                "`{}` is not allowed; use letters, digits, `.`, `-`, `+` and `_`",
                c.escape_debug()
            )));
        }
        let key = match self {
            VersionScheme::Java => java::parse(input).map(Key::Java),
            VersionScheme::Maven => Ok(Key::Maven(maven::parse(input))),
            VersionScheme::SemverLoose => loose::parse(input).map(Key::Loose),
        }
        .map_err(|reason| fail(reason.to_owned()))?;
        Ok(Version {
            raw: input.to_owned(),
            key,
        })
    }
}

impl fmt::Display for VersionScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Characters any scheme may contain. Keeping this narrow means a version is always safe to use
/// in a directory name and a URL path.
pub const fn is_version_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+' | '_')
}

/// A version string that failed to parse under a scheme.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{input}` is not a valid {scheme} version: {reason}")]
pub struct VersionError {
    pub scheme: VersionScheme,
    pub input: String,
    pub reason: String,
}

/// A parsed version. Ordering follows the scheme's rules; versions the scheme considers equal,
/// such as `21` and `21.0.0`, are ordered by their text so the order stays total.
#[derive(Debug, Clone)]
pub struct Version {
    raw: String,
    key: Key,
}

#[derive(Debug, Clone)]
enum Key {
    Java(java::JavaKey),
    Maven(maven::Item),
    Loose(loose::LooseKey),
}

impl Version {
    /// The version exactly as written.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub fn scheme(&self) -> VersionScheme {
        match self.key {
            Key::Java(_) => VersionScheme::Java,
            Key::Maven(_) => VersionScheme::Maven,
            Key::Loose(_) => VersionScheme::SemverLoose,
        }
    }

    /// Whether the scheme marks this as a pre-release, such as `24-ea`, `4.0.0-rc-2` or
    /// `8.11-rc-1`.
    pub fn is_prerelease(&self) -> bool {
        match &self.key {
            Key::Java(key) => key.is_prerelease(),
            Key::Maven(item) => maven::is_prerelease(item),
            Key::Loose(key) => key.is_prerelease(),
        }
    }

    /// Whether `prefix` is a whole-segment prefix of this version: `21` matches `21.0.5+11` but
    /// not `210.1`, and `8.11-rc` matches `8.11-rc-1`. A full version matches itself.
    pub fn matches_prefix(&self, prefix: &str) -> bool {
        let want = segments(prefix);
        let have = segments(&self.raw);
        !want.is_empty()
            && want.len() <= have.len()
            && want.iter().zip(&have).all(|(w, h)| w.same_as(h))
    }

    /// Compares two versions under their scheme's rules only, so `21` and `21.0.0` are equal.
    pub fn cmp_precedence(&self, other: &Version) -> Ordering {
        match (&self.key, &other.key) {
            (Key::Java(a), Key::Java(b)) => a.cmp(b),
            (Key::Maven(a), Key::Maven(b)) => maven::compare(a, Some(b)),
            (Key::Loose(a), Key::Loose(b)) => a.cmp(b),
            _ => self.scheme().cmp(&other.scheme()),
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Version) -> Ordering {
        self.cmp_precedence(other)
            .then_with(|| self.raw.cmp(&other.raw))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Version) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Version) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl std::hash::Hash for Version {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Equal versions have equal text, so hashing the text agrees with `Eq`.
        self.raw.hash(state);
    }
}

/// One run of digits or letters, with the separator before it (`None` at a digit-letter
/// boundary or at the start).
#[derive(Debug)]
struct Segment<'a> {
    separator: Option<char>,
    text: &'a str,
}

impl Segment<'_> {
    fn same_as(&self, other: &Segment<'_>) -> bool {
        self.separator == other.separator
            && match (is_numeric(self.text), is_numeric(other.text)) {
                (true, true) => cmp_numeric(self.text, other.text) == Ordering::Equal,
                (false, false) => self.text.eq_ignore_ascii_case(other.text),
                _ => false,
            }
    }
}

fn segments(input: &str) -> Vec<Segment<'_>> {
    let mut out = Vec::new();
    let mut separator = None;
    let mut start = None;
    let bytes = input.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii_alphanumeric() {
            match start {
                None => start = Some(i),
                Some(s) if bytes[s].is_ascii_digit() != b.is_ascii_digit() => {
                    out.push(Segment {
                        separator: separator.take(),
                        text: &input[s..i],
                    });
                    start = Some(i);
                }
                Some(_) => {}
            }
        } else {
            if let Some(s) = start.take() {
                out.push(Segment {
                    separator: separator.take(),
                    text: &input[s..i],
                });
            }
            separator = Some(char::from(b));
        }
    }
    if let Some(s) = start {
        out.push(Segment {
            separator,
            text: &input[s..],
        });
    }
    out
}

fn is_numeric(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Compares two digit strings by value, at any length.
fn cmp_numeric(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Compares two numeric lists as if padded with zeros to the same length.
fn cmp_numeric_lists(a: &[&str], b: &[&str]) -> Ordering {
    let len = a.len().max(b.len());
    (0..len)
        .map(|i| cmp_numeric(a.get(i).unwrap_or(&"0"), b.get(i).unwrap_or(&"0")))
        .find(|o| o.is_ne())
        .unwrap_or(Ordering::Equal)
}

#[cfg(test)]
mod tests;
