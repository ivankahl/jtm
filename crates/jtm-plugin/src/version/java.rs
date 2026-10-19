//! Java version strings, ordered like `java.lang.Runtime.Version`.
//!
//! Accepted forms:
//! - JEP 223: `$VNUM(-$PRE)?(+$BUILD)?(-$OPT)?`, such as `21.0.5+11` or `24-ea+3`.
//! - Vendor text after the build, kept as optional text: `21.0.5+11_openj9-0.48.0`,
//!   `21.0.5+11.1`.
//! - Pre-JEP 223 Java 8: `1.8.0_422-b05` and `8u422-b05`, which order exactly like `8.0.422+5`.

use std::cmp::Ordering;

use super::{cmp_numeric, cmp_numeric_lists, is_numeric};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct JavaKey {
    numbers: Vec<String>,
    pre: Option<String>,
    build: Option<String>,
    /// Optional text, including the separator that introduced it, such as `-LTS` or `.1`.
    opt: Option<String>,
    /// Whether the version was written in a pre-JEP 223 form.
    legacy: bool,
}

impl JavaKey {
    pub(super) fn is_prerelease(&self) -> bool {
        self.pre.is_some()
    }

    /// The JEP 223 spelling of a pre-JEP 223 version, such as `8.0.422+5` for `8u422-b05`, so
    /// `8` and `8.0.422` prefix-match it.
    pub(super) fn canonical(&self) -> Option<String> {
        if !self.legacy {
            return None;
        }
        let numbers = self.numbers.join(".");
        Some(match &self.build {
            Some(build) => format!("{numbers}+{}", build.trim_start_matches('0')),
            None => numbers,
        })
    }
}

pub(super) fn parse(input: &str) -> Result<JavaKey, &'static str> {
    if let Some(key) = parse_legacy(input) {
        return key;
    }

    let (main, build_part) = match input.split_once('+') {
        Some((main, build)) => (main, Some(build)),
        None => (input, None),
    };
    let (vnum, rest) = match main.split_once('-') {
        Some((vnum, rest)) => (vnum, Some(rest)),
        None => (main, None),
    };

    let numbers: Vec<String> = vnum.split('.').map(str::to_owned).collect();
    if numbers.iter().any(|n| !is_numeric(n)) {
        return Err("the version number must be dot-separated digits, such as `21.0.5`");
    }
    if numbers.iter().any(|n| n.len() > 1 && n.starts_with('0')) {
        return Err("version numbers cannot have leading zeros");
    }

    let (pre, opt_after_pre) = match rest {
        Some(rest) => match rest.find('-') {
            Some(at) => (Some(&rest[..at]), Some(&rest[at..])),
            None => (Some(rest), None),
        },
        None => (None, None),
    };
    if let Some(pre) = pre
        && (pre.is_empty() || !pre.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        return Err("the pre-release after `-` must be letters and digits, such as `ea`");
    }

    let (build, opt_after_build) = match build_part {
        Some(part) => {
            let digits = part.bytes().take_while(u8::is_ascii_digit).count();
            let (build, rest) = part.split_at(digits);
            if build.is_empty() && rest.is_empty() {
                return Err("a build number must follow `+`");
            }
            if !rest.is_empty() && !rest.starts_with(['-', '_', '.']) {
                return Err("the build number after `+` must be digits");
            }
            (
                Some(build).filter(|b| !b.is_empty()),
                Some(rest).filter(|r| !r.is_empty()),
            )
        }
        None => (None, None),
    };
    if opt_after_pre.is_some() && build_part.is_some() {
        return Err("optional text after the pre-release cannot be followed by `+`");
    }
    let opt = opt_after_pre.or(opt_after_build);
    if let Some(opt) = opt {
        check_opt(opt)?;
    }

    Ok(JavaKey {
        numbers,
        pre: pre.map(str::to_owned),
        build: build.map(str::to_owned),
        opt: opt.map(str::to_owned),
        legacy: false,
    })
}

/// Optional text is a separator followed by letters, digits, `-`, `_` and `.`.
fn check_opt(opt: &str) -> Result<(), &'static str> {
    let body = &opt[1..];
    if body.is_empty()
        || !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err("optional text must be letters, digits, `-`, `_` and `.`");
    }
    Ok(())
}

/// Parses `1.<major>.<minor>_<update>(-b<build>)?` and `<major>u<update>(-b<build>)?`.
/// Returns `None` when `input` is not in either form, so JEP 223 parsing can take over.
fn parse_legacy(input: &str) -> Option<Result<JavaKey, &'static str>> {
    let (numbers, build) = if let Some(rest) = input.strip_prefix("1.")
        && rest.contains('_')
    {
        let (version, build) = split_build(rest);
        let parts = version
            .split_once('_')
            .and_then(|(major_minor, update)| {
                let (major, minor) = major_minor.split_once('.')?;
                Some([major, minor, update])
            })
            .filter(|parts| parts.iter().all(|p| is_numeric(p)));
        let Some(parts) = parts else {
            return Some(Err(
                "a pre-JEP 223 version looks like `1.8.0_422` or `1.8.0_422-b05`",
            ));
        };
        (parts, build)
    } else {
        let digits = input.bytes().take_while(u8::is_ascii_digit).count();
        let (major, rest) = input.split_at(digits);
        let rest = rest.strip_prefix('u').filter(|_| digits > 0)?;
        let (update, build) = split_build(rest);
        if !is_numeric(update) {
            return Some(Err(
                "a pre-JEP 223 version looks like `8u422` or `8u422-b05`",
            ));
        }
        ([major, "0", update], build)
    };
    let build = match build {
        Some(build) if is_numeric(build) => Some(build.to_owned()),
        Some(_) => return Some(Err("the build after `-b` must be digits")),
        None => None,
    };
    Some(Ok(JavaKey {
        numbers: numbers.iter().map(|n| (*n).to_owned()).collect(),
        pre: None,
        build,
        opt: None,
        legacy: true,
    }))
}

/// Splits `422-b05` into `422` and the build `05`.
fn split_build(text: &str) -> (&str, Option<&str>) {
    match text.split_once("-b") {
        Some((version, build)) => (version, Some(build)),
        None => (text, None),
    }
}

impl Ord for JavaKey {
    fn cmp(&self, other: &JavaKey) -> Ordering {
        let a: Vec<&str> = self.numbers.iter().map(String::as_str).collect();
        let b: Vec<&str> = other.numbers.iter().map(String::as_str).collect();
        cmp_numeric_lists(&a, &b)
            // A pre-release sorts before the release it leads up to.
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => cmp_identifier(a, b),
            })
            .then_with(|| match (&self.build, &other.build) {
                (Some(a), Some(b)) => cmp_numeric(a, b),
                (a, b) => a.is_some().cmp(&b.is_some()),
            })
            .then_with(|| match (&self.opt, &other.opt) {
                (Some(a), Some(b)) => cmp_natural(a, b),
                (a, b) => a.is_some().cmp(&b.is_some()),
            })
    }
}

impl PartialOrd for JavaKey {
    fn partial_cmp(&self, other: &JavaKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Numeric identifiers compare by value and sort before alphanumeric ones, which compare as
/// text.
fn cmp_identifier(a: &str, b: &str) -> Ordering {
    match (is_numeric(a), is_numeric(b)) {
        (true, true) => cmp_numeric(a, b).then_with(|| a.cmp(b)),
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => a.cmp(b),
    }
}

/// Compares text in natural order: runs of digits by value, so `.10` sorts after `.2`. Equal
/// only for equal text, which keeps the order total.
fn cmp_natural(a: &str, b: &str) -> Ordering {
    let (ta, tb) = (runs(a), runs(b));
    ta.iter()
        .zip(&tb)
        .map(|(x, y)| cmp_identifier(x, y))
        .find(|o| o.is_ne())
        .unwrap_or_else(|| ta.len().cmp(&tb.len()))
}

/// Splits text into maximal runs of digits and of other characters.
fn runs(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut start = 0;
    for i in 1..bytes.len() {
        if bytes[i].is_ascii_digit() != bytes[i - 1].is_ascii_digit() {
            out.push(&text[start..i]);
            start = i;
        }
    }
    if start < text.len() {
        out.push(&text[start..]);
    }
    out
}
