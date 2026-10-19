//! JEP 223 version strings: `$VNUM(-$PRE)?(+$BUILD)?(-$OPT)?`, ordered like
//! `java.lang.Runtime.Version`.

use std::cmp::Ordering;

use super::{cmp_numeric, cmp_numeric_lists, is_numeric};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct JavaKey {
    numbers: Vec<String>,
    pre: Option<String>,
    build: Option<String>,
    opt: Option<String>,
}

impl JavaKey {
    pub(super) fn is_prerelease(&self) -> bool {
        self.pre.is_some()
    }
}

pub(super) fn parse(input: &str) -> Result<JavaKey, &'static str> {
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
        Some(rest) => match rest.split_once('-') {
            Some((pre, opt)) => (Some(pre), Some(opt)),
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
        Some(part) => match part.split_once('-') {
            Some((build, opt)) => (Some(build), Some(opt)),
            None => (Some(part), None),
        },
        None => (None, None),
    };
    if opt_after_pre.is_some() && build.is_some() {
        return Err("optional text after the pre-release cannot be followed by `+`");
    }
    let opt = opt_after_pre.or(opt_after_build);
    if let Some(build) = build {
        if build.is_empty() && opt.is_none() {
            return Err("a build number must follow `+`");
        }
        if !build.is_empty() && !is_numeric(build) {
            return Err("the build number after `+` must be digits");
        }
    }
    if let Some(opt) = opt
        && (opt.is_empty()
            || !opt
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.')))
    {
        return Err("optional text must be letters, digits, `-` and `.`");
    }

    Ok(JavaKey {
        numbers,
        pre: pre.map(str::to_owned),
        build: build.filter(|b| !b.is_empty()).map(str::to_owned),
        opt: opt.map(str::to_owned),
    })
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
            .then_with(|| self.opt.cmp(&other.opt))
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
