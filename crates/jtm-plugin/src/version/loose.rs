//! Loose semantic versions: one or more dot-separated numbers, an optional pre-release after
//! `-` and optional build text after `+`. Accepts `8.10`, `8.11-rc-1` and `2.1.0-Beta2`.

use std::cmp::Ordering;

use super::{cmp_numeric, cmp_numeric_lists, is_numeric};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LooseKey {
    numbers: Vec<String>,
    /// Lowercased pre-release identifiers, split at `.`, `-`, `_` and digit-letter boundaries.
    pre: Option<Vec<String>>,
    build: Option<String>,
}

impl LooseKey {
    pub(super) fn is_prerelease(&self) -> bool {
        self.pre.is_some()
    }
}

pub(super) fn parse(input: &str) -> Result<LooseKey, &'static str> {
    let (rest, build) = match input.split_once('+') {
        Some((rest, build)) => (rest, Some(build)),
        None => (input, None),
    };
    let (core, pre) = match rest.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (rest, None),
    };

    let numbers: Vec<String> = core.split('.').map(str::to_owned).collect();
    if numbers.iter().any(|n| !is_numeric(n)) {
        return Err("the version must start with dot-separated numbers, such as `8.10`");
    }

    let pre = match pre {
        Some(pre) => {
            let ids: Vec<&str> = pre.split(['.', '-', '_']).collect();
            if ids.iter().any(|id| id.is_empty()) {
                return Err("the pre-release after `-` has an empty part");
            }
            Some(
                ids.into_iter()
                    .flat_map(split_digit_boundaries)
                    .map(|id| id.to_ascii_lowercase())
                    .collect(),
            )
        }
        None => None,
    };

    if let Some(build) = build
        && (build.is_empty() || build.contains('+'))
    {
        return Err("the build text after `+` must be non-empty and contain no other `+`");
    }

    Ok(LooseKey {
        numbers,
        pre,
        build: build.map(str::to_owned),
    })
}

/// Splits `rc2` into `rc` and `2` so `beta10` sorts after `beta9`.
fn split_digit_boundaries(id: &str) -> Vec<&str> {
    let bytes = id.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0;
    for i in 1..bytes.len() {
        if bytes[i].is_ascii_digit() != bytes[i - 1].is_ascii_digit() {
            parts.push(&id[start..i]);
            start = i;
        }
    }
    parts.push(&id[start..]);
    parts
}

impl Ord for LooseKey {
    fn cmp(&self, other: &LooseKey) -> Ordering {
        let a: Vec<&str> = self.numbers.iter().map(String::as_str).collect();
        let b: Vec<&str> = other.numbers.iter().map(String::as_str).collect();
        cmp_numeric_lists(&a, &b)
            .then_with(|| match (&self.pre, &other.pre) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => cmp_pre(a, b),
            })
            .then_with(|| self.build.cmp(&other.build))
    }
}

impl PartialOrd for LooseKey {
    fn partial_cmp(&self, other: &LooseKey) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Semver pre-release precedence: identifiers left to right, numbers by value and before
/// words, and a shorter list first when one is a prefix of the other.
fn cmp_pre(a: &[String], b: &[String]) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        let order = match (is_numeric(x), is_numeric(y)) {
            (true, true) => cmp_numeric(x, y).then_with(|| x.cmp(y)),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => x.cmp(y),
        };
        if order.is_ne() {
            return order;
        }
    }
    a.len().cmp(&b.len())
}
