//! Maven's `ComparableVersion` ordering, ported from `org.apache.maven.artifact.versioning`.
//!
//! A version becomes a tree of items. `.` separates items in a list, while `-` and a change
//! between digits and letters start a nested list. Trailing zeros and release qualifiers are
//! dropped, so `1.0.0`, `1` and `1-ga` are equal. Qualifiers order as
//! `alpha < beta < milestone < rc = cr < snapshot < (release) < sp < anything else`.

use std::cmp::Ordering;

use super::cmp_numeric;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Item {
    /// Digits without leading zeros; `0` is stored as the empty string.
    Int(String),
    /// A lowercased qualifier, with aliases resolved (`a1` to `alpha`, `ga` to the empty string).
    Str(String),
    List(Vec<Item>),
}

const QUALIFIERS: &[&str] = &["alpha", "beta", "milestone", "rc", "snapshot", "", "sp"];
const RELEASE_INDEX: usize = 5;

impl Item {
    fn int(digits: &str) -> Item {
        Item::Int(digits.trim_start_matches('0').to_owned())
    }

    fn string(value: &str, followed_by_digit: bool) -> Item {
        let value = match value {
            "a" if followed_by_digit => "alpha",
            "b" if followed_by_digit => "beta",
            "m" if followed_by_digit => "milestone",
            "ga" | "final" | "release" => "",
            "cr" => "rc",
            other => other,
        };
        Item::Str(value.to_owned())
    }

    fn is_null(&self) -> bool {
        match self {
            Item::Int(digits) => digits.is_empty(),
            Item::Str(value) => value.is_empty(),
            Item::List(items) => items.is_empty(),
        }
    }
}

/// Parses any version text. Maven accepts every string, so this cannot fail.
pub(super) fn parse(input: &str) -> Item {
    let version = input.to_ascii_lowercase();
    let bytes = version.as_bytes();

    // A stack of lists under construction; each nested list is pushed into its parent when it
    // is closed, so the root ends up holding the whole tree.
    let mut stack: Vec<Vec<Item>> = vec![Vec::new()];
    let mut is_digit = false;
    let mut start = 0;

    let parse_item = |is_digit: bool, text: &str| {
        if is_digit {
            Item::int(text)
        } else {
            Item::string(text, false)
        }
    };

    for (i, &c) in bytes.iter().enumerate() {
        let list = stack.len() - 1;
        match c {
            b'.' | b'-' => {
                let item = if i == start {
                    Item::Int(String::new())
                } else {
                    parse_item(is_digit, &version[start..i])
                };
                stack[list].push(item);
                start = i + 1;
                if c == b'-' {
                    stack.push(Vec::new());
                }
            }
            b'0'..=b'9' => {
                if !is_digit && i > start {
                    stack[list].push(Item::string(&version[start..i], true));
                    start = i;
                    stack.push(Vec::new());
                }
                is_digit = true;
            }
            _ => {
                if is_digit && i > start {
                    stack[list].push(parse_item(true, &version[start..i]));
                    start = i;
                    stack.push(Vec::new());
                }
                is_digit = false;
            }
        }
    }
    if bytes.len() > start {
        let list = stack.len() - 1;
        stack[list].push(parse_item(is_digit, &version[start..]));
    }

    // Close nested lists innermost first, normalising each before it joins its parent.
    let mut closed = normalize(stack.pop().unwrap_or_default());
    while let Some(mut parent) = stack.pop() {
        parent.push(Item::List(closed));
        closed = normalize(parent);
    }
    Item::List(closed)
}

/// Drops trailing null items, looking through trailing nested lists.
fn normalize(mut items: Vec<Item>) -> Vec<Item> {
    let mut i = items.len();
    while i > 0 {
        i -= 1;
        if items[i].is_null() {
            items.remove(i);
        } else if !matches!(items[i], Item::List(_)) {
            break;
        }
    }
    items
}

fn qualifier_rank(value: &str) -> (usize, &str) {
    match QUALIFIERS.iter().position(|q| *q == value) {
        Some(index) => (index, ""),
        None => (QUALIFIERS.len(), value),
    }
}

/// Compares `a` with `b`, where `None` stands for a missing item at the end of a shorter list.
pub(super) fn compare(a: &Item, b: Option<&Item>) -> Ordering {
    match (a, b) {
        (Item::Int(x), None) => {
            if x.is_empty() {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        }
        (Item::Int(x), Some(Item::Int(y))) => cmp_numeric(x, y),
        (Item::Int(_), Some(_)) => Ordering::Greater,

        (Item::Str(x), None) => qualifier_rank(x).cmp(&(RELEASE_INDEX, "")),
        (Item::Str(_), Some(Item::Int(_))) => Ordering::Less,
        (Item::Str(x), Some(Item::Str(y))) => qualifier_rank(x).cmp(&qualifier_rank(y)),
        (Item::Str(_), Some(Item::List(_))) => Ordering::Less,

        (Item::List(items), None) => items
            .iter()
            .map(|item| compare(item, None))
            .find(|o| o.is_ne())
            .unwrap_or(Ordering::Equal),
        (Item::List(_), Some(Item::Int(_))) => Ordering::Less,
        (Item::List(_), Some(Item::Str(_))) => Ordering::Greater,
        (Item::List(xs), Some(Item::List(ys))) => {
            let len = xs.len().max(ys.len());
            (0..len)
                .map(|i| match (xs.get(i), ys.get(i)) {
                    (Some(x), y) => compare(x, y),
                    (None, Some(y)) => compare(y, None).reverse(),
                    (None, None) => Ordering::Equal,
                })
                .find(|o| o.is_ne())
                .unwrap_or(Ordering::Equal)
        }
    }
}

/// Whether the version carries a qualifier that sorts before a release, such as `rc`.
pub(super) fn is_prerelease(item: &Item) -> bool {
    match item {
        Item::Int(_) => false,
        Item::Str(value) => qualifier_rank(value).0 < RELEASE_INDEX,
        Item::List(items) => items.iter().any(is_prerelease),
    }
}
