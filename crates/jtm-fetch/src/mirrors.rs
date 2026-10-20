//! `[mirrors]` prefix rewrites (SPEC.md section 8). A rewrite changes where bytes come from,
//! never what is accepted: signatures and hashes are checked the same way afterwards.

use std::collections::BTreeMap;

/// Rewrites `url` with the longest prefix in `mirrors` that it starts with, or returns it
/// unchanged.
pub fn rewrite(url: &str, mirrors: &BTreeMap<String, String>) -> String {
    mirrors
        .iter()
        .filter(|(prefix, _)| url.starts_with(prefix.as_str()))
        .max_by_key(|(prefix, _)| prefix.len())
        .map_or_else(
            || url.to_owned(),
            |(prefix, replacement)| format!("{replacement}{}", &url[prefix.len()..]),
        )
}

#[cfg(test)]
mod tests;
