//! `cargo xtask check-tool-names`: the CI check that no core crate names a first-party tool.
//!
//! The tool names come from the first-party manifests themselves: each plugin's name, its
//! variants, `[env]` variables and interop keys. The check looks at string literals in the
//! library crates' source, skipping comments (where examples are fine) and test code, and fails
//! on any literal that contains one of the names as a whole word.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// The crates that must stay free of tool names.
const CORE_CRATES: &[&str] = &[
    "jtm-archive",
    "jtm-core",
    "jtm-fetch",
    "jtm-plugin",
    "jtm-security",
];
/// Where the first-party manifests live.
const PLUGINS: &str = "crates/jtm-cli/plugins";
/// Literals allowed anyway: the built-in version schemes are named after the conventions they
/// implement (SPEC.md section 7), not after the tools.
const ALLOWED: &[(&str, &str)] = &[
    ("crates/jtm-plugin/src/version/mod.rs", "java"),
    ("crates/jtm-plugin/src/version/mod.rs", "maven"),
];

/// One string literal naming a tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Hit {
    pub(crate) path: String,
    pub(crate) line: usize,
    pub(crate) literal: String,
    pub(crate) name: String,
}

pub(crate) fn run(root: &Path) -> ExitCode {
    let names = match tool_names(&root.join(PLUGINS)) {
        Ok(names) if !names.is_empty() => names,
        Ok(_) => {
            eprintln!("no first-party manifests found under {PLUGINS}");
            return ExitCode::FAILURE;
        }
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };
    let mut hits = Vec::new();
    for krate in CORE_CRATES {
        for file in rust_files(&root.join("crates").join(krate).join("src")) {
            let Ok(source) = fs::read_to_string(&file) else {
                continue;
            };
            let rel = file
                .strip_prefix(root)
                .unwrap_or(&file)
                .to_string_lossy()
                .replace('\\', "/");
            hits.extend(check_source(&rel, &source, &names));
        }
    }
    if hits.is_empty() {
        println!("no tool names in {}", CORE_CRATES.join(", "));
        return ExitCode::SUCCESS;
    }
    for hit in &hits {
        eprintln!(
            "{}:{}: string literal {:?} names the tool `{}`",
            hit.path, hit.line, hit.literal, hit.name
        );
    }
    eprintln!(
        "core crates must not mention specific tools (SPEC.md section 15); move this into a \
         plugin manifest"
    );
    ExitCode::FAILURE
}

/// Every name the manifests under `dir` give their tools.
pub(crate) fn tool_names(dir: &Path) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    let entries = fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path().join("plugin.toml");
        let Ok(text) = fs::read_to_string(&path) else {
            continue;
        };
        let manifest: toml::Table =
            toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        names.extend(manifest_names(&manifest));
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn manifest_names(manifest: &toml::Table) -> Vec<String> {
    let strings = |value: Option<&toml::Value>| -> Vec<String> {
        value
            .and_then(toml::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    let keys = |value: Option<&toml::Value>| -> Vec<String> {
        value
            .and_then(toml::Value::as_table)
            .map(|t| t.keys().cloned().collect())
            .unwrap_or_default()
    };
    let mut names = Vec::new();
    names.extend(
        manifest
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
    );
    names.extend(strings(
        manifest.get("versions").and_then(|v| v.get("variants")),
    ));
    names.extend(keys(manifest.get("env")));
    if let Some(interop) = manifest.get("interop").and_then(|v| v.as_array()) {
        for entry in interop {
            names.extend(entry.get("key").and_then(|v| v.as_str()).map(str::to_owned));
        }
    }
    names
}

/// The literals in `source` naming one of `names`, skipping allowed ones.
pub(crate) fn check_source(path: &str, source: &str, names: &[String]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for (line, literal) in string_literals(source) {
        let Some(name) = names.iter().find(|n| contains_word(&literal, n)) else {
            continue;
        };
        if ALLOWED.contains(&(path, literal.as_str())) {
            continue;
        }
        hits.push(Hit {
            path: path.to_owned(),
            line,
            literal,
            name: name.clone(),
        });
    }
    hits
}

/// Whether `word` appears in `text` with no letter, digit or `_` on either side.
pub(crate) fn contains_word(text: &str, word: &str) -> bool {
    let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + word.len()..].chars().next();
        !before.is_some_and(is_word) && !after.is_some_and(is_word)
    })
}

/// The `.rs` files under `dir` that are not test code: no `tests.rs`, `testing.rs` or `tests`
/// directory.
fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if name != "tests" {
                    pending.push(path);
                }
            } else if name.ends_with(".rs") && name != "tests.rs" && name != "testing.rs" {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// The contents of every string literal in Rust `source`, with the line each starts on.
/// Comments, character literals and lifetimes are skipped; escapes are kept as written.
pub(crate) fn string_literals(source: &str) -> Vec<(usize, String)> {
    let chars: Vec<char> = source.chars().collect();
    let mut out = Vec::new();
    let mut line = 1;
    let mut i = 0;
    let at = |i: usize| chars.get(i).copied();
    while let Some(c) = at(i) {
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            '/' if at(i + 1) == Some('/') => {
                while at(i).is_some_and(|c| c != '\n') {
                    i += 1;
                }
            }
            '/' if at(i + 1) == Some('*') => {
                let mut depth = 0;
                while let Some(c) = at(i) {
                    if c == '/' && at(i + 1) == Some('*') {
                        depth += 1;
                        i += 2;
                    } else if c == '*' && at(i + 1) == Some('/') {
                        depth -= 1;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        if c == '\n' {
                            line += 1;
                        }
                        i += 1;
                    }
                }
            }
            'r' | 'b'
                if !at(i.wrapping_sub(1)).is_some_and(|p| p.is_alphanumeric() || p == '_') =>
            {
                // `r"..."`, `r#"..."#`, `br"..."`, or `b"..."`.
                let mut j = i + 1;
                if c == 'b' && at(j) == Some('r') {
                    j += 1;
                }
                let raw = c == 'r' || at(i + 1) == Some('r');
                let mut hashes = 0;
                while raw && at(j) == Some('#') {
                    hashes += 1;
                    j += 1;
                }
                if at(j) != Some('"') {
                    i += 1;
                    continue;
                }
                let start_line = line;
                let mut text = String::new();
                j += 1;
                if raw {
                    let close: String = std::iter::once('"')
                        .chain((0..hashes).map(|_| '#'))
                        .collect();
                    let close: Vec<char> = close.chars().collect();
                    while j < chars.len() && chars[j..].iter().take(close.len()).ne(close.iter()) {
                        if chars[j] == '\n' {
                            line += 1;
                        }
                        text.push(chars[j]);
                        j += 1;
                    }
                    i = j + close.len();
                } else {
                    i = read_quoted(&chars, j, &mut text, &mut line);
                }
                out.push((start_line, text));
            }
            '"' => {
                let start_line = line;
                let mut text = String::new();
                i = read_quoted(&chars, i + 1, &mut text, &mut line);
                out.push((start_line, text));
            }
            '\'' => {
                // A character literal such as `'"'` or `'\''`, or a lifetime such as `'a`.
                if at(i + 1) == Some('\\') {
                    i += 2;
                    while at(i).is_some_and(|c| c != '\'') {
                        i += 1;
                    }
                    i += 1;
                } else if at(i + 2) == Some('\'') {
                    i += 3;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    out
}

/// Reads an escaped string body starting at `i`, just after the opening quote, into `text`.
/// Returns the index after the closing quote.
fn read_quoted(chars: &[char], mut i: usize, text: &mut String, line: &mut usize) -> usize {
    while let Some(&c) = chars.get(i) {
        match c {
            '\\' => {
                text.push(c);
                if let Some(&next) = chars.get(i + 1) {
                    if next == '\n' {
                        *line += 1;
                    }
                    text.push(next);
                }
                i += 2;
            }
            '"' => return i + 1,
            _ => {
                if c == '\n' {
                    *line += 1;
                }
                text.push(c);
                i += 1;
            }
        }
    }
    i
}

#[cfg(test)]
mod tests;
