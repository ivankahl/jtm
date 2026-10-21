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
    let mut lexer = Lexer {
        chars: source.chars().collect(),
        i: 0,
        line: 1,
        out: Vec::new(),
    };
    while let Some(c) = lexer.at(0) {
        match c {
            '\n' => {
                lexer.line += 1;
                lexer.i += 1;
            }
            '/' if lexer.at(1) == Some('/') => lexer.skip_line_comment(),
            '/' if lexer.at(1) == Some('*') => lexer.skip_block_comment(),
            'r' | 'b' if !lexer.after_identifier() => lexer.prefixed_string(c),
            '"' => {
                lexer.i += 1;
                lexer.quoted();
            }
            '\'' => lexer.skip_char_or_lifetime(),
            _ => lexer.i += 1,
        }
    }
    lexer.out
}

/// A cursor over Rust source collecting string literals.
struct Lexer {
    chars: Vec<char>,
    i: usize,
    line: usize,
    out: Vec<(usize, String)>,
}

impl Lexer {
    /// The character `offset` places after the cursor.
    fn at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.i + offset).copied()
    }

    /// Whether the cursor follows an identifier character, so an `r` or `b` there is part of
    /// a name rather than a string prefix.
    fn after_identifier(&self) -> bool {
        self.i
            .checked_sub(1)
            .and_then(|p| self.chars.get(p))
            .is_some_and(|p| p.is_alphanumeric() || *p == '_')
    }

    fn skip_line_comment(&mut self) {
        while self.at(0).is_some_and(|c| c != '\n') {
            self.i += 1;
        }
    }

    /// Skips a `/* ... */` comment, which may nest.
    fn skip_block_comment(&mut self) {
        let mut depth = 0;
        while let Some(c) = self.at(0) {
            if c == '/' && self.at(1) == Some('*') {
                depth += 1;
                self.i += 2;
            } else if c == '*' && self.at(1) == Some('/') {
                depth -= 1;
                self.i += 2;
                if depth == 0 {
                    return;
                }
            } else {
                self.newline(c);
                self.i += 1;
            }
        }
    }

    /// A string after an `r` or `b` prefix: `r"..."`, `r#"..."#`, `br"..."` or `b"..."`. Any
    /// other use of the letter is skipped.
    fn prefixed_string(&mut self, c: char) {
        let mut j = self.i + 1;
        if c == 'b' && self.chars.get(j) == Some(&'r') {
            j += 1;
        }
        let raw = c == 'r' || self.at(1) == Some('r');
        let mut hashes = 0;
        while raw && self.chars.get(j) == Some(&'#') {
            hashes += 1;
            j += 1;
        }
        if self.chars.get(j) != Some(&'"') {
            self.i += 1;
            return;
        }
        self.i = j + 1;
        if raw {
            self.raw(hashes);
        } else {
            self.quoted();
        }
    }

    /// A raw string body up to `"` and `hashes` hashes, with the cursor just after the opening
    /// quote.
    fn raw(&mut self, hashes: usize) {
        let close: Vec<char> = std::iter::once('"')
            .chain(std::iter::repeat_n('#', hashes))
            .collect();
        let start = self.line;
        let mut text = String::new();
        while self.i < self.chars.len() && !self.chars[self.i..].starts_with(&close) {
            let c = self.chars[self.i];
            self.newline(c);
            text.push(c);
            self.i += 1;
        }
        self.i += close.len();
        self.out.push((start, text));
    }

    /// An escaped string body, with the cursor just after the opening quote.
    fn quoted(&mut self) {
        let start = self.line;
        let mut text = String::new();
        while let Some(c) = self.at(0) {
            match c {
                '\\' => {
                    text.push(c);
                    if let Some(next) = self.at(1) {
                        self.newline(next);
                        text.push(next);
                    }
                    self.i += 2;
                }
                '"' => {
                    self.i += 1;
                    break;
                }
                _ => {
                    self.newline(c);
                    text.push(c);
                    self.i += 1;
                }
            }
        }
        self.out.push((start, text));
    }

    /// Skips a character literal such as `'"'` or `'\''`, or a lifetime such as `'a`.
    fn skip_char_or_lifetime(&mut self) {
        if self.at(1) == Some('\\') {
            self.i += 2;
            while self.at(0).is_some_and(|c| c != '\'') {
                self.i += 1;
            }
            self.i += 1;
        } else if self.at(2) == Some('\'') {
            self.i += 3;
        } else {
            self.i += 1;
        }
    }

    fn newline(&mut self, c: char) {
        if c == '\n' {
            self.line += 1;
        }
    }
}

#[cfg(test)]
mod tests;
