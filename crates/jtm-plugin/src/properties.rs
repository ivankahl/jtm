//! Java `.properties` files, as `java.util.Properties` reads and writes them: `key=value`,
//! `key: value` or `key value` lines, `#` and `!` comments, a trailing `\` continuing a line,
//! and backslash escapes including `\n`, `\t` and `\uXXXX`. Interop wrapper files and
//! `jtm ide sync` share this one reader so they cannot disagree.

/// One logical line holding a property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The index of its first physical line, as [`str::split_inclusive`] on `'\n'` counts them.
    pub first: usize,
    /// The index just past its last physical line.
    pub end: usize,
    /// The key, unescaped.
    pub key: String,
    /// The value, unescaped.
    pub value: String,
}

/// Every property in `text`, in file order.
pub fn entries(text: &str) -> Vec<Entry> {
    let lines: Vec<&str> = text.split_inclusive('\n').collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let first = i;
        let mut logical = String::new();
        loop {
            let line = lines[i].trim_end_matches(['\n', '\r']);
            // A continuation line's leading white space is not part of the value.
            let line = if i == first {
                line
            } else {
                line.trim_start_matches([' ', '\t', '\u{c}'])
            };
            i += 1;
            let trailing = line.len() - line.trim_end_matches('\\').len();
            let comment = i - 1 == first && is_comment(line);
            if trailing % 2 == 1 && !comment && i < lines.len() {
                logical.push_str(&line[..line.len() - 1]);
            } else {
                logical.push_str(line);
                break;
            }
        }
        if let Some((key, value)) = split(&logical) {
            out.push(Entry {
                first,
                end: i,
                key: unescape(key),
                value: unescape(value),
            });
        }
    }
    out
}

/// The value of `key` in `text`, the last one when it repeats, as `Properties` keeps it.
pub fn get(text: &str, key: &str) -> Option<String> {
    entries(text)
        .into_iter()
        .rev()
        .find(|e| e.key == key)
        .map(|e| e.value)
}

fn is_comment(line: &str) -> bool {
    line.trim_start_matches([' ', '\t', '\u{c}'])
        .starts_with(['#', '!'])
}

/// Splits a logical line into its raw key and raw value; `None` for blanks and comments.
fn split(line: &str) -> Option<(&str, &str)> {
    let line = line.trim_start_matches([' ', '\t', '\u{c}']);
    if line.is_empty() || line.starts_with(['#', '!']) {
        return None;
    }
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '=' | ':' | ' ' | '\t' | '\u{c}' => {
                let rest = line[i..].trim_start_matches([' ', '\t', '\u{c}']);
                let rest = rest
                    .strip_prefix(['=', ':'])
                    .unwrap_or(rest)
                    .trim_start_matches([' ', '\t', '\u{c}']);
                return Some((&line[..i], rest));
            }
            _ => {}
        }
    }
    Some((line, ""))
}

/// Resolves backslash escapes: `\t`, `\n`, `\r`, `\f`, `\uXXXX`, and any other character
/// standing for itself.
pub fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('f') => out.push('\u{c}'),
            Some('u') => {
                let Some(unit) = hex_unit(&mut chars) else {
                    continue;
                };
                // A character outside the BMP is written as a surrogate pair, `\uD83D\uDE00`.
                if (0xD800..0xDC00).contains(&unit) {
                    let mut ahead = chars.clone();
                    if ahead.next() == Some('\\')
                        && ahead.next() == Some('u')
                        && let Some(low) = hex_unit(&mut ahead)
                        && (0xDC00..0xE000).contains(&low)
                    {
                        chars = ahead;
                        out.extend(char::decode_utf16([unit, low]).flatten());
                    }
                    continue;
                }
                out.extend(char::from_u32(u32::from(unit)));
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// Four hex digits from `chars`, as a UTF-16 code unit.
fn hex_unit(chars: &mut std::str::Chars<'_>) -> Option<u16> {
    let hex: String = chars.by_ref().take(4).collect();
    u16::from_str_radix(&hex, 16).ok()
}

/// Escapes a value so `Properties` reads it back unchanged. Anything outside printable ASCII
/// is written as `\uXXXX`, since `Properties.load(InputStream)` reads ISO-8859-1.
pub fn escape_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (i, c) in value.chars().enumerate() {
        match c {
            '\\' => out.push_str("\\\\"),
            ':' => out.push_str("\\:"),
            '=' => out.push_str("\\="),
            '#' | '!' if i == 0 => {
                out.push('\\');
                out.push(c);
            }
            ' ' if i == 0 => out.push_str("\\ "),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
