//! `{name}` placeholders in `sources.toml` strings, checked when the file is loaded so a typo
//! fails the run before any request is made.

/// Checks that every `{name}` in `text` is one of `known`, and that braces are balanced.
pub(super) fn check(text: &str, known: &[&str]) -> Result<(), String> {
    let mut rest = text;
    while let Some(open) = rest.find(['{', '}']) {
        if rest.as_bytes()[open] == b'}' {
            return Err(format!("`{text}` has a `}}` with no `{{`"));
        }
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return Err(format!("`{text}` has a `{{` with no `}}`"));
        };
        let name = &after[..close];
        if name.contains('{') {
            return Err(format!("`{text}` has a `{{` inside a placeholder"));
        }
        if !known.contains(&name) {
            return Err(format!(
                "`{text}` uses `{{{name}}}`; the placeholders here are {}",
                list(known)
            ));
        }
        rest = &after[close + 1..];
    }
    Ok(())
}

/// Replaces every `{name}` in `text` with `value(name)`. Names that `value` does not know stay
/// as written, which [`check`] has already ruled out for loaded files.
pub(super) fn render(text: &str, value: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[open..]);
            return out;
        };
        let name = &after[..close];
        match value(name) {
            Some(v) => out.push_str(&v),
            None => {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    out
}

fn list(known: &[&str]) -> String {
    if known.is_empty() {
        return "none".to_owned();
    }
    known
        .iter()
        .map(|n| format!("`{{{n}}}`"))
        .collect::<Vec<_>>()
        .join(", ")
}
