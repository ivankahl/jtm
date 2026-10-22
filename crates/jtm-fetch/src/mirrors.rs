//! `[mirrors]` prefix rewrites (SPEC.md section 8). A rewrite changes where bytes come from,
//! never what is accepted: signatures and hashes are checked the same way afterwards.
//!
//! A mirror may point at another `https` (or, when allowed, `http`) location, at a `file://`
//! URL, or at a plain path. Only a rewrite can lead to a local file: a URL that no mirror
//! matched is always a network URL, so a signed index can never make jtm read a local file by
//! itself.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::error::{Error, Result};

/// Where the bytes of a URL come from once `[mirrors]` has been applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// A network URL, which the HTTP client checks before requesting.
    Url(String),
    /// A file on disk, reached through a `file://` or path mirror.
    File {
        path: PathBuf,
        /// The rewritten location as configured, for messages and receipts.
        display: String,
    },
}

/// Rewrites `url` with the longest prefix in `mirrors` that it starts with.
///
/// A network target takes the rest of the URL byte for byte. A local target takes it
/// percent-decoded, since the mirror holds files under their real names, and refuses a rest
/// that would leave the mirror directory (`.` or `..` segments, backslashes or NUL bytes,
/// including ones hidden by encoding) with [`Error::Scheme`].
pub fn resolve(url: &str, mirrors: &BTreeMap<String, String>) -> Result<Location> {
    let Some((prefix, replacement)) = mirrors
        .iter()
        .filter(|(prefix, _)| url.starts_with(prefix.as_str()))
        .max_by_key(|(prefix, _)| prefix.len())
    else {
        return Ok(Location::Url(url.to_owned()));
    };
    let rest = &url[prefix.len()..];
    if !is_local(replacement) {
        return Ok(Location::Url(format!("{replacement}{rest}")));
    }
    // SPEC-QUESTION: section 8 does not say how the rest of a URL maps onto a directory. A
    // mirror directory holds files under their real names (`jdk-21.0.5+11`), not the
    // percent-encoded ones in index URLs (`jdk-21.0.5%2B11`), so the rest is decoded, and
    // anything that could leave the mirror directory is refused (the most secure reading).
    let display = format!("{replacement}{}", decode_rest(url, rest)?);
    let path = local_path(&display).ok_or_else(|| Error::Scheme {
        url: url.to_owned(),
        reason: format!("`{replacement}` is not a usable mirror location"),
    })?;
    Ok(Location::File { path, display })
}

/// The local path a `file://` URL or plain path names, or `None` for a network URL.
pub fn local_path(location: &str) -> Option<PathBuf> {
    if !is_local(location) {
        return None;
    }
    let Some(rest) = location.strip_prefix("file://") else {
        return Some(PathBuf::from(location));
    };
    // `file:///C:/x` names `C:/x` on Windows.
    let bytes = rest.as_bytes();
    let windows_drive = bytes.len() >= 3 && bytes[0] == b'/' && bytes[2] == b':';
    Some(PathBuf::from(if windows_drive { &rest[1..] } else { rest }))
}

fn is_local(location: &str) -> bool {
    location.starts_with("file://") || !location.contains("://")
}

/// Percent-decodes `rest`, refusing anything that is not a plain relative file path.
fn decode_rest(url: &str, rest: &str) -> Result<String> {
    let refuse = |reason: &str| Error::Scheme {
        url: url.to_owned(),
        reason: format!("a local mirror cannot serve this URL: {reason}"),
    };
    let decoded = percent_decode(rest).ok_or_else(|| refuse("it is not valid percent-encoding"))?;
    if decoded.contains(['\0', '\\']) {
        return Err(refuse("it contains a NUL byte or a backslash"));
    }
    if decoded.split('/').any(|s| s == ".." || s == ".") {
        return Err(refuse("it contains a `.` or `..` segment"));
    }
    Ok(decoded)
}

/// Decodes `%XX` escapes, or `None` for a broken escape or bytes that are not UTF-8.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            // `from_str_radix` would also take a sign.
            if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests;
