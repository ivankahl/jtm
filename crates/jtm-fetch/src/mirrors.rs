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

/// Where `jtm mirror export` puts the file served at `url`, relative to the export directory:
/// `<host>/<path>`, with the path percent-decoded exactly as [`resolve`] decodes the tail of a
/// URL for a local target. A `[mirrors]` entry whose prefix ends at a host or deeper, aimed at
/// `<export dir>/<host>/` plus the rest of that prefix, therefore finds the file again.
///
/// The host is lowercased and a `:port` becomes `+port`, since a colon is not allowed in a
/// Windows file name. The scheme is not part of the place, so `http` and `https` mirrors can
/// share one tree. Anything that is not a plain `http(s)` URL to a file is refused with
/// [`Error::Scheme`]: user info, IP literals, a query or fragment, a trailing slash, empty or
/// `.`/`..` segments, backslashes and NUL bytes.
pub fn export_path(url: &str) -> Result<PathBuf> {
    let refuse = |reason: &str| Error::Scheme {
        url: url.to_owned(),
        reason: format!("it cannot be exported to a mirror directory: {reason}"),
    };
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(|| refuse("only http and https URLs can be exported"))?;
    if rest.contains(['?', '#']) {
        return Err(refuse("it has a query or fragment"));
    }
    let (authority, path) = rest
        .split_once('/')
        .ok_or_else(|| refuse("it names no file"))?;
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let host_ok = !host.is_empty()
        && !host.starts_with(['.', '-'])
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    let port_ok = port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    if !host_ok || !port_ok {
        return Err(refuse("its host is not a plain host name"));
    }
    let decoded = decode_rest(url, path)?;
    if decoded.is_empty() || decoded.ends_with('/') {
        return Err(refuse("it names no file"));
    }
    if decoded.split('/').any(str::is_empty) {
        return Err(refuse("it has an empty path segment"));
    }
    // A colon would make `C:` a drive prefix that `PathBuf` joins by replacing the export
    // directory on Windows; the others are not allowed in Windows file names either.
    if decoded.contains(|c: char| c.is_control() || "<>:\"|?*".contains(c)) {
        return Err(refuse(
            "it has a character that file names cannot hold on Windows",
        ));
    }
    let dir = match port {
        Some(port) => format!("{}+{port}", host.to_ascii_lowercase()),
        None => host.to_ascii_lowercase(),
    };
    let mut out = PathBuf::from(dir);
    out.extend(decoded.split('/'));
    Ok(out)
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
