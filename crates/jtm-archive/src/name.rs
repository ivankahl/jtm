//! Checks on entry names and link targets, before either is joined to a path.

/// One step of a link target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Step {
    Up,
    Name(String),
}

/// Checks an entry name and splits it into normal components. `.` and empty components are
/// dropped, so `./bin//java` is `bin/java`; an empty result names the root.
///
/// Refused on every platform, so an archive extracts the same everywhere: absolute paths,
/// `..`, NUL and other control characters, backslashes (a UNC path or a Windows separator) and
/// `:` (a drive letter or an NTFS alternate data stream).
// SPEC-QUESTION: section 10 lists drive letters and UNC paths; this refuses every backslash
// and colon rather than only those forms, which no supported archive uses in names.
pub(crate) fn entry_components(raw: &[u8]) -> Result<Vec<String>, String> {
    let text = checked_text(raw)?;
    if text.starts_with('/') {
        return Err("is an absolute path".to_owned());
    }
    let mut out = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err("contains a `..` component".to_owned()),
            name => out.push(name.to_owned()),
        }
    }
    Ok(out)
}

/// Checks a symbolic link target, which is relative to the link's directory and may climb with
/// `..`. Whether it stays inside the destination is decided once every link is known.
pub(crate) fn link_steps(raw: &[u8]) -> Result<Vec<Step>, String> {
    let text = checked_text(raw)?;
    if text.is_empty() {
        return Err("has an empty link target".to_owned());
    }
    if text.starts_with('/') {
        return Err("links to an absolute path".to_owned());
    }
    Ok(text
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .map(|p| {
            if p == ".." {
                Step::Up
            } else {
                Step::Name(p.to_owned())
            }
        })
        .collect())
}

fn checked_text(raw: &[u8]) -> Result<&str, String> {
    let text = std::str::from_utf8(raw).map_err(|_| "is not valid UTF-8".to_owned())?;
    if let Some(c) = text.chars().find(|c| c.is_control()) {
        return Err(if c == '\0' {
            "contains a NUL byte".to_owned()
        } else {
            "contains a control character".to_owned()
        });
    }
    if text.contains('\\') {
        return Err("contains a backslash".to_owned());
    }
    if text.contains(':') {
        return Err("contains `:`, as a drive letter or alternate data stream does".to_owned());
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_names_split_into_components() {
        assert_eq!(
            entry_components(b"jdk/bin/java").unwrap(),
            ["jdk", "bin", "java"]
        );
        assert_eq!(entry_components(b"./bin//java").unwrap(), ["bin", "java"]);
        assert_eq!(entry_components(b"dir/").unwrap(), ["dir"]);
        assert!(entry_components(b"./").unwrap().is_empty());
        assert_eq!(entry_components(b"a/.../b").unwrap(), ["a", "...", "b"]);
    }

    #[test]
    fn unsafe_names_are_refused() {
        for name in [
            &b"/etc/passwd"[..],
            b"../x",
            b"a/../../x",
            b"a/..",
            b"C:/Windows/x",
            b"C:x",
            b"\\\\server\\share\\x",
            b"a\\..\\..\\x",
            b"a\0b",
            b"a\nb",
            b"file.txt:stream",
            b"\xff\xfe",
        ] {
            assert!(
                entry_components(name).is_err(),
                "{:?} should be refused",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn link_targets_may_climb_but_not_start_at_the_root() {
        assert_eq!(
            link_steps(b"../lib/./libjli.dylib").unwrap(),
            [
                Step::Up,
                Step::Name("lib".into()),
                Step::Name("libjli.dylib".into())
            ]
        );
        assert!(link_steps(b"/etc/passwd").is_err());
        assert!(link_steps(b"").is_err());
        assert!(link_steps(b"C:/x").is_err());
        assert!(link_steps(b"..\\x").is_err());
    }
}
