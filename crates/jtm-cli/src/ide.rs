//! `jtm ide sync` (SPEC.md section 5): offers installed JDKs to Maven and Gradle toolchains,
//! which IDEs read when they import a project.
//!
//! Plugins say which installs to offer with `[ide]`. jtm owns only what it writes: a marked
//! block in `~/.m2/toolchains.xml`, and the entries under `<data>/tools` in Gradle's
//! `org.gradle.java.installations.paths`. Everything else in both files is left alone, and
//! re-running with the same installs changes nothing.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use jtm_core::session::{Session, home_dir};
use jtm_core::{Context, JtmError, Result};
use serde::Serialize;

const START: &str =
    "<!-- >>> jtm: managed by `jtm ide sync`; edits between these markers are replaced -->";
const END: &str = "<!-- <<< jtm -->";
const GRADLE_KEY: &str = "org.gradle.java.installations.paths";

/// One install offered to build tools.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Jdk {
    /// `tool@variant:version`.
    pub(crate) id: String,
    /// The Maven toolchain type.
    pub(crate) kind: String,
    pub(crate) vendor: String,
    pub(crate) version: String,
    /// The tool home.
    pub(crate) home: PathBuf,
}

/// The toolchains file's new text with jtm's block listing `jdks`, or `None` when it already
/// does. A file without `</toolchains>` is refused rather than guessed at.
pub(crate) fn update_toolchains(existing: Option<&str>, jdks: &[Jdk]) -> Result<Option<String>> {
    let mut sorted: Vec<&Jdk> = jdks.iter().collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let block = if sorted.is_empty() {
        String::new()
    } else {
        let mut block = format!("  {START}\n");
        for jdk in sorted {
            block.push_str(&format!(
                "  <toolchain>\n    <type>{}</type>\n    <provides>\n      <version>{}</version>\n      <vendor>{}</vendor>\n      <id>jtm:{}</id>\n    </provides>\n    <configuration>\n      <jdkHome>{}</jdkHome>\n    </configuration>\n  </toolchain>\n",
                xml(&jdk.kind),
                xml(&jdk.version),
                xml(&jdk.vendor),
                xml(&jdk.id),
                xml(&jdk.home.display().to_string()),
            ));
        }
        block.push_str(&format!("  {END}\n"));
        block
    };
    let Some(existing) = existing else {
        if block.is_empty() {
            return Ok(None);
        }
        return Ok(Some(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<toolchains>\n{block}</toolchains>\n"
        )));
    };
    let updated = match (existing.find(START), existing.find(END)) {
        (Some(start), Some(end)) if start < end => {
            let from = existing[..start].rfind('\n').map_or(0, |i| i + 1);
            let mut to = end + END.len();
            if existing[to..].starts_with('\n') {
                to += 1;
            }
            format!("{}{block}{}", &existing[..from], &existing[to..])
        }
        _ => {
            if block.is_empty() {
                return Ok(None);
            }
            let close = existing.rfind("</toolchains>").ok_or_else(|| {
                JtmError::usage(
                    "~/.m2/toolchains.xml has no `</toolchains>`, so jtm cannot add its entries; \
                     fix the file and run `jtm ide sync` again",
                )
            })?;
            let at = existing[..close].rfind('\n').map_or(0, |i| i + 1);
            format!("{}{block}{}", &existing[..at], &existing[at..])
        }
    };
    Ok((updated != existing).then_some(updated))
}

/// `gradle.properties`' new text listing `homes` in `org.gradle.java.installations.paths`,
/// keeping entries outside `tools`, or `None` when it already does.
pub(crate) fn update_gradle(
    existing: Option<&str>,
    homes: &[PathBuf],
    tools: &Path,
) -> Option<String> {
    let existing = existing.unwrap_or_default();
    let lines: Vec<&str> = existing.split_inclusive('\n').collect();
    // The logical line holding the key: its first and last physical lines.
    let mut span = None;
    let mut i = 0;
    while i < lines.len() {
        let start = i;
        let mut logical = String::new();
        loop {
            let line = lines[i].trim_end_matches(['\n', '\r']);
            let trailing = line.len() - line.trim_end_matches('\\').len();
            i += 1;
            if trailing % 2 == 1 && i < lines.len() {
                logical.push_str(line[..line.len() - 1].trim_start());
            } else {
                logical.push_str(line.trim_start());
                break;
            }
        }
        if let Some((key, value)) = split_property(&logical)
            && key == GRADLE_KEY
        {
            span = Some((start, i, value.to_owned()));
            break;
        }
    }
    let mut ours: Vec<String> = homes.iter().map(|h| h.display().to_string()).collect();
    ours.sort();
    // Entries under `tools` are jtm's from an earlier run; an entry equal to one of jtm's
    // would be listed twice.
    let user: Vec<String> = span
        .as_ref()
        .map(|(_, _, value)| {
            unescape(value)
                .split(',')
                .map(str::trim)
                .filter(|e| !e.is_empty() && !Path::new(e).starts_with(tools))
                .filter(|e| !ours.iter().any(|o| o == e))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let entries: Vec<String> = user.into_iter().chain(ours).collect();
    let line = if entries.is_empty() {
        String::new()
    } else {
        format!("{GRADLE_KEY}={}\n", escape(&entries.join(",")))
    };
    let updated = match span {
        Some((start, end, _)) => {
            let mut text: String = lines[..start].concat();
            text.push_str(&line);
            text.push_str(&lines[end..].concat());
            text
        }
        None if line.is_empty() => return None,
        None => {
            let mut text = existing.to_owned();
            if !text.is_empty() && !text.ends_with('\n') {
                text.push('\n');
            }
            text.push_str(&line);
            text
        }
    };
    (updated != existing).then_some(updated)
}

/// Splits a `.properties` line into its key and raw value, skipping comments and blanks.
fn split_property(line: &str) -> Option<(String, &str)> {
    let line = line.trim_start();
    if line.is_empty() || line.starts_with(['#', '!']) {
        return None;
    }
    let mut key = String::new();
    let mut chars = line.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                if let Some((_, next)) = chars.next() {
                    key.push(next);
                }
            }
            '=' | ':' | ' ' | '\t' => {
                let rest = line[i..].trim_start_matches([' ', '\t']);
                let rest = rest
                    .strip_prefix(['=', ':'])
                    .unwrap_or(rest)
                    .trim_start_matches([' ', '\t']);
                return Some((key, rest));
            }
            c => key.push(c),
        }
    }
    Some((key, ""))
}

fn unescape(value: &str) -> String {
    let mut out = String::new();
    let mut chars = value.chars();
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
                let hex: String = chars.by_ref().take(4).collect();
                if let Some(c) = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32) {
                    out.push(c);
                }
            }
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// Escapes a `.properties` value.
fn escape(value: &str) -> String {
    let mut out = String::new();
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ':' => out.push_str("\\:"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// One file `ide sync` wrote, or with `--dry-run` would write.
#[derive(Debug, Serialize)]
pub(crate) struct IdeFile {
    file: PathBuf,
    changed: bool,
    entries: usize,
}

#[derive(Debug, Serialize)]
pub(crate) struct IdeData {
    dry_run: bool,
    maven: Option<IdeFile>,
    gradle: Option<IdeFile>,
}

impl crate::output::Human for IdeData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        for (name, file) in [("Maven", &self.maven), ("Gradle", &self.gradle)] {
            let Some(file) = file else { continue };
            let verb = match (file.changed, self.dry_run) {
                (false, _) => "is up to date",
                (true, true) => "would be updated",
                (true, false) => "updated",
            };
            writeln!(
                out,
                "{name}: {} {verb} ({} entries)",
                file.file.display(),
                file.entries
            )?;
        }
        Ok(())
    }
}

/// Options for [`sync`].
#[derive(Debug, Clone, Copy)]
pub(crate) struct IdeOptions {
    pub(crate) dry_run: bool,
    pub(crate) maven: bool,
    pub(crate) gradle: bool,
}

pub(crate) fn sync(ctx: &Context, options: IdeOptions) -> Result<crate::output::Outcome<IdeData>> {
    let session = Session::open(ctx)?;
    let home = user_home()?;
    let mut maven_jdks = Vec::new();
    let mut gradle_homes = Vec::new();
    for item in session.list(None)? {
        let Ok(plugin) = session.plugin(&item.version.id.tool) else {
            continue;
        };
        let ide = &plugin.manifest.ide;
        let dir = PathBuf::from(&item.version.path);
        let jdk_home = jtm_core::install::Receipt::read(&dir)
            .map(|r| home_dir(&dir, &r.home))
            .unwrap_or(dir);
        if let Some(kind) = &ide.maven_toolchain {
            maven_jdks.push(Jdk {
                id: item.version.id.to_string(),
                kind: kind.clone(),
                vendor: item.version.id.variant.clone(),
                version: item.version.id.version.clone(),
                home: jdk_home.clone(),
            });
        }
        if ide.gradle_installations {
            gradle_homes.push(jdk_home);
        }
    }

    let write = |path: &Path, text: &str| -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| JtmError::io(dir, e))?;
        }
        jtm_core::project::write_atomic(path, text.as_bytes())
    };
    let read = |path: &Path| match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(JtmError::io(path, e)),
    };

    let maven = if options.maven {
        let file = home.join(".m2").join("toolchains.xml");
        let update = update_toolchains(read(&file)?.as_deref(), &maven_jdks)?;
        if let Some(text) = &update
            && !options.dry_run
        {
            write(&file, text)?;
        }
        Some(IdeFile {
            file,
            changed: update.is_some(),
            entries: maven_jdks.len(),
        })
    } else {
        None
    };
    let gradle = if options.gradle {
        let dir = std::env::var_os("GRADLE_USER_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home.join(".gradle"));
        let file = dir.join("gradle.properties");
        let update = update_gradle(
            read(&file)?.as_deref(),
            &gradle_homes,
            &session.dirs().tools(),
        );
        if let Some(text) = &update
            && !options.dry_run
        {
            write(&file, text)?;
        }
        Some(IdeFile {
            file,
            changed: update.is_some(),
            entries: gradle_homes.len(),
        })
    } else {
        None
    };
    let changed = !options.dry_run
        && [&maven, &gradle]
            .iter()
            .any(|f| f.as_ref().is_some_and(|f| f.changed));
    Ok(crate::output::Outcome {
        command: "ide sync",
        changed,
        data: IdeData {
            dry_run: options.dry_run,
            maven,
            gradle,
        },
        warnings: Vec::new(),
    })
}

/// The user's home directory: `HOME`, or `USERPROFILE` on Windows.
fn user_home() -> Result<PathBuf> {
    ["HOME", "USERPROFILE"]
        .iter()
        .filter_map(std::env::var_os)
        .map(PathBuf::from)
        .find(|p| p.is_absolute())
        .ok_or_else(|| JtmError::usage("cannot find your home directory; set HOME"))
}

#[cfg(test)]
mod tests;
