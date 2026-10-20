//! Writing checked entries into the destination. Format readers call [`Sink`] for each entry;
//! links are recorded and only created by [`Sink::finish`], once the whole archive is known.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::name::{self, Step};
use crate::{LinkMode, Options, Summary};

/// How many links one lookup may pass through, as on Linux.
const MAX_LINK_DEPTH: usize = 40;
/// How deeply copied directories may nest when links are materialised as copies.
const MAX_COPY_DEPTH: usize = 64;
const CHUNK: usize = 64 * 1024;

/// What has been written at a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Node {
    Dir,
    File,
}

#[derive(Debug)]
struct Symlink {
    display: String,
    target: String,
    steps: Vec<Step>,
}

#[derive(Debug)]
struct HardLink {
    display: String,
    target: Vec<String>,
}

/// Decides whether an entry that has produced `written` bytes is over the compression ratio.
/// Returns the reason when it is.
pub(crate) type RatioCheck<'a> = &'a dyn Fn(u64) -> Option<String>;

/// The destination of one extraction.
pub(crate) struct Sink<'o> {
    root: PathBuf,
    options: &'o Options,
    summary: Summary,
    entries: u64,
    written: BTreeMap<Vec<String>, Node>,
    symlinks: BTreeMap<Vec<String>, Symlink>,
    hardlinks: BTreeMap<Vec<String>, HardLink>,
}

impl<'o> Sink<'o> {
    pub(crate) fn new(dest: &Path, options: &'o Options) -> Result<Sink<'o>> {
        // On Windows this yields a `\\?\` path, so deep trees can exceed 260 characters.
        let root = fs::canonicalize(dest).map_err(|e| Error::io(dest, e))?;
        if !root.is_dir() {
            return Err(Error::io(
                dest,
                io::Error::new(io::ErrorKind::NotADirectory, "not a directory"),
            ));
        }
        Ok(Sink {
            root,
            options,
            summary: Summary::default(),
            entries: 0,
            written: BTreeMap::new(),
            symlinks: BTreeMap::new(),
            hardlinks: BTreeMap::new(),
        })
    }

    pub(crate) fn limits(&self) -> crate::Limits {
        self.options.limits
    }

    /// Counts one archive entry against the entry limit.
    pub(crate) fn count_entry(&mut self, display: &str) -> Result<()> {
        self.entries += 1;
        if self.entries > self.options.limits.max_entries {
            return Err(Error::unsafe_entry(
                display,
                format!(
                    "the archive has more than {} entries",
                    self.options.limits.max_entries
                ),
            ));
        }
        Ok(())
    }

    /// The checked components of an entry name after stripping, or `None` when stripping
    /// leaves nothing.
    fn place(&self, raw: &[u8]) -> Result<Option<Vec<String>>> {
        let display = String::from_utf8_lossy(raw);
        let mut parts =
            name::entry_components(raw).map_err(|r| Error::unsafe_entry(display.as_ref(), r))?;
        let strip = self.options.strip_components as usize;
        if parts.len() <= strip {
            return Ok(None);
        }
        parts.drain(..strip);
        Ok(Some(parts))
    }

    fn path(&self, parts: &[String]) -> PathBuf {
        let mut path = self.root.clone();
        path.extend(parts);
        path
    }

    pub(crate) fn dir(&mut self, raw: &[u8]) -> Result<()> {
        let Some(parts) = self.place(raw)? else {
            return Ok(());
        };
        let display = String::from_utf8_lossy(raw).into_owned();
        self.make_dirs(&display, &parts)
    }

    /// Creates `parts` and its parents, refusing to turn a file into a directory.
    fn make_dirs(&mut self, display: &str, parts: &[String]) -> Result<()> {
        for end in 1..=parts.len() {
            match self.written.get(&parts[..end]) {
                Some(Node::Dir) => continue,
                Some(Node::File) => {
                    return Err(Error::unsafe_entry(
                        display,
                        format!(
                            "`{}` is both a file and a directory",
                            parts[..end].join("/")
                        ),
                    ));
                }
                None => {
                    let path = self.path(&parts[..end]);
                    match fs::create_dir(&path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && path.is_dir() => {}
                        Err(e) => return Err(Error::io(&path, e)),
                    }
                    self.written.insert(parts[..end].to_vec(), Node::Dir);
                    self.summary.dirs += 1;
                }
            }
        }
        Ok(())
    }

    /// Writes a regular file from `reader`. `mode` is the Unix mode from the archive, if any.
    pub(crate) fn file(
        &mut self,
        raw: &[u8],
        mode: Option<u32>,
        reader: &mut dyn Read,
        ratio: RatioCheck<'_>,
    ) -> Result<()> {
        let display = String::from_utf8_lossy(raw).into_owned();
        let Some(parts) = self.place(raw)? else {
            return Ok(());
        };
        if parts.is_empty() {
            return Err(Error::unsafe_entry(display, "a file has no name"));
        }
        if self.written.get(&parts) == Some(&Node::Dir) {
            return Err(Error::unsafe_entry(
                display,
                "is both a file and a directory",
            ));
        }
        self.make_dirs(&display, &parts[..parts.len() - 1])?;
        let path = self.path(&parts);
        let mut out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| Error::io(&path, e))?;

        let mut written = 0u64;
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(Error::Malformed {
                        message: format!("cannot read `{display}`: {e}"),
                    });
                }
            };
            written += n as u64;
            self.add_bytes(&display, n as u64)?;
            if let Some(reason) = ratio(written) {
                return Err(Error::unsafe_entry(display, reason));
            }
            out.write_all(&buf[..n]).map_err(|e| Error::io(&path, e))?;
        }
        drop(out);
        set_mode(&path, mode)?;
        self.written.insert(parts, Node::File);
        self.summary.files += 1;
        Ok(())
    }

    fn add_bytes(&mut self, display: &str, n: u64) -> Result<()> {
        self.summary.bytes += n;
        if self.summary.bytes > self.options.limits.max_bytes {
            return Err(Error::unsafe_entry(
                display,
                format!(
                    "the archive expands to more than {} bytes",
                    self.options.limits.max_bytes
                ),
            ));
        }
        Ok(())
    }

    pub(crate) fn symlink(&mut self, raw: &[u8], target: &[u8]) -> Result<()> {
        let display = String::from_utf8_lossy(raw).into_owned();
        let Some(parts) = self.place(raw)? else {
            return Ok(());
        };
        if parts.is_empty() {
            return Err(Error::unsafe_entry(display, "a link has no name"));
        }
        let steps = name::link_steps(target).map_err(|r| Error::unsafe_entry(&display, r))?;
        let target = String::from_utf8_lossy(target).into_owned();
        self.symlinks.insert(
            parts,
            Symlink {
                display,
                target,
                steps,
            },
        );
        Ok(())
    }

    /// A hard link, whose target is another entry's name.
    pub(crate) fn hardlink(&mut self, raw: &[u8], target: &[u8]) -> Result<()> {
        let display = String::from_utf8_lossy(raw).into_owned();
        let Some(parts) = self.place(raw)? else {
            return Ok(());
        };
        let target = match self.place(target)? {
            Some(target) if !parts.is_empty() && !target.is_empty() => target,
            _ => {
                return Err(Error::unsafe_entry(
                    display,
                    "a hard link must name a file inside the archive",
                ));
            }
        };
        self.hardlinks.insert(parts, HardLink { display, target });
        Ok(())
    }

    /// Creates the links, once every file and directory is in place.
    pub(crate) fn finish(mut self) -> Result<Summary> {
        self.check_nothing_inside_links()?;

        let hardlinks = std::mem::take(&mut self.hardlinks);
        for (parts, link) in &hardlinks {
            let source = self
                .resolve_entry(&link.target, &hardlinks, 0)
                .map_err(|reason| Error::unsafe_entry(&link.display, reason))?;
            if self.written.get(&source) != Some(&Node::File) {
                return Err(Error::unsafe_entry(
                    &link.display,
                    "a hard link must name a regular file in the archive",
                ));
            }
            if self.written.contains_key(parts) {
                return Err(Error::unsafe_entry(
                    &link.display,
                    "is both a hard link and another entry",
                ));
            }
            self.make_dirs(&link.display, &parts[..parts.len() - 1])?;
            self.copy_file(&link.display, &self.path(&source), &self.path(parts))?;
            self.written.insert(parts.clone(), Node::File);
            self.summary.links += 1;
        }

        let top = self.single_top_level();
        let mut resolved = Vec::new();
        for (parts, link) in &self.symlinks {
            if self.written.contains_key(parts) {
                return Err(Error::unsafe_entry(
                    &link.display,
                    "is both a link and another entry",
                ));
            }
            let target = self
                .resolve(parts[..parts.len() - 1].to_vec(), &link.steps, 0)
                .map_err(|reason| Error::unsafe_entry(&link.display, reason))?;
            // A single top-level directory may become the install dir on its own (layout
            // `"auto"`), so a link must also stay inside it.
            if let Some(top) = &top
                && target.first() != Some(top)
            {
                return Err(Error::unsafe_entry(
                    &link.display,
                    format!("links outside the top-level directory `{top}`"),
                ));
            }
            resolved.push((parts.clone(), target));
        }
        for (parts, target) in resolved {
            let display = self.symlinks[&parts].display.clone();
            self.make_dirs(&display, &parts[..parts.len() - 1])?;
            let created = match self.options.links {
                LinkMode::Symlink if cfg!(unix) => {
                    self.create_symlink(&parts)?;
                    true
                }
                _ => self.copy_logical(&display, &target, &self.path(&parts), 0)?,
            };
            if created {
                self.summary.links += 1;
            } else {
                let link = display.as_str();
                tracing::warn!(link, "skipping a link whose target is not in the archive");
            }
        }
        Ok(self.summary)
    }

    /// The first component every entry shares, when the archive holds a single top-level
    /// directory.
    fn single_top_level(&self) -> Option<String> {
        let mut firsts = self
            .written
            .keys()
            .chain(self.symlinks.keys())
            .chain(self.hardlinks.keys())
            .map(|p| (p.first(), p.len()));
        let (first, _) = firsts.next()?;
        let first = first?;
        let mut is_dir = self.written.get(std::slice::from_ref(first)) == Some(&Node::Dir);
        for (other, len) in firsts {
            if other != Some(first) {
                return None;
            }
            is_dir |= len > 1;
        }
        is_dir.then(|| first.clone())
    }

    /// Refuses any entry whose path passes through a symbolic link, since writing it would
    /// write wherever the link points.
    fn check_nothing_inside_links(&self) -> Result<()> {
        let paths = self
            .written
            .keys()
            .map(|p| (p, p.join("/")))
            .chain(self.symlinks.iter().map(|(p, l)| (p, l.display.clone())))
            .chain(self.hardlinks.iter().map(|(p, l)| (p, l.display.clone())));
        for (parts, display) in paths {
            for end in 1..parts.len() {
                if self.symlinks.contains_key(&parts[..end]) {
                    return Err(Error::unsafe_entry(
                        display,
                        format!("is inside the link `{}`", parts[..end].join("/")),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Follows `steps` from the directory `base`, through any links in the archive, to a path
    /// inside the destination.
    fn resolve(
        &self,
        base: Vec<String>,
        steps: &[Step],
        depth: usize,
    ) -> std::result::Result<Vec<String>, String> {
        let mut current = base;
        for step in steps {
            match step {
                Step::Up => {
                    if current.pop().is_none() {
                        return Err("links outside the archive".to_owned());
                    }
                }
                Step::Name(name) => {
                    current.push(name.clone());
                    if let Some(link) = self.symlinks.get(&current) {
                        if depth >= MAX_LINK_DEPTH {
                            return Err("has too many levels of links".to_owned());
                        }
                        current.pop();
                        current = self.resolve(current, &link.steps, depth + 1)?;
                    }
                }
            }
        }
        Ok(current)
    }

    /// Resolves an entry name through links, following hard links to the file they copy.
    fn resolve_entry(
        &self,
        parts: &[String],
        hardlinks: &BTreeMap<Vec<String>, HardLink>,
        depth: usize,
    ) -> std::result::Result<Vec<String>, String> {
        let steps: Vec<Step> = parts.iter().cloned().map(Step::Name).collect();
        let path = self.resolve(Vec::new(), &steps, 0)?;
        match hardlinks.get(&path) {
            Some(_) if depth >= MAX_LINK_DEPTH => Err("has too many levels of links".to_owned()),
            Some(next) => self.resolve_entry(&next.target, hardlinks, depth + 1),
            None => Ok(path),
        }
    }

    #[cfg(unix)]
    fn create_symlink(&self, parts: &[String]) -> Result<()> {
        let path = self.path(parts);
        std::os::unix::fs::symlink(&self.symlinks[parts].target, &path)
            .map_err(|e| Error::io(&path, e))
    }

    #[cfg(not(unix))]
    fn create_symlink(&self, _parts: &[String]) -> Result<()> {
        unreachable!("symlinks are only created on Unix")
    }

    /// Copies what the archive path `source` holds to `dest`, following links inside it.
    /// Returns false when `source` does not exist.
    fn copy_logical(
        &mut self,
        display: &str,
        source: &[String],
        dest: &Path,
        depth: usize,
    ) -> Result<bool> {
        if depth > MAX_COPY_DEPTH {
            return Err(Error::unsafe_entry(
                display,
                "links nest too deeply to copy",
            ));
        }
        let from = self.path(source);
        let meta = match fs::symlink_metadata(&from) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(Error::io(&from, e)),
        };
        self.count_entry(display)?;
        if meta.is_file() {
            self.copy_file(display, &from, dest)?;
            return Ok(true);
        }
        if !meta.is_dir() {
            return Err(Error::unsafe_entry(
                display,
                "links to something that is not a file",
            ));
        }
        fs::create_dir(dest).map_err(|e| Error::io(dest, e))?;
        let mut children = BTreeSet::new();
        for child in fs::read_dir(&from).map_err(|e| Error::io(&from, e))? {
            let child = child.map_err(|e| Error::io(&from, e))?;
            children.insert(child.file_name().to_string_lossy().into_owned());
        }
        children.extend(
            self.symlinks
                .keys()
                .filter(|p| p.len() == source.len() + 1 && p.starts_with(source))
                .map(|p| p[source.len()].clone()),
        );
        for child in children {
            let mut path = source.to_vec();
            path.push(child.clone());
            let target = match self.symlinks.get(&path) {
                Some(link) => {
                    let steps = link.steps.clone();
                    self.resolve(source.to_vec(), &steps, 0)
                        .map_err(|reason| Error::unsafe_entry(display, reason))?
                }
                None => path,
            };
            self.copy_logical(display, &target, &dest.join(&child), depth + 1)?;
        }
        Ok(true)
    }

    fn copy_file(&mut self, display: &str, from: &Path, to: &Path) -> Result<()> {
        let len = fs::metadata(from).map_err(|e| Error::io(from, e))?.len();
        self.add_bytes(display, len)?;
        let mut input = File::open(from).map_err(|e| Error::io(from, e))?;
        let mut output = File::create(to).map_err(|e| Error::io(to, e))?;
        io::copy(&mut input, &mut output).map_err(|e| Error::io(to, e))?;
        drop(output);
        let mode = file_mode(from);
        set_mode(to, mode)
    }
}

/// Keeps the executable bits of `mode` and drops setuid, setgid, sticky and write access for
/// others: files become 0644, or 0755 when any executable bit was set.
#[cfg(unix)]
fn set_mode(path: &Path, mode: Option<u32>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let executable = mode.is_some_and(|m| m & 0o111 != 0);
    let mode = if executable { 0o755 } else { 0o644 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| Error::io(path, e))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: Option<u32>) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).ok().map(|m| m.permissions().mode())
}

#[cfg(not(unix))]
fn file_mode(_path: &Path) -> Option<u32> {
    None
}
