//! Finding plugin manifests (SPEC.md sections 7 and 14).
//!
//! First-party manifests are compiled into the binary and are the only ones whose anchors are
//! pre-approved. Every other manifest lives at `<data>/plugins/<name>@<rev>/plugin.toml`, where
//! `<name>` is the plugin name with `/` written as `--`, and its anchors count only once the
//! user trusts them. The unpacked `<data>/plugins/builtin-<key>` working copies are never read
//! here.

use std::fs;
use std::io;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use jtm_plugin::Manifest;
use jtm_plugin::script::{Host, Script};

use crate::dirs::{Dirs, dir_name};
use crate::error::{JtmError, Result};
use crate::indices::ManifestOrigin;
use crate::platform::Platform;

/// The name prefix of the files the working copy repair writes in `<data>/plugins`.
const TEMP_PREFIX: &str = ".jtm-builtin-";

/// The name prefix of the working copies in `<data>/plugins`, one per embedded set.
const COPY_PREFIX: &str = "builtin-";

/// The one working copy that jtm versions before per-set copies shared.
const LEGACY_COPY: &str = "builtin";

/// The number of hex digits in a working copy key.
const KEY_LEN: usize = 16;

/// The file in a working copy whose modification time is when a jtm process last used it.
/// Plugin names start with a letter, so no plugin directory can take this name.
const LAST_USED: &str = ".last-used";

/// How long a working copy that no jtm process uses is kept: 30 days.
const STALE_AFTER: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// The working copy files of one builtin plugin, as `(file name, bytes)`.
fn working_files(found: &BuiltinManifest) -> Vec<(&'static str, &'static [u8])> {
    let mut files = vec![("plugin.toml", found.text.as_bytes())];
    if let Some(script) = found.script {
        files.push(("plugin.lua", script.as_bytes()));
    }
    files
}

/// The key of the working copy for `builtin`: the first 16 hex digits of a SHA-256 over every
/// file the copy holds, its directory, name and bytes, in name order. Binaries that embed the
/// same set share a copy; any difference, such as a `cargo run` build with an edited manifest,
/// gets a copy of its own.
pub fn working_copy_key(builtin: &[BuiltinManifest]) -> String {
    let mut sorted: Vec<&BuiltinManifest> = builtin.iter().collect();
    sorted.sort_by_key(|b| b.name);
    let mut framed = Vec::new();
    for found in sorted {
        let dir = dir_name(found.name);
        for (file, bytes) in working_files(found) {
            // Each part is length-prefixed, so no two different sets frame to the same bytes.
            for part in [dir.as_bytes(), file.as_bytes(), bytes] {
                framed.extend_from_slice(&(part.len() as u64).to_le_bytes());
                framed.extend_from_slice(part);
            }
        }
    }
    let mut key = jtm_security::sha256_hex(&framed);
    key.truncate(KEY_LEN);
    key
}

/// `<data>/plugins/builtin-<key>`, the working copy of `builtin`.
pub fn working_copy_dir(dirs: &Dirs, builtin: &[BuiltinManifest]) -> PathBuf {
    dirs.builtin_plugins(&working_copy_key(builtin))
}

/// Makes the working copy of `builtin`, `<data>/plugins/builtin-<key>` (see
/// [`working_copy_key`]), match it byte for byte (SPEC.md sections 7, 9 and 14): one directory
/// per plugin holding its `plugin.toml` and any `plugin.lua`. A file that differs, or is a link
/// or a directory, is replaced; anything else in the working copy is removed, and links are
/// removed, never followed. Returns the paths it repaired, so `jtm doctor` can report them.
///
/// The working copy is for people and tools to read. jtm never reads it, so a modified copy
/// cannot change a trust decision; [`Registry`] reads only the compiled-in manifests.
///
/// Each embedded set has its own copy, so two jtm versions running side by side, such as an
/// MCP server started before an upgrade and the shell hook of the new binary, never rewrite
/// each other's copy. Every sync sets the copy's `.last-used` marker to now and removes the
/// copies of other sets that no process has used for 30 days (see [`remove_stale_copies`]).
///
/// Several jtm processes may start a repair at once, such as two shells' prompt hooks, so a
/// repair holds an exclusive lock in `<data>/locks`, shared by every copy. While another
/// process holds it, the sync is skipped and reports no repairs rather than waiting, so a
/// stopped process never stalls every prompt. New files are also written in `<data>/plugins`,
/// outside the copy, and renamed into place, so nothing that does not take the lock sees a
/// half-written file in the copy. Without any `builtin` manifests, such as from a context that
/// embeds none, there is nothing to compare against, so every copy is left alone.
pub fn sync_working_copy(dirs: &Dirs, builtin: &[BuiltinManifest]) -> Result<Vec<PathBuf>> {
    if builtin.is_empty() {
        return Ok(Vec::new());
    }
    let Some(_lock) = lock_working_copy(dirs)? else {
        tracing::debug!("another process is repairing the builtin plugin working copy");
        return Ok(Vec::new());
    };
    let root = working_copy_dir(dirs, builtin);
    let scratch = dirs.plugins();
    let mut repaired = Vec::new();
    ensure_dir(&root, &mut repaired)?;
    // Marked before the repair, so a copy in use is never stale even while repairs fail.
    mark_used(&scratch, &root.join(LAST_USED))?;
    sweep_temp_files(&scratch);
    remove_stale_copies(&scratch, &root, SystemTime::now());
    let wanted: Vec<(String, &BuiltinManifest)> =
        builtin.iter().map(|b| (dir_name(b.name), b)).collect();
    for entry in read_entries(&root)? {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name != LAST_USED && !wanted.iter().any(|(dir, _)| *dir == name) {
            remove_entry(&entry.path())?;
            repaired.push(entry.path());
        }
    }
    for (dir, found) in &wanted {
        let dir = root.join(dir);
        ensure_dir(&dir, &mut repaired)?;
        let files = working_files(found);
        for entry in read_entries(&dir)? {
            let name = entry.file_name();
            if !files.iter().any(|(file, _)| name == *file) {
                remove_entry(&entry.path())?;
                repaired.push(entry.path());
            }
        }
        for (file, bytes) in files {
            let path = dir.join(file);
            let current = match fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_file() => fs::read(&path).ok(),
                Ok(meta) if meta.is_dir() => {
                    remove_entry(&path)?;
                    None
                }
                // A link is replaced by the rename below, never followed.
                _ => None,
            };
            if current.as_deref() != Some(bytes) {
                write_replacing(&scratch, &path, bytes)?;
                repaired.push(path);
            }
        }
    }
    if !repaired.is_empty() {
        tracing::debug!(
            count = repaired.len(),
            "repaired the builtin plugin working copy"
        );
    }
    Ok(repaired)
}

/// Sets the modification time of a working copy's `.last-used` marker to now, creating the
/// marker if it is missing. A marker that is not a plain file, such as a link, is replaced,
/// never followed.
fn mark_used(scratch: &Path, marker: &Path) -> Result<()> {
    if fs::symlink_metadata(marker).is_ok_and(|meta| meta.is_file()) {
        let file = fs::OpenOptions::new()
            .write(true)
            .open(marker)
            .map_err(|e| JtmError::io(marker, e))?;
        return file
            .set_modified(SystemTime::now())
            .map_err(|e| JtmError::io(marker, e));
    }
    remove_entry(marker)?;
    write_replacing(scratch, marker, b"")
}

/// Whether `name` in `<data>/plugins` is a working copy: `builtin-<key>`, or the legacy
/// `builtin`. External plugins are `<name>@<rev>`, so they never match.
fn is_working_copy(name: &str) -> bool {
    name == LEGACY_COPY
        || name.strip_prefix(COPY_PREFIX).is_some_and(|key| {
            key.len() == KEY_LEN && key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
}

/// When a working copy was last used: its `.last-used` marker's modification time, or the
/// directory's own for a copy without one, such as the legacy `builtin`.
fn last_used(copy: &Path) -> Option<SystemTime> {
    fs::symlink_metadata(copy.join(LAST_USED))
        .or_else(|_| fs::symlink_metadata(copy))
        .and_then(|meta| meta.modified())
        .ok()
}

/// Removes every working copy in `plugins` other than `current` that was last used more than
/// [`STALE_AFTER`] before `now`. Only real directories named like a copy are candidates, so a
/// link is left alone; a copy whose age cannot be read, or that was used in the future, is
/// kept.
///
/// The caller holds the working copy lock, which every process takes before it marks or
/// repairs its own copy, so a copy cannot come back into use while it is removed. If its
/// binary runs again later, its next sync simply unpacks it afresh. Each copy is first renamed
/// to a temporary name, so a removal cut short leaves nothing that looks like a copy, and the
/// next sync sweeps what is left. Failures are ignored; the next sync tries again.
fn remove_stale_copies(plugins: &Path, current: &Path, now: SystemTime) {
    let Ok(entries) = fs::read_dir(plugins) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path == current
            || !is_working_copy(&name)
            || !entry.file_type().is_ok_and(|t| t.is_dir())
        {
            continue;
        }
        let stale = last_used(&path)
            .and_then(|used| now.duration_since(used).ok())
            .is_some_and(|age| age > STALE_AFTER);
        if !stale {
            continue;
        }
        let trash = plugins.join(format!("{TEMP_PREFIX}stale-{name}"));
        let removed = fs::rename(&path, &trash)
            .map_err(|e| JtmError::io(&path, e))
            .and_then(|()| remove_entry(&trash));
        match removed {
            Ok(()) => {
                tracing::debug!(copy = %path.display(), "removed a stale builtin plugin working copy")
            }
            Err(err) => tracing::debug!(%err, "cannot remove a stale builtin plugin working copy"),
        }
    }
}

/// Writes `bytes` to a new file in `scratch`, on the same file system, and renames it over
/// `path`. A rename replaces a link rather than writing through it, so a link planted in the
/// working copy is never followed.
///
/// Windows briefly refuses a rename onto a file another program has open, such as a virus
/// scanner or an editor, so there a refused rename is retried twice, waiting at most 60 ms in
/// all. Any other failure is returned at once.
fn write_replacing(scratch: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    write_replacing_with(scratch, path, bytes, rename_refused)
}

/// Whether a failed rename may work if tried again: on Windows, a refused or shared target.
fn rename_refused(error: &io::Error) -> bool {
    // ERROR_SHARING_VIOLATION, which std does not map to an error kind.
    const SHARING_VIOLATION: i32 = 32;
    cfg!(windows)
        && (error.kind() == io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(SHARING_VIOLATION))
}

/// [`write_replacing`], retrying a failed rename while `transient` says it may work.
fn write_replacing_with(
    scratch: &Path,
    path: &Path,
    bytes: &[u8],
    transient: impl Fn(&io::Error) -> bool,
) -> Result<()> {
    const ATTEMPTS: u32 = 3;
    let mut file = tempfile::Builder::new()
        .prefix(TEMP_PREFIX)
        .tempfile_in(scratch)
        .map_err(|e| JtmError::io(scratch, e))?;
    io::Write::write_all(&mut file, bytes).map_err(|e| JtmError::io(file.path(), e))?;
    let mut attempt = 1;
    loop {
        let failed = match file.persist(path) {
            Ok(_) => return Ok(()),
            Err(failed) => failed,
        };
        if !transient(&failed.error) || attempt == ATTEMPTS {
            return Err(JtmError::io(path, failed.error));
        }
        std::thread::sleep(std::time::Duration::from_millis(10 << attempt));
        attempt += 1;
        file = failed.file;
    }
}

/// Takes the exclusive lock on the working copy, or returns `None` while another process
/// holds it.
fn lock_working_copy(dirs: &Dirs) -> Result<Option<fs::File>> {
    let locks = dirs.locks();
    fs::create_dir_all(&locks).map_err(|e| JtmError::io(&locks, e))?;
    // A leading `.` keeps this apart from every install lock, which starts with a plugin name.
    let path = locks.join(".builtin-working-copy.lock");
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
        .map_err(|e| JtmError::io(&path, e))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(e)) => Err(JtmError::io(&path, e)),
    }
}

/// Removes the repair's temporary files in `scratch`, and stale copies whose removal was cut
/// short. Only a sync holding the working copy lock makes them, so with the lock held every
/// one is from a process killed mid-sync. Links are removed, never followed. Failures are
/// ignored; the next sync tries again.
fn sweep_temp_files(scratch: &Path) {
    let Ok(entries) = fs::read_dir(scratch) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(TEMP_PREFIX) {
            let _ = remove_entry(&entry.path());
        }
    }
}

/// Makes `dir` a real directory, replacing a file or link in its place.
fn ensure_dir(dir: &Path, repaired: &mut Vec<PathBuf>) -> Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() => return Ok(()),
        Ok(_) => {
            remove_entry(dir)?;
            repaired.push(dir.to_path_buf());
        }
        Err(_) => {}
    }
    fs::create_dir_all(dir).map_err(|e| JtmError::io(dir, e))
}

fn read_entries(dir: &Path) -> Result<Vec<fs::DirEntry>> {
    fs::read_dir(dir)
        .and_then(Iterator::collect::<io::Result<Vec<_>>>)
        .map_err(|e| JtmError::io(dir, e))
}

/// Removes a file, a link (not its target) or a whole directory.
fn remove_entry(path: &Path) -> Result<()> {
    let removed = match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path).or_else(|e| {
            // A Windows link to a directory is removed as a directory.
            if cfg!(windows) {
                fs::remove_dir(path)
            } else {
                Err(e)
            }
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    };
    removed.map_err(|e| JtmError::io(path, e))
}

/// A manifest compiled into jtm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinManifest {
    pub name: &'static str,
    pub text: &'static str,
    /// The plugin's `plugin.lua`, if it has one.
    pub script: Option<&'static str>,
}

/// A parsed plugin manifest and where it came from.
#[derive(Debug, Clone)]
pub struct Plugin {
    pub manifest: Manifest,
    /// Lowercase hex SHA-256 of the manifest bytes.
    pub sha256: String,
    pub origin: ManifestOrigin,
    /// Where the manifest was read: `builtin` or a file path.
    pub location: String,
    /// The manifest text, which hooks see as `jtm.manifest`.
    pub text: String,
    /// The `plugin.lua` source, when a hook needs it. It always matches the manifest's
    /// `hooks.script_sha256`, so the manifest hash covers it too.
    pub script: Option<String>,
}

/// The largest `plugin.lua` jtm reads.
const MAX_SCRIPT_BYTES: u64 = 1024 * 1024;

impl Plugin {
    /// The plugin's `plugin.lua` prepared to run hooks on `platform`, if it has one.
    pub fn script(&self, platform: Platform) -> Result<Option<Script>> {
        let Some(source) = &self.script else {
            return Ok(None);
        };
        let host = Host {
            platform: platform.as_str().to_owned(),
            os: platform.os().as_str().to_owned(),
            arch: platform.arch().as_str().to_owned(),
        };
        let name = &self.manifest.name;
        Script::new(
            name,
            source,
            &self.text,
            self.manifest.versions.scheme.builtin(),
            host,
        )
        .map(Some)
        .map_err(|e| JtmError::script(name, e))
    }
}

/// Plugin manifests for one jtm installation.
#[derive(Debug, Clone, Copy)]
pub struct Registry<'a> {
    pub dirs: &'a Dirs,
    pub builtin: &'a [BuiltinManifest],
}

impl Registry<'_> {
    /// The plugin named `name`. Builtin manifests win over any file of the same name.
    pub fn find(&self, name: &str) -> Result<Plugin> {
        if let Some(found) = self.builtin.iter().find(|b| b.name == name) {
            return parse(
                found.text.as_bytes(),
                || Ok(found.script.map(str::to_owned)),
                ManifestOrigin::Builtin,
                "builtin",
                name,
            );
        }
        let dirs = self.external_dirs(name)?;
        match dirs.as_slice() {
            [] => Err(JtmError::ToolUnknown {
                tool: name.to_owned(),
            }),
            [dir] => {
                let path = dir.join("plugin.toml");
                let bytes = fs::read(&path).map_err(|e| JtmError::io(&path, e))?;
                parse(
                    &bytes,
                    || read_script(&dir.join("plugin.lua")),
                    ManifestOrigin::External,
                    &path.display().to_string(),
                    name,
                )
            }
            // Which revision is active is recorded by `jtm plugin add` (T9.3); until then several
            // revisions of one plugin are refused rather than guessed.
            _ => Err(JtmError::usage(format!(
                "several revisions of plugin `{name}` are installed under {}; remove all but one",
                self.dirs.plugins().display()
            ))),
        }
    }

    /// The names of every plugin available, builtin first, each once.
    pub fn names(&self) -> Result<Vec<String>> {
        let mut names: Vec<String> = self.builtin.iter().map(|b| b.name.to_owned()).collect();
        for (dir_name, _) in self.external_entries()? {
            let name = dir_name.replace("--", "/");
            if !names.contains(&name) {
                names.push(name);
            }
        }
        Ok(names)
    }

    fn external_dirs(&self, name: &str) -> Result<Vec<PathBuf>> {
        let wanted = dir_name(name);
        Ok(self
            .external_entries()?
            .into_iter()
            .filter(|(dir, _)| *dir == wanted)
            .map(|(_, path)| path)
            .collect())
    }

    /// `(<name with -->, path)` for each `<name>@<rev>` directory with a `plugin.toml`.
    fn external_entries(&self) -> Result<Vec<(String, PathBuf)>> {
        let root = self.dirs.plugins();
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(JtmError::io(&root, e)),
        };
        let mut found = Vec::new();
        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            let Some((name, rev)) = file_name.split_once('@') else {
                continue;
            };
            if rev.is_empty() || !entry.path().join("plugin.toml").is_file() {
                continue;
            }
            found.push((name.to_owned(), entry.path()));
        }
        found.sort();
        Ok(found)
    }
}

/// The script at `path`, if there is one. One that is too large or not UTF-8 makes the plugin
/// invalid.
fn read_script(path: &Path) -> Result<Option<String>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(JtmError::io(path, e)),
    };
    let mut bytes = Vec::new();
    io::Read::take(file, MAX_SCRIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| JtmError::io(path, e))?;
    let problem = if bytes.len() as u64 > MAX_SCRIPT_BYTES {
        format!("is larger than {MAX_SCRIPT_BYTES} bytes")
    } else {
        match String::from_utf8(bytes) {
            Ok(text) => return Ok(Some(text)),
            Err(_) => "is not UTF-8".to_owned(),
        }
    };
    Err(JtmError::InvalidManifest {
        origin: path.display().to_string(),
        error: jtm_plugin::ManifestError {
            problems: vec![jtm_plugin::manifest::Problem {
                path: String::new(),
                message: format!("plugin.lua {problem}"),
                line: None,
            }],
        },
    })
}

/// Parses the manifest `bytes`, reading the plugin's script through `script` only when the
/// manifest names a hook.
fn parse(
    bytes: &[u8],
    script: impl FnOnce() -> Result<Option<String>>,
    origin: ManifestOrigin,
    location: &str,
    name: &str,
) -> Result<Plugin> {
    let invalid = |message: String| JtmError::InvalidManifest {
        origin: location.to_owned(),
        error: jtm_plugin::ManifestError {
            problems: vec![jtm_plugin::manifest::Problem {
                path: String::new(),
                message,
                line: None,
            }],
        },
    };
    let text = std::str::from_utf8(bytes).map_err(|_| invalid("is not UTF-8".to_owned()))?;
    let manifest = Manifest::parse(text).map_err(|error| JtmError::InvalidManifest {
        origin: location.to_owned(),
        error,
    })?;
    if manifest.name != name {
        return Err(invalid(format!(
            "declares plugin `{}`, not `{name}`",
            manifest.name
        )));
    }
    // Validation guarantees `script_sha256` exactly when a hook is named. A script no hook
    // uses is never read.
    let script = match &manifest.hooks.script_sha256 {
        None => None,
        Some(expected) => {
            let Some(source) = script()? else {
                let hook = first_hook(&manifest).unwrap_or("a hook");
                return Err(invalid(format!(
                    "names the hook `{hook}`, but the plugin has no plugin.lua"
                )));
            };
            let actual = jtm_security::sha256_hex(source.as_bytes());
            if actual != *expected {
                return Err(invalid(format!(
                    "plugin.lua has SHA-256 {actual}, but `hooks.script_sha256` is {expected}"
                )));
            }
            Some(source)
        }
    };
    Ok(Plugin {
        manifest,
        sha256: jtm_security::sha256_hex(bytes),
        origin,
        location: location.to_owned(),
        text: text.to_owned(),
        script,
    })
}

/// The first `[hooks]` entry the manifest sets, by its key.
fn first_hook(manifest: &Manifest) -> Option<&'static str> {
    manifest
        .hooks
        .named()
        .into_iter()
        .find_map(|(key, function)| function.is_some().then_some(key))
}

#[cfg(test)]
mod tests;
