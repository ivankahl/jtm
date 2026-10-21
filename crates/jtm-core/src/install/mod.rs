//! The install pipeline (SPEC.md section 10).
//!
//! An install either produces a complete, verified install dir with a receipt, or leaves
//! nothing behind except a reusable verified download. The install dir only ever appears
//! through an atomic rename of a fully prepared directory, so an install killed at any point
//! leaves no partial install dir; its temporary directory is removed by the next install of
//! the same version. An exclusive file lock per version stops parallel shells or agents from
//! racing, and whoever waits on it finds the version installed when it gets the lock.

pub mod layout;
pub mod receipt;

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use jtm_fetch::{Artifact, Client, DownloadCache, Downloaded};
use jtm_plugin::Manifest;
use jtm_plugin::script::{PostExtract, Script};
use jtm_security::{IndexEntry, Timestamp};
use serde::Serialize;

use crate::dirs::{Dirs, dir_name};
use crate::error::{JtmError, Result};
use crate::platform::Platform;

pub use receipt::{RECEIPT_FILE, Receipt};

/// How long a Windows rename is retried while antivirus scanners hold new files open.
const RENAME_RETRY: Duration = Duration::from_secs(10);

/// Where verified archives come from.
#[derive(Debug, Clone, Copy)]
pub struct Archives<'a> {
    pub cache: &'a DownloadCache,
    /// `None` when offline: only cached archives can be used.
    pub client: Option<&'a Client>,
    /// `[mirrors]` prefix rewrites, applied to artifact URLs before downloading.
    pub mirrors: &'a std::collections::BTreeMap<String, String>,
}

impl Archives<'_> {
    /// The verified archive for `entry`.
    pub fn get(
        &self,
        entry: &IndexEntry,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<Downloaded> {
        let url = jtm_fetch::mirrors::rewrite(&entry.url, self.mirrors);
        let artifact = Artifact {
            url: &url,
            sha256: &entry.sha256,
            size: entry.size,
        };
        match self.client {
            Some(client) => Ok(self.cache.fetch(client, &artifact, &mut |done, total| {
                progress(Progress::Download { done, total });
            })?),
            None => match self.cache.lookup(&artifact)? {
                Some(path) => Ok(Downloaded {
                    path,
                    origin: jtm_fetch::Origin::Cache,
                    url,
                }),
                None => Err(JtmError::Offline {
                    action: format!("downloading {url}"),
                }),
            },
        }
    }
}

/// Install progress, for progress bars and `--json --progress` events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    Download { done: u64, total: u64 },
    Verified,
    Extracted,
}

/// One version to install.
#[derive(Debug, Clone, Copy)]
pub struct InstallRequest<'a> {
    pub manifest: &'a Manifest,
    /// Lowercase hex SHA-256 of the manifest bytes, recorded in the receipt.
    pub manifest_sha256: &'a str,
    pub entry: &'a IndexEntry,
    pub platform: Platform,
    /// The sequence of the index the entry came from.
    pub index_sequence: u64,
    /// Reinstall even when a matching receipt exists.
    pub force: bool,
    /// The plugin's `plugin.lua`, which must be given when the manifest names a
    /// `post_extract` hook.
    pub script: Option<&'a Script>,
}

/// What happened, or with a dry run would happen, to one version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Installed,
    AlreadyInstalled,
    WouldInstall,
}

impl Status {
    /// Whether this outcome changed anything on disk.
    pub const fn changed(self) -> bool {
        matches!(self, Status::Installed)
    }
}

/// One version of one tool, written `<tool>@<variant>:<version>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct VersionId {
    pub tool: String,
    pub variant: String,
    pub version: String,
}

impl fmt::Display for VersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}:{}", self.tool, self.variant, self.version)
    }
}

impl VersionId {
    /// The version `entry` names for `tool`.
    pub fn of(tool: &str, entry: &IndexEntry) -> VersionId {
        VersionId {
            tool: tool.to_owned(),
            variant: entry.variant.clone(),
            version: entry.version.clone(),
        }
    }

    /// The install dir, refusing names that would not be a single directory.
    pub fn install_dir(&self, dirs: &Dirs) -> Result<PathBuf> {
        let name = format!("{}-{}", self.variant, self.version);
        // Variants and versions are checked when the index loads; this guards the path itself.
        if name.contains(['/', '\\', ':']) || name.starts_with('.') {
            return Err(JtmError::internal(format!(
                "`{name}` cannot name an install directory"
            )));
        }
        Ok(dirs.install_dir(&self.tool, &self.variant, &self.version))
    }

    /// Takes the exclusive lock for this version, waiting for any other holder.
    pub fn lock(&self, dirs: &Dirs) -> Result<fs::File> {
        let locks = dirs.locks();
        fs::create_dir_all(&locks).map_err(|e| JtmError::io(&locks, e))?;
        let path = locks.join(format!(
            "{}-{}-{}.lock",
            dir_name(&self.tool),
            self.variant,
            self.version
        ));
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|e| JtmError::io(&path, e))?;
        file.lock().map_err(|e| JtmError::io(&path, e))?;
        Ok(file)
    }

    /// The name prefix of this version's temporary directories.
    fn tmp_prefix(&self) -> String {
        // `@` appears in no plugin dir name, variant or version, so no other version's prefix
        // starts with this one.
        format!(
            "{}@{}@{}@",
            dir_name(&self.tool),
            self.variant,
            self.version
        )
    }
}

/// The result of [`install`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    pub status: Status,
    /// The install dir.
    pub path: PathBuf,
    pub receipt: Receipt,
}

/// Installs one version, or reports it already installed (SPEC.md section 10, steps 2 to 12).
pub fn install(
    dirs: &Dirs,
    archives: &Archives<'_>,
    request: &InstallRequest<'_>,
    limits: &jtm_archive::Limits,
    progress: &mut dyn FnMut(Progress),
) -> Result<Installed> {
    let manifest = request.manifest;
    let entry = request.entry;
    let plugin = manifest.name.as_str();
    let id = VersionId::of(plugin, entry);
    let dest = id.install_dir(dirs)?;

    if !request.force
        && let Some(installed) = already_installed(&dest, entry)?
    {
        return Ok(installed);
    }
    let post_extract = match (&manifest.hooks.post_extract, request.script) {
        (Some(function), Some(script)) => Some((function.as_str(), script)),
        (Some(_), None) => {
            return Err(JtmError::internal(format!(
                "installing `{plugin}` needs its post_extract hook, but no plugin.lua was given"
            )));
        }
        (None, _) => None,
    };

    let _lock = id.lock(dirs)?;
    // Whoever held the lock may have just installed this version.
    if !request.force
        && let Some(installed) = already_installed(&dest, entry)?
    {
        return Ok(installed);
    }
    let prefix = id.tmp_prefix();
    sweep_stale(&dirs.tools_tmp(), &prefix);

    let archive = archives.get(entry, progress)?;
    progress(Progress::Verified);

    let tmp_root = dirs.tools_tmp();
    fs::create_dir_all(&tmp_root).map_err(|e| JtmError::io(&tmp_root, e))?;
    // Removed on every return path; an install killed before that is swept as stale above.
    let tmp = tempfile::Builder::new()
        .prefix(&prefix)
        .tempdir_in(&tmp_root)
        .map_err(|e| JtmError::io(&tmp_root, e))?;
    let options = jtm_archive::Options {
        limits: *limits,
        strip_components: layout::extract_strip(&manifest.layout),
        links: jtm_archive::LinkMode::host(),
    };
    jtm_archive::extract(&archive.path, archive_format(entry), tmp.path(), &options)?;
    progress(Progress::Extracted);

    let os = request.platform.os();
    let placed = layout::apply(plugin, tmp.path(), &manifest.layout, os)?;
    if let Some((function, script)) = post_extract {
        // Confined to the directory that becomes the install dir; it only appears through
        // the rename in `commit`, so a failed hook leaves nothing behind.
        let home = receipt::home_string(&placed.home);
        let context = PostExtract {
            variant: &entry.variant,
            version: &entry.version,
            home: &home,
        };
        script
            .post_extract(function, &placed.root, &context)
            .map_err(|e| JtmError::script(plugin, e))?;
    }
    layout::check_bin_dirs(plugin, &placed, &manifest.layout)?;

    let receipt = Receipt {
        plugin: plugin.to_owned(),
        manifest_sha256: request.manifest_sha256.to_owned(),
        variant: entry.variant.clone(),
        version: entry.version.clone(),
        platform: request.platform.as_str().to_owned(),
        url: archive.url,
        sha256: entry.sha256.clone(),
        size: entry.size,
        index_sequence: request.index_sequence,
        installed_at: Timestamp::now().to_string(),
        jtm_version: env!("CARGO_PKG_VERSION").to_owned(),
        home: receipt::home_string(&placed.home),
    };
    receipt.write(&placed.root)?;
    commit(dirs, &placed.root, &dest)?;
    drop(tmp);

    Ok(Installed {
        status: Status::Installed,
        path: dest,
        receipt,
    })
}

/// The installed version at `dest`, if its receipt matches `entry`. A receipt that exists and
/// cannot be read is an error, so a live install is never replaced for want of reading it.
fn already_installed(dest: &Path, entry: &IndexEntry) -> Result<Option<Installed>> {
    let Some(receipt) = Receipt::load(dest)? else {
        return Ok(None);
    };
    Ok((receipt.sha256 == entry.sha256).then(|| Installed {
        status: Status::AlreadyInstalled,
        path: dest.to_path_buf(),
        receipt,
    }))
}

/// Removes temporary directories left by killed installs of the version whose lock is held.
fn sweep_stale(tmp_root: &Path, prefix: &str) {
    let Ok(entries) = fs::read_dir(tmp_root) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(prefix) {
            let path = entry.path();
            tracing::debug!(path = %path.display(), "removing an interrupted install");
            if let Err(err) = fs::remove_dir_all(&path) {
                tracing::warn!(path = %path.display(), %err, "cannot remove an interrupted install");
            }
        }
    }
}

fn archive_format(entry: &IndexEntry) -> jtm_archive::Format {
    match entry.archive {
        jtm_security::ArchiveKind::Zip => jtm_archive::Format::Zip,
        jtm_security::ArchiveKind::TarGz => jtm_archive::Format::TarGz,
        jtm_security::ArchiveKind::TarXz => jtm_archive::Format::TarXz,
    }
}

/// Moves the prepared `source` to `dest`, replacing any previous install there.
fn commit(dirs: &Dirs, source: &Path, dest: &Path) -> Result<()> {
    let parent = dest.parent().unwrap_or(dest);
    fs::create_dir_all(parent).map_err(|e| JtmError::io(parent, e))?;
    if fs::symlink_metadata(dest).is_ok() {
        let trashed = move_to_trash(dirs, dest)?;
        remove_trash(&trashed);
    }
    rename_with_retry(source, dest).map_err(|e| JtmError::io(dest, e))
}

/// Renames `path` into `tools/.trash`, failing with `E_IN_USE` when a running process holds
/// files in it open.
pub(crate) fn move_to_trash(dirs: &Dirs, path: &Path) -> Result<PathBuf> {
    let trash = dirs.tools_trash();
    fs::create_dir_all(&trash).map_err(|e| JtmError::io(&trash, e))?;
    let slot = tempfile::Builder::new()
        .prefix("removed.")
        .tempdir_in(&trash)
        .map_err(|e| JtmError::io(&trash, e))?
        .keep();
    let target = slot.join("dir");
    match rename_with_retry(path, &target) {
        Ok(()) => Ok(target),
        Err(e) => {
            let _ = fs::remove_dir(&slot);
            Err(if held_open(&e, cfg!(windows)) {
                JtmError::InUse {
                    path: path.to_path_buf(),
                }
            } else {
                JtmError::io(path, e)
            })
        }
    }
}

/// Whether a failed rename means a running process holds files open. Only Windows refuses to
/// rename a directory for that reason, with an access, sharing or lock violation.
fn held_open(err: &io::Error, windows: bool) -> bool {
    const ERROR_ACCESS_DENIED: i32 = 5;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    const ERROR_LOCK_VIOLATION: i32 = 33;
    windows
        && matches!(
            err.raw_os_error(),
            Some(ERROR_ACCESS_DENIED | ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION)
        )
}

/// Deletes a directory moved to the trash. A failure only leaves it for a later attempt.
pub(crate) fn remove_trash(trashed: &Path) {
    let slot = trashed.parent().unwrap_or(trashed);
    if let Err(err) = fs::remove_dir_all(slot) {
        tracing::warn!(path = %slot.display(), %err, "cannot delete a removed install yet");
    }
}

/// Renames, retrying on Windows for up to ten seconds because antivirus scanners briefly lock
/// new files.
fn rename_with_retry(from: &Path, to: &Path) -> io::Result<()> {
    let start = std::time::Instant::now();
    loop {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if cfg!(windows) && start.elapsed() < RENAME_RETRY => {
                tracing::debug!(%e, "retrying a rename");
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests;
