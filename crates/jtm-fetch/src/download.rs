//! Streaming downloads into the content-addressed archive cache (SPEC.md section 10, steps 4
//! to 6).
//!
//! An archive comes from the network ([`DownloadCache::fetch`]) or, when a `[mirrors]` entry
//! points at a `file://` URL or a path, from a local file ([`DownloadCache::fetch_file`]). Both
//! stream into the same `.part` file through the same hash and size checks, so a local copy is
//! trusted no more than a downloaded one.
//!
//! Archives live at `<cache>/downloads/<sha256>`. A cached file is re-hashed before every use.
//! A download streams into `<sha256>.part`, hashing as bytes arrive and aborting the moment the
//! expected size is exceeded. Network failures retry with backoff and resume from the bytes
//! already on disk, which are re-hashed from byte 0. A hash or size mismatch deletes the
//! partial file and is never retried. Only a verified file is renamed into place.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::client::{Client, Response, RetryPolicy, body_error};
use crate::error::{Error, Result};

/// The size of each read from the network or disk.
const CHUNK: usize = 64 * 1024;

/// What to download and how to recognise it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Artifact<'a> {
    pub url: &'a str,
    /// Lowercase hex SHA-256, from a signed index or the lockfile.
    pub sha256: &'a str,
    /// The exact size in bytes.
    pub size: u64,
}

/// Where a verified archive came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Cache,
    Network,
    /// A local file reached through a `file://` or path mirror.
    File,
}

/// A verified archive in the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Downloaded {
    pub path: PathBuf,
    pub origin: Origin,
    /// The URL the bytes came from after redirects, or the requested URL for a cache hit.
    pub url: String,
}

/// Download progress: bytes verified so far and the expected total.
pub type Progress<'a> = &'a mut dyn FnMut(u64, u64);

/// The content-addressed archive cache, `<cache>/downloads` or `download.cache_dir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadCache {
    dir: PathBuf,
}

impl DownloadCache {
    pub fn new(dir: impl Into<PathBuf>) -> DownloadCache {
        DownloadCache { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `<dir>/<sha256>`. Fails for anything but 64 lowercase hex digits, so a digest can never
    /// name a path outside the cache.
    pub fn path(&self, sha256: &str) -> Result<PathBuf> {
        check_digest(sha256)?;
        Ok(self.dir.join(sha256))
    }

    /// The cached archive for `artifact`, after re-hashing it. A cached file of the wrong size
    /// or hash is deleted and reported as missing.
    pub fn lookup(&self, artifact: &Artifact<'_>) -> Result<Option<PathBuf>> {
        let path = self.path(artifact.sha256)?;
        let len = match fs::metadata(&path) {
            Ok(meta) if meta.is_file() => meta.len(),
            Ok(_) => return Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::io(&path, e)),
        };
        if len == artifact.size {
            let file = File::open(&path).map_err(|e| Error::io(&path, e))?;
            let (hash, _) = hash_reader(file, artifact.size).map_err(|e| Error::io(&path, e))?;
            if hash == artifact.sha256 {
                return Ok(Some(path));
            }
        }
        tracing::warn!(path = %path.display(), "removing a cached archive that does not match its hash");
        remove_if_exists(&path)?;
        Ok(None)
    }

    /// Returns the verified archive for `artifact`, from the cache or downloaded with `client`.
    pub fn fetch(
        &self,
        client: &Client,
        artifact: &Artifact<'_>,
        progress: Progress<'_>,
    ) -> Result<Downloaded> {
        self.fetch_with(
            artifact,
            client.options().retry,
            Origin::Network,
            &|offset| client.open(artifact.url, offset).map(Opened::from),
            progress,
        )
    }

    /// Returns the verified archive for `artifact`, from the cache or copied from the local
    /// file `source`. `artifact.url` only names the location in results and errors. The copy
    /// is hashed and size-checked like a download, and nothing reaches the cache otherwise.
    pub fn fetch_file(
        &self,
        source: &Path,
        artifact: &Artifact<'_>,
        progress: Progress<'_>,
    ) -> Result<Downloaded> {
        let no_retry = RetryPolicy {
            retries: 0,
            backoff: Duration::ZERO,
        };
        self.fetch_with(
            artifact,
            no_retry,
            Origin::File,
            &|_| open_file(source, artifact),
            progress,
        )
    }

    fn fetch_with(
        &self,
        artifact: &Artifact<'_>,
        retry: RetryPolicy,
        origin: Origin,
        open: &dyn Fn(u64) -> Result<Opened>,
        progress: Progress<'_>,
    ) -> Result<Downloaded> {
        let path = self.path(artifact.sha256)?;
        if let Some(path) = self.lookup(artifact)? {
            return Ok(cached(path, artifact));
        }
        fs::create_dir_all(&self.dir).map_err(|e| Error::io(&self.dir, e))?;

        // Another process downloading the same archive holds this lock; once it is released
        // the archive is usually in the cache already.
        let lock_path = self.dir.join(format!("{}.lock", artifact.sha256));
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| Error::io(&lock_path, e))?;
        lock.lock().map_err(|e| Error::io(&lock_path, e))?;
        if let Some(path) = self.lookup(artifact)? {
            return Ok(cached(path, artifact));
        }

        let part = self.dir.join(format!("{}.part", artifact.sha256));
        let url = retry.run(|_| download_part(artifact, &part, open, &mut *progress))?;
        fs::rename(&part, &path).map_err(|e| Error::io(&path, e))?;
        Ok(Downloaded { path, origin, url })
    }
}

fn cached(path: PathBuf, artifact: &Artifact<'_>) -> Downloaded {
    Downloaded {
        path,
        origin: Origin::Cache,
        url: artifact.url.to_owned(),
    }
}

/// One attempt at completing `part`. Returns the URL the bytes came from once `part` holds
/// exactly the expected bytes.
fn download_part(
    artifact: &Artifact<'_>,
    part: &Path,
    open: &dyn Fn(u64) -> Result<Opened>,
    progress: Progress<'_>,
) -> Result<String> {
    let io_err = |e| Error::io(part, e);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(part)
        .map_err(io_err)?;

    // Bytes left by an interrupted attempt or run are re-hashed from byte 0, never trusted.
    let mut offset = file.metadata().map_err(io_err)?.len();
    if offset > artifact.size {
        file.set_len(0).map_err(io_err)?;
        offset = 0;
    }
    file.seek(SeekFrom::Start(0)).map_err(io_err)?;
    let mut hasher = Sha256::new();
    if offset > 0 {
        let copied = io::copy(&mut (&mut file).take(offset), &mut HashWriter(&mut hasher))
            .map_err(io_err)?;
        offset = copied;
    }
    if offset == artifact.size {
        // Every byte arrived before an earlier run stopped. Asking for the bytes after the
        // end would get HTTP 416, so verify what is here, or start over.
        if hex(&hasher.clone().finalize()) == artifact.sha256 {
            progress(offset, artifact.size);
            return Ok(artifact.url.to_owned());
        }
        file.set_len(0).map_err(io_err)?;
        file.seek(SeekFrom::Start(0)).map_err(io_err)?;
        hasher = Sha256::new();
        offset = 0;
    }

    let mut response = open(offset)?;
    if !response.resumed && offset > 0 {
        // The server sent the whole body, so start over.
        file.set_len(0).map_err(io_err)?;
        file.seek(SeekFrom::Start(0)).map_err(io_err)?;
        hasher = Sha256::new();
        offset = 0;
    }
    let url = response.final_url.clone();
    let too_large = || Error::TooLarge {
        url: url.clone(),
        limit: artifact.size,
    };
    if response
        .content_length
        .is_some_and(|len| offset.saturating_add(len) > artifact.size)
    {
        drop(file);
        remove_if_exists(part)?;
        return Err(too_large());
    }

    let mut total = offset;
    let mut buf = vec![0u8; CHUNK];
    progress(total, artifact.size);
    loop {
        let n = match response.body.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                // Keep what arrived so the retry can resume after it.
                file.flush().map_err(io_err)?;
                return Err(body_error(&url, e));
            }
        };
        total += n as u64;
        if total > artifact.size {
            drop(file);
            remove_if_exists(part)?;
            return Err(too_large());
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n]).map_err(io_err)?;
        progress(total, artifact.size);
    }
    file.sync_all().map_err(io_err)?;
    drop(file);

    let actual = hex(&hasher.finalize());
    if total != artifact.size || actual != artifact.sha256 {
        remove_if_exists(part)?;
        return Err(Error::HashMismatch {
            url,
            expected: artifact.sha256.to_owned(),
            actual,
        });
    }
    Ok(url)
}

/// An open source of bytes: a response, or a local file.
struct Opened {
    body: Box<dyn Read>,
    final_url: String,
    resumed: bool,
    content_length: Option<u64>,
}

impl From<Response> for Opened {
    fn from(response: Response) -> Opened {
        Opened {
            final_url: response.final_url.clone(),
            resumed: response.resumed,
            content_length: response.content_length,
            body: Box::new(response),
        }
    }
}

/// Opens a mirror file from its start. Only regular files are read, so a mirror path cannot
/// name a device or a pipe.
fn open_file(source: &Path, artifact: &Artifact<'_>) -> Result<Opened> {
    let io_err = |e| Error::io(source, e);
    let not_regular = || {
        io_err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ))
    };
    // Checked before opening: opening a FIFO blocks until a writer appears.
    if !fs::metadata(source).map_err(io_err)?.is_file() {
        return Err(not_regular());
    }
    let file = File::open(source).map_err(io_err)?;
    let meta = file.metadata().map_err(io_err)?;
    if !meta.is_file() {
        return Err(not_regular());
    }
    Ok(Opened {
        body: Box::new(file),
        final_url: artifact.url.to_owned(),
        resumed: false,
        content_length: Some(meta.len()),
    })
}

/// Hashes at most `limit` bytes of `reader`, returning the hex digest and the bytes read.
pub fn hash_reader(reader: impl Read, limit: u64) -> io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let read = io::copy(&mut reader.take(limit), &mut HashWriter(&mut hasher))?;
    Ok((hex(&hasher.finalize()), read))
}

struct HashWriter<'a>(&'a mut Sha256);

impl Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn check_digest(sha256: &str) -> Result<()> {
    if sha256.len() == 64
        && sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(Error::InvalidDigest {
            value: sha256.to_owned(),
        })
    }
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::io(path, e)),
    }
}

#[cfg(test)]
mod tests;
