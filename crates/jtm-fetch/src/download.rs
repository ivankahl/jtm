//! Streaming downloads into the content-addressed archive cache (SPEC.md section 10, steps 4
//! to 6).
//!
//! Archives live at `<cache>/downloads/<sha256>`. A cached file is re-hashed before every use.
//! A download streams into `<sha256>.part`, hashing as bytes arrive and aborting the moment the
//! expected size is exceeded. Network failures retry with backoff and resume from the bytes
//! already on disk, which are re-hashed from byte 0. A hash or size mismatch deletes the
//! partial file and is never retried. Only a verified file is renamed into place.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::client::{Client, body_error};
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
        let url = client
            .options()
            .retry
            .run(|_| download_part(client, artifact, &part, &mut *progress))?;
        fs::rename(&part, &path).map_err(|e| Error::io(&path, e))?;
        Ok(Downloaded {
            path,
            origin: Origin::Network,
            url,
        })
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
    client: &Client,
    artifact: &Artifact<'_>,
    part: &Path,
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

    let mut response = client.open(artifact.url, offset)?;
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
        let n = match response.read(&mut buf) {
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
mod tests {
    use super::*;

    #[test]
    fn digests_must_be_lowercase_hex() {
        let cache = DownloadCache::new("/cache");
        assert!(cache.path(&"a".repeat(64)).is_ok());
        assert!(cache.path(&"A".repeat(64)).is_err());
        assert!(cache.path(&"a".repeat(63)).is_err());
        assert!(cache.path("../../etc/passwd").is_err());
        assert!(cache.path(&format!("{}/x", "a".repeat(62))).is_err());
    }

    #[test]
    fn hashes_readers() {
        let (hash, n) = hash_reader(&b"abc"[..], 10).unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            hash,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
