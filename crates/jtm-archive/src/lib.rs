//! Safe zip and tar.gz extraction for jtm (SPEC.md section 10, Archive rules).
//!
//! Every entry name is checked before anything is written: absolute paths, `..` components,
//! drive letters, UNC paths, backslashes and NUL bytes are refused. Device files, FIFOs and
//! sockets are refused. Executable bits are kept and setuid, setgid and sticky bits dropped.
//! Total size, entry count and compression ratio are capped so an archive bomb fails early.
//!
//! Links are created last. Each link's target is resolved through the archive's own links, so
//! a chain of individually harmless links cannot point outside the destination, and no entry
//! may be written through a link. Names are matched without regard to case, as macOS and
//! Windows match them, and each link created is checked again against where the file system
//! itself resolves it. On Windows, links are materialised as copies so no privilege
//! is needed.

mod counting;
mod entry;
mod error;
mod name;
mod tarball;
mod zip_file;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

use std::path::Path;

pub use error::{Error, Result};

/// The bomb limits of SPEC.md section 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes written in total, links materialised as copies included.
    pub max_bytes: u64,
    /// The most entries an archive may hold.
    pub max_entries: u64,
    /// The highest compression ratio allowed, as uncompressed bytes per compressed byte.
    pub max_ratio: u64,
    /// The ratio is only enforced once an entry (zip) or the stream (tar.gz) has produced this
    /// many bytes, so small, highly compressible files such as license texts never trip it.
    pub ratio_floor: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_bytes: 4 * 1024 * 1024 * 1024,
            max_entries: 200_000,
            max_ratio: 200,
            ratio_floor: 1024 * 1024,
        }
    }
}

/// How archive links become files on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkMode {
    /// Create symbolic links. Hard links are always copied.
    Symlink,
    /// Copy what each link points at, so no privilege is needed.
    Copy,
}

impl LinkMode {
    /// `Copy` on Windows, where symlinks need a privilege, and `Symlink` elsewhere.
    pub const fn host() -> LinkMode {
        if cfg!(windows) {
            LinkMode::Copy
        } else {
            LinkMode::Symlink
        }
    }
}

/// The archive formats of SPEC.md section 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Zip,
    TarGz,
    TarXz,
}

/// How to extract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub limits: Limits,
    /// Leading path components to remove from every entry, as `tar --strip-components` does.
    /// Entries with no components left are skipped.
    pub strip_components: u32,
    pub links: LinkMode,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            limits: Limits::default(),
            strip_components: 0,
            links: LinkMode::host(),
        }
    }
}

/// What an extraction wrote.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Summary {
    pub files: u64,
    pub dirs: u64,
    pub links: u64,
    /// Bytes written, links materialised as copies included.
    pub bytes: u64,
}

/// Extracts `archive` into the existing, empty directory `dest`.
///
/// On failure `dest` may hold some of the archive; the caller extracts into a temporary
/// directory and removes it.
pub fn extract(archive: &Path, format: Format, dest: &Path, options: &Options) -> Result<Summary> {
    let mut sink = entry::Sink::new(dest, options)?;
    match format {
        Format::Zip => zip_file::read(archive, &mut sink)?,
        Format::TarGz => tarball::read(archive, tarball::Codec::Gzip, &mut sink)?,
        Format::TarXz => tarball::read(archive, tarball::Codec::Xz, &mut sink)?,
    }
    sink.finish()
}
