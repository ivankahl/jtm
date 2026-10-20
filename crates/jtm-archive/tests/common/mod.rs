//! Builds archives in memory, including ones no well-behaved tool would write.

#![allow(dead_code, clippy::unwrap_used, clippy::panic)]

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;
use jtm_archive::{Format, Options, Result, Summary};
use tar::{EntryType, Header};
use zip::write::SimpleFileOptions;

/// One entry to put in a test archive.
#[derive(Debug, Clone)]
pub(crate) enum E {
    Dir(String),
    File(String, Vec<u8>, u32),
    Symlink(String, String),
    Hard(String, String),
    Special(String, EntryType),
}

pub(crate) fn file(name: &str, data: &[u8]) -> E {
    E::File(name.to_owned(), data.to_vec(), 0o644)
}

pub(crate) fn exe(name: &str, data: &[u8]) -> E {
    E::File(name.to_owned(), data.to_vec(), 0o755)
}

pub(crate) fn dir(name: &str) -> E {
    E::Dir(name.to_owned())
}

pub(crate) fn symlink(name: &str, target: &str) -> E {
    E::Symlink(name.to_owned(), target.to_owned())
}

pub(crate) fn hard(name: &str, target: &str) -> E {
    E::Hard(name.to_owned(), target.to_owned())
}

/// A tar.gz holding `entries` exactly as given: names are written raw, unchecked.
pub(crate) fn tar_gz(entries: &[E]) -> Vec<u8> {
    let mut builder = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
    for entry in entries {
        let (name, kind, data, mode, link): (&str, EntryType, &[u8], u32, Option<&str>) =
            match entry {
                E::Dir(n) => (n, EntryType::Directory, &[], 0o755, None),
                E::File(n, d, m) => (n, EntryType::Regular, d, *m, None),
                E::Symlink(n, t) => (n, EntryType::Symlink, &[], 0o777, Some(t)),
                E::Hard(n, t) => (n, EntryType::Link, &[], 0o644, Some(t)),
                E::Special(n, k) => (n, *k, &[], 0o644, None),
            };
        let mut header = Header::new_gnu();
        header.set_entry_type(kind);
        header.set_size(data.len() as u64);
        header.set_mode(mode);
        if let Some(link) = link {
            let field = &mut header.as_old_mut().linkname;
            field[..link.len()].copy_from_slice(link.as_bytes());
        }
        if name.len() <= 100 {
            header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
            header.set_cksum();
            builder.append(&header, data).unwrap();
        } else {
            builder.append_data(&mut header, name, data).unwrap();
        }
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// A zip holding `entries`. Hard links and special entries cannot be expressed and panic.
pub(crate) fn zip(entries: &[E]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let deflated =
        SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for entry in entries {
        match entry {
            E::Dir(n) => writer.add_directory(n.as_str(), deflated).unwrap(),
            E::File(n, d, m) => {
                writer
                    .start_file(n.as_str(), deflated.unix_permissions(*m))
                    .unwrap();
                writer.write_all(d).unwrap();
            }
            E::Symlink(n, t) => writer
                .add_symlink(n.as_str(), t.as_str(), deflated)
                .unwrap(),
            E::Hard(..) | E::Special(..) => panic!("zip cannot hold {entry:?}"),
        }
    }
    writer.finish().unwrap().into_inner()
}

/// A temporary directory holding an archive and an empty `dest` directory beside it.
pub(crate) struct Scratch {
    pub(crate) dir: tempfile::TempDir,
}

impl Scratch {
    pub(crate) fn new() -> Scratch {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("dest")).unwrap();
        Scratch { dir }
    }

    pub(crate) fn dest(&self) -> PathBuf {
        self.dir.path().join("dest")
    }

    pub(crate) fn extract(
        &self,
        bytes: &[u8],
        format: Format,
        options: &Options,
    ) -> Result<Summary> {
        let archive = self.dir.path().join("archive");
        std::fs::write(&archive, bytes).unwrap();
        let result = jtm_archive::extract(&archive, format, &self.dest(), options);
        std::fs::remove_file(&archive).unwrap();
        result
    }

    /// Every path in the scratch directory outside `dest`, relative to it.
    pub(crate) fn outside(&self) -> Vec<PathBuf> {
        walk(self.dir.path())
            .into_iter()
            .filter(|p| !p.starts_with(self.dest()))
            .map(|p| p.strip_prefix(self.dir.path()).unwrap().to_path_buf())
            .collect()
    }
}

/// Every path under `root`, not following links.
pub(crate) fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            out.push(path.clone());
            if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                stack.push(path);
            }
        }
    }
    out
}
