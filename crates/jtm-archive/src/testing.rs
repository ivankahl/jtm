//! Builds archives in memory for tests, including ones no well-behaved tool would write.
//! Compiled only for this crate's tests and the `testing` feature.

#![allow(clippy::unwrap_used, clippy::panic, clippy::missing_panics_doc)]

use std::io::{Cursor, Write};

use flate2::Compression;
use flate2::write::GzEncoder;
use tar::{EntryType, Header};
use zip::write::SimpleFileOptions;

pub use tar::EntryType as TarEntryType;

/// One entry to put in a test archive.
#[derive(Debug, Clone)]
pub enum E {
    Dir(String),
    File(String, Vec<u8>, u32),
    Symlink(String, String),
    Hard(String, String),
    Special(String, EntryType),
}

pub fn file(name: &str, data: &[u8]) -> E {
    E::File(name.to_owned(), data.to_vec(), 0o644)
}

pub fn exe(name: &str, data: &[u8]) -> E {
    E::File(name.to_owned(), data.to_vec(), 0o755)
}

pub fn dir(name: &str) -> E {
    E::Dir(name.to_owned())
}

pub fn symlink(name: &str, target: &str) -> E {
    E::Symlink(name.to_owned(), target.to_owned())
}

pub fn hard(name: &str, target: &str) -> E {
    E::Hard(name.to_owned(), target.to_owned())
}

/// A tar.gz holding `entries` exactly as given: names are written raw, unchecked.
pub fn tar_gz(entries: &[E]) -> Vec<u8> {
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
pub fn zip(entries: &[E]) -> Vec<u8> {
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
