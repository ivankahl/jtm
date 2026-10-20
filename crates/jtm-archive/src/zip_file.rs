//! Reading `zip` archives.

use std::cell::Cell;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::rc::Rc;

use crate::counting::Counting;
use crate::entry::Sink;
use crate::error::{Error, Result};

/// The longest symbolic link target read from a zip entry.
const MAX_LINK_TARGET: u64 = 4096;

const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;
const S_IFLNK: u32 = 0o120_000;

/// What a Unix mode in a zip's external attributes says an entry is.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ModeKind {
    File,
    Dir,
    Symlink,
    Special(&'static str),
}

pub(crate) fn mode_kind(mode: u32) -> ModeKind {
    match mode & S_IFMT {
        0 | S_IFREG => ModeKind::File,
        S_IFDIR => ModeKind::Dir,
        S_IFLNK => ModeKind::Symlink,
        0o020_000 | 0o060_000 => ModeKind::Special("device files are not allowed"),
        0o010_000 => ModeKind::Special("FIFOs are not allowed"),
        0o140_000 => ModeKind::Special("sockets are not allowed"),
        _ => ModeKind::Special("unknown file type"),
    }
}

pub(crate) fn read(archive: &Path, sink: &mut Sink<'_>) -> Result<()> {
    let file = File::open(archive).map_err(|e| Error::io(archive, e))?;
    let consumed = Rc::new(Cell::new(0u64));
    let mut zip =
        zip::ZipArchive::new(Counting::new(BufReader::new(file), &consumed)).map_err(malformed)?;
    let limits = sink.limits();
    if zip.len() as u64 > limits.max_entries {
        return Err(Error::unsafe_entry(
            "",
            format!("the archive has more than {} entries", limits.max_entries),
        ));
    }
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(malformed)?;
        let start = consumed.get();
        let raw = entry.name_raw().to_vec();
        let display = String::from_utf8_lossy(&raw).into_owned();
        sink.count_entry(&display)?;
        let mode = entry.unix_mode();
        let kind = match mode {
            Some(mode) => mode_kind(mode),
            None if entry.is_dir() => ModeKind::Dir,
            None => ModeKind::File,
        };
        match kind {
            ModeKind::Dir => sink.dir(&raw)?,
            ModeKind::File if entry.is_dir() => sink.dir(&raw)?,
            ModeKind::File => {
                let ratio = |written: u64| {
                    let compressed = (consumed.get() - start).max(1);
                    (written > limits.ratio_floor && written / compressed > limits.max_ratio)
                        .then(|| format!("expands more than {}:1", limits.max_ratio))
                };
                sink.file(&raw, mode, &mut entry, &ratio)?;
            }
            ModeKind::Symlink => {
                let mut target = Vec::new();
                (&mut entry)
                    .take(MAX_LINK_TARGET + 1)
                    .read_to_end(&mut target)
                    .map_err(|e| Error::Malformed {
                        message: format!("cannot read `{display}`: {e}"),
                    })?;
                if target.len() as u64 > MAX_LINK_TARGET {
                    return Err(Error::unsafe_entry(display, "the link target is too long"));
                }
                sink.symlink(&raw, &target)?;
            }
            ModeKind::Special(reason) => return Err(Error::unsafe_entry(display, reason)),
        }
    }
    Ok(())
}

fn malformed(err: zip::result::ZipError) -> Error {
    Error::Malformed {
        message: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_modes_classify_entries() {
        assert_eq!(mode_kind(0o100_755), ModeKind::File);
        assert_eq!(mode_kind(0o644), ModeKind::File);
        assert_eq!(mode_kind(0o040_755), ModeKind::Dir);
        assert_eq!(mode_kind(0o120_777), ModeKind::Symlink);
        for special in [0o020_644, 0o060_644, 0o010_644, 0o140_644] {
            assert!(
                matches!(mode_kind(special), ModeKind::Special(_)),
                "{special:o}"
            );
        }
    }
}
