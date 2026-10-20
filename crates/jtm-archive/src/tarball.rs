//! Reading `tar.gz` and, with the `xz` feature, `tar.xz` archives.

use std::cell::Cell;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
use std::rc::Rc;

use flate2::read::GzDecoder;
use tar::EntryType;

use crate::entry::Sink;
use crate::error::{Error, Result};

/// Counts the bytes read through it.
struct Counting<R> {
    inner: R,
    count: Rc<Cell<u64>>,
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.set(self.count.get() + n as u64);
        Ok(n)
    }
}

/// The compression around the tar stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Codec {
    Gzip,
    #[cfg(feature = "xz")]
    Xz,
}

/// The most memory the xz decoder may use, so a stream claiming a huge dictionary fails
/// instead of exhausting memory. Real archives use at most 64 MiB.
#[cfg(feature = "xz")]
const XZ_MEMORY_LIMIT_KIB: u32 = 256 * 1024;

pub(crate) fn read(archive: &Path, codec: Codec, sink: &mut Sink<'_>) -> Result<()> {
    let file = File::open(archive).map_err(|e| Error::io(archive, e))?;
    let compressed = Rc::new(Cell::new(0u64));
    let expanded = Rc::new(Cell::new(0u64));
    let input = Counting {
        inner: BufReader::new(file),
        count: Rc::clone(&compressed),
    };
    let decoder: Box<dyn Read> = match codec {
        Codec::Gzip => Box::new(GzDecoder::new(input)),
        #[cfg(feature = "xz")]
        Codec::Xz => Box::new(lzma_rust2::XzReader::new_mem_limit(
            input,
            true,
            XZ_MEMORY_LIMIT_KIB,
        )),
    };
    let mut tar = tar::Archive::new(Counting {
        inner: decoder,
        count: Rc::clone(&expanded),
    });
    let limits = sink.limits();
    // SPEC-QUESTION: a gzip or xz stream does not say how many compressed bytes belong to each
    // entry, so the 200:1 ratio is applied to the stream as a whole once it has produced
    // `ratio_floor` bytes. A bomb hidden in one entry still trips it as that entry expands.
    let ratio = |_: u64| -> Option<String> {
        let (out, input) = (expanded.get(), compressed.get().max(1));
        (out > limits.ratio_floor && out / input > limits.max_ratio)
            .then(|| format!("the archive expands more than {}:1", limits.max_ratio))
    };

    let entries = tar.entries().map_err(malformed)?;
    for entry in entries {
        let mut entry = entry.map_err(malformed)?;
        let raw = entry.path_bytes().into_owned();
        let display = String::from_utf8_lossy(&raw).into_owned();
        sink.count_entry(&display)?;
        let kind = entry.header().entry_type();
        match kind {
            EntryType::Regular | EntryType::Continuous => {
                let mode = entry.header().mode().ok();
                sink.file(&raw, mode, &mut entry, &ratio)?;
            }
            EntryType::Directory => sink.dir(&raw)?,
            EntryType::Symlink | EntryType::Link => {
                let target = entry
                    .link_name_bytes()
                    .ok_or_else(|| Error::unsafe_entry(&display, "a link has no target"))?
                    .into_owned();
                if kind == EntryType::Symlink {
                    sink.symlink(&raw, &target)?;
                } else {
                    sink.hardlink(&raw, &target)?;
                }
            }
            EntryType::Char | EntryType::Block => {
                return Err(Error::unsafe_entry(display, "device files are not allowed"));
            }
            EntryType::Fifo => {
                return Err(Error::unsafe_entry(display, "FIFOs are not allowed"));
            }
            other => {
                return Err(Error::unsafe_entry(
                    display,
                    format!("unsupported entry type {:?}", other.as_byte() as char),
                ));
            }
        }
        if let Some(reason) = ratio(0) {
            return Err(Error::unsafe_entry(display, reason));
        }
    }
    Ok(())
}

fn malformed(err: io::Error) -> Error {
    Error::Malformed {
        message: err.to_string(),
    }
}
