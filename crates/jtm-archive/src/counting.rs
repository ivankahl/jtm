//! A reader that counts the bytes read through it, for the compression ratio checks.

use std::cell::Cell;
use std::io::{self, Read, Seek, SeekFrom};
use std::rc::Rc;

/// Counts the bytes read through it into a shared counter, so a ratio uses the bytes actually
/// consumed rather than the sizes an archive claims.
pub(crate) struct Counting<R> {
    inner: R,
    count: Rc<Cell<u64>>,
}

impl<R> Counting<R> {
    pub(crate) fn new(inner: R, count: &Rc<Cell<u64>>) -> Counting<R> {
        Counting {
            inner,
            count: Rc::clone(count),
        }
    }
}

impl<R: Read> Read for Counting<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.set(self.count.get() + n as u64);
        Ok(n)
    }
}

impl<R: Seek> Seek for Counting<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}
