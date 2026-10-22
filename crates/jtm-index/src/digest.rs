//! The digests the generator computes while it downloads an artifact.
//!
//! Upstreams publish SHA-1, SHA-256 or SHA-512, so one pass over the bytes computes all three:
//! every claim can be compared against the digest of its own algorithm, and the SHA-256 goes
//! into the index (SPEC.md section 15).

use std::io::{self, Write};

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::candidate::HashAlgorithm;

/// Hashers fed with the same bytes.
#[derive(Debug, Default)]
pub struct Digests {
    sha1: Sha1,
    sha256: Sha256,
    sha512: Sha512,
    size: u64,
}

/// The digests of one stream and its length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Computed {
    pub size: u64,
    sha1: String,
    sha256: String,
    sha512: String,
}

impl Digests {
    pub fn new() -> Digests {
        Digests::default()
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.sha1.update(bytes);
        self.sha256.update(bytes);
        self.sha512.update(bytes);
        self.size += bytes.len() as u64;
    }

    pub fn finish(self) -> Computed {
        Computed {
            size: self.size,
            sha1: hex(&self.sha1.finalize()),
            sha256: hex(&self.sha256.finalize()),
            sha512: hex(&self.sha512.finalize()),
        }
    }
}

impl Write for Digests {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Computed {
    /// The lowercase hex digest for `algorithm`.
    pub fn hex(&self, algorithm: HashAlgorithm) -> &str {
        match algorithm {
            HashAlgorithm::Sha1 => &self.sha1,
            HashAlgorithm::Sha256 => &self.sha256,
            HashAlgorithm::Sha512 => &self.sha512,
        }
    }

    /// The SHA-256 that goes into an index entry.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests;
