//! Signature verification, keys.json, trust state and index load checks for jtm.
//!
//! Everything here works on raw bytes first: a signed file is verified before any of it reaches
//! a parser (SPEC.md section 9).

pub mod checks;
pub mod error;
pub mod index;
pub mod key;
pub mod keys_json;
pub mod select;
pub mod signature;
pub mod time;
pub mod trust;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use checks::{ExpiryPolicy, IndexRequest, Warning, check_index, check_keys_json};
pub use error::{Error, Result};
pub use index::{ArchiveKind, IndexEntry, IndexFile, LoadedIndex};
pub use key::{KeyGroup, KeyId, KeyParseError, Keyring, PublicKey, Scope, TrustedKey};
pub use keys_json::{IndexKey, KeysFile, RootOfTrust};
pub use select::{IndexCopy, Selected, Selection, select};
pub use signature::{Subject, Verified, verify};
pub use time::Timestamp;
pub use trust::{Seen, SourceKind, TrustState, UserKey};

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}
