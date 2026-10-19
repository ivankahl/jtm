//! Signature verification, keys.json, trust state and index load checks for jtm.
//!
//! Everything here works on raw bytes first: a signed file is verified before any of it reaches
//! a parser (SPEC.md section 9).

pub mod error;
pub mod key;
pub mod signature;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use error::{Error, Result};
pub use key::{KeyGroup, KeyId, KeyParseError, Keyring, PublicKey, Scope, TrustedKey};
pub use signature::{Subject, Verified, verify};
