//! Manifest schema, version schemes, aliases, interop parsers and Luau sandbox for jtm.

pub mod alias;
pub mod manifest;
pub mod names;
pub mod version;

pub use alias::{AliasError, Candidate, resolve_alias, select_highest};
pub use manifest::{Manifest, ManifestError};
pub use version::{Version, VersionError, VersionScheme};
