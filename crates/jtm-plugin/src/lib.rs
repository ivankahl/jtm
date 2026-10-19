//! Manifest schema, version schemes, aliases, interop parsers and Luau sandbox for jtm.

pub mod manifest;
pub mod names;
pub mod version;

pub use manifest::{Manifest, ManifestError};
pub use version::{Version, VersionError, VersionScheme};
