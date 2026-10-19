//! Manifest schema, version schemes, aliases, interop parsers and Luau sandbox for jtm.

pub mod names;
pub mod version;

pub use version::{Version, VersionError, VersionScheme};
