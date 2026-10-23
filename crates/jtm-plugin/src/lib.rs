//! Manifest schema, version schemes, aliases and interop parsers for jtm.

pub mod alias;
pub mod interop;
pub mod manifest;
pub mod names;
pub mod properties;
pub mod version;

pub use alias::{
    Candidate, ResolveError, resolve_alias, resolve_default, resolve_value, select_highest,
    sorted_for_display,
};
pub use manifest::{Manifest, ManifestError};
pub use version::{MaybeVersion, Version, VersionError, VersionScheme};
