//! Manifest schema, version schemes, aliases, interop parsers and Luau sandbox for jtm.

pub mod alias;
pub mod manifest;
pub mod names;
pub mod version;

pub use alias::{
    Candidate, ResolveError, resolve_alias, resolve_value, select_highest, sorted_for_display,
};
pub use manifest::{Manifest, ManifestError};
pub use version::{MaybeVersion, Version, VersionError, VersionScheme};
