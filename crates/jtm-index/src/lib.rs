//! Source adapters and the `sources.toml` schema of the jtm index generator (SPEC.md sections
//! 8 and 15).
//!
//! A plugin's `sources.toml` lists the upstreams CI queries to discover versions and the
//! hashes they publish. Each [`sources::Source`] names an adapter; running it gives a
//! [`candidate::Discovery`] of [`candidate::Candidate`]s. Adapters only report what an
//! upstream claims. Whether two sources agree, whether a vendor signature holds, and the
//! SHA-256 that goes into an index are decided after them.

pub mod adapters;
pub mod candidate;
pub mod context;
pub mod error;
pub mod sources;

#[cfg(test)]
mod testing;

pub use candidate::{Candidate, ClaimedHash, Discovery, HashAlgorithm, Target};
pub use context::Context;
pub use error::{Error, Result};
pub use sources::{Role, Source, SourcesFile};
