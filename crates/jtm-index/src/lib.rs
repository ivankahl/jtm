//! Source adapters and the `sources.toml` schema of the jtm index generator (SPEC.md sections
//! 8 and 15).
//!
//! A plugin's `sources.toml` lists the upstreams CI queries to discover versions and the
//! hashes they publish. Each [`sources::Source`] names an adapter; running it gives a
//! [`candidate::Discovery`] of [`candidate::Candidate`]s. Adapters only report what an
//! upstream claims. [`confirm::Confirmer`] then decides, by downloading every artifact,
//! whether the claims agree with each other and with the bytes, whether a vendor signature
//! holds, and what SHA-256 goes into an index, and it records why in each entry's provenance.

pub mod adapters;
pub mod candidate;
pub mod confirm;
pub mod context;
pub mod digest;
pub mod error;
pub mod signature;
pub mod sources;

#[cfg(test)]
mod testing;

pub use candidate::{Candidate, ClaimedHash, Discovery, HashAlgorithm, Target};
pub use context::Context;
pub use error::{Error, Result};
pub use sources::{Role, Source, SourcesFile};
