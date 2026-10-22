//! The source adapters: one module per kind of upstream.
//!
//! Every adapter reads its settings from a `[[source]]` table of `sources.toml`, queries its
//! upstream through the shared [`Context`](crate::Context) and returns a
//! [`Discovery`](crate::Discovery). Adapters never download artifacts and never decide what is
//! trusted; they report what the upstream says, with every field checked on the way out.
//!
//! The endpoints are settings with defaults, not constants in the code, because vendors move
//! them (SPEC.md section 15). All of them must be `https`: the client refuses anything else.

use std::fmt;

use jtm_core::Platform;
use jtm_security::ArchiveKind;
use serde::Deserialize;

use crate::candidate::{Candidate, Target};

mod adoptium;
mod apache;
mod foojay;
mod github;
mod gradle;
mod maven_central;
mod template;

pub use adoptium::AdoptiumConfig;
pub use apache::ApacheConfig;
pub use foojay::FoojayConfig;
pub use github::{GithubConfig, HashFrom};
pub use gradle::{GradleConfig, GradleHash};
pub use maven_central::MavenCentralConfig;

/// The source a candidate is built for.
#[derive(Debug, Clone, Copy)]
pub struct Origin<'a> {
    pub id: &'a str,
    pub variant: Option<&'a str>,
}

impl Origin<'_> {
    /// A candidate with the fields every adapter knows; the rest start empty.
    pub(crate) fn candidate(
        &self,
        version: String,
        target: Target,
        url: String,
        archive: ArchiveKind,
    ) -> Candidate {
        Candidate {
            source: self.id.to_owned(),
            variant: self.variant.map(str::to_owned),
            version,
            target,
            tags: Vec::new(),
            url,
            archive,
            size: None,
            hash: None,
            signature_url: None,
            distribution_version: None,
        }
    }
}

/// A list of platforms in `sources.toml`, where an empty or missing list means every v1
/// platform.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct Platforms(Vec<String>);

impl Platforms {
    pub(crate) fn validate(&self) -> Result<(), String> {
        for name in &self.0 {
            match Target::parse(name) {
                Some(Target::Platform(_)) => {}
                _ => {
                    let known: Vec<&str> = Platform::ALL.iter().map(|p| p.as_str()).collect();
                    return Err(format!(
                        "`{name}` is not a platform; expected one of {}",
                        known.join(", ")
                    ));
                }
            }
        }
        Ok(())
    }

    /// The platforms to query, in a stable order.
    pub(crate) fn list(&self) -> Vec<Platform> {
        if self.0.is_empty() {
            return Platform::ALL.to_vec();
        }
        let mut platforms: Vec<Platform> = self
            .0
            .iter()
            .filter_map(|name| match Target::parse(name) {
                Some(Target::Platform(platform)) => Some(platform),
                _ => None,
            })
            .collect();
        platforms.sort();
        platforms.dedup();
        platforms
    }
}

/// Whether `value` is safe to put in a URL path or query as it is: ASCII letters, digits and
/// `-`, `_`, `.`.
pub(crate) fn is_url_token(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Checks that `url` is an `https` URL ending in `/` or not, as `what` is documented.
pub(crate) fn check_https(url: &str, what: &str) -> Result<(), String> {
    crate::candidate::check_url(url).map_err(|m| format!("{what}: {m}"))
}

/// A URL with exactly one trailing `/`, for joining paths onto it.
pub(crate) fn with_trailing_slash(url: &str) -> String {
    format!("{}/", url.trim_end_matches('/'))
}

/// A URL with no trailing `/`.
pub(crate) fn without_trailing_slash(url: &str) -> &str {
    url.trim_end_matches('/')
}

impl fmt::Display for Origin<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id)
    }
}

#[cfg(test)]
mod tests;
