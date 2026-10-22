//! The Gradle versions API (`adapter = "gradle"`).
//!
//! One request lists every distribution Gradle has published, with the download URL, the
//! `.sha256` URL and, for most, the digest itself. Snapshots, nightlies, broken builds and
//! milestones are skipped; release candidates become `rc`-tagged candidates unless
//! `include_rc = false`.
//!
//! The digest can come from two places, and a plugin lists the adapter twice to use both:
//!
//! - `hash_from = "checksum-url"` fetches each `.sha256` file the API points to, the primary
//!   source in SPEC.md section 15.
//! - `hash_from = "versions-api"` reads the `checksum` field of the listing, the second source.
//!
//! Both are served by Gradle itself, so they guard against a corrupted file rather than a
//! compromised vendor; the generator weighs that when it counts independent sources.

use jtm_security::ArchiveKind;
use serde::Deserialize;

use super::{Origin, check_https};
use crate::candidate::{
    ClaimedHash, Discovery, HashAlgorithm, Target, check_url, parse_checksum_file,
};
use crate::context::{CHECKSUM_LIMIT, Context, DOCUMENT_LIMIT, parse_json};
use crate::error::Result;

const DEFAULT_VERSIONS_URL: &str = "https://services.gradle.org/versions/all";

/// Where the digest of each distribution is read from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GradleHash {
    /// The `checksum` field of the versions listing.
    #[default]
    VersionsApi,
    /// The file at each version's `checksumUrl`.
    ChecksumUrl,
}

/// Settings of the `gradle` adapter.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GradleConfig {
    /// The versions listing.
    #[serde(default = "default_versions_url")]
    pub versions_url: String,
    #[serde(default)]
    pub hash_from: GradleHash,
    /// Whether release candidates are listed, tagged `rc`.
    #[serde(default = "yes")]
    pub include_rc: bool,
}

fn default_versions_url() -> String {
    DEFAULT_VERSIONS_URL.to_owned()
}

const fn yes() -> bool {
    true
}

#[derive(Deserialize)]
struct Distribution {
    version: String,
    #[serde(default)]
    snapshot: bool,
    #[serde(default)]
    nightly: bool,
    #[serde(default, rename = "releaseNightly")]
    release_nightly: bool,
    #[serde(default)]
    broken: bool,
    #[serde(default, rename = "rcFor")]
    rc_for: String,
    #[serde(default, rename = "milestoneFor")]
    milestone_for: String,
    #[serde(rename = "downloadUrl")]
    download_url: String,
    #[serde(default, rename = "checksumUrl")]
    checksum_url: String,
    #[serde(default)]
    checksum: String,
}

impl GradleConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        check_https(&self.versions_url, "versions_url")
    }

    pub(crate) fn discover(&self, origin: &Origin<'_>, ctx: &Context) -> Result<Discovery> {
        let body = ctx.get(origin.id, &self.versions_url, DOCUMENT_LIMIT)?;
        let all: Vec<Distribution> = parse_json(origin.id, &self.versions_url, &body)?;
        let mut discovery = Discovery::default();
        for dist in all {
            if dist.snapshot
                || dist.nightly
                || dist.release_nightly
                || dist.broken
                || !dist.milestone_for.is_empty()
            {
                continue;
            }
            let is_rc = !dist.rc_for.is_empty();
            if is_rc && !self.include_rc {
                continue;
            }
            if let Err(reason) = check_url(&dist.download_url) {
                discovery.warn(format!("{} {}: skipped, {reason}", origin.id, dist.version));
                continue;
            }
            let mut candidate = origin.candidate(
                dist.version.clone(),
                Target::Any,
                dist.download_url.clone(),
                ArchiveKind::Zip,
            );
            if is_rc {
                candidate.tags.push("rc".to_owned());
            }
            let (digest, from) = match self.hash_from {
                GradleHash::VersionsApi => (Some(dist.checksum.clone()), self.versions_url.clone()),
                GradleHash::ChecksumUrl => (
                    self.fetch_sidecar(origin, ctx, &dist)?,
                    dist.checksum_url.clone(),
                ),
            };
            match digest.and_then(|d| ClaimedHash::new(HashAlgorithm::Sha256, &d, &from)) {
                Some(claim) => candidate.hash = Some(claim),
                None => {
                    discovery.warn(format!(
                        "{} {}: skipped, no SHA-256 from {from}",
                        origin.id, dist.version
                    ));
                    continue;
                }
            }
            discovery.push(candidate);
        }
        Ok(discovery)
    }

    /// The digest in a version's `.sha256` file, or `None` when it has none to read.
    fn fetch_sidecar(
        &self,
        origin: &Origin<'_>,
        ctx: &Context,
        dist: &Distribution,
    ) -> Result<Option<String>> {
        if check_url(&dist.checksum_url).is_err() {
            return Ok(None);
        }
        let text = ctx.get_text(origin.id, &dist.checksum_url, CHECKSUM_LIMIT)?;
        Ok(text.and_then(|t| parse_checksum_file(&t, HashAlgorithm::Sha256)))
    }
}

#[cfg(test)]
mod tests;
