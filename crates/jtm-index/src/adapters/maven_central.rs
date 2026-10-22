//! A repository in Maven layout, Maven Central by default (`adapter = "maven-central"`).
//!
//! The versions come from the artifact's `maven-metadata.xml`. For each, the adapter builds the
//! file's URL from the coordinates and reads the checksum Maven publishes beside it. Central
//! offers `.sha1` for everything and `.sha256` or `.sha512` for newer releases; `hashes` lists
//! the algorithms to try, strongest first. A SHA-1 alone cannot confirm an artifact, so the
//! generator also computes SHA-256 of the download itself.
//!
//! The detached `.asc` signature is reported as `signature_url` when `signature = true`.

use regex::Regex;
use serde::Deserialize;

use super::{Origin, check_https, is_url_token, with_trailing_slash};
use crate::candidate::{
    ClaimedHash, Discovery, HashAlgorithm, Target, archive_from_name, check_url,
    parse_checksum_file,
};
use crate::context::{CHECKSUM_LIMIT, Context, DOCUMENT_LIMIT};
use crate::error::{Error, Result};

const DEFAULT_REPOSITORY: &str = "https://repo.maven.apache.org/maven2/";

/// Settings of the `maven-central` adapter.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MavenCentralConfig {
    /// The repository root.
    #[serde(default = "default_repository")]
    pub repository: String,
    pub group: String,
    pub artifact: String,
    /// The classifier of the file, such as `bin`.
    #[serde(default)]
    pub classifier: Option<String>,
    /// The file extension: `zip`, `tar.gz` or `tar.xz`.
    pub extension: String,
    /// The checksum algorithms to try, strongest first.
    #[serde(default = "default_hashes")]
    pub hashes: Vec<String>,
    /// Whether to report the `.asc` signature.
    #[serde(default = "yes")]
    pub signature: bool,
    /// A regular expression a version must match. Without one every version is listed.
    #[serde(default)]
    pub version_pattern: Option<String>,
}

fn default_repository() -> String {
    DEFAULT_REPOSITORY.to_owned()
}

fn default_hashes() -> Vec<String> {
    ["sha512", "sha256", "sha1"].map(str::to_owned).to_vec()
}

const fn yes() -> bool {
    true
}

impl MavenCentralConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        check_https(&self.repository, "repository")?;
        for part in self.group.split('.') {
            if !is_url_token(part) {
                return Err(format!("group: `{}` is not a Maven group id", self.group));
            }
        }
        if !is_url_token(&self.artifact) {
            return Err(format!(
                "artifact: `{}` is not a Maven artifact id",
                self.artifact
            ));
        }
        if let Some(classifier) = &self.classifier
            && !is_url_token(classifier)
        {
            return Err(format!(
                "classifier: `{classifier}` is not a Maven classifier"
            ));
        }
        if archive_from_name(&format!("x.{}", self.extension)).is_none() {
            return Err(format!(
                "extension: `{}` is not zip, tar.gz or tar.xz",
                self.extension
            ));
        }
        if self.hashes.is_empty() {
            return Err("hashes: needs at least one algorithm".to_owned());
        }
        for name in &self.hashes {
            if HashAlgorithm::parse(name).is_none() {
                return Err(format!("hashes: `{name}` is not sha1, sha256 or sha512"));
            }
        }
        self.pattern().map(|_| ())
    }

    fn pattern(&self) -> Result<Option<Regex>, String> {
        self.version_pattern
            .as_deref()
            .map(|p| Regex::new(p).map_err(|e| format!("version_pattern: {e}")))
            .transpose()
    }

    pub(crate) fn discover(&self, origin: &Origin<'_>, ctx: &Context) -> Result<Discovery> {
        let pattern = self
            .pattern()
            .map_err(|m| Error::response(origin.id, "sources.toml", m))?;
        let directory = format!(
            "{}{}/{}/",
            with_trailing_slash(&self.repository),
            self.group.replace('.', "/"),
            self.artifact
        );
        let metadata_url = format!("{directory}maven-metadata.xml");
        let metadata = ctx.get(origin.id, &metadata_url, DOCUMENT_LIMIT)?;
        let metadata = String::from_utf8_lossy(&metadata);
        let versions = metadata_versions(&metadata);
        if versions.is_empty() {
            return Err(Error::response(
                origin.id,
                &metadata_url,
                "lists no <version> inside <versions>",
            ));
        }
        let mut discovery = Discovery::default();
        for version in versions {
            if pattern.as_ref().is_some_and(|p| !p.is_match(&version)) {
                continue;
            }
            self.discover_version(origin, ctx, &directory, &version, &mut discovery)?;
        }
        Ok(discovery)
    }

    fn file_name(&self, version: &str) -> String {
        match &self.classifier {
            Some(classifier) => format!(
                "{}-{version}-{classifier}.{}",
                self.artifact, self.extension
            ),
            None => format!("{}-{version}.{}", self.artifact, self.extension),
        }
    }

    fn discover_version(
        &self,
        origin: &Origin<'_>,
        ctx: &Context,
        directory: &str,
        version: &str,
        discovery: &mut Discovery,
    ) -> Result<()> {
        // A version string comes from the repository, so it must be a plain path segment
        // before it is put in a URL.
        if !is_url_token(version) {
            discovery.warn(format!(
                "{} {version}: skipped, not a plain version string",
                origin.id
            ));
            return Ok(());
        }
        let url = format!("{directory}{version}/{}", self.file_name(version));
        let Some(archive) = archive_from_name(&url) else {
            return Ok(());
        };
        if let Err(reason) = check_url(&url) {
            discovery.warn(format!("{} {version}: skipped, {reason}", origin.id));
            return Ok(());
        }
        let mut claim = None;
        for name in &self.hashes {
            let Some(algorithm) = HashAlgorithm::parse(name) else {
                continue;
            };
            let sidecar = format!("{url}.{}", algorithm.as_str());
            let Some(text) = ctx.get_text(origin.id, &sidecar, CHECKSUM_LIMIT)? else {
                continue;
            };
            claim = parse_checksum_file(&text, algorithm)
                .and_then(|hex| ClaimedHash::new(algorithm, &hex, &sidecar));
            if claim.is_some() {
                break;
            }
        }
        let Some(claim) = claim else {
            discovery.warn(format!(
                "{} {version}: skipped, no checksum file ({}) beside {url}",
                origin.id,
                self.hashes.join(", ")
            ));
            return Ok(());
        };
        let mut candidate = origin.candidate(version.to_owned(), Target::Any, url.clone(), archive);
        candidate.hash = Some(claim);
        if self.signature {
            candidate.signature_url = Some(format!("{url}.asc"));
        }
        discovery.push(candidate);
        Ok(())
    }
}

/// The `<version>` values inside `<versions>` of a `maven-metadata.xml`. The file is
/// machine-generated with one element per version, so a scan is enough; markup anywhere else
/// (`<latest>`, `<release>`) is ignored on purpose, since only listed versions have files.
pub(crate) fn metadata_versions(xml: &str) -> Vec<String> {
    let Some(start) = xml.find("<versions>") else {
        return Vec::new();
    };
    let body = &xml[start + "<versions>".len()..];
    let body = body.split("</versions>").next().unwrap_or(body);
    let mut versions = Vec::new();
    let mut rest = body;
    while let Some(open) = rest.find("<version>") {
        let after = &rest[open + "<version>".len()..];
        let Some(close) = after.find("</version>") else {
            break;
        };
        let version = after[..close].trim();
        if !version.is_empty() && !versions.iter().any(|v| v == version) {
            versions.push(version.to_owned());
        }
        rest = &after[close + "</version>".len()..];
    }
    versions
}

#[cfg(test)]
mod tests;
