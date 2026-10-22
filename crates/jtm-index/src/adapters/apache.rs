//! Apache distribution directories (`adapter = "apache"`): `downloads.apache.org` for current
//! releases and `archive.apache.org/dist` for every release ever made.
//!
//! Each directory in `listings` has one subdirectory per version. The adapter reads the
//! directory index, builds the artifact URL from the `artifact` template and fetches the
//! digest published beside it (`<artifact>.sha512` by default). The URLs it reports are on
//! whichever host `listings` names, so a plugin that wants installs to keep working after a
//! release leaves the current directory points at the archive host.
//!
//! The detached `<artifact>.asc` signature is reported as `signature_url` when
//! `signature_suffix` is set; checking it against Apache's `KEYS` file is the generator's job.

use std::collections::BTreeSet;

use regex::Regex;
use serde::Deserialize;

use super::template;
use super::{Origin, check_https, with_trailing_slash};
use crate::candidate::{
    ClaimedHash, Discovery, HashAlgorithm, Target, archive_from_name, check_url,
    parse_checksum_file,
};
use crate::context::{CHECKSUM_LIMIT, Context, DOCUMENT_LIMIT};
use crate::error::{Error, Result};

/// The versions a directory may hold: they start with a digit, so `KEYS`, `binaries` and the
/// like are never taken for one.
const DEFAULT_VERSION_PATTERN: &str = r"^[0-9][0-9A-Za-z._+-]*$";

/// Settings of the `apache` adapter.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApacheConfig {
    /// Directories whose subdirectories are versions, such as
    /// `https://archive.apache.org/dist/maven/maven-3/`.
    pub listings: Vec<String>,
    /// The artifact's path below a version's directory, with `{version}`.
    pub artifact: String,
    /// The digest published beside the artifact: `sha512` (the default) is fetched from
    /// `<artifact>.sha512`.
    #[serde(default = "default_hash")]
    pub hash: String,
    /// Appended to the artifact URL to find its detached signature. Empty for none.
    #[serde(default = "default_signature")]
    pub signature_suffix: String,
    /// A regular expression a directory name must match to count as a version.
    #[serde(default)]
    pub version_pattern: Option<String>,
}

fn default_hash() -> String {
    "sha512".to_owned()
}

fn default_signature() -> String {
    ".asc".to_owned()
}

impl ApacheConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.listings.is_empty() {
            return Err("listings: needs at least one directory".to_owned());
        }
        for listing in &self.listings {
            check_https(listing, "listings")?;
        }
        template::check(&self.artifact, &["version"]).map_err(|m| format!("artifact: {m}"))?;
        if self.artifact.starts_with('/') || self.artifact.contains("..") {
            return Err("artifact: must be a relative path inside the version directory".into());
        }
        if !self.artifact.contains("{version}") {
            return Err("artifact: must contain `{version}`".to_owned());
        }
        if archive_from_name(&self.artifact).is_none() {
            return Err("artifact: must name a .zip, .tar.gz or .tar.xz file".to_owned());
        }
        if HashAlgorithm::parse(&self.hash).is_none() {
            return Err(format!(
                "hash: `{}` is not sha1, sha256 or sha512",
                self.hash
            ));
        }
        if !self.signature_suffix.is_empty() && !self.signature_suffix.starts_with('.') {
            return Err("signature_suffix: must start with `.`, such as `.asc`".to_owned());
        }
        self.pattern().map(|_| ())
    }

    fn pattern(&self) -> Result<Regex, String> {
        let text = self
            .version_pattern
            .as_deref()
            .unwrap_or(DEFAULT_VERSION_PATTERN);
        Regex::new(text).map_err(|e| format!("version_pattern: {e}"))
    }

    pub(crate) fn discover(&self, origin: &Origin<'_>, ctx: &Context) -> Result<Discovery> {
        let pattern = self
            .pattern()
            .map_err(|m| Error::response(origin.id, "sources.toml", m))?;
        let algorithm = HashAlgorithm::parse(&self.hash)
            .ok_or_else(|| Error::response(origin.id, "sources.toml", "unknown hash"))?;
        let mut discovery = Discovery::default();
        for listing in &self.listings {
            let listing = with_trailing_slash(listing);
            let page = ctx.get(origin.id, &listing, DOCUMENT_LIMIT)?;
            let page = String::from_utf8_lossy(&page);
            let mut seen = BTreeSet::new();
            for version in directory_names(&page) {
                if pattern.is_match(&version) && seen.insert(version.clone()) {
                    self.discover_version(
                        origin,
                        ctx,
                        &listing,
                        &version,
                        algorithm,
                        &mut discovery,
                    )?;
                }
            }
        }
        Ok(discovery)
    }

    fn discover_version(
        &self,
        origin: &Origin<'_>,
        ctx: &Context,
        listing: &str,
        version: &str,
        algorithm: HashAlgorithm,
        discovery: &mut Discovery,
    ) -> Result<()> {
        let path = template::render(&self.artifact, |name| {
            (name == "version").then(|| version.to_owned())
        });
        let url = format!("{listing}{version}/{path}");
        let Some(archive) = archive_from_name(&url) else {
            return Ok(());
        };
        if let Err(reason) = check_url(&url) {
            discovery.warn(format!("{} {version}: skipped, {reason}", origin.id));
            return Ok(());
        }
        let sidecar = format!("{url}.{}", algorithm.as_str());
        let text = ctx.get_text(origin.id, &sidecar, CHECKSUM_LIMIT)?;
        let claim = text
            .and_then(|t| parse_checksum_file(&t, algorithm))
            .and_then(|hex| ClaimedHash::new(algorithm, &hex, &sidecar));
        let Some(claim) = claim else {
            discovery.warn(format!(
                "{} {version}: skipped, no usable {algorithm} file at {sidecar}",
                origin.id
            ));
            return Ok(());
        };
        let mut candidate = origin.candidate(version.to_owned(), Target::Any, url.clone(), archive);
        candidate.hash = Some(claim);
        if !self.signature_suffix.is_empty() {
            candidate.signature_url = Some(format!("{url}{}", self.signature_suffix));
        }
        discovery.push(candidate);
        Ok(())
    }
}

/// The names of the subdirectories an Apache directory index links to, in page order. A link
/// counts only when it is one relative path segment ending in `/`, which leaves out the sort
/// links (`?C=N;O=D`), the parent directory and anything pointing elsewhere.
pub(crate) fn directory_names(html: &str) -> impl Iterator<Item = String> + '_ {
    let mut rest = html;
    std::iter::from_fn(move || {
        loop {
            let at = rest.find("href=\"")?;
            let after = &rest[at + "href=\"".len()..];
            let end = after.find('"')?;
            let href = &after[..end];
            rest = &after[end..];
            if let Some(name) = href.strip_suffix('/')
                && !name.is_empty()
                && !name.contains(['/', '?', '#', ':', '%', '\\'])
                && name != ".."
                && name != "."
            {
                return Some(name.to_owned());
            }
        }
    })
}

#[cfg(test)]
mod tests;
