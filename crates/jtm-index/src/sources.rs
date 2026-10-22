//! The `sources.toml` schema (SPEC.md sections 7 and 15).
//!
//! `sources.toml` sits next to a plugin's `plugin.toml` and tells the index generator where to
//! discover versions and the hashes their upstreams publish. Only the generator reads it; jtm
//! itself never does, so it cannot widen what a client trusts.
//!
//! ```toml
//! schema = 1
//!
//! [[source]]
//! id = "adoptium-api"        # recorded in an entry's `provenance`
//! adapter = "adoptium"       # which adapter queries this upstream
//! role = "primary"           # exactly one primary per variant: it supplies the entry
//! variant = "temurin"        # omit for a tool without variants
//! features = [17, 21]        # ...then whatever the adapter documents
//!
//! [[source]]
//! id = "github-sidecar"
//! adapter = "github-releases"
//! role = "confirm"           # only supplies a second opinion on the hash
//! variant = "temurin"
//! ```

use std::collections::BTreeSet;
use std::path::Path;

use jtm_plugin::names::check_name_segment;
use serde::Deserialize;

use crate::adapters::{
    AdoptiumConfig, ApacheConfig, FoojayConfig, GithubConfig, GradleConfig, MavenCentralConfig,
    Origin,
};
use crate::candidate::Discovery;
use crate::context::Context;
use crate::error::{Error, Result};

/// The only `sources.toml` schema this build reads.
pub const SOURCES_SCHEMA: u32 = 1;
/// The largest `sources.toml` accepted.
const MAX_SOURCES_FILE: u64 = 256 * 1024;

/// A parsed and validated `sources.toml`.
#[derive(Debug, Clone, PartialEq)]
pub struct SourcesFile {
    pub sources: Vec<Source>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    schema: u32,
    #[serde(default, rename = "source")]
    sources: Vec<Source>,
}

/// What a source contributes to an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// Supplies the entry: its version, URL, size and tags. There is exactly one per variant.
    Primary,
    /// Only reports what it knows about artifacts the primary found, so the generator can
    /// check that two upstreams agree on the hash.
    Confirm,
}

/// One upstream to query.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Source {
    /// A short name, recorded in the entry's `provenance` when this source agrees on a hash.
    pub id: String,
    pub role: Role,
    /// The index entry variant this source covers; omitted for a tool without variants.
    #[serde(default)]
    pub variant: Option<String>,
    /// Which adapter runs, and its settings.
    #[serde(flatten)]
    pub adapter: Adapter,
}

/// The adapters, selected by the `adapter` key. Each documents its own keys; an unknown key is
/// an error, so a typo cannot silently change what is queried.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "adapter", rename_all = "kebab-case")]
pub enum Adapter {
    Adoptium(AdoptiumConfig),
    Foojay(FoojayConfig),
    Apache(ApacheConfig),
    Gradle(GradleConfig),
    GithubReleases(GithubConfig),
    MavenCentral(MavenCentralConfig),
}

impl Adapter {
    /// The name used in `sources.toml`.
    pub const fn name(&self) -> &'static str {
        match self {
            Adapter::Adoptium(_) => "adoptium",
            Adapter::Foojay(_) => "foojay",
            Adapter::Apache(_) => "apache",
            Adapter::Gradle(_) => "gradle",
            Adapter::GithubReleases(_) => "github-releases",
            Adapter::MavenCentral(_) => "maven-central",
        }
    }

    fn validate(&self) -> std::result::Result<(), String> {
        match self {
            Adapter::Adoptium(c) => c.validate(),
            Adapter::Foojay(c) => c.validate(),
            Adapter::Apache(c) => c.validate(),
            Adapter::Gradle(c) => c.validate(),
            Adapter::GithubReleases(c) => c.validate(),
            Adapter::MavenCentral(c) => c.validate(),
        }
    }
}

impl Source {
    /// Queries the upstream and reports what it claims.
    pub fn discover(&self, ctx: &Context) -> Result<Discovery> {
        let origin = Origin {
            id: &self.id,
            variant: self.variant.as_deref(),
        };
        match &self.adapter {
            Adapter::Adoptium(c) => c.discover(&origin, ctx),
            Adapter::Foojay(c) => c.discover(&origin, ctx),
            Adapter::Apache(c) => c.discover(&origin, ctx),
            Adapter::Gradle(c) => c.discover(&origin, ctx),
            Adapter::GithubReleases(c) => c.discover(&origin, ctx),
            Adapter::MavenCentral(c) => c.discover(&origin, ctx),
        }
    }

    fn validate(&self) -> std::result::Result<(), String> {
        check_name_segment(&self.id, "source id").map_err(|(_, m)| m)?;
        if let Some(variant) = &self.variant {
            check_name_segment(variant, "variant").map_err(|(_, m)| m)?;
        }
        self.adapter.validate()
    }
}

impl SourcesFile {
    /// Parses `text`; `file` names it in messages.
    pub fn parse(file: &str, text: &str) -> Result<SourcesFile> {
        let invalid = |message: String| Error::Sources {
            file: file.to_owned(),
            message,
        };
        if text.len() as u64 > MAX_SOURCES_FILE {
            return Err(invalid(format!("larger than {MAX_SOURCES_FILE} bytes")));
        }
        let deserializer = toml::Deserializer::parse(text).map_err(|e| invalid(e.to_string()))?;
        let raw: RawFile = serde_path_to_error::deserialize(deserializer)
            .map_err(|e| invalid(format!("{}: {}", e.path(), e.inner())))?;
        if raw.schema != SOURCES_SCHEMA {
            return Err(invalid(format!(
                "schema {} is not supported; this jtm reads schema {SOURCES_SCHEMA}",
                raw.schema
            )));
        }
        let file = SourcesFile {
            sources: raw.sources,
        };
        file.validate().map_err(invalid)?;
        Ok(file)
    }

    /// Reads and parses the file at `path`.
    pub fn load(path: &Path) -> Result<SourcesFile> {
        let label = path.display().to_string();
        let bytes = std::fs::read(path).map_err(|e| Error::Sources {
            file: label.clone(),
            message: e.to_string(),
        })?;
        let text = String::from_utf8(bytes).map_err(|_| Error::Sources {
            file: label.clone(),
            message: "is not UTF-8".to_owned(),
        })?;
        SourcesFile::parse(&label, &text)
    }

    /// The sources that cover `variant` (`None` for a tool without variants).
    pub fn for_variant<'a>(&'a self, variant: Option<&'a str>) -> impl Iterator<Item = &'a Source> {
        self.sources
            .iter()
            .filter(move |s| s.variant.as_deref() == variant)
    }

    /// The distinct variants the sources cover, in file order.
    pub fn variants(&self) -> Vec<Option<&str>> {
        let mut seen = Vec::new();
        for source in &self.sources {
            let variant = source.variant.as_deref();
            if !seen.contains(&variant) {
                seen.push(variant);
            }
        }
        seen
    }

    fn validate(&self) -> std::result::Result<(), String> {
        if self.sources.is_empty() {
            return Err("lists no `[[source]]`".to_owned());
        }
        let mut ids = BTreeSet::new();
        for (i, source) in self.sources.iter().enumerate() {
            source
                .validate()
                .map_err(|m| format!("source[{i}] (`{}`): {m}", source.id))?;
            if !ids.insert(source.id.as_str()) {
                return Err(format!("source[{i}]: the id `{}` is used twice", source.id));
            }
        }
        for variant in self.variants() {
            let primaries = self
                .for_variant(variant)
                .filter(|s| s.role == Role::Primary)
                .count();
            if primaries != 1 {
                let which = variant.map_or_else(
                    || "the sources without a variant".to_owned(),
                    |v| format!("variant `{v}`"),
                );
                return Err(format!(
                    "{which} needs exactly one source with role = \"primary\", found {primaries}"
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
