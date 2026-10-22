//! GitHub releases (`adapter = "github-releases"`): the release assets of a repository and the
//! digests GitHub or the project publishes for them.
//!
//! The adapter lists `repos/<repo>/releases`. A release counts when its tag matches
//! `tag_pattern`; the named groups of that pattern fill `{name}` in the `version` template and
//! in the `assets` templates, which say what each platform's file is called. A release without
//! a platform's asset simply has no candidate for it.
//!
//! The digest comes from `hash_from`:
//!
//! - `"digest"`: the `digest` field GitHub computes for every asset (`sha256:<hex>`).
//! - `"sidecar"`: a checksum file the project uploads beside the asset, named by appending
//!   `sidecar_suffix` (`.sha256`, `.sha256.txt`) to the asset's name.
//!
//! Requests carry the token given to the [`Context`] when there is one; anonymous callers get
//! only a small hourly allowance.

use std::collections::BTreeMap;

use regex::Regex;
use serde::Deserialize;

use super::template;
use super::{Origin, check_https, is_url_token, without_trailing_slash};
use crate::candidate::{
    ClaimedHash, Discovery, HashAlgorithm, Target, archive_from_name, check_url,
    parse_checksum_file,
};
use crate::context::{CHECKSUM_LIMIT, Context, DOCUMENT_LIMIT, parse_json};
use crate::error::{Error, Result};
use jtm_plugin::names::check_name_segment;

const DEFAULT_API: &str = "https://api.github.com";
/// The most releases the API returns per page.
const PER_PAGE: usize = 100;

/// Where the digest of an asset comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HashFrom {
    /// The `digest` GitHub records for each asset.
    Digest,
    /// A checksum file uploaded as another asset of the same release.
    Sidecar,
}

/// Settings of the `github-releases` adapter.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GithubConfig {
    #[serde(default = "default_api")]
    pub api_url: String,
    /// `owner/name`, with `{feature}` when each feature release has its own repository.
    pub repo: String,
    /// The feature releases to list, one repository each; required when `repo` uses
    /// `{feature}`.
    #[serde(default)]
    pub features: Option<Vec<u32>>,
    /// A regular expression a release's tag must match completely. Its named groups are
    /// placeholders in `version` and `assets`.
    pub tag_pattern: String,
    /// The version, from the tag's groups. Defaults to `{version}`.
    #[serde(default = "default_version")]
    pub version: String,
    /// The asset name for each platform (`any` or a platform string), with placeholders.
    pub assets: BTreeMap<String, String>,
    pub hash_from: HashFrom,
    /// Appended to an asset's name to find its checksum file; required for `sidecar`.
    #[serde(default)]
    pub sidecar_suffix: Option<String>,
    /// Appended to an asset's name to find its detached signature, if the project has one.
    #[serde(default)]
    pub signature_suffix: Option<String>,
    /// Whether releases GitHub marks as pre-releases are listed.
    #[serde(default)]
    pub include_prereleases: bool,
    /// Tags given to every candidate.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Tags given to candidates of pre-releases, in addition to `tags`.
    #[serde(default)]
    pub prerelease_tags: Vec<String>,
    /// A bound on the pages of releases read per repository.
    #[serde(default = "default_max_pages")]
    pub max_pages: u32,
}

fn default_api() -> String {
    DEFAULT_API.to_owned()
}

fn default_version() -> String {
    "{version}".to_owned()
}

const fn default_max_pages() -> u32 {
    10
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    digest: Option<String>,
}

impl GithubConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        check_https(&self.api_url, "api_url")?;
        let pattern = self.pattern()?;
        let mut groups: Vec<&str> = pattern.capture_names().flatten().collect();
        let uses_feature = self.repo.contains("{feature}");
        match (&self.features, uses_feature) {
            (None, true) => return Err("features: required, since `repo` uses `{feature}`".into()),
            (Some(_), false) => {
                return Err("features: `repo` has no `{feature}` for them to fill".into());
            }
            (Some(features), true) if features.is_empty() => {
                return Err("features: needs at least one feature release".to_owned());
            }
            _ => {}
        }
        template::check(&self.repo, &["feature"]).map_err(|m| format!("repo: {m}"))?;
        let rendered = template::render(&self.repo, |_| Some("1".to_owned()));
        match rendered.split_once('/') {
            Some((owner, name))
                if is_url_token(owner) && is_url_token(name) && !name.contains('/') => {}
            _ => return Err(format!("repo: `{}` is not `owner/name`", self.repo)),
        }
        if self.features.is_some() {
            groups.push("feature");
        }
        template::check(&self.version, &groups).map_err(|m| format!("version: {m}"))?;
        if self.assets.is_empty() {
            return Err("assets: needs at least one platform".to_owned());
        }
        for (target, name) in &self.assets {
            if Target::parse(target).is_none() {
                return Err(format!("assets: `{target}` is not `any` or a platform"));
            }
            template::check(name, &groups).map_err(|m| format!("assets.{target}: {m}"))?;
        }
        match (self.hash_from, &self.sidecar_suffix) {
            (HashFrom::Sidecar, None) => {
                return Err("sidecar_suffix: required when hash_from = \"sidecar\"".into());
            }
            (HashFrom::Digest, Some(_)) => {
                return Err("sidecar_suffix: only used when hash_from = \"sidecar\"".into());
            }
            _ => {}
        }
        for (name, suffix) in [
            ("sidecar_suffix", &self.sidecar_suffix),
            ("signature_suffix", &self.signature_suffix),
        ] {
            if let Some(suffix) = suffix
                && (!suffix.starts_with('.') || suffix.contains('/'))
            {
                return Err(format!(
                    "{name}: `{suffix}` must start with `.`, like `.sha256`"
                ));
            }
        }
        for tag in self.tags.iter().chain(&self.prerelease_tags) {
            check_name_segment(tag, "tag").map_err(|(_, m)| m)?;
        }
        if self.max_pages == 0 {
            return Err("max_pages: must be at least 1".to_owned());
        }
        Ok(())
    }

    /// The tag pattern, anchored so it must match the whole tag.
    fn pattern(&self) -> Result<Regex, String> {
        Regex::new(&format!("^(?:{})$", self.tag_pattern)).map_err(|e| format!("tag_pattern: {e}"))
    }

    pub(crate) fn discover(&self, origin: &Origin<'_>, ctx: &Context) -> Result<Discovery> {
        let pattern = self
            .pattern()
            .map_err(|m| Error::response(origin.id, "sources.toml", m))?;
        let mut discovery = Discovery::default();
        match &self.features {
            None => self.discover_repo(origin, ctx, &pattern, None, &mut discovery)?,
            Some(features) => {
                for feature in features {
                    self.discover_repo(origin, ctx, &pattern, Some(*feature), &mut discovery)?;
                }
            }
        }
        Ok(discovery)
    }

    fn discover_repo(
        &self,
        origin: &Origin<'_>,
        ctx: &Context,
        pattern: &Regex,
        feature: Option<u32>,
        discovery: &mut Discovery,
    ) -> Result<()> {
        let repo = template::render(&self.repo, |name| {
            (name == "feature")
                .then(|| feature.map(|f| f.to_string()))
                .flatten()
        });
        let api = without_trailing_slash(&self.api_url);
        for page in 1..=self.max_pages {
            let url = format!("{api}/repos/{repo}/releases?per_page={PER_PAGE}&page={page}");
            // A repository that does not exist (or has no releases yet) is not an error: a
            // feature release may not have been published.
            let Some(body) = ctx.get_github_api(origin.id, &url, DOCUMENT_LIMIT)? else {
                discovery.warn(format!("{}: {url} does not exist", origin.id));
                return Ok(());
            };
            let releases: Vec<Release> = parse_json(origin.id, &url, &body)?;
            let count = releases.len();
            for release in releases {
                self.read_release(origin, ctx, pattern, feature, release, discovery)?;
            }
            if count < PER_PAGE {
                return Ok(());
            }
        }
        discovery.warn(format!(
            "{}: stopped after {} pages of releases of {repo}",
            origin.id, self.max_pages
        ));
        Ok(())
    }

    fn read_release(
        &self,
        origin: &Origin<'_>,
        ctx: &Context,
        pattern: &Regex,
        feature: Option<u32>,
        release: Release,
        discovery: &mut Discovery,
    ) -> Result<()> {
        if release.draft || (release.prerelease && !self.include_prereleases) {
            return Ok(());
        }
        let Some(captures) = pattern.captures(&release.tag_name) else {
            return Ok(());
        };
        let group = |name: &str| -> Option<String> {
            if name == "feature" {
                return feature.map(|f| f.to_string());
            }
            captures.name(name).map(|m| m.as_str().to_owned())
        };
        let version = template::render(&self.version, group);
        for (target, asset_template) in &self.assets {
            let Some(target) = Target::parse(target) else {
                continue;
            };
            let name = template::render(asset_template, group);
            let Some(asset) = release.assets.iter().find(|a| a.name == name) else {
                continue;
            };
            let Some(archive) = archive_from_name(&asset.name) else {
                discovery.warn(format!(
                    "{} {version}: skipped {name}, not an archive jtm can extract",
                    origin.id
                ));
                continue;
            };
            let mut candidate = origin.candidate(
                version.clone(),
                target,
                asset.browser_download_url.clone(),
                archive,
            );
            candidate.tags.clone_from(&self.tags);
            if release.prerelease {
                candidate.tags.extend(self.prerelease_tags.iter().cloned());
            }
            candidate.size = Some(asset.size).filter(|s| *s > 0);
            if let Some(suffix) = &self.signature_suffix {
                candidate.signature_url = release
                    .assets
                    .iter()
                    .find(|a| a.name == format!("{}{suffix}", asset.name))
                    .map(|a| a.browser_download_url.clone());
            }
            candidate.hash = self.claim(origin, ctx, &release, asset, discovery)?;
            if candidate.hash.is_none() {
                discovery.warn(format!(
                    "{} {version} {target}: skipped, no SHA-256 for {}",
                    origin.id, asset.name
                ));
                continue;
            }
            discovery.push(candidate);
        }
        Ok(())
    }

    fn claim(
        &self,
        origin: &Origin<'_>,
        ctx: &Context,
        release: &Release,
        asset: &Asset,
        discovery: &mut Discovery,
    ) -> Result<Option<ClaimedHash>> {
        match (self.hash_from, &self.sidecar_suffix) {
            (HashFrom::Digest, _) => Ok(asset
                .digest
                .as_deref()
                .and_then(|d| d.split_once(':'))
                .and_then(|(algorithm, hex)| {
                    let algorithm = HashAlgorithm::parse(algorithm)?;
                    ClaimedHash::new(algorithm, hex, &asset.browser_download_url)
                })),
            (HashFrom::Sidecar, Some(suffix)) => {
                let wanted = format!("{}{suffix}", asset.name);
                let Some(sidecar) = release.assets.iter().find(|a| a.name == wanted) else {
                    return Ok(None);
                };
                if let Err(reason) = check_url(&sidecar.browser_download_url) {
                    discovery.warn(format!("{}: {wanted}: {reason}", origin.id));
                    return Ok(None);
                }
                let text =
                    ctx.get_text(origin.id, &sidecar.browser_download_url, CHECKSUM_LIMIT)?;
                Ok(text
                    .and_then(|t| {
                        parse_checksum_file(&t, HashAlgorithm::Sha256, Some(asset.name.as_str()))
                    })
                    .and_then(|hex| {
                        ClaimedHash::new(HashAlgorithm::Sha256, &hex, &sidecar.browser_download_url)
                    }))
            }
            (HashFrom::Sidecar, None) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests;
