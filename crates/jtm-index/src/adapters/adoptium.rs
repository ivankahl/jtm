//! The Adoptium API (`adapter = "adoptium"`), which lists Eclipse Temurin builds with the
//! SHA-256 each package was published with.
//!
//! For every feature release (`17`, `21`, ...) and platform the adapter pages through
//! `/v3/assets/feature_releases/<feature>/<ga|ea>` and reports one candidate per package. The
//! feature releases come from `features`, or from `/v3/info/available_releases` when that is
//! not set; the same endpoint says which of them have long-term support, which becomes the
//! `lts` tag. `ga` and `ea` tags follow the release type.
//!
//! Versions are written from the API's `version_data` the way `java.lang.Runtime.Version`
//! prints them: `21.0.5+11`, `8.0.432+6`, `21+35` (trailing zero components are dropped) and
//! `26-ea+5` for early access builds.

use jtm_core::Platform;
use serde::Deserialize;

use super::{Origin, Platforms, check_https, is_url_token, without_trailing_slash};
use crate::candidate::{
    ClaimedHash, Discovery, HashAlgorithm, Target, archive_from_name, check_url,
};
use crate::context::{Context, DOCUMENT_LIMIT, parse_json};
use crate::error::Result;

const DEFAULT_API: &str = "https://api.adoptium.net";
/// The most results the API returns per page.
const PAGE_SIZE: usize = 20;

/// Settings of the `adoptium` adapter.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptiumConfig {
    #[serde(default = "default_api")]
    pub api_url: String,
    /// The feature releases to list. Without it, every release the API knows.
    #[serde(default)]
    pub features: Option<Vec<u32>>,
    /// The platforms to list. Without it, every v1 platform.
    #[serde(default)]
    pub platforms: Platforms,
    /// `jdk` or `jre`.
    #[serde(default = "default_image_type")]
    pub image_type: String,
    #[serde(default = "default_jvm_impl")]
    pub jvm_impl: String,
    /// The API's name for the builder.
    #[serde(default = "default_vendor")]
    pub vendor: String,
    /// Whether early access builds are listed, tagged `ea`.
    #[serde(default)]
    pub include_ea: bool,
    /// A bound on the pages read for one feature release and platform.
    #[serde(default = "default_max_pages")]
    pub max_pages: u32,
}

fn default_api() -> String {
    DEFAULT_API.to_owned()
}

fn default_image_type() -> String {
    "jdk".to_owned()
}

fn default_jvm_impl() -> String {
    "hotspot".to_owned()
}

fn default_vendor() -> String {
    "eclipse".to_owned()
}

const fn default_max_pages() -> u32 {
    50
}

#[derive(Deserialize)]
struct Available {
    #[serde(default)]
    available_releases: Vec<u32>,
    #[serde(default)]
    available_lts_releases: Vec<u32>,
}

#[derive(Deserialize)]
struct Release {
    release_type: String,
    version_data: VersionData,
    #[serde(default)]
    binaries: Vec<Binary>,
}

#[derive(Deserialize)]
struct VersionData {
    major: u32,
    #[serde(default)]
    minor: u32,
    #[serde(default)]
    security: u32,
    #[serde(default)]
    patch: u32,
    #[serde(default)]
    build: Option<u32>,
}

#[derive(Deserialize)]
struct Binary {
    os: String,
    architecture: String,
    image_type: String,
    jvm_impl: String,
    package: Option<Package>,
}

#[derive(Deserialize)]
struct Package {
    name: String,
    link: String,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    checksum: Option<String>,
    #[serde(default)]
    checksum_link: Option<String>,
    #[serde(default)]
    signature_link: Option<String>,
}

impl AdoptiumConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        check_https(&self.api_url, "api_url")?;
        self.platforms
            .validate()
            .map_err(|m| format!("platforms: {m}"))?;
        for (name, value) in [
            ("image_type", &self.image_type),
            ("jvm_impl", &self.jvm_impl),
            ("vendor", &self.vendor),
        ] {
            if !is_url_token(value) {
                return Err(format!("{name}: `{value}` is not a plain word"));
            }
        }
        if self.features.as_ref().is_some_and(Vec::is_empty) {
            return Err("features: is empty; leave it out to list every release".to_owned());
        }
        if self.max_pages == 0 {
            return Err("max_pages: must be at least 1".to_owned());
        }
        Ok(())
    }

    pub(crate) fn discover(&self, origin: &Origin<'_>, ctx: &Context) -> Result<Discovery> {
        let api = without_trailing_slash(&self.api_url);
        let info_url = format!("{api}/v3/info/available_releases");
        let info: Available = parse_json(
            origin.id,
            &info_url,
            &ctx.get(origin.id, &info_url, DOCUMENT_LIMIT)?,
        )?;
        let features = self
            .features
            .clone()
            .unwrap_or_else(|| info.available_releases.clone());
        let mut release_types = vec!["ga"];
        if self.include_ea {
            release_types.push("ea");
        }
        let mut discovery = Discovery::default();
        for feature in features {
            let lts = info.available_lts_releases.contains(&feature);
            for platform in self.platforms.list() {
                for release_type in &release_types {
                    self.discover_platform(
                        origin,
                        ctx,
                        (feature, lts),
                        platform,
                        release_type,
                        &mut discovery,
                    )?;
                }
            }
        }
        Ok(discovery)
    }

    fn discover_platform(
        &self,
        origin: &Origin<'_>,
        ctx: &Context,
        (feature, lts): (u32, bool),
        platform: Platform,
        release_type: &str,
        discovery: &mut Discovery,
    ) -> Result<()> {
        let (os, arch) = api_names(platform);
        let api = without_trailing_slash(&self.api_url);
        for page in 0..self.max_pages {
            let url = format!(
                "{api}/v3/assets/feature_releases/{feature}/{release_type}?architecture={arch}\
                 &os={os}&image_type={}&jvm_impl={}&vendor={}&heap_size=normal&project=jdk\
                 &page_size={PAGE_SIZE}&page={page}&sort_order=DESC",
                self.image_type, self.jvm_impl, self.vendor
            );
            // Past the last page the API answers 404 rather than an empty list.
            let Some(body) = ctx.get_optional(origin.id, &url, DOCUMENT_LIMIT)? else {
                return Ok(());
            };
            let releases: Vec<Release> = parse_json(origin.id, &url, &body)?;
            let count = releases.len();
            for release in releases {
                self.read_release(origin, release, lts, platform, (os, arch), discovery);
            }
            if count < PAGE_SIZE {
                return Ok(());
            }
        }
        discovery.warn(format!(
            "{}: stopped after {} pages of feature {feature} {release_type} for {platform}",
            origin.id, self.max_pages
        ));
        Ok(())
    }

    fn read_release(
        &self,
        origin: &Origin<'_>,
        release: Release,
        lts: bool,
        platform: Platform,
        (os, arch): (&str, &str),
        discovery: &mut Discovery,
    ) {
        let early = release.release_type == "ea";
        let version = java_version(&release.version_data, early);
        for binary in release.binaries {
            // The query already filters, but the answer is not trusted to have obeyed it.
            if binary.os != os
                || binary.architecture != arch
                || binary.image_type != self.image_type
                || binary.jvm_impl != self.jvm_impl
            {
                continue;
            }
            let Some(package) = binary.package else {
                continue;
            };
            let Some(archive) = archive_from_name(&package.name) else {
                continue;
            };
            let mut candidate = origin.candidate(
                version.clone(),
                Target::Platform(platform),
                package.link.clone(),
                archive,
            );
            if lts {
                candidate.tags.push("lts".to_owned());
            }
            candidate
                .tags
                .push(if early { "ea" } else { "ga" }.to_owned());
            candidate.size = package.size;
            candidate.signature_url = package.signature_link.filter(|u| check_url(u).is_ok());
            let origin_url = package.checksum_link.as_deref().unwrap_or(&package.link);
            candidate.hash = package
                .checksum
                .as_deref()
                .and_then(|hex| ClaimedHash::new(HashAlgorithm::Sha256, hex, origin_url));
            if candidate.hash.is_none() {
                discovery.warn(format!(
                    "{} {version} {platform}: skipped, no SHA-256 in the API",
                    origin.id
                ));
                continue;
            }
            discovery.push(candidate);
        }
    }
}

/// The API's names for an operating system and architecture.
fn api_names(platform: Platform) -> (&'static str, &'static str) {
    let os = match platform {
        Platform::LinuxMuslX64 => "alpine-linux",
        Platform::WindowsX64 | Platform::WindowsAarch64 => "windows",
        Platform::MacosX64 | Platform::MacosAarch64 => "mac",
        Platform::LinuxX64 | Platform::LinuxAarch64 => "linux",
    };
    let arch = match platform {
        Platform::WindowsAarch64 | Platform::MacosAarch64 | Platform::LinuxAarch64 => "aarch64",
        _ => "x64",
    };
    (os, arch)
}

/// `21.0.5+11`, `8.0.432+6`, `21+35` or `26-ea+5`.
fn java_version(data: &VersionData, early: bool) -> String {
    let mut parts = vec![data.major, data.minor, data.security, data.patch];
    while parts.len() > 1 && parts.last() == Some(&0) {
        parts.pop();
    }
    let mut version = parts
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(".");
    if early {
        version.push_str("-ea");
    }
    if let Some(build) = data.build {
        version.push_str(&format!("+{build}"));
    }
    version
}

#[cfg(test)]
mod tests;
