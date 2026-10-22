//! The Foojay Disco API (`adapter = "foojay"`), which lists the builds of most OpenJDK
//! distributions and the checksum each one published.
//!
//! For every feature release and platform the adapter asks `/disco/v3.0/packages` for one
//! `distro`, then asks `/disco/v3.0/ids/<id>` about each package for its direct download link,
//! signature link and checksum; the listing itself carries none of them. Packages that are not
//! directly downloadable archives are skipped. `term_of_support = "lts"` becomes the `lts`
//! tag and `release_status` the `ga` or `ea` tag.
//!
//! The response is checked against the request: a package for another operating system,
//! architecture or C library than the one asked for is dropped, not trusted.

use jtm_core::Platform;
use serde::Deserialize;

use super::{Origin, Platforms, check_https, is_url_token, without_trailing_slash};
use crate::candidate::{
    ClaimedHash, Discovery, HashAlgorithm, Target, archive_from_name, check_url,
};
use crate::context::{Context, DOCUMENT_LIMIT, parse_json};
use crate::error::Result;

const DEFAULT_API: &str = "https://api.foojay.io";

/// Settings of the `foojay` adapter.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoojayConfig {
    #[serde(default = "default_api")]
    pub api_url: String,
    /// The API's name for the distribution, such as `zulu` or `corretto`.
    pub distro: String,
    /// The feature releases to list.
    pub features: Vec<u32>,
    /// The platforms to list. Without it, every v1 platform.
    #[serde(default)]
    pub platforms: Platforms,
    /// `jdk` or `jre`.
    #[serde(default = "default_package_type")]
    pub package_type: String,
    /// The `latest` query parameter, which decides how many builds of a version are listed.
    #[serde(default = "default_latest")]
    pub latest: String,
    /// Whether early access builds are listed, tagged `ea`.
    #[serde(default)]
    pub include_ea: bool,
}

fn default_api() -> String {
    DEFAULT_API.to_owned()
}

fn default_package_type() -> String {
    "jdk".to_owned()
}

fn default_latest() -> String {
    // SPEC-QUESTION: whether `all_of_version` is the right value to list every build of a
    // feature release could not be checked against the live API from the sandbox this was
    // written in (SPEC.md section 15: endpoints are confirmed during implementation). It is
    // a setting so the first CI run can correct it without a code change.
    "all_of_version".to_owned()
}

#[derive(Deserialize)]
struct Packages {
    #[serde(default)]
    result: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    id: String,
    java_version: String,
    #[serde(default)]
    distribution_version: Option<String>,
    #[serde(default)]
    release_status: String,
    #[serde(default)]
    term_of_support: Option<String>,
    operating_system: String,
    #[serde(default)]
    lib_c_type: Option<String>,
    architecture: String,
    #[serde(default)]
    package_type: String,
    #[serde(default)]
    javafx_bundled: bool,
    #[serde(default = "yes")]
    directly_downloadable: bool,
    #[serde(default)]
    filename: String,
    #[serde(default)]
    size: Option<u64>,
}

const fn yes() -> bool {
    true
}

#[derive(Deserialize)]
struct Details {
    #[serde(default)]
    result: Vec<Detail>,
}

#[derive(Deserialize)]
struct Detail {
    #[serde(default)]
    direct_download_uri: String,
    #[serde(default)]
    signature_uri: String,
    #[serde(default)]
    checksum_uri: String,
    #[serde(default)]
    checksum: String,
    #[serde(default)]
    checksum_type: String,
}

impl FoojayConfig {
    pub(crate) fn validate(&self) -> Result<(), String> {
        check_https(&self.api_url, "api_url")?;
        self.platforms
            .validate()
            .map_err(|m| format!("platforms: {m}"))?;
        for (name, value) in [
            ("distro", &self.distro),
            ("package_type", &self.package_type),
            ("latest", &self.latest),
        ] {
            if !is_url_token(value) {
                return Err(format!("{name}: `{value}` is not a plain word"));
            }
        }
        if self.features.is_empty() {
            return Err("features: needs at least one feature release".to_owned());
        }
        Ok(())
    }

    pub(crate) fn discover(&self, origin: &Origin<'_>, ctx: &Context) -> Result<Discovery> {
        let mut statuses = vec!["ga"];
        if self.include_ea {
            statuses.push("ea");
        }
        let mut discovery = Discovery::default();
        for feature in &self.features {
            for platform in self.platforms.list() {
                for status in &statuses {
                    self.discover_platform(
                        origin,
                        ctx,
                        *feature,
                        platform,
                        status,
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
        feature: u32,
        platform: Platform,
        status: &str,
        discovery: &mut Discovery,
    ) -> Result<()> {
        let (os, arch, libc) = api_names(platform);
        let api = without_trailing_slash(&self.api_url);
        let mut url = format!(
            "{api}/disco/v3.0/packages?distro={}&version={feature}&architecture={arch}\
             &operating_system={os}&package_type={}&release_status={status}&latest={}\
             &javafx_bundled=false&directly_downloadable=true",
            self.distro, self.package_type, self.latest
        );
        if let Some(libc) = libc {
            url.push_str("&lib_c_type=");
            url.push_str(libc);
        }
        let Some(body) = ctx.get_optional(origin.id, &url, DOCUMENT_LIMIT)? else {
            return Ok(());
        };
        let packages: Packages = parse_json(origin.id, &url, &body)?;
        for package in packages.result {
            let right_target = package.operating_system == os
                && package.architecture == arch
                && libc.is_none_or(|l| package.lib_c_type.as_deref() == Some(l))
                && package.package_type == self.package_type
                && package.release_status == status
                && !package.javafx_bundled
                && package.directly_downloadable;
            if !right_target {
                continue;
            }
            self.read_package(origin, ctx, package, platform, discovery)?;
        }
        Ok(())
    }

    fn read_package(
        &self,
        origin: &Origin<'_>,
        ctx: &Context,
        package: Package,
        platform: Platform,
        discovery: &mut Discovery,
    ) -> Result<()> {
        let version = package.java_version.clone();
        // Installers and system packages are not asked about at all.
        if !package.filename.is_empty() && archive_from_name(&package.filename).is_none() {
            return Ok(());
        }
        if !is_url_token(&package.id) {
            discovery.warn(format!("{} {version}: skipped, odd package id", origin.id));
            return Ok(());
        }
        let api = without_trailing_slash(&self.api_url);
        let details_url = format!("{api}/disco/v3.0/ids/{}", package.id);
        let Some(body) = ctx.get_optional(origin.id, &details_url, DOCUMENT_LIMIT)? else {
            discovery.warn(format!(
                "{} {version} {platform}: skipped, {details_url} does not exist",
                origin.id
            ));
            return Ok(());
        };
        let details: Details = parse_json(origin.id, &details_url, &body)?;
        let Some(detail) = details.result.into_iter().next() else {
            discovery.warn(format!(
                "{} {version} {platform}: skipped, no details for the package",
                origin.id
            ));
            return Ok(());
        };
        let name = Some(package.filename.as_str())
            .filter(|n| !n.is_empty())
            .unwrap_or(&detail.direct_download_uri);
        let Some(archive) = archive_from_name(name) else {
            return Ok(());
        };
        let mut candidate = origin.candidate(
            version.clone(),
            Target::Platform(platform),
            detail.direct_download_uri.clone(),
            archive,
        );
        if package.term_of_support.as_deref() == Some("lts") {
            candidate.tags.push("lts".to_owned());
        }
        candidate.tags.push(package.release_status.clone());
        candidate.size = package.size.filter(|s| *s > 0);
        candidate.distribution_version = package.distribution_version.clone();
        if check_url(&detail.signature_uri).is_ok() {
            candidate.signature_url = Some(detail.signature_uri.clone());
        }
        let origin_url = if detail.checksum_uri.is_empty() {
            details_url.as_str()
        } else {
            detail.checksum_uri.as_str()
        };
        candidate.hash = HashAlgorithm::parse(&detail.checksum_type)
            .and_then(|algorithm| ClaimedHash::new(algorithm, &detail.checksum, origin_url));
        if candidate.hash.is_none() {
            discovery.warn(format!(
                "{} {version} {platform}: skipped, no usable checksum ({:?}) from {details_url}",
                origin.id, detail.checksum_type
            ));
            return Ok(());
        }
        discovery.push(candidate);
        Ok(())
    }
}

/// The API's names for an operating system, architecture and, on Linux, C library.
fn api_names(platform: Platform) -> (&'static str, &'static str, Option<&'static str>) {
    let os = match platform {
        Platform::WindowsX64 | Platform::WindowsAarch64 => "windows",
        Platform::MacosX64 | Platform::MacosAarch64 => "macos",
        Platform::LinuxX64 | Platform::LinuxAarch64 | Platform::LinuxMuslX64 => "linux",
    };
    let arch = match platform {
        Platform::WindowsAarch64 | Platform::MacosAarch64 | Platform::LinuxAarch64 => "aarch64",
        _ => "x64",
    };
    let libc = match platform {
        Platform::LinuxMuslX64 => Some("musl"),
        Platform::LinuxX64 | Platform::LinuxAarch64 => Some("glibc"),
        _ => None,
    };
    (os, arch, libc)
}

#[cfg(test)]
mod tests;
