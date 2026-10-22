//! What a source adapter reports: one downloadable artifact and the hash its upstream claims
//! for it (SPEC.md sections 8 and 15).
//!
//! A [`Candidate`] is a claim, not a fact. Nothing here confirms a hash; agreement between
//! independent sources, vendor signatures and the SHA-256 the generator computes itself are
//! the next step's job. What this module does is refuse malformed claims before they travel
//! any further, since the fields of a candidate end up in a signed index: URLs must be
//! `https`, versions and names must be the characters an index accepts, and hashes must be
//! well-formed hex of the right length.

use std::fmt;

use jtm_core::Platform;
use jtm_plugin::names::{check_name_segment, check_version_or_alias};
use jtm_security::ArchiveKind;

/// The longest URL accepted, the same limit the client applies to index entries.
const MAX_URL_LEN: usize = 2048;

/// The platform an artifact is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Target {
    /// Runs anywhere, so it goes into the platform-independent (`any`) index.
    Any,
    Platform(Platform),
}

impl Target {
    /// The platform string an index file carries: `any` or one of the v1 platforms.
    pub const fn as_str(self) -> &'static str {
        match self {
            Target::Any => "any",
            Target::Platform(platform) => platform.as_str(),
        }
    }

    /// Parses `any` or a v1 platform string such as `linux-musl-x64`.
    pub fn parse(text: &str) -> Option<Target> {
        if text == "any" {
            return Some(Target::Any);
        }
        Platform::ALL
            .iter()
            .copied()
            .find(|platform| platform.as_str() == text)
            .map(Target::Platform)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A hash algorithm an upstream publishes. SHA-1 is here because some vendors publish nothing
/// else; it can never confirm an artifact by itself, which is why every claim records the
/// algorithm and the generator computes SHA-256 independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl HashAlgorithm {
    /// The length of the hex digest.
    pub const fn hex_len(self) -> usize {
        match self {
            HashAlgorithm::Sha1 => 40,
            HashAlgorithm::Sha256 => 64,
            HashAlgorithm::Sha512 => 128,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            HashAlgorithm::Sha1 => "sha1",
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Sha512 => "sha512",
        }
    }

    /// Parses a name as vendors spell it: `sha256`, `SHA-256`, `SHA256`.
    pub fn parse(text: &str) -> Option<HashAlgorithm> {
        let folded: String = text
            .chars()
            .filter(|c| *c != '-' && *c != '_')
            .map(|c| c.to_ascii_lowercase())
            .collect();
        match folded.as_str() {
            "sha1" => Some(HashAlgorithm::Sha1),
            "sha256" => Some(HashAlgorithm::Sha256),
            "sha512" => Some(HashAlgorithm::Sha512),
            _ => None,
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A digest an upstream published for an artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedHash {
    pub algorithm: HashAlgorithm,
    /// Lowercase hex, exactly [`HashAlgorithm::hex_len`] characters.
    pub hex: String,
    /// Where the digest was read from, for messages when sources disagree.
    pub origin: String,
}

impl ClaimedHash {
    /// A claim from `hex`, which may be upper case. `None` when it is not a digest of
    /// `algorithm`.
    pub fn new(algorithm: HashAlgorithm, hex: &str, origin: &str) -> Option<ClaimedHash> {
        let hex = hex.trim();
        if hex.len() != algorithm.hex_len() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        Some(ClaimedHash {
            algorithm,
            hex: hex.to_ascii_lowercase(),
            origin: origin.to_owned(),
        })
    }
}

/// One artifact a source says exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// The `id` of the source in `sources.toml`; it ends up in the entry's `provenance`.
    pub source: String,
    pub variant: Option<String>,
    /// The version in the plugin's scheme, as the index entry will spell it.
    pub version: String,
    pub target: Target,
    pub tags: Vec<String>,
    pub url: String,
    pub archive: ArchiveKind,
    /// The size in bytes, when the upstream says. The generator measures it when downloading.
    pub size: Option<u64>,
    /// The digest the upstream publishes, if it publishes one.
    pub hash: Option<ClaimedHash>,
    /// A detached vendor signature of the artifact, for the generator to verify.
    pub signature_url: Option<String>,
    /// The vendor's own build identifier where the version alone does not identify a build,
    /// such as a distribution's release number.
    pub distribution_version: Option<String>,
}

impl Candidate {
    /// Checks that every field is something an index entry may carry.
    pub fn check(&self) -> Result<(), String> {
        if let Some(variant) = &self.variant {
            check_name_segment(variant, "variant").map_err(|(_, m)| m)?;
        }
        check_version_or_alias(&self.version).map_err(|(_, m)| format!("version: {m}"))?;
        for tag in &self.tags {
            check_name_segment(tag, "tag").map_err(|(_, m)| m)?;
        }
        check_url(&self.url).map_err(|m| format!("url: {m}"))?;
        if let Some(url) = &self.signature_url {
            check_url(url).map_err(|m| format!("signature url: {m}"))?;
        }
        if self.size == Some(0) {
            return Err("size: must be greater than 0".to_owned());
        }
        Ok(())
    }
}

/// Whether `url` may be recorded in an index: `https`, printable ASCII, a sane length.
pub(crate) fn check_url(url: &str) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("`{url}` is not an https URL"))?;
    if rest.is_empty() || rest.starts_with('/') {
        return Err(format!("`{url}` has no host"));
    }
    if url.len() > MAX_URL_LEN {
        return Err(format!("longer than {MAX_URL_LEN} characters"));
    }
    if !url.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "`{url}` holds characters that are not printable ASCII"
        ));
    }
    Ok(())
}

/// What one source produced: the candidates that passed [`Candidate::check`], and a message
/// for everything it left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Discovery {
    pub candidates: Vec<Candidate>,
    /// Records that were skipped and why. Nothing is dropped silently: the generator prints
    /// these, so a vendor changing its format shows up as warnings, not as missing versions.
    pub warnings: Vec<String>,
}

impl Discovery {
    /// Keeps `candidate` if it is well-formed, otherwise records why it was dropped.
    pub(crate) fn push(&mut self, candidate: Candidate) {
        match candidate.check() {
            Ok(()) => self.candidates.push(candidate),
            Err(reason) => self.warn(format!(
                "{} {}: dropped, {reason}",
                candidate.source, candidate.version
            )),
        }
    }

    pub(crate) fn warn(&mut self, message: String) {
        tracing::warn!("{message}");
        self.warnings.push(message);
    }
}

/// The archive kind a file name says, or `None` for anything jtm cannot extract (installers,
/// disk images, checksums).
pub(crate) fn archive_from_name(name: &str) -> Option<ArchiveKind> {
    let name = name.to_ascii_lowercase();
    if name.ends_with(".zip") {
        Some(ArchiveKind::Zip)
    } else if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        Some(ArchiveKind::TarGz)
    } else if name.ends_with(".tar.xz") || name.ends_with(".txz") {
        Some(ArchiveKind::TarXz)
    } else {
        None
    }
}

/// The digest in a published checksum file, for `algorithm`.
///
/// Accepts the forms vendors use: the bare digest, `<digest>  <file>` and `<digest> *<file>`
/// from `sha256sum`, the BSD form `SHA512 (<file>) = <digest>`, and the digest split into
/// groups of hex digits across spaces. Only the first line counts, and anything that is not
/// exactly one digest of the right length gives `None`, so an HTML error page or a digest of
/// another algorithm never passes for a claim.
pub fn parse_checksum_file(text: &str, algorithm: HashAlgorithm) -> Option<String> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    let want = algorithm.hex_len();
    if let Some((_, after)) = line.split_once(" = ") {
        let digest = after.trim();
        return is_digest(digest, want).then(|| digest.to_ascii_lowercase());
    }
    let mut digest = String::new();
    for token in line.split_whitespace() {
        if digest.len() >= want || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            break;
        }
        digest.push_str(token);
    }
    is_digest(&digest, want).then(|| digest.to_ascii_lowercase())
}

fn is_digest(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests;
