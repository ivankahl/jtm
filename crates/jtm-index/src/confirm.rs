//! Hash confirmation: turns the claims of the source adapters into entries whose SHA-256 the
//! generator has computed itself and whose provenance says why it is believed (SPEC.md
//! sections 8 and 15).
//!
//! # The rule
//!
//! Candidates are grouped by variant, version and platform. A group becomes an entry only
//! when its hash is confirmed in one of three ways, tried in this order:
//!
//! 1. **[`Confirmation::Independent`]**: two different sources claim a SHA-256 or SHA-512
//!    for it. Which sources count as independent is decided by `sources.toml`: each `id` is
//!    one opinion, however many files it was read from.
//! 2. **[`Confirmation::SourceAndSignature`]**: at least one source claims a hash and a
//!    detached vendor signature of the download verifies against the keyring the plugin pins
//!    (`signing_keys`). The signature is made over the bytes the generator downloaded, so it
//!    carries the weight; this is the path for an upstream that publishes only a SHA-1.
//! 3. **[`Confirmation::SourceAndComputed`]**: the primary source is marked `sole_source`
//!    (an upstream with no second one) and claims a SHA-256 or SHA-512. The generator's own
//!    download is the second opinion. The provenance records `computed:sha256` so such an
//!    entry can be told from one with two independent sources.
//!
//! SHA-1 is only ever corroboration: it cannot make a source count for the first or third
//! way, and MD5 is not representable at all. A published hash is a claim about the download,
//! so *every* claim, of whatever algorithm, must equal the digest the generator computed, and
//! two claims of one algorithm must equal each other.
//!
//! # Failing closed
//!
//! Nothing is dropped and nothing is partly published. Anything wrong with any entry (sources
//! that disagree, a download that is not what was claimed, a signature that does not hold, too
//! little evidence) fails the whole run with [`Error::Rejected`] listing every problem found.
//! Problems visible in the claims alone are reported before a single artifact is downloaded.
//! A signature that is merely not usable (no keyring for the source, a key that is not in it,
//! a weak hash, a file the vendor does not publish) is recorded in the provenance but is not
//! evidence; a signature that *claims* to be by a keyring key and is not valid is an error
//! even when two sources agree.
//!
//! The SHA-256 in an entry is always the generator's own, whatever the vendors publish.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::Path;

use jtm_security::{ArchiveKind, Timestamp};
use serde::Serialize;

use crate::candidate::{Candidate, HashAlgorithm, Target};
use crate::context::{Context, SIGNATURE_LIMIT};
use crate::error::{Error, Reason, Rejection, Result};
use crate::signature::{Keyring, Verification};
use crate::sources::{Role, Source, SourcesFile};

/// The default cap on one artifact: larger than any JDK or build tool distribution, small
/// enough that a hostile upstream cannot fill a CI runner's disk.
pub const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// The largest keyring file read. An Apache `KEYS` file is a few hundred KiB.
const MAX_KEY_FILE: u64 = 8 * 1024 * 1024;

/// Limits of a confirmation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// A download is aborted the moment it passes this many bytes, or the largest size a
    /// source claims for it if that is smaller.
    pub max_artifact_bytes: u64,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            max_artifact_bytes: DEFAULT_MAX_ARTIFACT_BYTES,
        }
    }
}

/// How an entry's hash came to be believed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confirmation {
    /// Two sources claimed a strong hash, and both equal the download's.
    Independent,
    /// A source claimed a hash and a pinned vendor key signed the download.
    SourceAndSignature,
    /// The only source claimed a strong hash and the generator's download agrees. Weaker than
    /// the other two, and labelled so in the index.
    SourceAndComputed,
}

/// A hash a source published, which the download was found to equal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ClaimRecord {
    pub source: String,
    pub algorithm: HashAlgorithm,
    /// Where the source read it from, such as a checksum file URL.
    pub origin: String,
}

/// What became of a published signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum SignatureStatus {
    /// A key in the plugin's keyring made it over the downloaded bytes.
    Verified { fingerprint: String },
    /// The source named a signature file the vendor does not serve.
    NotPublished,
    /// It exists but proves nothing: no keyring, an unknown key, or a weak hash.
    Unverified { reason: String },
}

/// One signature file and what became of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignatureRecord {
    pub source: String,
    pub url: String,
    #[serde(flatten)]
    pub status: SignatureStatus,
}

/// Why an entry's hash is believed, recorded for the index writer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Provenance {
    pub confirmation: Confirmation,
    /// Every source whose claim equals the download, whatever its algorithm.
    pub sources: Vec<String>,
    pub claims: Vec<ClaimRecord>,
    pub signatures: Vec<SignatureRecord>,
    /// When the artifact was downloaded, `YYYY-MM-DDTHH:MM:SSZ`.
    pub fetched_at: String,
}

impl Provenance {
    /// The strings for an index entry's `provenance` array: the sources that agreed, then
    /// `signature:pgp` when a vendor signature verified and `computed:sha256` when the
    /// generator's own download stood in for a second source. The `:` keeps these apart from
    /// source ids, which cannot contain one.
    pub fn labels(&self) -> Vec<String> {
        let mut labels = self.sources.clone();
        if self
            .signatures
            .iter()
            .any(|s| matches!(s.status, SignatureStatus::Verified { .. }))
        {
            labels.push("signature:pgp".to_owned());
        }
        if self.confirmation == Confirmation::SourceAndComputed {
            labels.push("computed:sha256".to_owned());
        }
        labels
    }
}

/// An artifact whose hash is confirmed, ready for the index writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedEntry {
    pub variant: Option<String>,
    pub version: String,
    pub target: Target,
    pub tags: Vec<String>,
    pub url: String,
    pub archive: ArchiveKind,
    /// The measured size in bytes.
    pub size: u64,
    /// The SHA-256 the generator computed.
    pub sha256: String,
    pub distribution_version: Option<String>,
    pub provenance: Provenance,
}

/// The result of a successful run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Confirmed {
    /// One entry per variant, version and platform the primary sources list, in a stable order.
    pub entries: Vec<ConfirmedEntry>,
    /// Things worth a human's attention that do not stop the run, such as what only a
    /// confirming source knows about.
    pub warnings: Vec<String>,
}

/// Confirms candidates against the rule above.
#[derive(Debug)]
pub struct Confirmer<'a> {
    ctx: &'a Context,
    sources: &'a SourcesFile,
    keyrings: BTreeMap<String, Keyring>,
    options: Options,
}

/// The identity of an entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    variant: Option<String>,
    version: String,
    target: Target,
}

impl Key {
    fn of(candidate: &Candidate) -> Key {
        Key {
            variant: candidate.variant.clone(),
            version: candidate.version.clone(),
            target: candidate.target,
        }
    }

    fn reject(&self, reason: Reason) -> Rejection {
        Rejection {
            variant: self.variant.clone(),
            version: self.version.clone(),
            target: self.target,
            reason,
        }
    }
}

/// What the sources say about one artifact.
struct Group<'a> {
    key: Key,
    primary: Candidate,
    primary_source: &'a Source,
    others: Vec<Candidate>,
}

impl Group<'_> {
    fn candidates(&self) -> impl Iterator<Item = &Candidate> {
        std::iter::once(&self.primary).chain(&self.others)
    }
}

/// A published hash, with its source.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Claim {
    source: String,
    algorithm: HashAlgorithm,
    hex: String,
    origin: String,
}

impl Claim {
    /// Whether the claim can stand as an opinion on its own. SHA-1 cannot.
    const fn is_strong(&self) -> bool {
        !matches!(self.algorithm, HashAlgorithm::Sha1)
    }
}

impl<'a> Confirmer<'a> {
    /// `keyrings` maps a source id to the keys whose signatures count for it, as
    /// [`Confirmer::load_keyrings`] reads them.
    pub fn new(
        ctx: &'a Context,
        sources: &'a SourcesFile,
        keyrings: BTreeMap<String, Keyring>,
        options: Options,
    ) -> Confirmer<'a> {
        Confirmer {
            ctx,
            sources,
            keyrings,
            options,
        }
    }

    /// Reads the `signing_keys` files of every source from `dir`, the directory holding
    /// `sources.toml`. A file that is missing or holds no key is an error, so a deleted or
    /// damaged keyring cannot silently turn into "no signature checks".
    pub fn load_keyrings(dir: &Path, sources: &SourcesFile) -> Result<BTreeMap<String, Keyring>> {
        let mut keyrings = BTreeMap::new();
        for source in sources
            .sources
            .iter()
            .filter(|s| !s.signing_keys.is_empty())
        {
            let mut keyring = Keyring::default();
            for name in &source.signing_keys {
                let path = dir.join(name);
                let label = path.display().to_string();
                let invalid = |message: String| Error::Sources {
                    file: label.clone(),
                    message,
                };
                let size = std::fs::metadata(&path)
                    .map_err(|e| invalid(e.to_string()))?
                    .len();
                if size > MAX_KEY_FILE {
                    return Err(invalid(format!("larger than {MAX_KEY_FILE} bytes")));
                }
                let bytes = std::fs::read(&path).map_err(|e| invalid(e.to_string()))?;
                keyring.extend(Keyring::parse(&label, &bytes).map_err(invalid)?);
            }
            keyrings.insert(source.id.clone(), keyring);
        }
        Ok(keyrings)
    }

    /// Confirms `candidates`, which are what the adapters returned for every source.
    pub fn confirm(&self, candidates: Vec<Candidate>) -> Result<Confirmed> {
        let mut confirmed = Confirmed::default();
        let mut rejections = Vec::new();
        let groups = self.group(candidates, &mut confirmed.warnings, &mut rejections);
        for group in &groups {
            if let Err(reason) = self.precheck(group) {
                rejections.push(group.key.reject(reason));
            }
        }
        if !rejections.is_empty() {
            rejections.sort_by(|a, b| {
                (&a.variant, &a.version, a.target).cmp(&(&b.variant, &b.version, b.target))
            });
            return Err(Error::Rejected { rejections });
        }
        // A problem with one artifact does not stop the others from being checked, so a
        // maintainer sees every bad entry in one run. Only a failure to fetch (network, disk)
        // stops at once: it says nothing about the entries not yet reached.
        let mut refused = Vec::new();
        for group in groups {
            tracing::info!(
                "downloading {} {} ({})",
                group.key.variant.as_deref().unwrap_or("-"),
                group.key.version,
                group.key.target
            );
            match self.verify(group) {
                Ok(entry) => confirmed.entries.push(entry),
                Err(Error::Rejected { rejections }) => refused.extend(rejections),
                Err(other) => return Err(other),
            }
        }
        if !refused.is_empty() {
            return Err(Error::Rejected {
                rejections: refused,
            });
        }
        Ok(confirmed)
    }

    /// Groups candidates by entry. A group without a candidate from a primary source is not
    /// an entry; it is reported in `warnings`. Groups that cannot be built are rejected.
    fn group(
        &self,
        candidates: Vec<Candidate>,
        warnings: &mut Vec<String>,
        rejections: &mut Vec<Rejection>,
    ) -> Vec<Group<'a>> {
        let mut by_key: BTreeMap<Key, Vec<Candidate>> = BTreeMap::new();
        for candidate in candidates {
            let key = Key::of(&candidate);
            if self.source(&candidate.source).is_none() {
                rejections.push(key.reject(Reason::UnknownSource {
                    source_id: candidate.source.clone(),
                }));
            } else {
                by_key.entry(key).or_default().push(candidate);
            }
        }
        let mut groups = Vec::new();
        for (key, candidates) in by_key {
            let (primaries, others): (Vec<Candidate>, Vec<Candidate>) =
                candidates.into_iter().partition(|c| {
                    self.source(&c.source)
                        .is_some_and(|s| s.role == Role::Primary)
                });
            // The same candidate reported twice is not a conflict.
            let mut unique: Vec<Candidate> = Vec::new();
            for candidate in primaries {
                if !unique.contains(&candidate) {
                    unique.push(candidate);
                }
            }
            if unique.len() > 1 {
                let urls = unique.into_iter().map(|c| c.url).collect();
                rejections.push(key.reject(Reason::AmbiguousPrimary { urls }));
                continue;
            }
            let Some(primary) = unique.pop() else {
                warnings.push(format!(
                    "{}: no primary source lists it, so it is not an entry (reported by {})",
                    describe(&key),
                    source_list(&others)
                ));
                continue;
            };
            let Some(primary_source) = self.source(&primary.source) else {
                continue;
            };
            groups.push(Group {
                key,
                primary,
                primary_source,
                others,
            });
        }
        groups
    }

    fn source(&self, id: &str) -> Option<&'a Source> {
        self.sources.sources.iter().find(|s| s.id == id)
    }

    fn keyring(&self, source: &str) -> Option<&Keyring> {
        self.keyrings.get(source).filter(|k| !k.is_empty())
    }

    /// Everything that can be refused from the claims alone, before downloading.
    fn precheck(&self, group: &Group<'_>) -> std::result::Result<(), Reason> {
        let claims = claims(group);
        for algorithm in [
            HashAlgorithm::Sha1,
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha512,
        ] {
            let of_kind: BTreeSet<(&str, &str)> = claims
                .iter()
                .filter(|c| c.algorithm == algorithm)
                .map(|c| (c.source.as_str(), c.hex.as_str()))
                .collect();
            let distinct: BTreeSet<&str> = of_kind.iter().map(|(_, hex)| *hex).collect();
            if distinct.len() > 1 {
                return Err(Reason::SourcesDisagree {
                    algorithm,
                    claims: of_kind
                        .into_iter()
                        .map(|(source, hex)| (source.to_owned(), hex.to_owned()))
                        .collect(),
                });
            }
        }
        let strong = strong_sources(&claims);
        let signed = group
            .candidates()
            .any(|c| c.signature_url.is_some() && self.keyring(&c.source).is_some());
        if strong.len() >= 2
            || (signed && !claims.is_empty())
            || self.sole_source_confirmed(group, &strong)
        {
            return Ok(());
        }
        Err(Reason::NotConfirmed {
            message: self.explain_shortfall(group, &strong),
        })
    }

    fn sole_source_confirmed(&self, group: &Group<'_>, strong: &BTreeSet<&str>) -> bool {
        group.primary_source.sole_source && strong.contains(group.primary.source.as_str())
    }

    fn explain_shortfall(&self, group: &Group<'_>, strong: &BTreeSet<&str>) -> String {
        let have = if strong.is_empty() {
            "no source claims a SHA-256 or SHA-512".to_owned()
        } else {
            let names: Vec<&str> = strong.iter().copied().collect();
            format!("only {} claims a SHA-256 or SHA-512", names.join(", "))
        };
        let unusable_signature = group
            .candidates()
            .any(|c| c.signature_url.is_some() && self.keyring(&c.source).is_none());
        let note = if unusable_signature {
            "; a vendor signature is published but its source lists no `signing_keys` to check it with"
        } else {
            ""
        };
        format!(
            "{have}, which is not enough: an entry needs a second source, a hash claim plus a \
             vendor signature that verifies, or `sole_source = true` on an upstream that has no \
             second one (SHA-1 and MD5 never count on their own){note}"
        )
    }

    /// Downloads the primary's artifact and settles the group.
    fn verify(&self, group: Group<'_>) -> Result<ConfirmedEntry> {
        let claims = claims(&group);
        let limit = group
            .candidates()
            .filter_map(|c| c.size)
            .max()
            .map_or(self.options.max_artifact_bytes, |claimed| {
                claimed.min(self.options.max_artifact_bytes)
            });
        let refuse = |reason| Error::Rejected {
            rejections: vec![group.key.reject(reason)],
        };
        // The bytes are only kept on disk when a signature can be checked against them.
        let spool = group
            .candidates()
            .any(|c| c.signature_url.is_some() && self.keyring(&c.source).is_some());
        let (mut file, computed) =
            match self
                .ctx
                .download(&group.primary.source, &group.primary.url, limit, spool)
            {
                Ok(downloaded) => downloaded,
                Err(Error::Fetch {
                    error: jtm_fetch::Error::TooLarge { url, limit },
                    ..
                }) => return Err(refuse(Reason::TooLarge { url, limit })),
                Err(other) => return Err(other),
            };
        let fetched_at = Timestamp::now().to_string();

        for candidate in group.candidates() {
            if let Some(claimed) = candidate.size.filter(|s| *s != computed.size) {
                return Err(refuse(Reason::SizeMismatch {
                    source_id: candidate.source.clone(),
                    claimed,
                    measured: computed.size,
                }));
            }
        }
        for claim in &claims {
            let actual = computed.hex(claim.algorithm);
            if actual != claim.hex {
                return Err(refuse(Reason::ClaimMismatch {
                    source_id: claim.source.clone(),
                    origin: claim.origin.clone(),
                    algorithm: claim.algorithm,
                    claimed: claim.hex.clone(),
                    computed: actual.to_owned(),
                }));
            }
        }

        let mut signatures = Vec::new();
        let mut seen = BTreeSet::new();
        for candidate in group.candidates() {
            let Some(url) = &candidate.signature_url else {
                continue;
            };
            if !seen.insert((candidate.source.as_str(), url.as_str())) {
                continue;
            }
            let status = self
                .check_signature(&candidate.source, url, file.as_mut())?
                .map_err(|message| {
                    refuse(Reason::SignatureInvalid {
                        source_id: candidate.source.clone(),
                        url: url.clone(),
                        message,
                    })
                })?;
            signatures.push(SignatureRecord {
                source: candidate.source.clone(),
                url: url.clone(),
                status,
            });
        }

        let strong = strong_sources(&claims);
        let verified = signatures
            .iter()
            .any(|s| matches!(s.status, SignatureStatus::Verified { .. }));
        let confirmation = if strong.len() >= 2 {
            Confirmation::Independent
        } else if verified && !claims.is_empty() {
            Confirmation::SourceAndSignature
        } else if self.sole_source_confirmed(&group, &strong) {
            Confirmation::SourceAndComputed
        } else {
            let mut message = self.explain_shortfall(&group, &strong);
            for signature in &signatures {
                match &signature.status {
                    SignatureStatus::Verified { .. } => {}
                    SignatureStatus::NotPublished => {
                        message.push_str(&format!("; {} does not exist", signature.url));
                    }
                    SignatureStatus::Unverified { reason } => {
                        message.push_str(&format!("; {} proves nothing: {reason}", signature.url));
                    }
                }
            }
            return Err(refuse(Reason::NotConfirmed { message }));
        };

        let sources: BTreeSet<&str> = claims.iter().map(|c| c.source.as_str()).collect();
        let Group { key, primary, .. } = group;
        Ok(ConfirmedEntry {
            variant: key.variant,
            version: key.version,
            target: key.target,
            tags: primary.tags,
            url: primary.url,
            archive: primary.archive,
            size: computed.size,
            sha256: computed.sha256().to_owned(),
            distribution_version: primary.distribution_version,
            provenance: Provenance {
                confirmation,
                sources: sources.into_iter().map(str::to_owned).collect(),
                claims: claims
                    .iter()
                    .map(|c| ClaimRecord {
                        source: c.source.clone(),
                        algorithm: c.algorithm,
                        origin: c.origin.clone(),
                    })
                    .collect(),
                signatures,
                fetched_at,
            },
        })
    }

    /// Fetches the signature at `url` and checks it against the keyring of `source`. The
    /// inner `Err` is a signature that is not valid, which fails the run; the outer one is a
    /// fetch failure.
    fn check_signature(
        &self,
        source: &str,
        url: &str,
        file: Option<&mut File>,
    ) -> Result<std::result::Result<SignatureStatus, String>> {
        // Without a keyring the answer is the same whatever the vendor serves, so do not spend a
        // request on it, or let a failing signature host abort a run over a non-evidence file.
        let (Some(keyring), Some(file)) = (self.keyring(source), file) else {
            return Ok(Ok(SignatureStatus::Unverified {
                reason: format!("source `{source}` lists no signing_keys"),
            }));
        };
        let Some(bytes) = self.ctx.get_optional(source, url, SIGNATURE_LIMIT)? else {
            return Ok(Ok(SignatureStatus::NotPublished));
        };
        Ok(match keyring.verify(&bytes, file) {
            Verification::Valid { fingerprint } => Ok(SignatureStatus::Verified { fingerprint }),
            Verification::Invalid(message) => Err(message),
            Verification::UnknownKey(issuers) => Ok(SignatureStatus::Unverified {
                reason: format!(
                    "signed by a key that is not in the keyring ({})",
                    issuers.join(", ")
                ),
            }),
            Verification::Unsupported(reason) => Ok(SignatureStatus::Unverified { reason }),
        })
    }
}

/// Every hash the group's candidates claim, sorted and without repeats.
fn claims(group: &Group<'_>) -> Vec<Claim> {
    let mut claims: Vec<Claim> = group
        .candidates()
        .filter_map(|c| {
            c.hash.as_ref().map(|h| Claim {
                source: c.source.clone(),
                algorithm: h.algorithm,
                hex: h.hex.clone(),
                origin: h.origin.clone(),
            })
        })
        .collect();
    claims.sort();
    claims.dedup();
    claims
}

/// The sources with a claim that can stand as an opinion.
fn strong_sources(claims: &[Claim]) -> BTreeSet<&str> {
    claims
        .iter()
        .filter(|c| c.is_strong())
        .map(|c| c.source.as_str())
        .collect()
}

fn describe(key: &Key) -> String {
    let variant = key
        .variant
        .as_deref()
        .map_or(String::new(), |v| format!("{v} "));
    format!("{variant}{} ({})", key.version, key.target)
}

fn source_list(candidates: &[Candidate]) -> String {
    let ids: BTreeSet<&str> = candidates.iter().map(|c| c.source.as_str()).collect();
    ids.into_iter().collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests;
