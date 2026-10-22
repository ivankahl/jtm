//! Binding, rollback and expiry checks run on every verified index (SPEC.md section 9).
//!
//! These run after [`crate::index::load`] has verified the signature, on embedded, cached,
//! mirrored and freshly downloaded copies alike.

use crate::error::{Error, Result};
use crate::index::LoadedIndex;
use crate::key::KeyId;
use crate::keys_json::{KEYS_FILE, KeysFile};
use crate::time::Timestamp;
use crate::trust::{Seen, SourceKind, TrustState};

/// The value of `security.expiry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryPolicy {
    /// An expired index is an error from the canonical remote and a warning elsewhere, since
    /// air-gapped mirrors go stale by design.
    RemoteOnly,
    /// An expired index is an error from every source.
    Enforce,
}

/// The index that was asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexRequest<'a> {
    pub plugin: &'a str,
    pub platform: &'a str,
}

/// A non-fatal finding, reported alongside the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Warning {
    pub code: &'static str,
    pub message: String,
}

/// Warning code for an expired index accepted from a source where expiry is not enforced.
pub const W_INDEX_EXPIRED: &str = "W_INDEX_EXPIRED";

/// An index that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    /// What to record in the trust state once this copy is used.
    pub seen: Seen,
    /// The keys whose floors this copy must be recorded under.
    pub signers: Vec<KeyId>,
    pub warnings: Vec<Warning>,
}

/// Runs the binding, rollback and expiry checks, in that order, on a verified index copy that
/// came from `source`. `file` names the copy in messages.
pub fn check_index(
    loaded: &LoadedIndex,
    file: &str,
    request: IndexRequest<'_>,
    source: SourceKind,
    state: &TrustState,
    policy: ExpiryPolicy,
    now: Timestamp,
) -> Result<Accepted> {
    let index = &loaded.index;
    if index.plugin != request.plugin || index.platform != request.platform {
        return Err(Error::IndexBinding {
            file: file.to_owned(),
            expected: describe(request.plugin, request.platform),
            got: describe(&index.plugin, &index.platform),
        });
    }

    // Each signing key has its own floor. A key that was revoked or rotated therefore stops
    // constraining copies signed by its replacement, which is what lets a poisoned record
    // (say, an attacker-published `u64::MAX`) be recovered from by rotating the key.
    for signer in &loaded.verified.signers {
        if let Some(seen) = state.index_floor(request.plugin, request.platform, signer) {
            check_rollback(file, seen, index.sequence, &loaded.sha256)?;
        }
    }

    // A cached copy carries the expiry policy of the source it was saved from. A cache file
    // whose origin is not on record is held to the strictest policy.
    let origin = match source {
        SourceKind::Cache => {
            // The same bytes may have been recorded under more than one signing key. If any
            // record came from the canonical remote, keep its stricter expiry policy.
            let sources: Vec<SourceKind> = state
                .index_floors(request.plugin, request.platform)
                .filter(|seen| seen.sequence == index.sequence && seen.sha256 == loaded.sha256)
                .filter_map(|seen| seen.source)
                .filter(|kind| *kind != SourceKind::Cache)
                .collect();
            if sources.contains(&SourceKind::Remote) {
                SourceKind::Remote
            } else {
                sources.first().copied().unwrap_or(SourceKind::Remote)
            }
        }
        other => other,
    };

    let mut warnings = Vec::new();
    if now >= index.expires {
        let enforced = policy == ExpiryPolicy::Enforce || origin == SourceKind::Remote;
        if enforced {
            return Err(Error::IndexExpired {
                file: file.to_owned(),
                expires: index.expires.to_string(),
            });
        }
        warnings.push(Warning {
            code: W_INDEX_EXPIRED,
            message: format!(
                "{file} from the {} source expired at {}; using it because expiry is only \
                 enforced for the canonical remote",
                origin.as_str(),
                index.expires
            ),
        });
    }

    Ok(Accepted {
        seen: Seen {
            sequence: index.sequence,
            sha256: loaded.sha256.clone(),
            source: Some(origin),
        },
        signers: loaded.verified.signers.clone(),
        warnings,
    })
}

/// Refuses a keys file for `plugin` older than one already seen under any of the anchors that
/// signed it. Returns what to record.
pub fn check_keys_file(keys: &KeysFile, plugin: &str, state: &TrustState) -> Result<Seen> {
    for signer in &keys.verified.signers {
        if let Some(seen) = state.keys_file_floor(plugin, signer) {
            check_rollback(KEYS_FILE, seen, keys.sequence, &keys.sha256)?;
        }
    }
    Ok(Seen {
        sequence: keys.sequence,
        sha256: keys.sha256.clone(),
        source: None,
    })
}

/// A lower sequence is a rollback. An equal one is accepted only for the same bytes.
fn check_rollback(file: &str, seen: &Seen, got: u64, sha256: &str) -> Result<()> {
    let reason = if got < seen.sequence {
        "older than the newest copy already seen"
    } else if got == seen.sequence && sha256 != seen.sha256 {
        "the same as the newest copy already seen but with different content"
    } else {
        return Ok(());
    };
    Err(Error::IndexRollback {
        file: file.to_owned(),
        seen: seen.sequence,
        got,
        reason: reason.to_owned(),
    })
}

fn describe(plugin: &str, platform: &str) -> String {
    format!("plugin `{plugin}` on `{platform}`")
}

#[cfg(test)]
mod tests;
