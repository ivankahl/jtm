//! Choosing one index from every available copy (SPEC.md section 8).
//!
//! Each copy, whether embedded, cached, mirrored or freshly downloaded, is verified and checked
//! in exactly the same way. The valid copy with the highest `sequence` wins.

use crate::checks::{Accepted, ExpiryPolicy, IndexRequest, Warning, check_index};
use crate::error::{Error, Result};
use crate::index::{self, LoadedIndex};
use crate::key::Keyring;
use crate::signature::Subject;
use crate::time::Timestamp;
use crate::trust::{SourceKind, TrustState};

/// Warning code for a copy that failed verification while another copy was used.
pub const W_INDEX_COPY_REJECTED: &str = "W_INDEX_COPY_REJECTED";

/// One copy of an index and its detached signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexCopy {
    pub source: SourceKind,
    /// The path or URL it was read from, for messages.
    pub origin: String,
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

/// The copy that was chosen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selected {
    pub loaded: LoadedIndex,
    pub source: SourceKind,
    pub origin: String,
    /// What to record in the trust state.
    pub accepted: Accepted,
    /// The chosen copy's raw bytes and signature, for caching.
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
    /// Warnings from the chosen copy and about copies that failed.
    pub warnings: Vec<Warning>,
}

/// What to verify the copies against.
#[derive(Debug, Clone, Copy)]
pub struct Selection<'a> {
    pub request: IndexRequest<'a>,
    /// The index file name, such as `demo-linux-x64.json`, for messages and scope checks.
    pub file: &'a str,
    pub keyring: &'a Keyring,
    pub state: &'a TrustState,
    pub policy: ExpiryPolicy,
    pub now: Timestamp,
}

/// Verifies every copy and returns the valid one with the highest sequence, or `Ok(None)`
/// when there are no copies at all.
///
/// When two valid copies share the highest sequence, they must be byte-identical; two different
/// files signed with the same sequence are refused as a rollback-style conflict. Among
/// identical copies the remote is preferred, then a mirror, the cache and the embedded
/// snapshot. When no copy is valid, the error of the most authoritative source is returned.
pub fn select(copies: Vec<IndexCopy>, sel: Selection<'_>) -> Result<Option<Selected>> {
    if copies.is_empty() {
        return Ok(None);
    }
    let mut valid: Vec<(IndexCopy, LoadedIndex, Accepted)> = Vec::new();
    let mut rejected: Vec<(IndexCopy, Error)> = Vec::new();
    for copy in copies {
        match verify_copy(&copy, sel) {
            Ok((loaded, accepted)) => valid.push((copy, loaded, accepted)),
            Err(err) => rejected.push((copy, err)),
        }
    }

    let Some(top) = valid.iter().map(|(_, l, _)| l.index.sequence).max() else {
        rejected.sort_by_key(|(copy, _)| preference(copy.source));
        let (_, err) = rejected.swap_remove(0);
        return Err(err);
    };
    let mut best: Vec<_> = valid
        .into_iter()
        .filter(|(_, l, _)| l.index.sequence == top)
        .collect();
    if best.iter().any(|(_, l, _)| l.sha256 != best[0].1.sha256) {
        return Err(Error::IndexRollback {
            file: sel.file.to_owned(),
            seen: top,
            got: top,
            reason: format!(
                "but copies from {} differ while claiming the same sequence",
                best.iter()
                    .map(|(c, _, _)| c.origin.as_str())
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        });
    }
    best.sort_by_key(|(copy, _, _)| preference(copy.source));
    let (copy, loaded, accepted) = best.swap_remove(0);

    let mut warnings = accepted.warnings.clone();
    for (bad, err) in &rejected {
        // An older embedded snapshot or cache is expected after an update; only report copies
        // that look damaged or tampered with.
        let routine = matches!(err, Error::IndexRollback { seen, got, .. } if got < seen);
        if !routine {
            warnings.push(Warning {
                code: W_INDEX_COPY_REJECTED,
                message: format!("ignored the copy from {}: {err}", bad.origin),
            });
        }
    }
    Ok(Some(Selected {
        loaded,
        source: copy.source,
        origin: copy.origin,
        accepted,
        data: copy.data,
        signature: copy.signature,
        warnings,
    }))
}

fn verify_copy(copy: &IndexCopy, sel: Selection<'_>) -> Result<(LoadedIndex, Accepted)> {
    let subject = Subject {
        file: sel.file,
        plugin: sel.request.plugin,
    };
    let loaded = index::load(&copy.data, &copy.signature, sel.keyring, subject, sel.now)?;
    let accepted = check_index(
        &loaded,
        sel.file,
        sel.request,
        copy.source,
        sel.state,
        sel.policy,
        sel.now,
    )?;
    Ok((loaded, accepted))
}

/// Lower is preferred.
fn preference(source: SourceKind) -> u8 {
    match source {
        SourceKind::Remote => 0,
        SourceKind::Mirror => 1,
        SourceKind::Cache => 2,
        SourceKind::Embedded => 3,
    }
}

#[cfg(test)]
mod tests;
