//! Minisign signature verification over raw bytes (SPEC.md section 9).
//!
//! A signature file holds one or more minisign signatures, one after another, so a file can
//! carry the co-signatures a threshold needs. Each signature is the usual four lines: untrusted
//! comment, signature, trusted comment, global signature. Only pre-hashed (`ED`) signatures are
//! accepted; the legacy mode that signs raw bytes is refused.

use std::collections::BTreeSet;

use crate::error::{Error, Result};
use crate::key::{KeyGroup, KeyId, Keyring, TrustedKey};
use crate::time::Timestamp;

/// The largest signature file accepted, far more than [`MAX_SIGNATURES`] need.
pub const MAX_SIGNATURE_FILE: usize = 64 * 1024;
/// The most signatures one file may carry.
pub const MAX_SIGNATURES: usize = 16;

/// What is being verified, for scope checks and messages.
#[derive(Debug, Clone, Copy)]
pub struct Subject<'a> {
    /// The file, such as `java-linux-x64.json`, for messages.
    pub file: &'a str,
    /// The plugin the file belongs to. A keys file is verified for the plugin that fetched it.
    pub plugin: &'a str,
}

/// A successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The origin of the group whose threshold was met.
    pub group: String,
    /// The keys in that group that signed, in id order.
    pub signers: Vec<KeyId>,
}

/// One parsed signature and the key id it claims.
struct Parsed {
    key_id: KeyId,
    signature: minisign_verify::Signature,
}

/// Verifies `signatures`, the contents of a `.minisig` file, over the raw `data` bytes.
///
/// `data` is never parsed. The file is accepted when some group in `keyring` has at least its
/// threshold of distinct keys, each unexpired at `now` and with a scope covering
/// `subject.plugin`, whose signatures verify. When none does, the error says why, preferring the
/// most alarming reason: a signature by a trusted key that does not match the bytes, then a
/// legacy-format signature, then a signature by an expired key, then too few signatures, then
/// keys not trusted for this file.
pub fn verify(
    data: &[u8],
    signatures: &[u8],
    keyring: &Keyring,
    subject: Subject<'_>,
    now: Timestamp,
) -> Result<Verified> {
    let invalid = |message: String| Error::SignatureInvalid {
        file: subject.file.to_owned(),
        message,
    };
    let parsed = parse(signatures).map_err(invalid)?;

    let mut tampered = false;
    let mut legacy: Option<KeyId> = None;
    let mut expired: Option<&TrustedKey> = None;
    let mut short: Option<(&KeyGroup, usize)> = None;
    for group in &keyring.groups {
        let mut signers = BTreeSet::new();
        for sig in &parsed {
            for trusted in group.keys.iter().filter(|k| k.key.id() == sig.key_id) {
                if !trusted.scope.covers(subject.plugin) {
                    continue;
                }
                if trusted.is_expired(now) {
                    expired = Some(trusted);
                    continue;
                }
                match trusted.key.inner().verify(data, &sig.signature, false) {
                    Ok(()) => {
                        signers.insert(sig.key_id);
                    }
                    // The signature was made over the raw bytes instead of their hash; it is
                    // refused on purpose, not a sign of tampering.
                    Err(minisign_verify::Error::UnexpectedAlgorithm) => {
                        legacy = Some(sig.key_id);
                    }
                    // `UnexpectedKeyId` cannot occur: the filter above matches ids already.
                    Err(_) => tampered = true,
                }
            }
        }
        if !signers.is_empty() && signers.len() >= threshold(group) {
            return Ok(Verified {
                group: group.origin.clone(),
                signers: signers.into_iter().collect(),
            });
        }
        if !signers.is_empty() && short.is_none_or(|(_, n)| signers.len() > n) {
            short = Some((group, signers.len()));
        }
    }

    if tampered {
        return Err(invalid(
            "a signature by a trusted key does not match the file; it may have been tampered with"
                .to_owned(),
        ));
    }
    if let Some(key_id) = legacy {
        return Err(invalid(format!(
            "it is signed by key {key_id} in the legacy minisign format, which jtm refuses; ask \
             the publisher to re-sign it with a pre-hashed signature"
        )));
    }
    if let Some(key) = expired {
        let expires = key.expires.map(|t| t.to_string()).unwrap_or_default();
        return Err(invalid(format!(
            "it is signed by key {}, which expired at {expires}",
            key.key.id()
        )));
    }
    if let Some((group, found)) = short {
        return Err(invalid(format!(
            "{} needs {} signatures from distinct keys, found {found}",
            group.origin,
            threshold(group)
        )));
    }
    let key_id = parsed
        .iter()
        .map(|s| s.key_id.to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ");
    Err(Error::KeyUntrusted {
        file: subject.file.to_owned(),
        key_id,
        resolve: crate::anchors::company_keys_setting(subject.plugin),
    })
}

/// A threshold of 0 is treated as 1, so no group ever accepts a file nobody signed.
fn threshold(group: &KeyGroup) -> usize {
    usize::try_from(group.threshold.max(1)).unwrap_or(usize::MAX)
}

fn parse(bytes: &[u8]) -> std::result::Result<Vec<Parsed>, String> {
    if bytes.len() > MAX_SIGNATURE_FILE {
        return Err(format!(
            "the signature file is larger than {MAX_SIGNATURE_FILE} bytes"
        ));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "the signature file is not UTF-8")?;
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim_end_matches('\r'))
        .filter(|l| !l.trim().is_empty())
        .collect();
    if lines.is_empty() {
        return Err("the signature file is empty".to_owned());
    }
    if !lines.len().is_multiple_of(4) {
        return Err("the signature file is truncated or malformed".to_owned());
    }
    if lines.len() / 4 > MAX_SIGNATURES {
        return Err(format!(
            "the signature file holds more than {MAX_SIGNATURES} signatures"
        ));
    }
    lines
        .chunks(4)
        .enumerate()
        .map(|(i, block)| {
            let n = i + 1;
            if !block[0].starts_with("untrusted comment:") {
                return Err(format!(
                    "signature {n} does not start with an untrusted comment"
                ));
            }
            let signature = minisign_verify::Signature::decode(&block.join("\n"))
                .map_err(|e| format!("signature {n} is malformed: {e}"))?;
            let key_id =
                key_id_of(block[1]).ok_or_else(|| format!("signature {n} is malformed"))?;
            Ok(Parsed { key_id, signature })
        })
        .collect()
}

/// The key id in the second line of a signature: algorithm, then 8 bytes of key id.
fn key_id_of(line: &str) -> Option<KeyId> {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(line.trim())
        .ok()?;
    let mut id = [0; 8];
    id.copy_from_slice(bytes.get(2..10)?);
    Some(KeyId(id))
}

#[cfg(test)]
mod tests;
