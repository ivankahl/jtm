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
/// signature by an expired key, then too few signatures, then keys not trusted for this file.
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
    let resolve = format!("jtm trust add <public key> --scope {}", subject.plugin);
    Err(Error::KeyUntrusted {
        file: subject.file.to_owned(),
        key_id,
        resolve,
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
mod tests {
    use super::*;
    use crate::key::{Scope, TrustedKey};
    use crate::testing::TestKey;

    const DATA: &[u8] = br#"{"format":1,"plugin":"demo"}"#;
    const NOW: Timestamp = Timestamp::from_unix(1_800_000_000);

    fn subject() -> Subject<'static> {
        Subject {
            file: "demo-linux-x64.json",
            plugin: "demo",
        }
    }

    fn group(keys: &[&TestKey], scope: &[&str], threshold: u32) -> KeyGroup {
        KeyGroup {
            origin: "test keys".into(),
            keys: keys
                .iter()
                .map(|k| TrustedKey {
                    key: k.public(),
                    scope: Scope::plugins(scope.iter().copied()).unwrap(),
                    expires: None,
                })
                .collect(),
            threshold,
        }
    }

    fn ring(groups: Vec<KeyGroup>) -> Keyring {
        Keyring { groups }
    }

    #[test]
    fn valid_signature_verifies() {
        let key = TestKey::generate();
        let sig = key.sign(DATA);
        let verified = verify(
            DATA,
            &sig,
            &ring(vec![group(&[&key], &["demo"], 1)]),
            subject(),
            NOW,
        )
        .unwrap();
        assert_eq!(verified.signers, vec![key.public().id()]);
        assert_eq!(verified.group, "test keys");
    }

    #[test]
    fn wrong_key_is_untrusted() {
        let signer = TestKey::generate();
        let trusted = TestKey::generate();
        let sig = signer.sign(DATA);
        let err = verify(
            DATA,
            &sig,
            &ring(vec![group(&[&trusted], &["demo"], 1)]),
            subject(),
            NOW,
        )
        .unwrap_err();
        match err {
            Error::KeyUntrusted {
                key_id, resolve, ..
            } => {
                assert_eq!(key_id, signer.public().id().to_string());
                assert_eq!(resolve, "jtm trust add <public key> --scope demo");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn tampered_byte_is_invalid() {
        let key = TestKey::generate();
        let sig = key.sign(DATA);
        let keyring = ring(vec![group(&[&key], &["demo"], 1)]);
        for i in [0, DATA.len() / 2, DATA.len() - 1] {
            let mut tampered = DATA.to_vec();
            tampered[i] ^= 0x01;
            let err = verify(&tampered, &sig, &keyring, subject(), NOW).unwrap_err();
            assert!(
                matches!(err, Error::SignatureInvalid { .. }),
                "byte {i}: {err:?}"
            );
        }
    }

    #[test]
    fn truncated_data_is_invalid() {
        let key = TestKey::generate();
        let sig = key.sign(DATA);
        let keyring = ring(vec![group(&[&key], &["demo"], 1)]);
        for len in [0, 1, DATA.len() - 1] {
            let err = verify(&DATA[..len], &sig, &keyring, subject(), NOW).unwrap_err();
            assert!(matches!(err, Error::SignatureInvalid { .. }), "{len}");
        }
    }

    #[test]
    fn truncated_or_corrupt_signature_file_is_invalid() {
        let key = TestKey::generate();
        let sig = key.sign(DATA);
        let keyring = ring(vec![group(&[&key], &["demo"], 1)]);
        let text = String::from_utf8(sig.clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let mut cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            sig[..sig.len() / 2].to_vec(),
            lines[..3].join("\n").into_bytes(),
            vec![0xff, 0xfe],
            lines[1..].join("\n").into_bytes(),
        ];
        // A flipped bit in the global signature, which covers the trusted comment.
        let mut global = lines.clone();
        let flipped = flip_base64(lines[3]);
        global[3] = &flipped;
        cases.push(global.join("\n").into_bytes());
        // A changed trusted comment.
        let mut comment = lines.clone();
        comment[2] = "trusted comment: something else";
        cases.push(comment.join("\n").into_bytes());
        for (i, bad) in cases.iter().enumerate() {
            let err = verify(DATA, bad, &keyring, subject(), NOW).unwrap_err();
            assert!(
                matches!(err, Error::SignatureInvalid { .. }),
                "case {i}: {err:?}"
            );
        }
    }

    #[test]
    fn out_of_scope_key_is_untrusted() {
        let key = TestKey::generate();
        let sig = key.sign(DATA);
        let err = verify(
            DATA,
            &sig,
            &ring(vec![group(&[&key], &["other"], 1)]),
            subject(),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, Error::KeyUntrusted { .. }), "{err:?}");
    }

    #[test]
    fn expired_key_is_rejected() {
        let key = TestKey::generate();
        let sig = key.sign(DATA);
        let mut expiring = group(&[&key], &["demo"], 1);
        expiring.keys[0].expires = Some(Timestamp::from_unix(NOW.unix() + 1));
        verify(DATA, &sig, &ring(vec![expiring.clone()]), subject(), NOW).unwrap();
        expiring.keys[0].expires = Some(NOW);
        let err = verify(DATA, &sig, &ring(vec![expiring]), subject(), NOW).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid { .. }), "{err:?}");
        assert!(err.to_string().contains("expired"), "{err}");
    }

    #[test]
    fn threshold_two_needs_two_distinct_keys() {
        let (a, b, c) = (
            TestKey::generate(),
            TestKey::generate(),
            TestKey::generate(),
        );
        let keyring = ring(vec![group(&[&a, &b, &c], &["demo"], 2)]);

        let one = a.sign(DATA);
        let err = verify(DATA, &one, &keyring, subject(), NOW).unwrap_err();
        assert!(err.to_string().contains("needs 2 signatures"), "{err}");

        let same_twice = [a.sign(DATA), a.sign(DATA)].concat();
        assert!(verify(DATA, &same_twice, &keyring, subject(), NOW).is_err());

        let two = [a.sign(DATA), c.sign(DATA)].concat();
        let verified = verify(DATA, &two, &keyring, subject(), NOW).unwrap();
        assert_eq!(verified.signers.len(), 2);
    }

    #[test]
    fn any_group_can_accept() {
        let (a, b, user) = (
            TestKey::generate(),
            TestKey::generate(),
            TestKey::generate(),
        );
        let keyring = ring(vec![
            group(&[&a, &b], &["demo"], 2),
            KeyGroup {
                origin: "user trust store".into(),
                ..group(&[&user], &["demo"], 1)
            },
        ]);
        let verified = verify(DATA, &user.sign(DATA), &keyring, subject(), NOW).unwrap();
        assert_eq!(verified.group, "user trust store");
    }

    #[test]
    fn a_bad_extra_signature_does_not_mask_tampering() {
        let (a, b) = (TestKey::generate(), TestKey::generate());
        let keyring = ring(vec![group(&[&a, &b], &["demo"], 2)]);
        let mut tampered = DATA.to_vec();
        tampered[0] ^= 1;
        let sig = [a.sign(DATA), b.sign(DATA)].concat();
        let err = verify(&tampered, &sig, &keyring, subject(), NOW).unwrap_err();
        assert!(err.to_string().contains("tampered"), "{err}");
    }

    #[test]
    fn legacy_signatures_are_refused() {
        let key = TestKey::generate();
        let sig = key.sign_legacy(DATA);
        let err = verify(
            DATA,
            &sig,
            &ring(vec![group(&[&key], &["demo"], 1)]),
            subject(),
            NOW,
        )
        .unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid { .. }), "{err:?}");
    }

    #[test]
    fn signature_file_limits() {
        let key = TestKey::generate();
        let keyring = ring(vec![group(&[&key], &["demo"], 1)]);
        let many = key.sign(DATA).repeat(MAX_SIGNATURES + 1);
        assert!(verify(DATA, &many, &keyring, subject(), NOW).is_err());
        let huge = vec![b'a'; MAX_SIGNATURE_FILE + 1];
        assert!(verify(DATA, &huge, &keyring, subject(), NOW).is_err());
        let crlf = String::from_utf8(key.sign(DATA))
            .unwrap()
            .replace('\n', "\r\n");
        verify(DATA, crlf.as_bytes(), &keyring, subject(), NOW).unwrap();
    }

    fn flip_base64(line: &str) -> String {
        let mut chars: Vec<char> = line.chars().collect();
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
        chars.into_iter().collect()
    }
}
