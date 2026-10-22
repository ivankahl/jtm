//! Vendor signatures: detached OpenPGP signatures (`.asc`, `.sig`) of an artifact, checked
//! against a keyring the repository pins (SPEC.md section 15).
//!
//! Upstreams that sign their downloads do it with OpenPGP: Apache and Maven Central publish
//! `.asc` files and a `KEYS` file, Adoptium publishes `.sig` files. A valid signature by a key
//! in the plugin's keyring is the second piece of evidence that lets one source's hash into an
//! index. The keyring is a file committed beside `sources.toml` and reviewed like any other
//! change; the generator never trusts a key because a download or an upstream says so.
//!
//! The outcome is one of four things, and only [`Verification::Valid`] is evidence:
//!
//! * `Valid`: a keyring key made this signature over exactly these bytes.
//! * `Invalid`: the signature does not parse, or a keyring key it names did not make it. That
//!   is never ignored; the run fails.
//! * `UnknownKey`: the signature names only keys the keyring does not hold, so it says nothing.
//! * `Unsupported`: a signature made with a hash that is too weak to rely on (MD5, SHA-1,
//!   RIPEMD-160), which says nothing either.

use std::io::{Read, Seek, SeekFrom};

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::packet::{PublicKey, PublicSubkey};
use pgp::types::{Fingerprint, KeyDetails, KeyId};

const BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const END: &str = "-----END PGP PUBLIC KEY BLOCK-----";
const SIGNATURE_BEGIN: &str = "-----BEGIN PGP SIGNATURE-----";

/// What a signature check found out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    /// Made by the key with this fingerprint (upper-case hex) over the bytes checked.
    Valid { fingerprint: String },
    /// Malformed, or made by no keyring key that it names over these bytes.
    Invalid(String),
    /// Signed only by keys that are not in the keyring: the issuers it names.
    UnknownKey(Vec<String>),
    /// Cannot be relied on, and why.
    Unsupported(String),
}

#[derive(Debug, Clone)]
enum Material {
    Primary(PublicKey),
    Subkey(PublicSubkey),
}

#[derive(Debug, Clone)]
struct Entry {
    fingerprint: Fingerprint,
    key_id: KeyId,
    material: Material,
}

/// The public keys whose signatures are accepted, primary keys and subkeys alike.
#[derive(Debug, Clone, Default)]
pub struct Keyring {
    entries: Vec<Entry>,
}

impl Keyring {
    /// Reads every armored public key block in `text`, which may be a single exported key or
    /// a `KEYS` file with prose between the blocks. `origin` names the file in messages.
    ///
    /// Strict on purpose: a block that does not parse, or a file with no public key block,
    /// is an error rather than a smaller keyring, so a damaged file cannot quietly weaken or
    /// empty what is trusted. Secret key blocks are not read at all.
    pub fn parse(origin: &str, text: &[u8]) -> Result<Keyring, String> {
        let text = std::str::from_utf8(text).map_err(|_| format!("{origin}: not UTF-8 text"))?;
        let mut keyring = Keyring::default();
        let mut rest = text;
        while let Some(start) = rest.find(BEGIN) {
            let block = &rest[start..];
            let Some(end) = block.find(END) else {
                return Err(format!("{origin}: a key block is never closed"));
            };
            let (block, after) = block.split_at(end + END.len());
            let (key, _) = SignedPublicKey::from_armor_single(block.as_bytes())
                .map_err(|e| format!("{origin}: cannot read a public key block: {e}"))?;
            keyring.add(&key);
            rest = after;
        }
        if keyring.entries.is_empty() {
            return Err(format!("{origin}: holds no PGP public key block"));
        }
        Ok(keyring)
    }

    fn add(&mut self, key: &SignedPublicKey) {
        self.entries.push(Entry {
            fingerprint: key.primary_key.fingerprint(),
            key_id: key.primary_key.legacy_key_id(),
            material: Material::Primary(key.primary_key.clone()),
        });
        for subkey in &key.public_subkeys {
            self.entries.push(Entry {
                fingerprint: subkey.key.fingerprint(),
                key_id: subkey.key.legacy_key_id(),
                material: Material::Subkey(subkey.key.clone()),
            });
        }
    }

    /// Adds every key of `other`.
    pub fn extend(&mut self, other: Keyring) {
        self.entries.extend(other.entries);
    }

    /// Keys held, counting each subkey.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The fingerprints of every key, sorted.
    pub fn fingerprints(&self) -> Vec<String> {
        let mut all: Vec<String> = self
            .entries
            .iter()
            .map(|e| fingerprint(&e.fingerprint))
            .collect();
        all.sort();
        all
    }

    /// Checks the detached `signature` (armored or binary) over `data`, which is read from
    /// its start for every key tried.
    pub fn verify(&self, signature: &[u8], data: &mut (impl Read + Seek)) -> Verification {
        let signature = match parse_signature(signature) {
            Ok(signature) => signature,
            Err(message) => return Verification::Invalid(message),
        };
        if let Some(weak) = signature.signature.hash_alg().filter(|alg| is_weak(*alg)) {
            return Verification::Unsupported(format!("signed with the weak hash {weak:?}"));
        }
        let key_ids = signature.signature.issuer_key_id();
        let fingerprints = signature.signature.issuer_fingerprint();
        let names_issuer = !key_ids.is_empty() || !fingerprints.is_empty();
        let candidates: Vec<&Entry> = self
            .entries
            .iter()
            .filter(|entry| {
                !names_issuer
                    || key_ids.iter().any(|id| **id == entry.key_id)
                    || fingerprints.iter().any(|fp| **fp == entry.fingerprint)
            })
            .collect();
        if candidates.is_empty() {
            let issuers = key_ids
                .iter()
                .map(|id| format!("{id:?}"))
                .chain(fingerprints.iter().map(|fp| fingerprint(fp)))
                .collect();
            return Verification::UnknownKey(issuers);
        }
        let mut last_error = String::new();
        for entry in candidates {
            if let Err(e) = data.seek(SeekFrom::Start(0)) {
                return Verification::Invalid(format!("cannot read the signed bytes: {e}"));
            }
            let result = match &entry.material {
                Material::Primary(key) => signature.signature.verify(key, &mut *data),
                Material::Subkey(key) => signature.signature.verify(key, &mut *data),
            };
            match result {
                Ok(()) => {
                    return Verification::Valid {
                        fingerprint: fingerprint(&entry.fingerprint),
                    };
                }
                Err(e) => last_error = e.to_string(),
            }
        }
        Verification::Invalid(last_error)
    }
}

fn parse_signature(bytes: &[u8]) -> Result<DetachedSignature, String> {
    let armored =
        std::str::from_utf8(bytes).is_ok_and(|text| text.trim_start().starts_with(SIGNATURE_BEGIN));
    let parsed = if armored {
        DetachedSignature::from_armor_single(bytes).map(|(signature, _)| signature)
    } else {
        DetachedSignature::from_bytes(bytes)
    };
    parsed.map_err(|e| format!("not a readable OpenPGP signature: {e}"))
}

fn is_weak(algorithm: HashAlgorithm) -> bool {
    matches!(
        algorithm,
        HashAlgorithm::Md5 | HashAlgorithm::Sha1 | HashAlgorithm::Ripemd160
    )
}

fn fingerprint(fingerprint: &Fingerprint) -> String {
    format!("{fingerprint:X}")
}

#[cfg(test)]
mod tests;
