//! Minisign public keys and the scopes they are trusted for (SPEC.md section 9).

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jtm_plugin::names::check_plugin_name;

use crate::time::Timestamp;

/// The 8-byte key id minisign embeds in every key and signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(pub(crate) [u8; 8]);

impl fmt::Display for KeyId {
    /// Upper-case hex of the id read as a little-endian integer, as `minisign` prints it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016X}", u64::from_le_bytes(self.0))
    }
}

/// A minisign Ed25519 public key, as the base64 line of a `minisign.pub` file (`RW...`).
#[derive(Clone)]
pub struct PublicKey {
    text: String,
    id: KeyId,
    inner: minisign_verify::PublicKey,
}

/// Why a string is not a usable public key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("`{input}` is not a minisign public key; expected the base64 line starting with `RW`")]
pub struct KeyParseError {
    pub input: String,
}

/// Algorithm bytes of a minisign Ed25519 key.
const ED25519: &[u8; 2] = b"Ed";
/// Length of the decoded key: algorithm, key id and Ed25519 key.
const KEY_BYTES: usize = 2 + 8 + 32;

impl PublicKey {
    /// Parses the base64 line of a minisign public key. Surrounding whitespace is ignored.
    pub fn parse(input: &str) -> Result<PublicKey, KeyParseError> {
        let text = input.trim();
        let err = || KeyParseError {
            input: text.to_owned(),
        };
        let bytes = STANDARD.decode(text).map_err(|_| err())?;
        if bytes.len() != KEY_BYTES || &bytes[..2] != ED25519 {
            return Err(err());
        }
        let inner = minisign_verify::PublicKey::from_base64(text).map_err(|_| err())?;
        let mut id = [0; 8];
        id.copy_from_slice(&bytes[2..10]);
        Ok(PublicKey {
            text: text.to_owned(),
            id: KeyId(id),
            inner,
        })
    }

    /// The key as its base64 line.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn id(&self) -> KeyId {
        self.id
    }

    pub(crate) fn inner(&self) -> &minisign_verify::PublicKey {
        &self.inner
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&self.text).finish()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

impl Eq for PublicKey {}

impl FromStr for PublicKey {
    type Err = KeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PublicKey::parse(s)
    }
}

/// Which plugins a key may sign for. Every trusted key is limited to named plugins; there is no
/// wildcard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope(BTreeSet<String>);

impl Scope {
    /// A scope of the given plugin names, each checked as a plugin name.
    pub fn plugins<I, S>(names: I) -> Result<Scope, String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        plugin_set(names).map(Scope)
    }

    /// A scope of names already checked, such as those read back from `trust.json`.
    pub(crate) fn from_set(names: BTreeSet<String>) -> Scope {
        Scope(names)
    }

    /// Whether a signature on a file belonging to `plugin` is within this scope.
    pub fn covers(&self, plugin: &str) -> bool {
        self.0.contains(plugin)
    }

    pub fn names(&self) -> &BTreeSet<String> {
        &self.0
    }
}

/// Checks plugin names for a scope: at least one, each a valid plugin name. There is no
/// wildcard; trusting a key for every plugin is never a single step.
pub fn plugin_set<I, S>(names: I) -> Result<BTreeSet<String>, String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut set = BTreeSet::new();
    for name in names {
        let name = name.into();
        check_plugin_name(&name).map_err(|(_, message)| format!("scope `{name}`: {message}"))?;
        set.insert(name);
    }
    if set.is_empty() {
        return Err("a scope must name at least one plugin".to_owned());
    }
    Ok(set)
}

/// A key and what it is trusted to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedKey {
    pub key: PublicKey,
    pub scope: Scope,
    /// After this time no signature by the key is accepted. `None` never expires.
    pub expires: Option<Timestamp>,
}

impl TrustedKey {
    pub fn is_expired(&self, now: Timestamp) -> bool {
        self.expires.is_some_and(|expires| now >= expires)
    }
}

/// Keys that are trusted together: a signed file is accepted by the group when at least
/// `threshold` distinct keys of the group, each in scope, signed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyGroup {
    /// Where the keys come from, such as a plugin's signing keys, its keys file or the user trust store, for messages.
    pub origin: String,
    pub keys: Vec<TrustedKey>,
    pub threshold: u32,
}

/// Every group of keys trusted for one verification. A file is accepted when any one group
/// accepts it, so a key a user trusts never needs the co-signatures a keys file requires.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Keyring {
    pub groups: Vec<KeyGroup>,
}

impl Keyring {
    pub fn new() -> Keyring {
        Keyring::default()
    }

    pub fn with(mut self, group: KeyGroup) -> Keyring {
        self.groups.push(group);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "RWTB5jyFnNg68V0CwSpHcVuDAhAhJj5aYJboedszhloVwCP5cHSTI+PB";

    #[test]
    fn parses_a_minisign_public_key() {
        let key = PublicKey::parse(&format!("  {KEY}\n")).unwrap();
        assert_eq!(key.as_str(), KEY);
        assert_eq!(key.to_string(), KEY);
        assert_eq!(key.id().to_string().len(), 16);
        assert_eq!(key, KEY.parse::<PublicKey>().unwrap());
    }

    #[test]
    fn rejects_anything_else() {
        for bad in [
            "",
            "RW",
            "not base64!",
            // Valid base64 of the wrong length.
            "RWTB5jyFnNg68V0CwSpHcVuDAhAhJj5aYJboedszhloVwCP5cHSTI+PBAAAA",
            // Right length, wrong algorithm bytes.
            "AAAA5jyFnNg68V0CwSpHcVuDAhAhJj5aYJboedszhloVwCP5cHSTI+PB",
            // Padding in the middle.
            "RW==5jyFnNg68V0CwSpHcVuDAhAhJj5aYJboedszhloVwCP5cHSTI+PB",
        ] {
            assert!(PublicKey::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn scopes_name_valid_plugins() {
        let scope = Scope::plugins(["java", "acme/flyway"]).unwrap();
        assert!(scope.covers("java"));
        assert!(scope.covers("acme/flyway"));
        assert!(!scope.covers("maven"));
        assert!(Scope::plugins(["Java"]).is_err());
        assert!(Scope::plugins(["*"]).is_err());
        assert!(Scope::plugins(Vec::<String>::new()).is_err());
    }
}
