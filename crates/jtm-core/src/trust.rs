//! Keys the user trusts explicitly, as `jtm trust add/remove/list` manage them (SPEC.md sections
//! 8, 9 and 12).
//!
//! A key is always trusted for named plugins only. Adding one is the explicit human step that
//! `E_KEY_UNTRUSTED` asks for, so it never prompts and `--yes` plays no part in it.

use std::collections::BTreeSet;

use jtm_security::key::plugin_set;
use jtm_security::{PublicKey, Timestamp, TrustState, UserKey};

use crate::dirs::Dirs;
use crate::error::{JtmError, Result};
use crate::indices::trust_path;

/// A trusted key as commands report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyInfo {
    pub key: String,
    /// The key id as `minisign` prints it.
    pub key_id: String,
    pub scope: Vec<String>,
    pub added: String,
}

impl From<&UserKey> for KeyInfo {
    fn from(key: &UserKey) -> Self {
        KeyInfo {
            key: key.key.as_str().to_owned(),
            key_id: key.key.id().to_string(),
            scope: key.scope.iter().cloned().collect(),
            added: key.added.to_string(),
        }
    }
}

/// What `remove_key` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Removal {
    /// Whether any trusted key matched.
    pub found: bool,
    pub changed: bool,
    /// The key as it remains, when scopes were removed but some are left.
    pub remaining: Option<KeyInfo>,
}

/// Trusts `key` for each plugin in `scopes`, adding to any scopes it already has. Returns the
/// key as now trusted and whether anything changed.
pub fn add_key(
    dirs: &Dirs,
    key: &str,
    scopes: &[String],
    now: Timestamp,
) -> Result<(KeyInfo, bool)> {
    let key = PublicKey::parse(key).map_err(|e| JtmError::usage(e.to_string()))?;
    let scope = parse_scope(scopes)?;
    TrustState::update(&trust_path(dirs), |state| {
        let changed = state.add_key(key.clone(), scope, now);
        let info = state
            .keys
            .iter()
            .find(|k| k.key == key)
            .map(KeyInfo::from)
            .ok_or_else(|| jtm_security::Error::Invalid {
                file: "trust.json".to_owned(),
                message: "the added key is missing".to_owned(),
            })?;
        Ok((info, changed))
    })
    .map_err(JtmError::from)
}

/// Stops trusting `key` (a public key or a key id) for `scopes`, or entirely when `scopes` is
/// empty.
pub fn remove_key(dirs: &Dirs, key: &str, scopes: &[String]) -> Result<Removal> {
    let key = normalise_key_or_id(key)?;
    let scope = if scopes.is_empty() {
        BTreeSet::new()
    } else {
        parse_scope(scopes)?
    };
    let matches = |k: &UserKey| k.key.as_str() == key || k.key.id().to_string() == key;
    let (removal, _) = TrustState::update(&trust_path(dirs), |state| {
        let found = state.keys.iter().any(matches);
        let changed = state.remove_key(&key, &scope);
        let remaining = state.keys.iter().find(|k| matches(k)).map(KeyInfo::from);
        Ok((
            Removal {
                found,
                changed,
                remaining,
            },
            changed,
        ))
    })?;
    Ok(removal)
}

/// Every key the user trusts, in the order they were added.
pub fn list_keys(dirs: &Dirs) -> Result<Vec<KeyInfo>> {
    let state = TrustState::load(&trust_path(dirs))?;
    Ok(state.keys.iter().map(KeyInfo::from).collect())
}

fn parse_scope(scopes: &[String]) -> Result<BTreeSet<String>> {
    // SPEC-QUESTION: section 4 shows `--scope <plugin>` without saying whether it is required
    // or whether a wildcard exists. A key trusted for every plugin could sign any index, so at
    // least one plugin must be named and there is no wildcard.
    plugin_set(scopes.iter().cloned()).map_err(|e| {
        JtmError::usage(format!(
            "{e}; name each plugin the key may sign for with --scope <plugin>"
        ))
    })
}

/// A public key as given, or a 16-digit key id in upper case.
fn normalise_key_or_id(input: &str) -> Result<String> {
    let input = input.trim();
    if let Ok(key) = PublicKey::parse(input) {
        return Ok(key.as_str().to_owned());
    }
    if input.len() == 16 && input.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Ok(input.to_ascii_uppercase());
    }
    Err(JtmError::usage(format!(
        "`{input}` is neither a minisign public key nor a 16-digit key id"
    )))
}

#[cfg(test)]
mod tests;
