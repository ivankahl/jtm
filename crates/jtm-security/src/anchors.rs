//! Trust anchors: the keys a plugin's manifest lists in `[index] signing_keys` (SPEC.md
//! sections 7 and 9).
//!
//! First-party and third-party plugins use the same model. A plugin's anchors sign its indices
//! directly, or sign a keys file that delegates to short-lived index keys. The only difference
//! is how the anchors become trusted:
//!
//! - **Pre-approved**: the manifest is compiled into jtm, as the first-party plugins are, or the
//!   anchors are the jtm root keys that sign the marketplace. Installing jtm is the decision to
//!   trust them.
//! - **Confirmed**: every other plugin. Only anchors the user has trusted for the plugin, by
//!   answering the prompt, `--trust-key` or `jtm trust add`, count. Being listed in the
//!   marketplace confirms nothing.
//!
//! Pre-approval is provenance, never file contents: [`TrustAnchors::preapproved`] must only be
//! called for anchors that ship inside the jtm binary. A signature checked inside the same
//! binary cannot protect the binary's own data, so nothing read from disk, the marketplace or
//! the network may take this path; that is what [`TrustAnchors::confirmed`] is for.

use crate::error::{Error, Result};
use crate::key::{KeyGroup, Keyring, PublicKey, Scope, TrustedKey};
use crate::keys_json::KeysFile;
use crate::trust::TrustState;

/// A plugin's trusted signing keys and how many of them must sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchors {
    /// The plugin the anchors belong to. They are never used for any other plugin.
    pub plugin: String,
    pub keys: Vec<PublicKey>,
    pub threshold: u32,
}

impl TrustAnchors {
    /// Anchors trusted because they ship inside jtm: a first-party manifest's `signing_keys`,
    /// or the jtm root keys.
    ///
    /// Only call this for manifests compiled into jtm. Every other manifest's anchors go
    /// through [`TrustAnchors::confirmed`], whatever the plugin is called and wherever the
    /// manifest was read from.
    pub fn preapproved(plugin: &str, keys: &[String], threshold: u32) -> Result<TrustAnchors> {
        let keys = keys
            .iter()
            .map(|k| {
                PublicKey::parse(k).map_err(|e| Error::SigningKeys {
                    plugin: plugin.to_owned(),
                    message: e.to_string(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(TrustAnchors {
            plugin: plugin.to_owned(),
            keys,
            threshold,
        })
    }

    /// Anchors for a plugin that does not ship with jtm: only the `keys` the user trusts for
    /// `plugin` count. When fewer than `threshold` are trusted, the error names a key to trust
    /// and the command that would trust it.
    pub fn confirmed(
        plugin: &str,
        keys: &[String],
        threshold: u32,
        state: &TrustState,
    ) -> Result<TrustAnchors> {
        let listed = TrustAnchors::preapproved(plugin, keys, threshold)?;
        let (trusted, untrusted): (Vec<PublicKey>, Vec<PublicKey>) = listed
            .keys
            .into_iter()
            .partition(|key| state.trusts(key, plugin));
        if trusted.len() < usize::try_from(threshold.max(1)).unwrap_or(usize::MAX) {
            let key_id = untrusted
                .iter()
                .map(|k| k.id().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let resolve = match untrusted.first() {
                Some(key) => format!("jtm trust add {key} --scope {plugin}"),
                None => format!("jtm trust add <public key> --scope {plugin}"),
            };
            return Err(Error::KeyUntrusted {
                file: format!("plugin `{plugin}` signing keys"),
                key_id,
                resolve,
            });
        }
        Ok(TrustAnchors {
            plugin: plugin.to_owned(),
            keys: trusted,
            threshold,
        })
    }

    /// The anchors as a key group scoped to their plugin.
    pub fn group(&self) -> KeyGroup {
        let scope = Scope::from_set([self.plugin.clone()].into_iter().collect());
        KeyGroup {
            origin: format!("plugin `{}` signing keys", self.plugin),
            keys: self
                .keys
                .iter()
                .map(|key| TrustedKey {
                    key: key.clone(),
                    scope: scope.clone(),
                    expires: None,
                })
                .collect(),
            threshold: self.threshold,
        }
    }
}

/// Every key group that may accept an index of `anchors.plugin`, each on its own:
///
/// 1. The anchors, at the manifest's threshold.
/// 2. The delegated keys in the plugin's verified keys file, if it has one, at that file's
///    threshold and only where their scope names the plugin.
/// 3. Other keys the user trusts for the plugin, such as a company key that re-signs an
///    internal mirror, one signature each. Anchor keys and keys file keys are left out, so
///    trusting a key that already counts toward a threshold never lowers that threshold.
pub fn plugin_keyring(
    anchors: &TrustAnchors,
    keys_file: Option<&KeysFile>,
    state: &TrustState,
) -> Keyring {
    let mut keyring = Keyring::new().with(anchors.group());
    if let Some(file) = keys_file {
        keyring = keyring.with(file.group());
    }
    let listed_in_keys_file = |key: &PublicKey| {
        keys_file.is_some_and(|file| file.keys.iter().any(|listed| listed.key == *key))
    };
    let mut user = state.user_group();
    user.keys.retain(|k| {
        k.scope.covers(&anchors.plugin)
            && !anchors.keys.contains(&k.key)
            && !listed_in_keys_file(&k.key)
    });
    if !user.keys.is_empty() {
        keyring = keyring.with(user);
    }
    keyring
}

#[cfg(test)]
mod tests;
