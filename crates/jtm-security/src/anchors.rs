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
//! - **Confirmed**: every other plugin. Only anchors the user config lists for the plugin in
//!   [`company_keys_setting`] count. Being listed in the marketplace confirms nothing.
//!
//! Pre-approval is provenance, never file contents: [`TrustAnchors::preapproved`] must only be
//! called for anchors that ship inside the jtm binary. A signature checked inside the same
//! binary cannot protect the binary's own data, so nothing read from disk (including the
//! unpacked `plugins/builtin` working copy), the marketplace or the network may take this path;
//! that is what [`TrustAnchors::confirmed`] is for.

use crate::error::{Error, Result};
use crate::key::{KeyGroup, Keyring, PublicKey, Scope, TrustedKey};
use crate::keys_json::KeysFile;

/// The user config key that lists company keys for `plugin`, which `E_KEY_UNTRUSTED` names in
/// `details.resolve`. Company keys come only from the user config, never from a project file,
/// a flag, a prompt or an environment variable (SPEC.md section 9).
// T5.7 renames the table to `tools.<name>`.
pub fn company_keys_setting(plugin: &str) -> String {
    format!("plugins.{plugin}.signing_keys")
}

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

    /// Anchors for a plugin that does not ship with jtm: only the `keys` that `company_keys`,
    /// the keys the user config lists for `plugin`, also name count. When fewer than
    /// `threshold` are trusted, the error names the untrusted keys and the config key that
    /// would trust them.
    pub fn confirmed(
        plugin: &str,
        keys: &[String],
        threshold: u32,
        company_keys: &[PublicKey],
    ) -> Result<TrustAnchors> {
        let listed = TrustAnchors::preapproved(plugin, keys, threshold)?;
        let (trusted, untrusted): (Vec<PublicKey>, Vec<PublicKey>) = listed
            .keys
            .into_iter()
            .partition(|key| company_keys.contains(key));
        if trusted.len() < usize::try_from(threshold.max(1)).unwrap_or(usize::MAX) {
            let key_id = untrusted
                .iter()
                .map(|k| k.id().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Error::KeyUntrusted {
                file: format!("plugin `{plugin}` signing keys"),
                key_id,
                resolve: company_keys_setting(plugin),
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
/// 3. `company_keys`, the keys the user config lists for the plugin, such as a company key that
///    re-signs an internal mirror, one signature each and scoped to the plugin. Anchor keys and
///    keys file keys are left out, so listing a key that already counts toward a threshold
///    never lowers that threshold.
pub fn plugin_keyring(
    anchors: &TrustAnchors,
    keys_file: Option<&KeysFile>,
    company_keys: &[PublicKey],
) -> Keyring {
    let mut keyring = Keyring::new().with(anchors.group());
    if let Some(file) = keys_file {
        keyring = keyring.with(file.group());
    }
    let listed_in_keys_file = |key: &PublicKey| {
        keys_file.is_some_and(|file| file.keys.iter().any(|listed| listed.key == *key))
    };
    let scope = Scope::from_set([anchors.plugin.clone()].into_iter().collect());
    let mut company: Vec<TrustedKey> = Vec::new();
    for key in company_keys {
        if !anchors.keys.contains(key)
            && !listed_in_keys_file(key)
            && !company.iter().any(|k| k.key == *key)
        {
            company.push(TrustedKey {
                key: key.clone(),
                scope: scope.clone(),
                expires: None,
            });
        }
    }
    if !company.is_empty() {
        keyring = keyring.with(KeyGroup {
            origin: format!(
                "company keys in `{}`",
                company_keys_setting(&anchors.plugin)
            ),
            keys: company,
            threshold: 1,
        });
    }
    keyring
}

#[cfg(test)]
mod tests;
