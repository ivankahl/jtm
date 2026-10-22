//! Checking generated and previously published index files with the client's own loader.
//!
//! The generator never writes a file it has not first pushed through
//! [`jtm_security::index::load`], the function every jtm client uses, so the parser and the
//! signature check that decide whether a client accepts a file also decide whether the
//! generator may publish it.

use jtm_security::signature::Subject;
use jtm_security::{IndexFile, KeyGroup, Keyring, PublicKey, Scope, Timestamp, TrustedKey, index};

use crate::error::{Error, Result};
use crate::signing::Signer;

/// A file that the client's loader accepted, and the signature that made it so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub index: IndexFile,
    /// The contents of the `.minisig`.
    pub signature: Vec<u8>,
}

/// A keyring trusting exactly `keys`, each for `plugin` only and without an expiry. This is
/// what a client holds after a user has trusted the keys, minus everything else.
pub fn keyring(plugin: &str, keys: &[PublicKey]) -> Result<Keyring> {
    let scope = Scope::plugins([plugin]).map_err(|message| Error::Invalid { message })?;
    Ok(Keyring::new().with(KeyGroup {
        origin: "the generator's keys".to_owned(),
        keys: keys
            .iter()
            .map(|key| TrustedKey {
                key: key.clone(),
                scope: scope.clone(),
                expires: None,
            })
            .collect(),
        threshold: 1,
    }))
}

/// Signs `bytes` with `signer` and loads the result as a client would. Fails with
/// `E_INDEX_INVALID` when the client would refuse the file, whatever the reason.
pub fn sign_and_load(
    signer: &Signer,
    plugin: &str,
    file: &str,
    bytes: &[u8],
    now: Timestamp,
) -> Result<Signed> {
    let signature = signer.sign(file, bytes, now)?;
    let keyring = keyring(plugin, std::slice::from_ref(signer.public_key()))?;
    let subject = Subject { file, plugin };
    let loaded =
        index::load(bytes, &signature, &keyring, subject, now).map_err(|error| Error::Invalid {
            message: format!("{file} would not be accepted by jtm: {error}"),
        })?;
    Ok(Signed {
        index: loaded.index,
        signature,
    })
}

/// Loads a previously published file, which must verify against one of `keys`.
pub fn load_previous(
    keys: &[PublicKey],
    plugin: &str,
    file: &str,
    data: &[u8],
    signature: &[u8],
    now: Timestamp,
) -> Result<IndexFile> {
    let keyring = keyring(plugin, keys)?;
    let subject = Subject { file, plugin };
    index::load(data, signature, &keyring, subject, now)
        .map(|loaded| loaded.index)
        .map_err(|error| Error::Previous {
            file: file.to_owned(),
            error,
        })
}
