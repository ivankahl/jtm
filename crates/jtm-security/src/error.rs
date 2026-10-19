//! Failures of the checks in this crate. `jtm-core` maps each variant onto a stable `E_` code
//! (SPEC.md section 12).

use std::path::PathBuf;

/// Why a signed file was not accepted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The signature file is malformed, a signature does not match the bytes, or not enough
    /// valid signatures were found. Maps to `E_SIGNATURE_INVALID`.
    #[error("invalid signature on {file}: {message}")]
    SignatureInvalid { file: String, message: String },

    /// No signature was made by a key trusted for this file. Maps to `E_KEY_UNTRUSTED`.
    #[error("{file} is signed by key {key_id}, which is not trusted for it")]
    KeyUntrusted {
        file: String,
        /// Key ids found in the signature file, comma-separated.
        key_id: String,
        /// The command that would trust the key, for `details.resolve`.
        resolve: String,
    },

    /// A correctly signed file that is not what jtm expects: malformed, an unsupported format,
    /// or failing validation. Maps to `E_INDEX_INVALID`.
    #[error("{file} is signed but not valid: {message}")]
    Invalid { file: String, message: String },

    /// A plugin manifest whose `[index] signing_keys` are not usable public keys. Maps to
    /// `E_PLUGIN_INVALID`.
    #[error("plugin `{plugin}` signing keys are not valid: {message}")]
    SigningKeys { plugin: String, message: String },

    /// The signed plugin or platform is not the one requested. Maps to `E_INDEX_BINDING`.
    #[error("{file} is signed for {got}, not {expected}")]
    IndexBinding {
        file: String,
        expected: String,
        got: String,
    },

    /// An older copy than one already seen, or the same sequence with different content. Maps
    /// to `E_INDEX_ROLLBACK`.
    #[error("{file} has sequence {got}, {reason} (sequence {seen})")]
    IndexRollback {
        file: String,
        seen: u64,
        got: u64,
        reason: String,
    },

    /// An expired index where expiry is enforced. Maps to `E_INDEX_EXPIRED`.
    #[error("{file} expired at {expires}; run `jtm update` to fetch a current copy")]
    IndexExpired { file: String, expires: String },

    /// `trust.json` cannot be read as jtm wrote it. It is never silently reset, since that
    /// would forget trusted keys and rollback history.
    #[error(
        "{}: {message}; fix or remove the file (removing it forgets trusted keys and \
         rollback history)",
        path.display()
    )]
    State { path: PathBuf, message: String },

    /// Reading or writing jtm's own state failed.
    #[error("cannot access {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
