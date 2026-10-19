//! Failures of the checks in this crate. `jtm-core` maps each variant onto a stable `E_` code
//! (SPEC.md section 12).

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
    /// or failing validation.
    #[error("{file} is signed but not valid: {message}")]
    Invalid { file: String, message: String },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
