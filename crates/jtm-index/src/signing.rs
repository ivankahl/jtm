//! Signing index files with a minisign key (SPEC.md sections 8 and 9).
//!
//! A [`Signer`] signs the raw bytes of a finished file and returns the contents of its
//! `.minisig`. The signature is the pre-hashed (`ED`) kind, the only one clients accept.
//!
//! # Handling the secret key
//!
//! The key comes from the caller as the text of a `minisign.key` file, normally a CI secret.
//! This module never reads files or the environment itself, never prompts (the `minisign`
//! crate would ask on the terminal for an encrypted key whose password is missing, so that
//! case is detected first), and never puts the key, the password or anything derived from
//! them into an error message or a `Debug` rendering. Only the public key is ever shown.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jtm_security::{PublicKey, Timestamp};

use crate::error::{Error, Result};

/// The key derivation algorithm of a password-protected key (`Sc`, scrypt) and of an
/// unprotected one (two zero bytes), at offset 2 of the decoded key.
const KDF_SCRYPT: &[u8] = b"Sc";
const KDF_NONE: &[u8] = &[0, 0];
/// The signature algorithm bytes of an Ed25519 key: `Ed`.
const SIG_ALG: &[u8] = b"Ed";
/// The decoded length of a minisign secret key.
const SECRET_KEY_BYTES: usize = 2 + 2 + 2 + 32 + 8 + 8 + 8 + 64 + 32;

/// Signs index files. Holds a decrypted secret key.
pub struct Signer {
    secret: minisign::SecretKey,
    public: PublicKey,
}

impl fmt::Debug for Signer {
    /// Shows the public key only. `minisign::SecretKey` prints its secret bytes in `Debug`, so
    /// it must never be formatted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("public_key", &self.public.as_str())
            .finish_non_exhaustive()
    }
}

impl Signer {
    /// Opens the secret key in `text`, the contents of a `minisign.key` file. `password` is
    /// required for a key that is password-protected and refused for one that is not, so a
    /// mix-up in the CI secrets is reported instead of ignored.
    pub fn from_secret_key(text: &str, password: Option<String>) -> Result<Signer> {
        let box_ = minisign::SecretKeyBox::from_string(text).map_err(|_| not_a_key())?;
        let lines: Vec<&str> = text.lines().collect();
        let encoded = lines.get(1).ok_or_else(not_a_key)?.trim();
        let bytes = STANDARD.decode(encoded).map_err(|_| not_a_key())?;
        if bytes.len() != SECRET_KEY_BYTES || &bytes[..2] != SIG_ALG {
            return Err(not_a_key());
        }
        let secret = match (&bytes[2..4], password) {
            (kdf, None) if kdf == KDF_SCRYPT => {
                return Err(key_error(
                    "the key is protected by a password, and none was given",
                ));
            }
            (kdf, Some(password)) if kdf == KDF_SCRYPT => {
                minisign::SecretKey::from_box(box_, Some(password))
                    .map_err(|_| key_error("the password does not open the key"))?
            }
            (kdf, None) if kdf == KDF_NONE => minisign::SecretKey::from_unencrypted_box(box_)
                .map_err(|_| key_error("the key file is damaged"))?,
            (kdf, Some(_)) if kdf == KDF_NONE => {
                return Err(key_error(
                    "a password was given, but the key is not password-protected",
                ));
            }
            _ => return Err(key_error("the key uses an unsupported encryption")),
        };
        Signer::from_secret(secret)
    }

    /// A signer with a key made just now and kept in memory. Its signatures prove nothing to
    /// anyone; it exists so a dry run can push a file through the same signing and loading
    /// steps as a real one without holding the real key.
    pub fn ephemeral() -> Result<Signer> {
        let pair = minisign::KeyPair::generate_unencrypted_keypair()
            .map_err(|_| key_error("cannot generate a temporary key"))?;
        Signer::from_secret(pair.sk)
    }

    fn from_secret(secret: minisign::SecretKey) -> Result<Signer> {
        let public = minisign::PublicKey::from_secret_key(&secret)
            .map_err(|_| key_error("the public key cannot be derived"))?;
        let public = PublicKey::parse(&public.to_base64())
            .map_err(|_| key_error("the public key is not a minisign key"))?;
        Ok(Signer { secret, public })
    }

    /// The public key to publish or to hand to a verifier.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The contents of the `.minisig` for `data`, which is named `file` in the signed trusted
    /// comment together with the time `now`, as `minisign -S` records them.
    pub fn sign(&self, file: &str, data: &[u8], now: Timestamp) -> Result<Vec<u8>> {
        let trusted = format!("timestamp:{}\tfile:{file}", now.unix());
        // Signing reads from memory and the key is already decrypted, so the only failure
        // `minisign` has left is the system's random number generator.
        minisign::sign(
            None,
            &self.secret,
            data,
            Some(&trusted),
            Some("signature from the jtm index generator"),
        )
        .map(|signature| signature.to_bytes())
        .map_err(|_| key_error("signing failed"))
    }
}

fn not_a_key() -> Error {
    key_error("this is not a minisign secret key file")
}

// SPEC-QUESTION: section 12 has no code for "the signing key is unusable". It is a mistake in
// how the command was invoked or in the CI secrets, so it is `E_USAGE` (exit 2) and the message
// never repeats the key or the password.
fn key_error(message: &str) -> Error {
    Error::SigningKey {
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests;
