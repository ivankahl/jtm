//! One publish: read the previous files, write and sign the new ones, check them the way a
//! client will, and put them in a directory (SPEC.md sections 8 and 18, T6.3).
//!
//! Everything that can fail is done before the first byte is written: the previous files are
//! verified, the new ones are rendered, signed and loaded with the client's loader, and only
//! then does anything touch the output directory. A failed run therefore leaves no partial
//! release behind, bar an operating system error halfway through the copy. Each file is
//! replaced atomically, so a reader never sees half of one.

use std::fs::{self, File};
use std::io::Read as _;
use std::path::{Path, PathBuf};

use jtm_core::Platform;
use jtm_security::index::MAX_INDEX_FILE;
use jtm_security::signature::MAX_SIGNATURE_FILE;
use jtm_security::{PublicKey, Timestamp};
use serde::Serialize;

use crate::confirm::Confirmed;
use crate::error::{Error, Result};
use crate::signing::Signer;
use crate::verify;
use crate::writer::{self, Action, Binding, Output, Previous, Settings, Warning, file_name};

// SPEC-QUESTION: section 12 lists the warning codes clients emit. The generator's warnings
// (`W_SOURCE_NOTE` here, `W_HASH_CHANGED` in the writer) are new and only appear in
// `jtm-index --json`; they are not part of the client contract.
/// Warning code for a note from the source adapters or the confirmation step.
pub const W_SOURCE_NOTE: &str = "W_SOURCE_NOTE";

/// What one publish needs.
#[derive(Debug)]
pub struct Request<'a> {
    pub binding: &'a Binding,
    pub confirmed: &'a Confirmed,
    /// The directory holding the previous publish, if there was one. Without it every
    /// platform starts at sequence 1, so a first publish is the only time to leave it out.
    pub previous_dir: Option<&'a Path>,
    /// Keys, besides the signer's, that the previous files may be signed by, such as the key
    /// they were signed with before a rotation.
    pub previous_keys: &'a [PublicKey],
    pub out_dir: &'a Path,
    /// The key to sign with. Only a dry run can go without.
    pub signer: Option<&'a Signer>,
    pub settings: Settings,
    /// Do everything except write into `out_dir`.
    pub dry_run: bool,
}

/// What a publish did, or with `dry_run` would do.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub plugin: String,
    pub dry_run: bool,
    /// Whether any file is new, which is whether there is anything to release.
    pub changed: bool,
    /// The public key the files verify with, when a key signed them.
    pub public_key: Option<String>,
    pub files: Vec<FileReport>,
    /// Reported beside the data, in the envelope's `warnings`, not inside it.
    #[serde(skip)]
    pub warnings: Vec<Warning>,
}

/// One platform's file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileReport {
    pub file: String,
    pub signature_file: String,
    pub platform: String,
    pub action: Action,
    pub sequence: u64,
    pub generated: String,
    pub expires: String,
    pub entries: usize,
    pub added: usize,
    pub removed: usize,
    pub changed: usize,
    /// SHA-256 of the file's bytes.
    pub sha256: String,
}

/// Publishes `req`.
pub fn publish(req: &Request<'_>) -> Result<Report> {
    let now = req.settings.now;
    let plugin = req.binding.plugin.as_str();
    if req.signer.is_none() && !req.dry_run {
        return Err(Error::Usage {
            message: "a signing key is required unless this is a dry run".to_owned(),
        });
    }

    let previous = match req.previous_dir {
        Some(dir) => read_previous(dir, req, now)?,
        None => Default::default(),
    };
    let written = writer::write(req.binding, req.confirmed, &previous, &req.settings)?;

    // Sign every file that needs it, loading the result as a client would. A signer is
    // present in a real run, so only a dry run without a key skips this.
    let mut signatures: Vec<Vec<u8>> = Vec::with_capacity(written.files.len());
    for output in &written.files {
        let signature = match (&output.signature, req.signer) {
            (Some(carried), _) => carried.clone(),
            (None, Some(signer)) => {
                let signed =
                    verify::sign_and_load(signer, plugin, &output.file, &output.bytes, now)?;
                if signed.index.sequence != output.sequence
                    || signed.index.platform != output.platform
                {
                    return Err(Error::Invalid {
                        message: format!(
                            "{} did not come back from the loader as written",
                            output.file
                        ),
                    });
                }
                signed.signature
            }
            (None, None) => Vec::new(),
        };
        signatures.push(signature);
    }

    if !req.dry_run {
        fs::create_dir_all(req.out_dir).map_err(|source| Error::Output {
            path: req.out_dir.to_path_buf(),
            source,
        })?;
        for (output, signature) in written.files.iter().zip(&signatures) {
            put(&req.out_dir.join(&output.file), &output.bytes)?;
            put(
                &req.out_dir.join(format!("{}.minisig", output.file)),
                signature,
            )?;
        }
    }

    let mut warnings: Vec<Warning> = req
        .confirmed
        .warnings
        .iter()
        .map(|message| Warning {
            code: W_SOURCE_NOTE,
            message: message.clone(),
        })
        .collect();
    warnings.extend(written.warnings.iter().cloned());
    Ok(Report {
        plugin: plugin.to_owned(),
        dry_run: req.dry_run,
        changed: written.changed(),
        public_key: req.signer.map(|s| s.public_key().to_string()),
        files: written.files.iter().map(file_report).collect(),
        warnings,
    })
}

fn file_report(output: &Output) -> FileReport {
    FileReport {
        file: output.file.clone(),
        signature_file: format!("{}.minisig", output.file),
        platform: output.platform.clone(),
        action: output.action,
        sequence: output.sequence,
        generated: output.generated.to_string(),
        expires: output.expires.to_string(),
        entries: output.entries,
        added: output.added,
        removed: output.removed,
        changed: output.changed,
        sha256: jtm_security::sha256_hex(&output.bytes),
    }
}

/// Reads and verifies every file of the plugin in `dir`, by platform.
fn read_previous(
    dir: &Path,
    req: &Request<'_>,
    now: Timestamp,
) -> Result<std::collections::BTreeMap<String, Previous>> {
    let plugin = req.binding.plugin.as_str();
    if !dir.is_dir() {
        return Err(Error::Usage {
            message: format!("the previous publish {} is not a directory", dir.display()),
        });
    }
    let platforms = std::iter::once("any").chain(Platform::ALL.iter().map(|p| p.as_str()));
    let mut found = Vec::new();
    for platform in platforms {
        let file = file_name(plugin, platform);
        let path = dir.join(&file);
        if path.exists() {
            found.push((platform, file, path));
        }
    }
    if found.is_empty() {
        return Err(Error::Usage {
            message: format!(
                "{} holds no index of `{plugin}`; leave out --previous for the first publish",
                dir.display()
            ),
        });
    }

    let mut keys: Vec<PublicKey> = req.previous_keys.to_vec();
    keys.extend(req.signer.map(|s| s.public_key().clone()));
    if keys.is_empty() {
        return Err(Error::Usage {
            message: "the previous publish can only be checked with a key: give the signing key \
                      or --previous-key"
                .to_owned(),
        });
    }

    let mut previous = std::collections::BTreeMap::new();
    for (platform, file, path) in found {
        let invalid = |message: String| Error::Previous {
            file: file.clone(),
            error: jtm_security::Error::SignatureInvalid {
                file: file.clone(),
                message,
            },
        };
        let bytes = read_capped(&path, MAX_INDEX_FILE)?;
        let sig_path = PathBuf::from(format!("{}.minisig", path.display()));
        if !sig_path.exists() {
            return Err(invalid(format!(
                "there is no {file}.minisig next to it, so it cannot be trusted"
            )));
        }
        let signature = read_capped(&sig_path, MAX_SIGNATURE_FILE)?;
        let index = verify::load_previous(&keys, plugin, &file, &bytes, &signature, now)?;
        previous.insert(
            platform.to_owned(),
            Previous {
                index,
                bytes,
                signature,
            },
        );
    }
    Ok(previous)
}

/// Reads a file of at most `limit` bytes.
fn read_capped(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let io = |source| Error::Output {
        path: path.to_path_buf(),
        source,
    };
    let file = File::open(path).map_err(io)?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() > limit {
        return Err(Error::Invalid {
            message: format!("{} is larger than {limit} bytes", path.display()),
        });
    }
    Ok(bytes)
}

/// Writes `bytes` to `path` unless it already holds exactly them.
fn put(path: &Path, bytes: &[u8]) -> Result<()> {
    if fs::read(path).is_ok_and(|existing| existing == bytes) {
        return Ok(());
    }
    jtm_security::trust::write_atomically(path, bytes).map_err(|error| match error {
        jtm_security::Error::Io { path, source } => Error::Output { path, source },
        other => Error::Invalid {
            message: other.to_string(),
        },
    })
}

#[cfg(test)]
mod tests;
