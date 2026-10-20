//! Failures of extraction. `jtm-core` maps each variant onto a stable `E_` code (SPEC.md
//! section 12).

use std::path::PathBuf;

/// Why an archive was not extracted.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An entry breaks an archive rule, or the archive exceeds a bomb limit. Maps to
    /// `E_ARCHIVE_UNSAFE`.
    #[error("unsafe archive entry `{entry}`: {reason}")]
    Unsafe { entry: String, reason: String },

    /// The archive cannot be read as its format. Maps to `E_ARCHIVE_UNSAFE`, since its hash
    /// matched a signed index and its contents still cannot be trusted to mean anything.
    #[error("the archive is malformed: {message}")]
    Malformed { message: String },

    /// Reading the archive or writing the destination failed.
    #[error("cannot access {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    pub(crate) fn unsafe_entry(entry: impl Into<String>, reason: impl Into<String>) -> Error {
        Error::Unsafe {
            entry: entry.into(),
            reason: reason.into(),
        }
    }

    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Error {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
