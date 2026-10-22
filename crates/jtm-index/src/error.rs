//! Failures of the index generator's source adapters. Each maps onto a stable `E_` code
//! (SPEC.md section 12) so the commands built on top report them like every other jtm failure.

use std::fmt;
use std::path::PathBuf;

use jtm_core::ErrorCode;

use crate::candidate::{HashAlgorithm, Target};

/// Why a `sources.toml` could not be read or a source could not be queried.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A `sources.toml` that does not follow the schema. Maps to `E_PLUGIN_INVALID`, since the
    /// file is part of the plugin.
    #[error("invalid {file}: {message}")]
    Sources { file: String, message: String },

    /// A request to an upstream failed in transport, answered with an error status, or returned
    /// more than the adapter accepts.
    #[error("source `{source_id}`: {error}")]
    Fetch {
        source_id: String,
        #[source]
        error: jtm_fetch::Error,
    },

    /// A file the source must publish is missing (HTTP 404 or 410).
    #[error("source `{source_id}`: {url} does not exist")]
    Missing { source_id: String, url: String },

    /// An upstream answered, but not with the shape the adapter relies on.
    #[error("source `{source_id}`: unexpected response from {url}: {message}")]
    Response {
        source_id: String,
        url: String,
        message: String,
    },

    /// Entries the generator refuses to publish: sources that disagree, a download that does
    /// not match what was claimed, a bad signature, or too little evidence. The whole run
    /// fails, so no index is ever written from part of the data.
    #[error("{}", summarize(.rejections))]
    Rejected { rejections: Vec<Rejection> },

    /// A temporary file for a download could not be made or read.
    #[error("cannot use a temporary file: {0}")]
    Io(#[source] std::io::Error),

    /// The command line or its environment is wrong. Maps to `E_USAGE`.
    #[error("{message}")]
    Usage { message: String },

    /// The signing key cannot be used: it is not a minisign secret key, or the password is
    /// missing or wrong. The message never repeats key material or the password. Maps to
    /// `E_USAGE`.
    #[error("signing key: {message}")]
    SigningKey { message: String },

    /// An index the generator refuses to write, or whose written form does not verify with
    /// the client's loader. Maps to `E_INDEX_INVALID`.
    #[error("{message}")]
    Invalid { message: String },

    /// Writing would take an index's sequence or time backwards. Maps to `E_INDEX_ROLLBACK`.
    #[error("{file}: {message}")]
    Rollback { file: String, message: String },

    /// The previously published index could not be read or does not verify. Its failure keeps
    /// the code the client would give it.
    #[error("previous index {file}: {error}")]
    Previous {
        file: String,
        #[source]
        error: jtm_security::Error,
    },

    /// An output file could not be written. Maps to `E_IO`.
    #[error("cannot write {}: {source}", path.display())]
    Output {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// One entry the confirmation step refused, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub variant: Option<String>,
    pub version: String,
    pub target: Target,
    pub reason: Reason,
}

/// Why an entry was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Reason {
    /// A candidate names a source that `sources.toml` does not list.
    UnknownSource { source_id: String },
    /// The primary source reports the same version and platform more than once, so which
    /// artifact the entry is for is not clear.
    AmbiguousPrimary { urls: Vec<String> },
    /// Two claims with the same algorithm differ.
    SourcesDisagree {
        algorithm: HashAlgorithm,
        /// `(source id, digest)` for each claim, in source order.
        claims: Vec<(String, String)>,
    },
    /// The digest of the download differs from what a source claimed.
    ClaimMismatch {
        source_id: String,
        origin: String,
        algorithm: HashAlgorithm,
        claimed: String,
        computed: String,
    },
    /// The download is larger than allowed: the largest size a source claimed, or the cap on
    /// one artifact. It was abandoned there.
    TooLarge { url: String, limit: u64 },
    /// The download is not the size a source claimed.
    SizeMismatch {
        source_id: String,
        claimed: u64,
        measured: u64,
    },
    /// A signature that does not hold: it cannot be read, or a key in the keyring that it
    /// names did not make it over this download.
    SignatureInvalid {
        source_id: String,
        url: String,
        message: String,
    },
    /// Nothing is wrong with the evidence, there is just not enough of it.
    NotConfirmed { message: String },
}

impl Reason {
    /// The stable error code for this reason.
    pub const fn code(&self) -> ErrorCode {
        match self {
            Reason::SourcesDisagree { .. } | Reason::ClaimMismatch { .. } => {
                ErrorCode::HashMismatch
            }
            Reason::TooLarge { .. } => ErrorCode::SizeExceeded,
            // A download longer than claimed exceeds its size; a shorter one is not the
            // content that was claimed, like any other digest that does not match.
            Reason::SizeMismatch {
                claimed, measured, ..
            } => {
                if *measured > *claimed {
                    ErrorCode::SizeExceeded
                } else {
                    ErrorCode::HashMismatch
                }
            }
            Reason::SignatureInvalid { .. } => ErrorCode::SignatureInvalid,
            // SPEC-QUESTION: SPEC.md section 12 has no code for "not enough independent
            // evidence for a hash" or "the generator's input is inconsistent". Like an
            // unusable upstream response, they map to `E_INDEX_INVALID` (exit 5): the run
            // fails, is not retried, and nothing reaches an index.
            _ => ErrorCode::IndexInvalid,
        }
    }

    /// How serious the reason is when several are reported together; the run's code is the
    /// most serious one.
    const fn severity(&self) -> u8 {
        match self.code() {
            ErrorCode::HashMismatch => 4,
            ErrorCode::SignatureInvalid => 3,
            ErrorCode::SizeExceeded => 2,
            _ => 1,
        }
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::UnknownSource { source_id } => {
                write!(f, "source `{source_id}` is not listed in sources.toml")
            }
            Reason::AmbiguousPrimary { urls } => write!(
                f,
                "the primary source lists it {} times ({})",
                urls.len(),
                urls.join(", ")
            ),
            Reason::SourcesDisagree { algorithm, claims } => {
                let claims: Vec<String> = claims
                    .iter()
                    .map(|(source, hex)| format!("{source} says {hex}"))
                    .collect();
                write!(
                    f,
                    "sources disagree on the {algorithm}: {}",
                    claims.join("; ")
                )
            }
            Reason::ClaimMismatch {
                source_id,
                origin,
                algorithm,
                claimed,
                computed,
            } => write!(
                f,
                "the download has {algorithm} {computed}, but {source_id} ({origin}) says \
                 {claimed}"
            ),
            Reason::TooLarge { url, limit } => {
                write!(
                    f,
                    "{url} is larger than {limit} bytes; the download was abandoned"
                )
            }
            Reason::SizeMismatch {
                source_id,
                claimed,
                measured,
            } => write!(
                f,
                "the download is {measured} bytes, but {source_id} says {claimed}"
            ),
            Reason::SignatureInvalid {
                source_id,
                url,
                message,
            } => write!(
                f,
                "the signature {url} (from {source_id}) is invalid: {message}"
            ),
            Reason::NotConfirmed { message } => f.write_str(message),
        }
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(variant) = &self.variant {
            write!(f, "{variant} ")?;
        }
        write!(f, "{} ({}): {}", self.version, self.target, self.reason)
    }
}

/// How many rejected entries a message lists before summarising the rest.
const LISTED: usize = 10;

fn summarize(rejections: &[Rejection]) -> String {
    let mut text = match rejections.len() {
        1 => "1 index entry refused".to_owned(),
        n => format!("{n} index entries refused"),
    };
    for rejection in rejections.iter().take(LISTED) {
        text.push_str("\n  ");
        text.push_str(&rejection.to_string());
    }
    if rejections.len() > LISTED {
        text.push_str(&format!("\n  ... and {} more", rejections.len() - LISTED));
    }
    text
}

impl Error {
    /// The stable error code for this failure.
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Sources { .. } => ErrorCode::PluginInvalid,
            Error::Fetch { error, .. } => match error {
                jtm_fetch::Error::Scheme { .. } => ErrorCode::Usage,
                jtm_fetch::Error::TooLarge { .. } => ErrorCode::SizeExceeded,
                jtm_fetch::Error::HashMismatch { .. } => ErrorCode::HashMismatch,
                jtm_fetch::Error::Io { .. } => ErrorCode::Io,
                _ => ErrorCode::Network,
            },
            Error::Missing { .. } => ErrorCode::Network,
            // SPEC-QUESTION: SPEC.md section 12 has no code for "an upstream sent data the
            // generator cannot use". `E_INDEX_INVALID` (exit 5, "invalid signed file") is the
            // closest: it fails the run without a retry, and it never lets the data reach an
            // index.
            Error::Response { .. } => ErrorCode::IndexInvalid,
            Error::Rejected { rejections } => rejections
                .iter()
                .map(|r| &r.reason)
                .max_by_key(|reason| reason.severity())
                .map_or(ErrorCode::IndexInvalid, Reason::code),
            Error::Io(_) | Error::Output { .. } => ErrorCode::Io,
            Error::Usage { .. } | Error::SigningKey { .. } => ErrorCode::Usage,
            Error::Invalid { .. } => ErrorCode::IndexInvalid,
            Error::Rollback { .. } => ErrorCode::IndexRollback,
            Error::Previous { error, .. } => security_code(error),
        }
    }

    pub(crate) fn response(source_id: &str, url: &str, message: impl std::fmt::Display) -> Error {
        Error::Response {
            source_id: source_id.to_owned(),
            url: url.to_owned(),
            message: message.to_string(),
        }
    }
}

/// The code the client gives a failure of the same check.
fn security_code(error: &jtm_security::Error) -> ErrorCode {
    use jtm_security::Error as S;
    match error {
        S::SignatureInvalid { .. } => ErrorCode::SignatureInvalid,
        S::KeyUntrusted { .. } => ErrorCode::KeyUntrusted,
        S::Invalid { .. } => ErrorCode::IndexInvalid,
        S::IndexBinding { .. } => ErrorCode::IndexBinding,
        S::IndexRollback { .. } => ErrorCode::IndexRollback,
        S::IndexExpired { .. } => ErrorCode::IndexExpired,
        S::Io { .. } => ErrorCode::Io,
        _ => ErrorCode::Internal,
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests;
