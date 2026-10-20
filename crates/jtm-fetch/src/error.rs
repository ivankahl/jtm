//! Failures of the HTTP client and the download cache. `jtm-core` maps each variant onto a
//! stable `E_` code (SPEC.md section 12).

use std::path::PathBuf;

/// Why a fetch or download failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A URL jtm refuses to request: not `https`, or `http` while `http` mirrors are not
    /// allowed. Maps to `E_USAGE`, since only configuration can produce one.
    #[error("refusing to fetch {url}: {reason}")]
    Scheme { url: String, reason: String },

    /// The request failed in transport: connecting, TLS, a refused redirect, a timeout, or the
    /// connection dropping mid-body. `transient` failures are retried. Maps to `E_NETWORK`.
    #[error("network error fetching {url}: {message}")]
    Network {
        url: String,
        message: String,
        transient: bool,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// The server answered with an error status. 5xx and 429 are retried. Maps to
    /// `E_NETWORK`.
    #[error("{url} returned HTTP {status}")]
    Status { url: String, status: u16 },

    /// The body is larger than allowed. Maps to `E_SIZE_EXCEEDED`.
    #[error("{url} is larger than the limit of {limit} bytes")]
    TooLarge { url: String, limit: u64 },

    /// The downloaded bytes do not have the expected SHA-256. Never retried. Maps to
    /// `E_HASH_MISMATCH`.
    #[error("hash mismatch for {url}: expected {expected}, got {actual}")]
    HashMismatch {
        url: String,
        expected: String,
        actual: String,
    },

    /// Reading or writing the download cache failed.
    #[error("cannot access {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    /// Whether retrying the same request may succeed: transport failures and server-side
    /// statuses (5xx and 429). Client errors, refused URLs, size and hash failures never are.
    pub fn is_transient(&self) -> bool {
        match self {
            Error::Network { transient, .. } => *transient,
            Error::Status { status, .. } => *status >= 500 || *status == 429,
            _ => false,
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
