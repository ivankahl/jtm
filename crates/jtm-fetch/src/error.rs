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
    /// connection dropping mid-body. `transient` failures are retried; TLS failures and refused
    /// redirects are not. Maps to `E_NETWORK`.
    #[error("network error fetching {url}: {message}")]
    Network {
        url: String,
        message: String,
        transient: bool,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// The server answered with an error status. Never retried: it is an answer, not a network
    /// error. Maps to `E_NETWORK`.
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

    /// A SHA-256 that is not 64 lowercase hex digits, so it cannot name a cache entry.
    #[error("`{value}` is not a SHA-256 digest")]
    InvalidDigest { value: String },

    /// Reading or writing the download cache failed.
    #[error("cannot access {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl Error {
    /// Whether retrying the same request may succeed. Only network errors are: connecting,
    /// timeouts and dropped transfers. HTTP statuses, TLS failures, refused URLs and
    /// redirects, size and hash failures never are.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Error::Network {
                transient: true,
                ..
            }
        )
    }

    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Error {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
