//! Failures of the index generator's source adapters. Each maps onto a stable `E_` code
//! (SPEC.md section 12) so the commands built on top report them like every other jtm failure.

use jtm_core::ErrorCode;

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
}

impl Error {
    /// The stable error code for this failure.
    pub const fn code(&self) -> ErrorCode {
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

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests;
