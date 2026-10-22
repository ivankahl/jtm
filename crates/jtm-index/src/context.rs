//! How adapters reach their upstreams: the shared HTTP client, optional prefix rewrites and
//! the token for APIs that rate-limit anonymous callers.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use jtm_fetch::{Client, Response, RetryPolicy, mirrors};
use serde::de::DeserializeOwned;

use crate::digest::{Computed, Digests};
use crate::error::{Error, Result};

/// The largest JSON, XML or HTML document an adapter reads. Version lists are a few hundred
/// KiB, and a page of 100 GitHub releases with their assets a few MiB.
pub(crate) const DOCUMENT_LIMIT: u64 = 16 * 1024 * 1024;
/// The only host that receives the GitHub token.
const GITHUB_API: &str = "https://api.github.com/";
/// The largest checksum file an adapter reads.
pub(crate) const CHECKSUM_LIMIT: u64 = 64 * 1024;
/// The largest detached signature the generator reads. Real ones are a few hundred bytes.
pub(crate) const SIGNATURE_LIMIT: u64 = 64 * 1024;

/// Shared by every adapter run.
pub struct Context {
    client: Client,
    mirrors: BTreeMap<String, String>,
    github_token: Option<String>,
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("mirrors", &self.mirrors)
            // The token is a credential and stays out of logs.
            .field("github_token", &self.github_token.as_ref().map(|_| "<set>"))
            .finish_non_exhaustive()
    }
}

impl Context {
    pub fn new(client: Client) -> Context {
        Context {
            client,
            mirrors: BTreeMap::new(),
            github_token: None,
        }
    }

    /// Rewrites request URLs by prefix (SPEC.md section 8 `[mirrors]`), for a proxy cache in
    /// CI or for tests. Candidates keep the URLs the upstream reported.
    #[must_use]
    pub fn with_mirrors(mut self, mirrors: BTreeMap<String, String>) -> Context {
        self.mirrors = mirrors;
        self
    }

    /// The token sent to `https://api.github.com`, which allows far more requests to
    /// authenticated callers. It is sent to nothing else: not to download URLs, and not to
    /// another `api_url` a `sources.toml` names.
    #[must_use]
    pub fn with_github_token(mut self, token: Option<String>) -> Context {
        self.github_token = token.filter(|t| !t.is_empty());
        self
    }

    /// Fetches `url`. `Ok(None)` when the upstream has no such file.
    pub(crate) fn get_optional(
        &self,
        source: &str,
        url: &str,
        limit: u64,
    ) -> Result<Option<Vec<u8>>> {
        let target = mirrors::rewrite(url, &self.mirrors);
        self.client
            .get_bytes(&target, limit)
            .map_err(|error| fetch_error(source, error))
    }

    /// Fetches `url`, which must exist.
    pub(crate) fn get(&self, source: &str, url: &str, limit: u64) -> Result<Vec<u8>> {
        self.get_optional(source, url, limit)?
            .ok_or_else(|| Error::Missing {
                source_id: source.to_owned(),
                url: url.to_owned(),
            })
    }

    /// Fetches an API `url` with the GitHub token, if one is set. `Ok(None)` for a 404.
    pub(crate) fn get_github_api(
        &self,
        source: &str,
        url: &str,
        limit: u64,
    ) -> Result<Option<Vec<u8>>> {
        // `sources.toml` can name any `api_url`, so the token is only ever offered to the
        // GitHub API itself. (SPEC-QUESTION: GitHub Enterprise hosts are not supported.)
        let token = self
            .github_token
            .as_ref()
            .filter(|_| url.starts_with(GITHUB_API));
        let Some(token) = token else {
            return self.get_optional(source, url, limit);
        };
        let target = mirrors::rewrite(url, &self.mirrors);
        self.client
            .get_bytes_with_bearer(&target, limit, token)
            .map_err(|error| fetch_error(source, error))
    }

    /// Downloads the artifact at `url`, hashing it as the bytes arrive, and returns its
    /// digests. With `keep`, the bytes are also spooled to an anonymous temporary file that
    /// is returned rewound to its start, for a signature check; without it nothing touches
    /// the disk.
    ///
    /// The transfer is aborted the moment it passes `limit` bytes, whatever the server
    /// declared, so a hostile or broken upstream cannot fill the disk. A dropped connection
    /// restarts the transfer from byte 0 under the client's retry policy, so a half-read body
    /// is never mistaken for a whole one.
    pub(crate) fn download(
        &self,
        source: &str,
        url: &str,
        limit: u64,
        keep: bool,
    ) -> Result<(Option<File>, Computed)> {
        let target = mirrors::rewrite(url, &self.mirrors);
        let mut file = if keep {
            Some(tempfile::tempfile().map_err(Error::Io)?)
        } else {
            None
        };
        let retry: RetryPolicy = self.client.options().retry;
        let computed = retry
            .run(|_| {
                if let Some(file) = file.as_mut() {
                    file.set_len(0).map_err(|e| temp_error(&e))?;
                    file.seek(SeekFrom::Start(0)).map_err(|e| temp_error(&e))?;
                }
                let response = self.client.open(&target, 0)?;
                stream_into(response, file.as_mut(), url, limit)
            })
            .map_err(|error| fetch_error(source, error))?;
        if let Some(file) = file.as_mut() {
            file.seek(SeekFrom::Start(0)).map_err(Error::Io)?;
        }
        Ok((file, computed))
    }

    /// Fetches a checksum file as text. `Ok(None)` when it does not exist.
    pub(crate) fn get_text(&self, source: &str, url: &str, limit: u64) -> Result<Option<String>> {
        Ok(self
            .get_optional(source, url, limit)?
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
    }
}

/// Hashes `response`, copying it into `file` if there is one, and refuses more than `limit`
/// bytes.
fn stream_into(
    mut response: Response,
    mut file: Option<&mut File>,
    url: &str,
    limit: u64,
) -> jtm_fetch::Result<Computed> {
    let too_large = || jtm_fetch::Error::TooLarge {
        url: url.to_owned(),
        limit,
    };
    if response.content_length.is_some_and(|len| len > limit) {
        return Err(too_large());
    }
    let mut digests = Digests::new();
    let mut total = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = response
            .read(&mut buffer)
            .map_err(|e| jtm_fetch::Error::Network {
                url: url.to_owned(),
                message: format!("the transfer broke off: {e}"),
                transient: true,
                source: Some(Box::new(e)),
            })?;
        if read == 0 {
            return Ok(digests.finish());
        }
        total += read as u64;
        if total > limit {
            return Err(too_large());
        }
        digests.update(&buffer[..read]);
        if let Some(file) = file.as_mut() {
            file.write_all(&buffer[..read])
                .map_err(|e| temp_error(&e))?;
        }
    }
}

fn temp_error(error: &std::io::Error) -> jtm_fetch::Error {
    jtm_fetch::Error::Io {
        path: PathBuf::from("<temporary file>"),
        source: std::io::Error::new(error.kind(), error.to_string()),
    }
}

fn fetch_error(source: &str, error: jtm_fetch::Error) -> Error {
    Error::Fetch {
        source_id: source.to_owned(),
        error,
    }
}

/// Parses `bytes` as JSON, naming the field that does not fit when it does not.
pub(crate) fn parse_json<T: DeserializeOwned>(source: &str, url: &str, bytes: &[u8]) -> Result<T> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    serde_path_to_error::deserialize(&mut deserializer)
        .map_err(|err| Error::response(source, url, err))
}

#[cfg(test)]
mod tests;
