//! How adapters reach their upstreams: the shared HTTP client, optional prefix rewrites and
//! the token for APIs that rate-limit anonymous callers.

use std::collections::BTreeMap;
use std::fmt;

use jtm_fetch::{Client, mirrors};
use serde::de::DeserializeOwned;

use crate::error::{Error, Result};

/// The largest JSON, XML or HTML document an adapter reads. Version lists are a few hundred
/// KiB, and a page of 100 GitHub releases with their assets a few MiB.
pub(crate) const DOCUMENT_LIMIT: u64 = 16 * 1024 * 1024;
/// The only host that receives the GitHub token.
const GITHUB_API: &str = "https://api.github.com/";
/// The largest checksum file an adapter reads.
pub(crate) const CHECKSUM_LIMIT: u64 = 64 * 1024;

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

    /// Fetches a checksum file as text. `Ok(None)` when it does not exist.
    pub(crate) fn get_text(&self, source: &str, url: &str, limit: u64) -> Result<Option<String>> {
        Ok(self
            .get_optional(source, url, limit)?
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
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
