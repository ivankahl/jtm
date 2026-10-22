//! The HTTP client (SPEC.md section 9, Transport).
//!
//! HTTPS only, through `reqwest` with `rustls` and the platform verifier, so corporate root
//! certificates in the OS store work. `http` is accepted only when `http` mirrors are allowed,
//! and never after an `https` hop: a redirect from `https` to `http` is always refused, and at
//! most [`MAX_REDIRECTS`] redirects are followed. Transport security is defence in depth only;
//! everything fetched is verified by signature or hash afterwards.
//!
//! Proxies come from [`ClientOptions::proxy`] (`network.proxy`), else from `HTTPS_PROXY`,
//! `HTTP_PROXY`, `ALL_PROXY` and `NO_PROXY` (and their lowercase forms), else from the Windows
//! system proxy; see [`crate::proxy`] (SPEC.md section 13). Behind a proxy `https` URLs are
//! tunnelled with `CONNECT`, so the TLS session still ends at the server and the redirect rules
//! above hold unchanged.

use std::fmt;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Once;
use std::time::Duration;

use reqwest::StatusCode;
use reqwest::blocking::Response as HttpResponse;
use reqwest::header::{CONTENT_RANGE, RANGE};
use reqwest::{Certificate, redirect};

use crate::error::{Error, Result};
use crate::proxy::{ProxyConfig, ProxyReport, redact_url};

/// The most redirects followed for one request.
pub const MAX_REDIRECTS: usize = 10;

/// What to tell someone whose proxy wants credentials jtm did not send.
const PROXY_AUTH_HINT: &str = "The proxy requires authentication; put Basic credentials in \
    `network.proxy` as http://user:password@host:port. NTLM and Kerberos are not supported: \
    point `network.proxy` at a local authenticating proxy such as px or Cntlm";

/// How failed requests are retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Attempts after the first. Only transient failures are retried.
    pub retries: u32,
    /// The wait before the first retry; it doubles for each one after.
    pub backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            retries: 3,
            backoff: Duration::from_millis(500),
        }
    }
}

impl RetryPolicy {
    /// Runs `attempt` until it succeeds, fails with a non-transient error, or the retries run
    /// out. `attempt` receives the zero-based attempt number.
    pub fn run<T>(&self, mut attempt: impl FnMut(u32) -> Result<T>) -> Result<T> {
        let mut wait = self.backoff;
        for n in 0.. {
            match attempt(n) {
                Err(err) if err.is_transient() && n < self.retries => {
                    tracing::debug!(%err, attempt = n + 1, "retrying after a transient failure");
                    std::thread::sleep(wait);
                    wait = wait.saturating_mul(2);
                }
                result => return result,
            }
        }
        unreachable!("the loop returns before the counter overflows")
    }
}

/// How to build a [`Client`].
#[derive(Clone)]
pub struct ClientOptions {
    pub user_agent: String,
    /// Permit `http` URLs, as `security.allow_http_mirrors` does. A redirect from `https` to
    /// `http` is refused regardless.
    pub allow_http: bool,
    pub retry: RetryPolicy,
    pub connect_timeout: Duration,
    /// The longest wait for the next bytes of a response. There is no limit on the whole
    /// transfer, since archives can be hundreds of megabytes.
    pub read_timeout: Duration,
    /// An explicit proxy for every request, as `network.proxy` sets it. It replaces the proxy
    /// variables; `NO_PROXY` still applies. `None` uses the environment, then the Windows
    /// system proxy. The URL may hold credentials, which `Debug` redacts.
    pub proxy: Option<String>,
    /// A PEM bundle trusted in addition to the OS store, as `network.extra_ca_file` sets it.
    pub extra_ca_file: Option<PathBuf>,
}

impl ClientOptions {
    /// Defaults for jtm `version`.
    pub fn new(version: &str) -> ClientOptions {
        ClientOptions {
            user_agent: user_agent(version),
            allow_http: false,
            retry: RetryPolicy::default(),
            connect_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(60),
            proxy: None,
            extra_ca_file: None,
        }
    }
}

impl fmt::Debug for ClientOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientOptions")
            .field("user_agent", &self.user_agent)
            .field("allow_http", &self.allow_http)
            .field("retry", &self.retry)
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("proxy", &self.proxy.as_deref().map(redact_url))
            .field("extra_ca_file", &self.extra_ca_file)
            .finish()
    }
}

/// The `User-Agent` header: `jtm/<version> (<os>-<arch>)`.
pub fn user_agent(version: &str) -> String {
    format!(
        "jtm/{version} ({}-{})",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
}

/// A blocking HTTP client with jtm's transport rules.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::blocking::Client,
    options: ClientOptions,
    proxies: ProxyConfig,
}

/// An open response body.
#[derive(Debug)]
pub struct Response {
    inner: HttpResponse,
    /// The URL that answered, after redirects.
    pub final_url: String,
    /// The body continues from the requested offset. When false, it starts from byte 0.
    pub resumed: bool,
    /// The length of the body as sent, if the server said.
    pub content_length: Option<u64>,
}

impl Read for Response {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Client {
    /// Builds a client that finds its proxy as [`ProxyConfig::detect`] does, from
    /// [`ClientOptions::proxy`], the environment and the Windows settings. An unusable proxy
    /// setting is an error, never a direct connection.
    pub fn new(options: ClientOptions) -> Result<Client> {
        let proxies = ProxyConfig::detect(options.proxy.as_deref())?;
        Client::with_proxies(options, proxies)
    }

    /// Builds a client with exactly these proxies; [`ClientOptions::proxy`] is not consulted.
    pub fn with_proxies(options: ClientOptions, proxies: ProxyConfig) -> Result<Client> {
        install_crypto_provider();
        let allow_http = options.allow_http;
        let policy = redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() > MAX_REDIRECTS {
                return attempt.error(format!("more than {MAX_REDIRECTS} redirects"));
            }
            let from = attempt.previous().last().map(reqwest::Url::scheme);
            match check_redirect(from, attempt.url().scheme(), allow_http) {
                Ok(()) => attempt.follow(),
                Err(reason) => attempt.error(reason),
            }
        });
        // The report copies and redacts every route, so build it only when it will be logged.
        if tracing::enabled!(tracing::Level::DEBUG) {
            let report = proxies.report();
            tracing::debug!(
                http = report.http.as_ref().map(|r| r.url.as_str()),
                https = report.https.as_ref().map(|r| r.url.as_str()),
                no_proxy = report.no_proxy.as_deref(),
                "proxy configuration"
            );
        }
        let mut builder = proxies.apply(reqwest::blocking::Client::builder())?;
        if let Some(path) = &options.extra_ca_file {
            let pem = std::fs::read(path).map_err(|e| Error::io(path, e))?;
            let certs = Certificate::from_pem_bundle(&pem)
                .ok()
                .filter(|certs| !certs.is_empty())
                .ok_or_else(|| {
                    Error::io(
                        path,
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "holds no PEM certificates",
                        ),
                    )
                })?;
            builder = builder.tls_certs_merge(certs);
        }
        let http = builder
            .user_agent(options.user_agent.clone())
            .redirect(policy)
            .https_only(!allow_http)
            .connect_timeout(options.connect_timeout)
            // The blocking client applies this to the response headers and to each read of
            // the body, not to the whole transfer.
            .timeout(options.read_timeout)
            .build()
            .map_err(|e| start_error("cannot start the HTTP client", e))?;
        Ok(Client {
            http,
            options,
            proxies,
        })
    }

    pub fn options(&self) -> &ClientOptions {
        &self.options
    }

    /// The proxy each kind of URL uses and where that setting came from, with credentials
    /// redacted, for `jtm doctor`.
    pub fn proxy_report(&self) -> ProxyReport {
        self.proxies.report()
    }

    /// Fetches `url` in full, refusing a body larger than `limit` bytes. `Ok(None)` means the
    /// server has no such file (HTTP 404 or 410). Transient failures are retried.
    pub fn get_bytes(&self, url: &str, limit: u64) -> Result<Option<Vec<u8>>> {
        self.fetch_bytes(url, limit, None)
    }

    /// Like [`Client::get_bytes`], sending `token` as a bearer token, for APIs that rate-limit
    /// anonymous callers. The header is marked sensitive and reqwest drops it on a redirect to
    /// another origin, so the token reaches only the host that was asked.
    pub fn get_bytes_with_bearer(
        &self,
        url: &str,
        limit: u64,
        token: &str,
    ) -> Result<Option<Vec<u8>>> {
        self.fetch_bytes(url, limit, Some(token))
    }

    fn fetch_bytes(&self, url: &str, limit: u64, bearer: Option<&str>) -> Result<Option<Vec<u8>>> {
        self.options.retry.run(|_| {
            let mut response = match self.open_with(url, 0, bearer) {
                Ok(response) => response,
                Err(Error::Status { status, .. }) if status == 404 || status == 410 => {
                    return Ok(None);
                }
                Err(err) => return Err(err),
            };
            if response.content_length.is_some_and(|len| len > limit) {
                return Err(Error::TooLarge {
                    url: url.to_owned(),
                    limit,
                });
            }
            let mut body = Vec::new();
            (&mut response)
                .take(limit.saturating_add(1))
                .read_to_end(&mut body)
                .map_err(|e| body_error(url, e))?;
            if body.len() as u64 > limit {
                return Err(Error::TooLarge {
                    url: url.to_owned(),
                    limit,
                });
            }
            Ok(Some(body))
        })
    }

    /// Opens `url` for streaming, asking for the body from byte `offset` on. A server that
    /// ignores the range sends the whole body, which [`Response::resumed`] reports. Not
    /// retried; callers decide how to resume.
    pub fn open(&self, url: &str, offset: u64) -> Result<Response> {
        self.open_with(url, offset, None)
    }

    fn open_with(&self, url: &str, offset: u64, bearer: Option<&str>) -> Result<Response> {
        check_scheme(url, self.options.allow_http)?;
        let mut request = self.http.get(url);
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        if offset > 0 {
            request = request.header(RANGE, format!("bytes={offset}-"));
        }
        let response = request.send().map_err(|e| request_error(url, e))?;
        let status = response.status();
        if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            return Err(Error::Network {
                url: url.to_owned(),
                message: format!("the proxy answered HTTP 407. {PROXY_AUTH_HINT}"),
                transient: false,
                source: None,
            });
        }
        if !status.is_success() {
            return Err(Error::Status {
                url: url.to_owned(),
                status: status.as_u16(),
            });
        }
        let resumed = offset > 0
            && status == StatusCode::PARTIAL_CONTENT
            && response
                .headers()
                .get(CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| content_range_starts_at(v, offset));
        if offset > 0 && status == StatusCode::PARTIAL_CONTENT && !resumed {
            return Err(Error::Network {
                url: url.to_owned(),
                message: "the server sent a different range than requested".to_owned(),
                transient: false,
                source: None,
            });
        }
        Ok(Response {
            final_url: response.url().to_string(),
            content_length: response.content_length(),
            resumed,
            inner: response,
        })
    }
}

/// A failure to build the client, which retrying cannot fix.
fn start_error(message: &str, err: reqwest::Error) -> Error {
    Error::Network {
        url: String::new(),
        message: format!("{message}: {err}"),
        transient: false,
        source: Some(Box::new(err)),
    }
}

/// Checks the scheme of a URL about to be requested.
pub fn check_scheme(url: &str, allow_http: bool) -> Result<()> {
    let scheme = url.split_once("://").map(|(s, _)| s.to_ascii_lowercase());
    match scheme.as_deref() {
        Some("https") => Ok(()),
        Some("http") if allow_http => Ok(()),
        Some("http") => Err(Error::Scheme {
            url: url.to_owned(),
            reason: "http is not allowed; set `security.allow_http_mirrors = true` to permit \
                     http mirrors"
                .to_owned(),
        }),
        _ => Err(Error::Scheme {
            url: url.to_owned(),
            reason: "only https URLs can be downloaded".to_owned(),
        }),
    }
}

/// Decides whether a redirect from a URL with scheme `from` to one with scheme `to` may be
/// followed. `https` is always allowed; `http` only when `allow_http` is set and the previous
/// hop was not `https`, so a redirect can never downgrade a secure request.
pub fn check_redirect(from: Option<&str>, to: &str, allow_http: bool) -> Result<(), String> {
    match to {
        "https" => Ok(()),
        "http" if from == Some("https") => Err("refusing a redirect from https to http".to_owned()),
        "http" if allow_http => Ok(()),
        "http" => Err("refusing a redirect to http".to_owned()),
        other => Err(format!("refusing a redirect to a `{other}` URL")),
    }
}

/// Whether a `Content-Range` value such as `bytes 100-199/200` starts at `offset`.
fn content_range_starts_at(value: &str, offset: u64) -> bool {
    value
        .strip_prefix("bytes ")
        .and_then(|rest| rest.split_once('-'))
        .and_then(|(start, _)| start.trim().parse::<u64>().ok())
        == Some(offset)
}

fn request_error(url: &str, err: reqwest::Error) -> Error {
    // A refused redirect or a failed TLS handshake is a decision, not a hiccup; everything
    // else in transport may pass.
    let mut transient = !err.is_redirect() && !err.is_builder() && !is_tls_failure(&err);
    let mut message = err.to_string();
    let mut source = std::error::Error::source(&err);
    while let Some(cause) = source {
        message = format!("{message}: {cause}");
        source = cause.source();
    }
    // What a proxy refusing a `CONNECT` for want of credentials looks like to the caller.
    if message.contains("proxy authorization required") {
        transient = false;
        message = format!("{message}. {PROXY_AUTH_HINT}");
    }
    Error::Network {
        url: url.to_owned(),
        message,
        transient,
        source: Some(Box::new(err)),
    }
}

/// Whether a TLS error, such as an untrusted certificate, lies anywhere in `err`'s causes.
fn is_tls_failure(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut next = Some(err);
    while let Some(e) = next {
        if e.is::<rustls::Error>() {
            return true;
        }
        // `io::Error` hides the error it wraps from `source()`.
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && io.get_ref().is_some_and(|inner| is_tls_failure(inner))
        {
            return true;
        }
        next = e.source();
    }
    false
}

/// A failure while reading a response body, such as the connection dropping.
pub(crate) fn body_error(url: &str, err: std::io::Error) -> Error {
    Error::Network {
        url: url.to_owned(),
        message: format!("the transfer was interrupted: {err}"),
        transient: true,
        source: Some(Box::new(err)),
    }
}

fn install_crypto_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // Fails only when another provider is already installed, which serves as well.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod tests;
