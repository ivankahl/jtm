//! Which proxy each request uses (SPEC.md section 13).
//!
//! The order, first match wins:
//!
//! 1. `network.proxy`, which replaces the variables for every scheme.
//! 2. The environment: `HTTPS_PROXY` for `https` URLs and `HTTP_PROXY` for `http` ones, each
//!    falling back to `ALL_PROXY`. The upper-case name beats the lower-case one.
//! 3. When no proxy variable is set at all, the Windows system proxy ([`wininet`]).
//!
//! `NO_PROXY` applies to whichever proxy was chosen; on Windows the system bypass list stands
//! in when the variable is unset. An unusable proxy is an error, never a silent direct
//! connection. Credentials in a proxy URL are sent to the proxy as `Proxy-Authorization:
//! Basic` and are redacted everywhere jtm prints a proxy: [`redact_url`], [`ProxyReport`] and
//! the `Debug` output of every type here.

// SPEC-QUESTION: section 13 names `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` only. `ALL_PROXY`
// is honoured too, as curl and most tools do, and an upper-case name beats a lower-case one.
// SPEC-QUESTION: section 14 lists `network.proxy` but no `network.no_proxy`, so no such key was
// added; `NO_PROXY` still applies to a configured proxy. Adding a key needs a spec change.
// SPEC-QUESTION: `socks5` and `socks5h` proxies are accepted, since `network.proxy` validation
// in jtm-core already allows those schemes; section 13 does not mention SOCKS.

use std::fmt;

use reqwest::blocking::ClientBuilder;
use reqwest::{NoProxy, Proxy, Url};

use crate::error::{Error, Result};

pub mod wininet;

/// Where a proxy setting came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxySource {
    /// The `network.proxy` setting, whichever layer set it.
    Config,
    /// An environment variable, by name.
    Environment(String),
    /// The Windows system proxy settings.
    WindowsSystem,
}

impl ProxySource {
    /// A phrase for messages, such as "the environment variable HTTPS_PROXY".
    pub fn describe(&self) -> String {
        match self {
            ProxySource::Config => "the `network.proxy` setting".to_owned(),
            ProxySource::Environment(name) => format!("the environment variable {name}"),
            ProxySource::WindowsSystem => "the Windows proxy settings".to_owned(),
        }
    }

    /// What error messages call the setting, without its value.
    fn origin(&self) -> String {
        match self {
            ProxySource::Config => "network.proxy".to_owned(),
            ProxySource::Environment(name) => name.clone(),
            ProxySource::WindowsSystem => "the Windows proxy settings".to_owned(),
        }
    }
}

/// A validated proxy URL. The URL may hold credentials, so it is never printed.
#[derive(Clone, PartialEq, Eq)]
struct Route {
    url: String,
    source: ProxySource,
}

impl fmt::Debug for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Route")
            .field("url", &redact_proxy_url(&self.url))
            .field("source", &self.source)
            .finish()
    }
}

/// The proxies chosen for `http` and `https` URLs, and the hosts that bypass them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyConfig {
    http: Option<Route>,
    https: Option<Route>,
    no_proxy: Option<String>,
    notes: Vec<String>,
}

/// The proxy used for one scheme, with credentials redacted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRoute {
    pub url: String,
    pub source: ProxySource,
}

/// The effective proxy configuration for `jtm doctor`. Safe to print: credentials are redacted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyReport {
    /// The proxy for `http` URLs, or `None` for a direct connection.
    pub http: Option<ProxyRoute>,
    /// The proxy for `https` URLs, or `None` for a direct connection.
    pub https: Option<ProxyRoute>,
    /// The hosts that bypass the proxy, in `NO_PROXY` syntax.
    pub no_proxy: Option<String>,
    /// Settings found but not honoured, such as a PAC file.
    pub notes: Vec<String>,
}

impl ProxyConfig {
    /// No proxy: every request connects directly.
    pub fn none() -> ProxyConfig {
        ProxyConfig::default()
    }

    /// The configuration for this process: `explicit` is `network.proxy`, then the real
    /// environment, then the Windows system proxy.
    pub fn detect(explicit: Option<&str>) -> Result<ProxyConfig> {
        // A value that is not valid Unicode is passed on lossily, so it fails validation as a
        // proxy URL instead of reading as unset, which would connect directly.
        ProxyConfig::resolve(
            explicit,
            &|name| std::env::var_os(name).map(|v| v.to_string_lossy().into_owned()),
            &wininet::read,
        )
    }

    /// [`ProxyConfig::detect`] with the environment and the Windows settings passed in.
    pub fn resolve(
        explicit: Option<&str>,
        env: &dyn Fn(&str) -> Option<String>,
        system: &dyn Fn() -> Option<wininet::WinInetSettings>,
    ) -> Result<ProxyConfig> {
        let env_no_proxy = first_set(env, &["NO_PROXY", "no_proxy"]).map(|(_, value)| value);
        if let Some(explicit) = explicit.map(str::trim).filter(|e| !e.is_empty()) {
            let route = Route::new(explicit, ProxySource::Config)?;
            return Ok(ProxyConfig {
                http: Some(route.clone()),
                https: Some(route),
                no_proxy: env_no_proxy,
                notes: Vec::new(),
            });
        }

        let http = env_route(env, &["HTTP_PROXY", "http_proxy"])?;
        let https = env_route(env, &["HTTPS_PROXY", "https_proxy"])?;
        let all = env_route(env, &["ALL_PROXY", "all_proxy"])?;
        if http.is_some() || https.is_some() || all.is_some() {
            return Ok(ProxyConfig {
                http: http.or_else(|| all.clone()),
                https: https.or(all),
                no_proxy: env_no_proxy,
                notes: Vec::new(),
            });
        }

        let system = system().map(|settings| settings.interpret());
        let Some(system) = system else {
            return Ok(ProxyConfig {
                no_proxy: env_no_proxy,
                ..ProxyConfig::default()
            });
        };
        let route = |address: &Option<String>| {
            address
                .as_deref()
                .map(|address| Route::new(address, ProxySource::WindowsSystem))
                .transpose()
        };
        Ok(ProxyConfig {
            http: route(&system.http)?,
            https: route(&system.https)?,
            no_proxy: env_no_proxy.or(system.bypass),
            notes: system.notes,
        })
    }

    /// What `jtm doctor` shows: the proxy for each scheme and where it came from, with
    /// credentials redacted.
    pub fn report(&self) -> ProxyReport {
        let show = |route: &Option<Route>| {
            route.as_ref().map(|route| ProxyRoute {
                url: redact_proxy_url(&route.url),
                source: route.source.clone(),
            })
        };
        ProxyReport {
            http: show(&self.http),
            https: show(&self.https),
            no_proxy: self.no_proxy.clone(),
            notes: self.notes.clone(),
        }
    }

    /// Makes `builder` use exactly this configuration. The HTTP library's own proxy detection
    /// is switched off, so nothing is read that [`ProxyReport`] cannot show.
    pub(crate) fn apply(&self, builder: ClientBuilder) -> Result<ClientBuilder> {
        let no_proxy = self.no_proxy.as_deref().and_then(NoProxy::from_string);
        let mut builder = builder.no_proxy();
        if let Some(route) = &self.http {
            builder = builder.proxy(route.proxy(|url| Proxy::http(url), no_proxy.clone())?);
        }
        if let Some(route) = &self.https {
            builder = builder.proxy(route.proxy(|url| Proxy::https(url), no_proxy)?);
        }
        Ok(builder)
    }
}

impl Route {
    /// Checks `raw`, naming `source` if it is unusable.
    fn new(raw: &str, source: ProxySource) -> Result<Route> {
        let bad = |message: String| Error::Proxy {
            origin: source.origin(),
            message,
        };
        let raw = raw.trim();
        // Proxy variables are often written without a scheme, as `proxy.corp:3128`.
        let with_scheme = if raw.contains("://") {
            raw.to_owned()
        } else {
            format!("http://{raw}")
        };
        // The parser's messages describe the problem without quoting the input.
        let url = Url::parse(&with_scheme).map_err(|e| bad(format!("not a valid URL ({e})")))?;
        match url.scheme() {
            "http" | "https" | "socks5" | "socks5h" => {}
            other => {
                return Err(bad(format!(
                    "the scheme `{other}` is not supported; use http, https, socks5 or socks5h"
                )));
            }
        }
        if url.host_str().is_none_or(str::is_empty) {
            return Err(bad("the URL has no host".to_owned()));
        }
        Ok(Route {
            url: url.to_string(),
            source,
        })
    }

    fn proxy(
        &self,
        for_scheme: impl FnOnce(&str) -> reqwest::Result<Proxy>,
        no_proxy: Option<NoProxy>,
    ) -> Result<Proxy> {
        // The error is dropped: it can quote the URL, which may hold credentials.
        let proxy = for_scheme(&self.url).map_err(|_| Error::Proxy {
            origin: self.source.origin(),
            message: "the HTTP library cannot use this proxy".to_owned(),
        })?;
        Ok(proxy.no_proxy(no_proxy))
    }
}

/// The first of `names` that is set to something other than whitespace.
fn first_set(env: &dyn Fn(&str) -> Option<String>, names: &[&str]) -> Option<(String, String)> {
    names.iter().find_map(|name| {
        env(name)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .map(|value| ((*name).to_owned(), value))
    })
}

fn env_route(env: &dyn Fn(&str) -> Option<String>, names: &[&str]) -> Result<Option<Route>> {
    first_set(env, names)
        .map(|(name, value)| Route::new(&value, ProxySource::Environment(name)))
        .transpose()
}

/// Hides the credentials in a URL, as in `http://user:pass@proxy:8080`, so that errors, logs
/// and `jtm doctor` never show them.
pub fn redact_url(url: &str) -> String {
    let (scheme, rest) = match url.find("://") {
        Some(at) => url.split_at(at + 3),
        None => ("", url),
    };
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    match authority.rfind('@') {
        Some(at) => format!("{scheme}***@{}", &rest[at + 1..]),
        None => url.to_owned(),
    }
}

/// Like [`redact_url`], for a proxy URL, which has no path: everything before the last `@` is
/// credentials, even when an unescaped password holds `/`, `?` or `#`.
pub fn redact_proxy_url(url: &str) -> String {
    let (scheme, rest) = match url.find("://") {
        Some(at) => url.split_at(at + 3),
        None => ("", url),
    };
    match rest.rfind('@') {
        Some(at) => format!("{scheme}***@{}", &rest[at + 1..]),
        None => url.to_owned(),
    }
}

#[cfg(test)]
mod tests;
