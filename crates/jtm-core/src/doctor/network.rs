//! The proxy and TLS checks (SPEC.md section 13).

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use jtm_fetch::proxy::wininet;
use jtm_fetch::{Client, ProxyConfig, ProxyReport, ProxyRoute, mirrors};
use serde_json::{Value, json};

use crate::error::{ErrorCode, JtmError};
use crate::session::client_options;

use super::{Check, Finding, Inputs, Prober, W_PROXY_UNSUPPORTED, list, scrub};

/// The most hosts the connection test visits.
const MAX_HOSTS: usize = 8;

/// The environment variables that can hold a proxy URL.
const PROXY_VARIABLES: &[&str] = &[
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
];

/// The proxy check and the TLS check.
pub(super) fn checks(inputs: &Inputs<'_>) -> (Check, Check) {
    let config = ProxyConfig::resolve(
        inputs.settings.network.proxy.as_deref(),
        inputs.env,
        &wininet::read,
    );
    (proxy_check(config), tls_check(inputs))
}

/// What the proxy configuration `resolved` comes to.
pub(super) fn proxy_check(resolved: jtm_fetch::Result<ProxyConfig>) -> Check {
    const ID: &str = "proxy";
    let config = match resolved {
        Ok(config) => config,
        Err(err) => {
            // The error names the setting and never its value, which may hold a password.
            let mut check = Check::pass(ID, "the proxy settings are not usable");
            check.push(Finding::from_error(&JtmError::from(err)).hint(
                "correct the setting named above, or unset it to connect directly; \
                 `network.proxy` overrides the proxy variables",
            ));
            return check;
        }
    };
    let report = config.report();
    let mut check = Check::pass(ID, describe(&report))
        .detail("http", route(report.http.as_ref()))
        .detail("https", route(report.https.as_ref()))
        .detail("no_proxy", report.no_proxy.clone());
    for note in &report.notes {
        check.push(
            Finding::warning(W_PROXY_UNSUPPORTED, note.clone())
                .hint("set `network.proxy` to the proxy URL, which overrides the system settings"),
        );
    }
    check
}

fn route(route: Option<&ProxyRoute>) -> Value {
    route.map_or(
        Value::Null,
        |route| json!({ "url": route.url, "source": route.source.describe() }),
    )
}

fn describe(report: &ProxyReport) -> String {
    let via = |route: &ProxyRoute| format!("{} (from {})", route.url, route.source.describe());
    let mut parts = match (&report.http, &report.https) {
        (None, None) => vec!["connections are direct, with no proxy".to_owned()],
        (Some(http), Some(https)) if http == https => {
            vec![format!("all connections go through {}", via(https))]
        }
        (http, https) => vec![
            format!(
                "https goes {}",
                https
                    .as_ref()
                    .map_or("direct".to_owned(), |r| format!("through {}", via(r)))
            ),
            format!(
                "http goes {}",
                http.as_ref()
                    .map_or("direct".to_owned(), |r| format!("through {}", via(r)))
            ),
        ],
    };
    if let Some(no_proxy) = &report.no_proxy {
        parts.push(format!("these hosts bypass it: {no_proxy}"));
    }
    parts.join("; ")
}

/// The passwords and user names in the proxy URLs jtm may use, to keep out of messages.
fn secrets(inputs: &Inputs<'_>) -> Vec<String> {
    let configured = inputs.settings.network.proxy.clone();
    let variables = PROXY_VARIABLES.iter().filter_map(|name| (inputs.env)(name));
    configured
        .into_iter()
        .chain(variables)
        .flat_map(|url| {
            let rest = url.split_once("://").map_or(url.as_str(), |(_, rest)| rest);
            // As in `redact_url`, everything before the last `@` is credentials.
            let Some((userinfo, _)) = rest.rsplit_once('@') else {
                return Vec::new();
            };
            let mut found = vec![userinfo.to_owned()];
            if let Some((user, password)) = userinfo.split_once(':') {
                found.extend([user.to_owned(), password.to_owned()]);
            }
            found
        })
        .collect()
}

/// The extra CA file and, unless offline, a connection to every host the indices come from.
fn tls_check(inputs: &Inputs<'_>) -> Check {
    const ID: &str = "tls";
    let mut check = Check::pass(ID, "");
    let mut parts = Vec::new();
    match &inputs.settings.network.extra_ca_file {
        None => parts.push("the OS certificate store is used".to_owned()),
        Some(path) => match jtm_fetch::check_ca_bundle(path) {
            Ok(count) => parts.push(format!(
                "network.extra_ca_file adds {count} certificate{} from {}",
                if count == 1 { "" } else { "s" },
                path.display()
            )),
            Err(err) => check.push(bundle_finding(path, err)),
        },
    }
    if inputs.offline {
        check
            .notes
            .push("the connection test was skipped because jtm is offline".to_owned());
    } else {
        connect(inputs, &mut check, &mut parts);
    }
    if !parts.is_empty() {
        check.summary = parts.join("; ");
    }
    check
}

fn bundle_finding(path: &Path, err: jtm_fetch::Error) -> Finding {
    let hint = "fix the path, or remove `network.extra_ca_file`; it must be a PEM file with \
                the certificates to trust";
    let setting = format!("network.extra_ca_file {}", path.display());
    let finding = match err {
        jtm_fetch::Error::Io { path, source } => {
            let err = JtmError::io(&path, source);
            Finding::error(err.kind(), format!("{setting} cannot be read: {err}"))
        }
        other => Finding::from_error(&JtmError::from(other)),
    };
    finding
        .hint(hint)
        .detail("path", path.display().to_string())
}

/// Connects to each host the indices come from, to find out whether TLS and the network work.
fn connect(inputs: &Inputs<'_>, check: &mut Check, parts: &mut Vec<String>) {
    let hosts = hosts(inputs);
    if hosts.is_empty() {
        parts.push(
            "every index comes from a local source, so there is nothing to connect to".to_owned(),
        );
        return;
    }
    let owned;
    let prober: &dyn Prober = match inputs.prober {
        Some(prober) => prober,
        None => {
            let options = jtm_fetch::ClientOptions {
                connect_timeout: Duration::from_secs(5),
                read_timeout: Duration::from_secs(10),
                ..client_options(inputs.settings)
            };
            match Client::new(options) {
                Ok(client) => {
                    owned = client;
                    &owned
                }
                Err(err) => {
                    let secrets = secrets(inputs);
                    check.notes.push(scrub(
                        &format!(
                            "connectivity was not tested: the HTTP client cannot start: {err}"
                        ),
                        &secrets,
                    ));
                    return;
                }
            }
        }
    };
    let secrets = secrets(inputs);
    // The hosts are independent, so a blocked network costs one timeout, not one per host.
    let results: Vec<jtm_fetch::Result<()>> = std::thread::scope(|scope| {
        let handles: Vec<_> = hosts
            .iter()
            .map(|host| scope.spawn(|| prober.probe(host)))
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle.join().unwrap_or_else(|_| {
                    Err(jtm_fetch::Error::Network {
                        url: String::new(),
                        message: "the connection test stopped unexpectedly".to_owned(),
                        transient: false,
                        source: None,
                    })
                })
            })
            .collect()
    });
    let mut reached = Vec::new();
    for (host, result) in hosts.iter().zip(results) {
        match result {
            Ok(()) => reached.push(host_name(host).to_owned()),
            Err(err) => check.push(unreachable_host(host, err, &secrets)),
        }
    }
    if !reached.is_empty() {
        parts.push(format!("connected to {}", list(&reached)));
    }
}

fn host_name(origin: &str) -> &str {
    origin
        .split_once("://")
        .map_or(origin, |(_, rest)| rest)
        .trim_end_matches('/')
}

fn unreachable_host(origin: &str, err: jtm_fetch::Error, secrets: &[String]) -> Finding {
    let host = host_name(origin).to_owned();
    let tls = err.is_tls_failure();
    let finding = if tls {
        Finding::error(
            ErrorCode::Network,
            scrub(
                &format!(
                    "the TLS connection to {host} failed, so its certificate is not trusted: {}",
                    cause(&err)
                ),
                secrets,
            ),
        )
        .hint(
            "if a proxy or firewall inspects TLS, add its root certificate to the OS trust \
             store, or point `network.extra_ca_file` at a PEM file that holds it",
        )
    } else {
        let hint = match &err {
            jtm_fetch::Error::Scheme { .. } => {
                "use an https URL, or set `security.allow_http_mirrors = true` for an http mirror"
            }
            _ => {
                "check that the host is reachable from this machine and that `HTTPS_PROXY` or \
                 `network.proxy` is right; behind a firewall, point `[mirrors]` at an approved \
                 host and run with `--offline`"
            }
        };
        let mapped = JtmError::from(err);
        Finding::error(
            mapped.kind(),
            scrub(
                &format!("cannot connect to {host}: {}", cause_of(&mapped)),
                secrets,
            ),
        )
        .hint(hint)
    };
    finding.detail("host", origin)
}

/// Why a request failed, without the URL that is named separately.
fn cause(err: &jtm_fetch::Error) -> String {
    match err {
        jtm_fetch::Error::Network { message, .. } => message.clone(),
        other => other.to_string(),
    }
}

fn cause_of(err: &JtmError) -> String {
    match err {
        JtmError::Network { message, .. } => message.clone(),
        other => other.to_string(),
    }
}

/// `scheme://host[:port]/` of each place the indices come from, once each, mirrors applied.
/// Local sources are left out.
fn hosts(inputs: &Inputs<'_>) -> Vec<String> {
    let settings = inputs.settings;
    let mut found = BTreeSet::new();
    for name in inputs.registry.names() {
        let Ok(plugin) = inputs.registry.find(&name) else {
            continue;
        };
        let index = &plugin.manifest.index;
        // As `Session` loads indices: an `index_url` override is used as written; otherwise
        // `[mirrors]` rewrite the canonical index URL, and the keys file and each signature
        // are rewritten as URLs of their own. A rewrite to a local directory is not a host.
        let override_url = settings
            .plugins
            .get(&name)
            .and_then(|p| p.index_url.as_deref());
        let mut urls: Vec<String> = Vec::new();
        match override_url {
            Some(url) => urls.push(url.to_owned()),
            None => urls.extend(mirrored(&index.url, &settings.mirrors)),
        }
        if let Some(keys_url) = index.keys_url.as_deref() {
            urls.extend(mirrored(keys_url, &settings.mirrors));
        }
        found.extend(urls.iter().filter_map(|url| origin(url)));
    }
    found.into_iter().take(MAX_HOSTS).collect()
}

/// The network URLs `url` and its signature are fetched from once `[mirrors]` has been
/// applied. A local target is left out, and so is a rewrite `Session` would refuse, which it
/// reports when it loads the index.
fn mirrored(url: &str, mirrors: &std::collections::BTreeMap<String, String>) -> Vec<String> {
    [url.to_owned(), format!("{url}.minisig")]
        .iter()
        .filter_map(|url| match mirrors::resolve(url, mirrors) {
            Ok(mirrors::Location::Url(target)) => Some(target),
            Ok(mirrors::Location::File { .. }) | Err(_) => None,
        })
        .collect()
}

/// `scheme://host[:port]/` of a network URL, without any credentials; `None` for a local path.
fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if !matches!(scheme, "https" | "http") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    (!host.is_empty()).then(|| format!("{scheme}://{host}/"))
}
