//! `network.extra_ca_file` and TLS inspection: a proxy that ends TLS with its own CA, servers
//! whose certificates the client must or must not trust, and the redirect rule over a
//! connection that really is TLS. Every server is local and every CA is made by the test.

#![allow(clippy::unwrap_used)]

mod common;

use common::tls::{intercepting_proxy, tls_server, tls_server_redirecting_to};
use common::{Mock, options};
use jtm_fetch::{ClientOptions, Error};
use std::sync::atomic::Ordering;

use common::proxy::client_with_proxy;

fn with_ca(ca_file: &std::path::Path) -> ClientOptions {
    ClientOptions {
        extra_ca_file: Some(ca_file.to_owned()),
        ..options(false)
    }
}

/// The failure text and debug form, which together must not hide the cause.
fn describe(err: &Error) -> String {
    format!("{err} / {err:?}").to_ascii_lowercase()
}

#[test]
fn a_tls_inspecting_proxy_works_once_its_ca_is_in_extra_ca_file() {
    let proxy = intercepting_proxy();
    let client = client_with_proxy(with_ca(&proxy.ca_file), Some(&proxy.url()), &[]);
    let body = client
        .get_bytes("https://downloads.corp.example/jdk/index.json", 1024)
        .unwrap();
    assert_eq!(body.as_deref(), Some(&b"intercepted"[..]));
    let seen = proxy.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, "downloads.corp.example:443");
    assert_eq!(
        seen[0].request.as_deref(),
        Some("GET /jdk/index.json HTTP/1.1")
    );
}

#[test]
fn a_tls_inspecting_proxy_fails_without_its_ca_and_is_not_retried() {
    let proxy = intercepting_proxy();
    let client = client_with_proxy(options(false), Some(&proxy.url()), &[]);
    let err = client
        .get_bytes("https://downloads.corp.example/jdk/index.json", 1024)
        .unwrap_err();
    assert!(matches!(err, Error::Network { .. }), "{err:?}");
    assert!(!err.is_transient(), "{err:?}");
    assert!(describe(&err).contains("certificate"), "{err:?}");
    let seen = proxy.seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "an untrusted certificate is not retried");
    assert_eq!(seen[0].request, None, "no request went into the tunnel");
}

#[test]
fn the_proxy_url_does_not_stand_in_for_its_ca() {
    // Another proxy's CA, or any other bundle, does not vouch for this one.
    let proxy = intercepting_proxy();
    let other = intercepting_proxy();
    let client = client_with_proxy(with_ca(&other.ca_file), Some(&proxy.url()), &[]);
    let err = client
        .get_bytes("https://downloads.corp.example/jdk/index.json", 1024)
        .unwrap_err();
    assert!(!err.is_transient(), "{err:?}");
    assert_eq!(proxy.seen.lock().unwrap().len(), 1);
}

#[test]
fn an_untrusted_server_certificate_fails_at_once_without_a_retry() {
    let server = tls_server();
    // The CA is not in the OS store and the client was not told about it.
    let client = client_with_proxy(options(false), None, &[]);
    let err = client.get_bytes(&server.url("/file"), 1024).unwrap_err();
    assert!(matches!(err, Error::Network { .. }), "{err:?}");
    assert!(!err.is_transient(), "{err:?}");
    assert!(describe(&err).contains("certificate"), "{err:?}");
    assert_eq!(server.connections.load(Ordering::SeqCst), 1, "no retry");
    assert!(server.requests.lock().unwrap().is_empty());
}

#[test]
fn a_server_signed_by_a_different_ca_is_untrusted_even_with_an_extra_ca_file() {
    let server = tls_server();
    let other = tls_server();
    let client = client_with_proxy(with_ca(&other.ca_file), None, &[]);
    let err = client.get_bytes(&server.url("/file"), 1024).unwrap_err();
    assert!(!err.is_transient(), "{err:?}");
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert!(server.requests.lock().unwrap().is_empty());
    // The same client does trust the server whose CA it was given.
    let body = client.get_bytes(&other.url("/file"), 1024).unwrap();
    assert_eq!(body.as_deref(), Some(&b"tls-ok"[..]));
}

/// An HTTPS server that redirects to a plain-http URL, then checks the client refused it:
/// no retry, and nothing ever reached the http target.
fn assert_https_to_http_redirect_is_refused(allow_http: bool) {
    let target = Mock::start();
    let server = tls_server_redirecting_to(&target.url("/downgraded"));
    let client = client_with_proxy(
        ClientOptions {
            allow_http,
            ..with_ca(&server.ca_file)
        },
        None,
        &[],
    );
    let err = client
        .get_bytes(&server.url("/redirect-to-http"), 1024)
        .unwrap_err();
    assert!(matches!(err, Error::Network { .. }), "{err:?}");
    assert!(!err.is_transient(), "{err:?}");
    assert!(describe(&err).contains("https to http"), "{err:?}");
    assert_eq!(
        server.requests.lock().unwrap().as_slice(),
        ["GET /redirect-to-http HTTP/1.1"],
        "the redirect was asked for once and not retried"
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert!(
        target.requests().is_empty(),
        "a request reached the http target: {:?}",
        target.requests()
    );
}

#[test]
fn a_redirect_from_https_to_http_is_refused_end_to_end() {
    assert_https_to_http_redirect_is_refused(false);
}

#[test]
fn a_redirect_from_https_to_http_is_refused_even_when_http_mirrors_are_allowed() {
    assert_https_to_http_redirect_is_refused(true);
}

#[test]
fn a_ca_file_with_no_certificates_names_the_setting_and_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let key_only =
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n";
    for (name, content) in [
        ("empty.pem", ""),
        ("text.pem", "not a certificate"),
        ("key.pem", key_only),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, content).unwrap();
        let err = jtm_fetch::Client::new(with_ca(&path)).unwrap_err();
        assert!(matches!(err, Error::CaFile { .. }), "{name}: {err:?}");
        let text = err.to_string();
        assert!(text.contains(&path.display().to_string()), "{text}");
        assert!(text.contains("network.extra_ca_file"), "{text}");
    }
}

#[test]
fn a_ca_file_with_one_broken_certificate_is_rejected_whole() {
    // A bundle that is half good must not be half trusted.
    let server = tls_server();
    let good = std::fs::read_to_string(&server.ca_file).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    let broken = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    std::fs::write(&path, format!("{good}{broken}")).unwrap();
    let err = jtm_fetch::Client::new(with_ca(&path)).unwrap_err();
    assert!(matches!(err, Error::CaFile { .. }), "{err:?}");
}

#[test]
fn a_missing_or_unreadable_ca_file_names_the_path() {
    let dir = tempfile::tempdir().unwrap();
    // A directory cannot be read as a file on any platform.
    for path in [dir.path().join("missing.pem"), dir.path().to_owned()] {
        let err = jtm_fetch::Client::new(with_ca(&path)).unwrap_err();
        assert!(matches!(err, Error::Io { .. }), "{err:?}");
        assert!(
            err.to_string().contains(&path.display().to_string()),
            "{err}"
        );
    }
}

#[test]
fn a_bundle_of_several_certificates_trusts_each() {
    let (a, b) = (tls_server(), tls_server());
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("bundle.pem");
    let pem = |s: &common::tls::TlsServer| std::fs::read_to_string(&s.ca_file).unwrap();
    std::fs::write(&bundle, format!("{}\n{}", pem(&a), pem(&b))).unwrap();
    let client = client_with_proxy(with_ca(&bundle), None, &[]);
    for server in [&a, &b] {
        let body = client.get_bytes(&server.url("/file"), 1024).unwrap();
        assert_eq!(body.as_deref(), Some(&b"tls-ok"[..]));
    }
}

#[test]
fn a_certificate_in_a_format_jtm_cannot_read_is_an_error_not_a_skipped_block() {
    // OpenSSL's `TRUSTED CERTIFICATE` and `X509 CERTIFICATE` labels are not plain PEM
    // certificates. Skipping them would trust the rest of the bundle and drop, say, the
    // proxy's own CA, which then shows up as an unexplained TLS failure.
    let server = tls_server();
    let good = std::fs::read_to_string(&server.ca_file).unwrap();
    let dir = tempfile::tempdir().unwrap();
    for label in ["TRUSTED CERTIFICATE", "X509 CERTIFICATE"] {
        let path = dir.path().join("bundle.pem");
        let odd = format!("-----BEGIN {label}-----\nAAAA\n-----END {label}-----\n");
        std::fs::write(&path, format!("{good}{odd}")).unwrap();
        let err = jtm_fetch::Client::new(with_ca(&path)).unwrap_err();
        assert!(matches!(err, Error::CaFile { .. }), "{label}: {err:?}");
        assert!(err.to_string().contains(label), "{err}");
    }
    // Keys and certificate requests are not certificates and stay ignored.
    let path = dir.path().join("mixed.pem");
    let other = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n\
                 -----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n";
    std::fs::write(&path, format!("{good}{other}")).unwrap();
    jtm_fetch::Client::new(with_ca(&path)).unwrap();
}
