//! The HTTP client behind proxies: forwarding, CONNECT tunnels, credentials, bypass lists and
//! SOCKS. Every proxy is a local one started by the test.

mod common;

use common::proxy::{client_with_proxy, connect_proxy, socks5_proxy, tls_server};
use common::{Mock, options};
use jtm_fetch::proxy::{ProxyConfig, ProxySource};
use jtm_fetch::{Client, ClientOptions, Error};
use wiremock::matchers::{method, path};
use wiremock::{Mock as Route, ResponseTemplate};

/// A mock server that answers every `GET` with `proxied`, to stand in for a forwarding proxy
/// or an origin.
fn answering_mock() -> Mock {
    let mock = Mock::start();
    mock.mount(
        Route::given(method("GET"))
            .and(path("/a.json"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"proxied".to_vec())),
    );
    mock
}

/// Options for talking to the TLS test server, which a throwaway CA signed.
fn tls_options(ca_file: &std::path::Path) -> ClientOptions {
    ClientOptions {
        extra_ca_file: Some(ca_file.to_owned()),
        ..options(false)
    }
}

#[test]
fn https_goes_through_a_connect_tunnel() {
    let server = tls_server();
    let (proxy, connects) = connect_proxy(None);
    let client = client_with_proxy(
        tls_options(&server.ca_file),
        Some(&format!("http://{proxy}")),
        &[],
    );
    let body = client.get_bytes(&server.url("/file"), 1024).unwrap();
    assert_eq!(body.as_deref(), Some(&b"tls-ok"[..]));
    let connects = connects.lock().unwrap();
    assert_eq!(connects.len(), 1);
    assert_eq!(
        connects[0].target,
        format!("localhost:{}", server.addr.port())
    );
    assert_eq!(connects[0].authorization, None);
}

#[test]
fn the_https_proxy_variable_carries_https_requests() {
    let server = tls_server();
    let (proxy, connects) = connect_proxy(None);
    let client = client_with_proxy(
        tls_options(&server.ca_file),
        None,
        &[("HTTPS_PROXY", &format!("http://{proxy}"))],
    );
    let body = client.get_bytes(&server.url("/file"), 1024).unwrap();
    assert_eq!(body.as_deref(), Some(&b"tls-ok"[..]));
    assert_eq!(connects.lock().unwrap().len(), 1);
}

#[test]
fn credentials_in_the_proxy_url_are_sent_to_the_tunnel() {
    let server = tls_server();
    let (proxy, connects) = connect_proxy(Some("Basic YWxpY2U6cEBzcw=="));
    // The password is percent-encoded in the URL: `p@ss`.
    let client = client_with_proxy(
        tls_options(&server.ca_file),
        Some(&format!("http://alice:p%40ss@{proxy}")),
        &[],
    );
    let body = client.get_bytes(&server.url("/file"), 1024).unwrap();
    assert_eq!(body.as_deref(), Some(&b"tls-ok"[..]));
    assert_eq!(
        connects.lock().unwrap()[0].authorization.as_deref(),
        Some("Basic YWxpY2U6cEBzcw==")
    );
}

#[test]
fn a_proxy_that_rejects_the_credentials_fails_without_echoing_them() {
    let server = tls_server();
    let (proxy, connects) = connect_proxy(Some("Basic YWxpY2U6d3Jvbmc="));
    let client = client_with_proxy(
        tls_options(&server.ca_file),
        Some(&format!("http://alice:s3cret@{proxy}")),
        &[],
    );
    let err = client.get_bytes(&server.url("/file"), 1024).unwrap_err();
    assert!(matches!(err, Error::Network { .. }), "{err:?}");
    assert!(!err.is_transient(), "retrying cannot fix credentials");
    let text = format!("{err} {err:?}");
    assert!(text.contains("proxy"), "{text}");
    assert!(text.contains("network.proxy"), "{text}");
    assert!(!text.contains("s3cret"), "{text}");
    assert_eq!(connects.lock().unwrap().len(), 1, "no retries");
}

#[test]
fn http_requests_are_forwarded_with_credentials() {
    let proxy = answering_mock();
    let client = client_with_proxy(
        options(true),
        Some(&format!("http://alice:p%40ss@{}", proxy.server.address())),
        &[],
    );
    let body = client
        .get_bytes("http://jtm-proxy-test.invalid/a.json", 1024)
        .unwrap();
    assert_eq!(body.as_deref(), Some(&b"proxied"[..]));
    let requests = proxy.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].headers.get("proxy-authorization").unwrap(),
        "Basic YWxpY2U6cEBzcw=="
    );
}

#[test]
fn a_forwarding_proxy_asking_for_credentials_gets_a_hint_and_no_retries() {
    let proxy = Mock::start();
    proxy.mount(Route::given(method("GET")).respond_with(ResponseTemplate::new(407)));
    let client = client_with_proxy(options(true), Some(&proxy.server.uri()), &[]);
    let err = client
        .get_bytes("http://jtm-proxy-test.invalid/a.json", 1024)
        .unwrap_err();
    assert!(matches!(err, Error::Network { .. }), "{err:?}");
    assert!(!err.is_transient());
    assert!(err.to_string().contains("network.proxy"), "{err}");
    assert_eq!(proxy.requests().len(), 1);
}

#[test]
fn the_http_proxy_variable_carries_http_requests() {
    let proxy = answering_mock();
    let client = client_with_proxy(options(true), None, &[("http_proxy", &proxy.server.uri())]);
    let body = client
        .get_bytes("http://jtm-proxy-test.invalid/a.json", 1024)
        .unwrap();
    assert_eq!(body.as_deref(), Some(&b"proxied"[..]));
    assert_eq!(proxy.requests().len(), 1);
}

#[test]
fn the_config_proxy_beats_the_variables() {
    let config_proxy = answering_mock();
    let env_proxy = answering_mock();
    let client = client_with_proxy(
        options(true),
        Some(&config_proxy.server.uri()),
        &[("HTTP_PROXY", &env_proxy.server.uri())],
    );
    client
        .get_bytes("http://jtm-proxy-test.invalid/a.json", 1024)
        .unwrap();
    assert_eq!(config_proxy.requests().len(), 1);
    assert_eq!(env_proxy.requests().len(), 0);
}

#[test]
fn no_proxy_hosts_connect_directly() {
    // The proxy is a closed port, so a request that used it would fail.
    let origin = answering_mock();
    let client = client_with_proxy(
        options(true),
        Some("http://127.0.0.1:9"),
        &[("NO_PROXY", "127.0.0.1")],
    );
    let url = origin.url("/a.json");
    let body = client.get_bytes(&url, 1024).unwrap();
    assert_eq!(body.as_deref(), Some(&b"proxied"[..]));

    // Without the bypass the same request goes to the closed proxy and fails.
    let proxied = client_with_proxy(options(true), Some("http://127.0.0.1:9"), &[]);
    assert!(proxied.get_bytes(&url, 1024).is_err());
}

#[test]
fn no_proxy_also_covers_domains_and_ranges() {
    let origin = answering_mock();
    let url = origin.url("/a.json");
    for list in ["10.0.0.0/8,127.0.0.0/8", "other.test, 127.0.0.1"] {
        let client = client_with_proxy(
            options(true),
            Some("http://127.0.0.1:9"),
            &[("no_proxy", list)],
        );
        assert!(client.get_bytes(&url, 1024).unwrap().is_some(), "{list}");
    }
}

#[test]
fn a_redirect_from_https_to_http_is_still_refused_through_a_proxy() {
    let server = tls_server();
    let (proxy, connects) = connect_proxy(None);
    // `allow_http` is on, as for an `http` mirror; the downgrade is refused regardless.
    let client = client_with_proxy(
        ClientOptions {
            allow_http: true,
            ..tls_options(&server.ca_file)
        },
        Some(&format!("http://{proxy}")),
        &[],
    );
    let err = client
        .get_bytes(&server.url("/redirect-to-http"), 1024)
        .unwrap_err();
    assert!(err.to_string().contains("https to http"), "{err} / {err:?}");
    assert!(!err.is_transient());
    assert_eq!(connects.lock().unwrap().len(), 1);
}

#[test]
fn an_unreachable_proxy_is_a_network_error_that_does_not_echo_credentials() {
    let client = client_with_proxy(options(true), Some("http://alice:s3cret@127.0.0.1:9"), &[]);
    let err = client
        .get_bytes("http://jtm-proxy-test.invalid/a.json", 1024)
        .unwrap_err();
    assert!(matches!(err, Error::Network { .. }), "{err:?}");
    let text = format!("{err} {err:?}");
    assert!(!text.contains("s3cret"), "{text}");
    assert!(!text.contains("alice"), "{text}");
}

#[test]
fn credentials_stay_out_of_debug_output() {
    let proxies =
        ProxyConfig::resolve(Some("http://alice:s3cret@127.0.0.1:9"), &|_| None, &|| None).unwrap();
    let options = ClientOptions {
        proxy: Some("http://alice:s3cret@127.0.0.1:9".to_owned()),
        ..options(true)
    };
    let client = Client::with_proxies(options.clone(), proxies).unwrap();
    for text in [
        format!("{client:?}"),
        format!("{options:?}"),
        format!("{:?}", client.proxy_report()),
    ] {
        assert!(!text.contains("s3cret"), "{text}");
        assert!(!text.contains("alice"), "{text}");
    }
}

#[test]
fn the_client_reports_the_proxy_it_uses() {
    let client = client_with_proxy(
        options(true),
        None,
        &[("HTTPS_PROXY", "http://alice:s3cret@proxy.corp:8080")],
    );
    let report = client.proxy_report();
    let https = report.https.unwrap();
    assert_eq!(https.url, "http://***@proxy.corp:8080/");
    assert_eq!(
        https.source,
        ProxySource::Environment("HTTPS_PROXY".to_owned())
    );
    assert_eq!(report.http, None);
}

#[test]
fn an_invalid_proxy_stops_the_client_from_starting() {
    let err = Client::new(ClientOptions {
        proxy: Some("ftp://alice:s3cret@proxy.corp".to_owned()),
        ..options(false)
    })
    .unwrap_err();
    assert!(matches!(err, Error::Proxy { .. }), "{err:?}");
    assert!(!format!("{err} {err:?}").contains("s3cret"));
}

#[test]
fn socks5h_proxies_resolve_names_remotely() {
    let origin = answering_mock();
    let (proxy, names) = socks5_proxy(*origin.server.address());
    let client = client_with_proxy(options(true), Some(&format!("socks5h://{proxy}")), &[]);
    let body = client
        .get_bytes("http://jtm-socks-test.invalid/a.json", 1024)
        .unwrap();
    assert_eq!(body.as_deref(), Some(&b"proxied"[..]));
    assert_eq!(names.lock().unwrap().as_slice(), ["jtm-socks-test.invalid"]);
}
