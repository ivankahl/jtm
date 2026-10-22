//! The HTTP client against local servers: redirects, retries and limits.

mod common;

use std::sync::atomic::Ordering;

use common::{Mock, client, flaky_server, options};
use jtm_fetch::{Client, ClientOptions, Error, MAX_REDIRECTS};
use wiremock::matchers::{header_exists, method, path};
use wiremock::{Mock as Route, ResponseTemplate};

#[test]
fn fetches_a_body() {
    let mock = Mock::start();
    mock.mount(
        Route::given(method("GET"))
            .and(path("/a.json"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello".to_vec())),
    );
    let body = client().get_bytes(&mock.url("/a.json"), 1024).unwrap();
    assert_eq!(body.as_deref(), Some(&b"hello"[..]));
}

#[test]
fn sends_the_jtm_user_agent() {
    let mock = Mock::start();
    mock.mount(
        Route::given(method("GET"))
            .and(header_exists("user-agent"))
            .respond_with(ResponseTemplate::new(200)),
    );
    client().get_bytes(&mock.url("/a"), 1024).unwrap();
    let requests = mock.requests();
    let ua = requests[0]
        .headers
        .get("user-agent")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ua.starts_with("jtm/0.0.0-test ("), "{ua}");
}

#[test]
fn not_found_is_none_and_not_retried() {
    let mock = Mock::start();
    mock.mount(Route::given(method("GET")).respond_with(ResponseTemplate::new(404)));
    assert_eq!(
        client().get_bytes(&mock.url("/missing"), 1024).unwrap(),
        None
    );
    assert_eq!(mock.requests().len(), 1);
}

#[test]
fn client_errors_are_not_retried() {
    let mock = Mock::start();
    mock.mount(Route::given(method("GET")).respond_with(ResponseTemplate::new(403)));
    let err = client().get_bytes(&mock.url("/denied"), 1024).unwrap_err();
    assert!(matches!(err, Error::Status { status: 403, .. }), "{err:?}");
    assert_eq!(mock.requests().len(), 1);
}

#[test]
fn server_errors_are_not_retried() {
    // Only network errors are retried; an HTTP status is an answer, not a network error.
    let mock = Mock::start();
    mock.mount(Route::given(method("GET")).respond_with(ResponseTemplate::new(503)));
    let err = client().get_bytes(&mock.url("/busy"), 1024).unwrap_err();
    assert!(matches!(err, Error::Status { status: 503, .. }), "{err:?}");
    assert!(!err.is_transient());
    assert_eq!(mock.requests().len(), 1);
}

#[test]
fn tls_failures_are_not_retried() {
    // A server that does not speak TLS fails the handshake; retrying cannot fix that.
    let (url, count) = flaky_server(0, b"hello");
    let url = url.replace("http://", "https://");
    let err = client().get_bytes(&url, 1024).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Network {
                transient: false,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn dropped_connections_are_retried() {
    let (url, count) = flaky_server(2, b"hello");
    let body = client().get_bytes(&url, 1024).unwrap();
    assert_eq!(body.as_deref(), Some(&b"hello"[..]));
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

#[test]
fn network_errors_give_up_after_three_retries() {
    let (url, count) = flaky_server(usize::MAX, b"");
    let err = client().get_bytes(&url, 1024).unwrap_err();
    assert!(matches!(err, Error::Network { .. }), "{err:?}");
    assert!(err.is_transient());
    assert_eq!(count.load(Ordering::SeqCst), 4);
}

#[test]
fn oversize_bodies_are_refused() {
    let mock = Mock::start();
    mock.mount(
        Route::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 100])),
    );
    let err = client().get_bytes(&mock.url("/big"), 99).unwrap_err();
    assert!(matches!(err, Error::TooLarge { limit: 99, .. }), "{err:?}");
    assert_eq!(mock.requests().len(), 1);
}

#[test]
fn http_is_refused_unless_allowed() {
    let mock = Mock::start();
    mock.mount(Route::given(method("GET")).respond_with(ResponseTemplate::new(200)));
    let strict = Client::new(options(false)).unwrap();
    let err = strict.get_bytes(&mock.url("/a"), 1024).unwrap_err();
    assert!(matches!(err, Error::Scheme { .. }), "{err:?}");
    assert!(!err.is_transient());
    assert!(mock.requests().is_empty());
}

/// Mounts a chain `/r0 -> /r1 -> ... -> /r<hops>` that ends in a 200.
fn redirect_chain(mock: &Mock, hops: usize) {
    for i in 0..hops {
        mock.mount(
            Route::given(method("GET"))
                .and(path(format!("/r{i}")))
                .respond_with(
                    ResponseTemplate::new(302).insert_header("location", format!("/r{}", i + 1)),
                ),
        );
    }
    mock.mount(
        Route::given(method("GET"))
            .and(path(format!("/r{hops}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"end".to_vec())),
    );
}

#[test]
fn follows_up_to_ten_redirects() {
    let mock = Mock::start();
    redirect_chain(&mock, MAX_REDIRECTS);
    let body = client().get_bytes(&mock.url("/r0"), 1024).unwrap();
    assert_eq!(body.as_deref(), Some(&b"end"[..]));
}

#[test]
fn refuses_an_eleventh_redirect_without_retrying() {
    let mock = Mock::start();
    redirect_chain(&mock, MAX_REDIRECTS + 1);
    let err = client().get_bytes(&mock.url("/r0"), 1024).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Network {
                transient: false,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(mock.requests().len(), MAX_REDIRECTS + 1);
}

#[test]
fn refuses_a_redirect_to_another_scheme() {
    let mock = Mock::start();
    mock.mount(Route::given(method("GET")).respond_with(
        ResponseTemplate::new(302).insert_header("location", "ftp://example.test/a"),
    ));
    let err = client().get_bytes(&mock.url("/a"), 1024).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Network {
                transient: false,
                ..
            }
        ),
        "{err:?}"
    );
    assert_eq!(mock.requests().len(), 1);
}

#[test]
fn an_explicit_proxy_carries_every_request() {
    // The proxy is a mock server; the requested host does not exist, so only a request sent
    // through the proxy can be answered.
    let proxy = Mock::start();
    proxy.mount(
        Route::given(method("GET"))
            .and(path("/a.json"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"proxied".to_vec())),
    );
    let client = Client::new(ClientOptions {
        proxy: Some(proxy.server.uri()),
        ..options(true)
    })
    .unwrap();
    let body = client
        .get_bytes("http://jtm-proxy-test.invalid/a.json", 1024)
        .unwrap();
    assert_eq!(body.as_deref(), Some(&b"proxied"[..]));
    let requests = proxy.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].headers.get("host").unwrap(),
        "jtm-proxy-test.invalid"
    );
}

#[test]
fn an_invalid_proxy_is_refused() {
    let err = Client::new(ClientOptions {
        proxy: Some("http://user:s3cret@[bad".to_owned()),
        ..options(false)
    })
    .unwrap_err();
    assert!(!err.to_string().contains("s3cret"), "{err}");
}

#[test]
fn an_extra_ca_file_is_loaded() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/extra-ca.pem");
    Client::new(ClientOptions {
        extra_ca_file: Some(fixture),
        ..options(false)
    })
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.pem");
    let err = Client::new(ClientOptions {
        extra_ca_file: Some(missing),
        ..options(false)
    })
    .unwrap_err();
    assert!(matches!(err, Error::Io { .. }), "{err:?}");

    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, b"not a certificate").unwrap();
    let err = Client::new(ClientOptions {
        extra_ca_file: Some(empty),
        ..options(false)
    })
    .unwrap_err();
    assert!(matches!(err, Error::Io { .. }), "{err:?}");
}

#[test]
fn bearer_token_is_sent_when_asked_and_never_otherwise() {
    let mock = Mock::start();
    mock.mount(Route::given(method("GET")).respond_with(ResponseTemplate::new(200)));
    let client = client();
    client
        .get_bytes_with_bearer(&mock.url("/api"), 1024, "s3cret")
        .unwrap();
    client.get_bytes(&mock.url("/plain"), 1024).unwrap();
    let requests = mock.requests();
    let auth = |i: usize| {
        requests[i]
            .headers
            .get("authorization")
            .map(|v| v.to_str().unwrap().to_owned())
    };
    assert_eq!(auth(0).as_deref(), Some("Bearer s3cret"));
    assert_eq!(auth(1), None);
}

#[test]
fn bearer_token_is_not_forwarded_to_another_origin_on_redirect() {
    let target = Mock::start();
    target.mount(Route::given(method("GET")).respond_with(ResponseTemplate::new(200)));
    let origin = Mock::start();
    // A different port is a different origin, so the token must not follow the redirect.
    origin.mount(Route::given(method("GET")).respond_with(
        ResponseTemplate::new(302).insert_header("location", target.url("/asset").as_str()),
    ));
    client()
        .get_bytes_with_bearer(&origin.url("/api"), 1024, "s3cret")
        .unwrap();
    assert_eq!(origin.requests().len(), 1);
    let forwarded = target.requests();
    assert_eq!(forwarded.len(), 1);
    assert!(forwarded[0].headers.get("authorization").is_none());
}
