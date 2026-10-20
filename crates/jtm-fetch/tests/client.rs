//! The HTTP client against local servers: redirects, retries and limits.

mod common;

use std::sync::atomic::Ordering;

use common::{Mock, client, flaky_server, options};
use jtm_fetch::{Client, Error, MAX_REDIRECTS};
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
fn server_errors_are_retried_three_times() {
    let mock = Mock::start();
    mock.mount(Route::given(method("GET")).respond_with(ResponseTemplate::new(503)));
    let err = client().get_bytes(&mock.url("/busy"), 1024).unwrap_err();
    assert!(matches!(err, Error::Status { status: 503, .. }), "{err:?}");
    assert_eq!(mock.requests().len(), 4);
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
