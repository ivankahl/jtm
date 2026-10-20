use super::*;

#[test]
fn redirects_never_downgrade_to_http() {
    assert!(check_redirect(Some("https"), "http", false).is_err());
    assert!(check_redirect(Some("https"), "http", true).is_err());
    assert!(check_redirect(Some("https"), "https", false).is_ok());
    assert!(check_redirect(Some("http"), "https", false).is_ok());
}

#[test]
fn http_redirects_need_http_to_be_allowed() {
    assert!(check_redirect(Some("http"), "http", false).is_err());
    assert!(check_redirect(Some("http"), "http", true).is_ok());
}

#[test]
fn other_schemes_are_refused() {
    assert!(check_redirect(Some("https"), "file", true).is_err());
    assert!(check_redirect(Some("https"), "ftp", true).is_err());
    assert!(check_scheme("file:///etc/passwd", true).is_err());
    assert!(check_scheme("ftp://example.test/a", true).is_err());
}

#[test]
fn http_urls_need_http_to_be_allowed() {
    assert!(check_scheme("https://example.test/a", false).is_ok());
    assert!(check_scheme("HTTPS://example.test/a", false).is_ok());
    assert!(matches!(
        check_scheme("http://example.test/a", false),
        Err(Error::Scheme { .. })
    ));
    assert!(check_scheme("http://example.test/a", true).is_ok());
}

#[test]
fn user_agent_names_jtm_and_the_platform() {
    let ua = user_agent("1.2.3");
    assert!(ua.starts_with("jtm/1.2.3 ("), "{ua}");
    assert!(ua.contains(std::env::consts::OS), "{ua}");
}

#[test]
fn content_range_must_start_at_the_offset() {
    assert!(content_range_starts_at("bytes 100-199/200", 100));
    assert!(!content_range_starts_at("bytes 0-199/200", 100));
    assert!(!content_range_starts_at("items 100-199/200", 100));
}

#[test]
fn retry_stops_at_non_transient_failures() {
    let policy = RetryPolicy {
        retries: 3,
        backoff: Duration::ZERO,
    };
    let mut calls = 0;
    let result: Result<()> = policy.run(|_| {
        calls += 1;
        Err(Error::Status {
            url: "u".into(),
            status: 404,
        })
    });
    assert!(result.is_err());
    assert_eq!(calls, 1);
}

#[test]
fn retry_gives_up_after_the_configured_retries() {
    let policy = RetryPolicy {
        retries: 3,
        backoff: Duration::ZERO,
    };
    let mut calls = 0;
    let result: Result<()> = policy.run(|_| {
        calls += 1;
        Err(Error::Network {
            url: "u".into(),
            message: "connection reset".into(),
            transient: true,
            source: None,
        })
    });
    assert!(result.is_err());
    assert_eq!(calls, 4);
}
