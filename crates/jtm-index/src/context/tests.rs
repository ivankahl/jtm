use std::collections::BTreeMap;

use super::*;
use crate::testing::{Mock, client};

#[test]
fn a_missing_file_is_none_or_an_error_as_asked() {
    let mock = Mock::start();
    mock.status("/gone", 404);
    let ctx = mock.context();
    assert_eq!(
        ctx.get_optional("s", &mock.url("/gone"), 1024).unwrap(),
        None
    );
    let err = ctx.get("s", &mock.url("/gone"), 1024).unwrap_err();
    assert!(matches!(err, Error::Missing { .. }), "{err:?}");
    assert_eq!(err.code().as_str(), "E_NETWORK");
}

#[test]
fn server_errors_name_the_source() {
    let mock = Mock::start();
    mock.status("/boom", 500);
    let err = mock
        .context()
        .get("vendor-api", &mock.url("/boom"), 1024)
        .unwrap_err();
    assert!(err.to_string().contains("vendor-api"), "{err}");
    assert_eq!(err.code().as_str(), "E_NETWORK");
}

#[test]
fn oversized_bodies_are_refused() {
    let mock = Mock::start();
    mock.serve("/big", vec![b'x'; 100]);
    let err = mock.context().get("s", &mock.url("/big"), 10).unwrap_err();
    assert_eq!(err.code().as_str(), "E_SIZE_EXCEEDED");
}

#[test]
fn http_is_refused_unless_the_client_allows_it() {
    let mock = Mock::start();
    mock.serve("/a", "x");
    let strict = jtm_fetch::Client::new(jtm_fetch::ClientOptions::new("0.0.0-test")).unwrap();
    let err = Context::new(strict)
        .get("s", &mock.url("/a"), 10)
        .unwrap_err();
    assert_eq!(err.code().as_str(), "E_USAGE");
}

#[test]
fn mirrors_change_where_bytes_come_from() {
    let mock = Mock::start();
    mock.serve("/mirror/a.txt", "from the mirror");
    let mirrors = BTreeMap::from([("https://upstream.example/".to_owned(), mock.url("/mirror/"))]);
    let ctx = Context::new(client()).with_mirrors(mirrors);
    let body = ctx
        .get("s", "https://upstream.example/a.txt", 1024)
        .unwrap();
    assert_eq!(body, b"from the mirror");
}

#[test]
fn a_mirror_to_a_local_directory_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "local bytes").unwrap();
    let mirrors = BTreeMap::from([(
        "https://upstream.example/".to_owned(),
        format!("{}/", dir.path().display()),
    )]);
    let err = Context::new(client())
        .with_mirrors(mirrors)
        .get("s", "https://upstream.example/a.txt", 1024)
        .unwrap_err();
    assert_eq!(err.code().as_str(), "E_USAGE", "{err}");
    assert!(err.to_string().contains("network only"), "{err}");
}

#[test]
fn the_github_token_goes_to_the_github_api_only() {
    let mock = Mock::start();
    mock.serve("/api.github.com/repos/o/r/releases", "[]");
    mock.serve("/github.com/o/r/download", "bytes");
    mock.serve("/api.attacker.example/repos/o/r/releases", "[]");
    let mirrors = BTreeMap::from([
        (
            "https://api.github.com/".to_owned(),
            mock.url("/api.github.com/"),
        ),
        ("https://github.com/".to_owned(), mock.url("/github.com/")),
        (
            "https://api.attacker.example/".to_owned(),
            mock.url("/api.attacker.example/"),
        ),
    ]);
    let ctx = Context::new(client())
        .with_mirrors(mirrors)
        .with_github_token(Some("tok".to_owned()));
    ctx.get_github_api("s", "https://api.github.com/repos/o/r/releases", 1024)
        .unwrap();
    ctx.get("s", "https://github.com/o/r/download", 1024)
        .unwrap();
    // A sources.toml can name any api_url; the token must not follow it.
    ctx.get_github_api("s", "https://api.attacker.example/repos/o/r/releases", 1024)
        .unwrap();
    let requests = mock.requests();
    let bearer = |i: usize| {
        requests[i]
            .headers
            .get("authorization")
            .map(|v| v.to_str().unwrap().to_owned())
    };
    assert_eq!(bearer(0).as_deref(), Some("Bearer tok"));
    assert_eq!(bearer(1), None);
    assert_eq!(bearer(2), None);
}

#[test]
fn an_empty_token_is_no_token() {
    let mock = Mock::start();
    mock.serve("/api", "{}");
    let ctx = Context::new(client()).with_github_token(Some(String::new()));
    ctx.get_github_api("s", &mock.url("/api"), 1024).unwrap();
    assert!(mock.requests()[0].headers.get("authorization").is_none());
}

#[test]
fn the_token_stays_out_of_debug_output() {
    let ctx = Context::new(client()).with_github_token(Some("hunter2".to_owned()));
    let shown = format!("{ctx:?}");
    assert!(!shown.contains("hunter2"), "{shown}");
}

#[test]
fn json_errors_name_the_offending_field() {
    #[derive(Debug, serde::Deserialize)]
    #[allow(dead_code)]
    struct Shape {
        items: Vec<u32>,
    }
    let err = parse_json::<Shape>("s", "https://x.test/a", br#"{"items":["a"]}"#).unwrap_err();
    assert!(err.to_string().contains("items"), "{err}");
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
}
