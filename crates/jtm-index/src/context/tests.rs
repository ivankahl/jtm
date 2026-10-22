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

#[test]
fn a_download_is_hashed_and_kept_for_a_second_look() {
    use std::io::Read;
    let mock = Mock::start();
    mock.serve("/a.zip", b"abc".to_vec());
    let (file, computed) = mock
        .context()
        .download("s", &mock.url("/a.zip"), 1024, true)
        .unwrap();
    let mut file = file.expect("the bytes were asked for");
    assert_eq!(computed.size, 3);
    // The SHA-256 of "abc", from FIPS 180.
    assert_eq!(
        computed.sha256(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let mut kept = Vec::new();
    file.read_to_end(&mut kept).unwrap();
    assert_eq!(kept, b"abc");
}

#[test]
fn a_download_nobody_will_read_again_is_hashed_without_touching_the_disk() {
    let mock = Mock::start();
    mock.serve("/a.zip", b"abc".to_vec());
    let (file, computed) = mock
        .context()
        .download("s", &mock.url("/a.zip"), 1024, false)
        .unwrap();
    assert!(file.is_none());
    assert_eq!(computed.size, 3);
    assert_eq!(
        computed.sha256(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn a_download_over_the_limit_is_refused_before_it_is_read_in_full() {
    let mock = Mock::start();
    mock.serve("/big.zip", vec![b'x'; 100]);
    let err = mock
        .context()
        .download("s", &mock.url("/big.zip"), 99, false)
        .unwrap_err();
    assert_eq!(err.code().as_str(), "E_SIZE_EXCEEDED");
    // Exactly at the limit is fine.
    let (_, computed) = mock
        .context()
        .download("s", &mock.url("/big.zip"), 100, false)
        .unwrap();
    assert_eq!(computed.size, 100);
}

#[test]
fn a_missing_artifact_fails_the_download() {
    let mock = Mock::start();
    mock.status("/gone.zip", 404);
    let err = mock
        .context()
        .download("vendor", &mock.url("/gone.zip"), 1024, false)
        .unwrap_err();
    assert_eq!(err.code().as_str(), "E_NETWORK");
    assert!(err.to_string().contains("vendor"), "{err}");
}
