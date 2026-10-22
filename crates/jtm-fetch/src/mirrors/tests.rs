use super::*;

fn mirrors(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
        .collect()
}

fn url(location: Location) -> String {
    match location {
        Location::Url(url) => url,
        other => panic!("expected a URL, got {other:?}"),
    }
}

fn file(location: Location) -> PathBuf {
    match location {
        Location::File { path, .. } => path,
        other => panic!("expected a file, got {other:?}"),
    }
}

#[test]
fn the_longest_prefix_wins() {
    let mirrors = mirrors(&[
        ("https://github.com/", "https://a.test/gh/"),
        ("https://github.com/adoptium/", "https://a.test/adoptium/"),
    ]);
    assert_eq!(
        url(resolve("https://github.com/adoptium/x.zip", &mirrors).unwrap()),
        "https://a.test/adoptium/x.zip"
    );
    assert_eq!(
        url(resolve("https://github.com/other/x.zip", &mirrors).unwrap()),
        "https://a.test/gh/other/x.zip"
    );
    assert_eq!(
        url(resolve("https://example.test/x.zip", &mirrors).unwrap()),
        "https://example.test/x.zip"
    );
}

#[test]
fn a_network_target_keeps_the_tail_byte_for_byte() {
    let mirrors = mirrors(&[("https://github.com/", "https://a.test/gh/")]);
    assert_eq!(
        url(resolve("https://github.com/jdk-21.0.5%2B11/x.zip", &mirrors).unwrap()),
        "https://a.test/gh/jdk-21.0.5%2B11/x.zip"
    );
}

#[test]
fn a_file_url_target_names_a_local_path_with_the_tail_decoded() {
    let mirrors = mirrors(&[("https://github.com/", "file:///opt/mirror/gh/")]);
    let location = resolve(
        "https://github.com/adoptium/jdk-21.0.5%2B11/x.zip",
        &mirrors,
    )
    .unwrap();
    assert_eq!(
        file(location),
        PathBuf::from("/opt/mirror/gh/adoptium/jdk-21.0.5+11/x.zip")
    );
}

#[test]
fn a_plain_path_target_names_a_local_path() {
    let mirrors = mirrors(&[("https://github.com/", "/opt/mirror/")]);
    let location = resolve("https://github.com/a/x.zip", &mirrors).unwrap();
    assert_eq!(file(location), PathBuf::from("/opt/mirror/a/x.zip"));
}

#[test]
fn a_local_target_reports_the_location_it_read() {
    let mirrors = mirrors(&[("https://github.com/", "file:///opt/mirror/")]);
    let Location::File { display, .. } = resolve("https://github.com/x.zip", &mirrors).unwrap()
    else {
        panic!("expected a file");
    };
    assert_eq!(display, "file:///opt/mirror/x.zip");
}

#[test]
fn a_local_target_refuses_a_tail_that_leaves_the_mirror() {
    let mirrors = mirrors(&[("https://github.com/", "file:///opt/mirror/")]);
    for tail in [
        "../etc/passwd",
        "a/../../b",
        "a/%2e%2e/b",
        "a%2F..%2Fb",
        "a%5Cb",
        "a%00b",
        "a/./b",
        "%ff",
        "a%2",
    ] {
        let err = resolve(&format!("https://github.com/{tail}"), &mirrors).unwrap_err();
        assert!(matches!(err, Error::Scheme { .. }), "{tail}: {err:?}");
    }
}

#[test]
fn an_unmatched_url_is_never_local() {
    let mirrors = mirrors(&[("https://github.com/", "file:///opt/mirror/")]);
    for raw in ["file:///etc/passwd", "/etc/passwd", "https://other.test/x"] {
        assert_eq!(
            resolve(raw, &mirrors).unwrap(),
            Location::Url(raw.to_owned())
        );
    }
}

#[test]
fn local_paths_come_from_file_urls_and_plain_paths_only() {
    assert_eq!(
        local_path("file:///opt/x.json"),
        Some(PathBuf::from("/opt/x.json"))
    );
    assert_eq!(
        local_path("file:///C:/x.json"),
        Some(PathBuf::from("C:/x.json"))
    );
    assert_eq!(
        local_path("/opt/x.json"),
        Some(PathBuf::from("/opt/x.json"))
    );
    assert_eq!(local_path("https://a.test/x.json"), None);
    assert_eq!(local_path("http://a.test/x.json"), None);
}

fn exported(url: &str) -> String {
    export_path(url)
        .unwrap()
        .iter()
        .map(|part| part.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

#[test]
fn an_exported_file_sits_under_its_host_and_decoded_path() {
    assert_eq!(
        exported("https://github.com/adoptium/jdk-21.0.5%2B11/x.zip"),
        "github.com/adoptium/jdk-21.0.5+11/x.zip"
    );
    assert_eq!(
        exported("https://Index.Example.test/demo-linux-x64.json"),
        "index.example.test/demo-linux-x64.json"
    );
    // The scheme does not change the place, and a port cannot contain a colon on Windows.
    assert_eq!(
        exported("http://mirror.test:8080/a/b.json"),
        "mirror.test+8080/a/b.json"
    );
}

#[test]
fn an_exported_file_is_found_again_through_a_mirror_on_the_host_directory() {
    let url = "https://github.com/adoptium/jdk-21.0.5%2B11/x.zip";
    let mirrors = mirrors(&[("https://github.com/", "file:///opt/mirror/github.com/")]);
    let found = file(resolve(url, &mirrors).unwrap());
    assert_eq!(
        found,
        PathBuf::from("/opt/mirror").join(export_path(url).unwrap())
    );
}

#[test]
fn a_url_that_cannot_be_a_file_is_refused() {
    for url in [
        "https://example.test/",
        "https://example.test",
        "https://example.test/dir/",
        "https://example.test/a.zip?token=1",
        "https://example.test/a.zip#frag",
        "https://user@example.test/a.zip",
        "https://[::1]/a.zip",
        "https://example.test/../a.zip",
        "https://example.test/a/%2E%2E/b.zip",
        "https://example.test/a%5Cb.zip",
        "https://example.test/a//b.zip",
        "https://example.test/C%3A/b.zip",
        "https://example.test/a%3Ab.zip",
        "ftp://example.test/a.zip",
        "file:///etc/passwd",
        "/etc/passwd",
        "https:///a.zip",
        "https://exa mple.test/a.zip",
        "https://example.test:80x/a.zip",
    ] {
        assert!(
            matches!(export_path(url), Err(Error::Scheme { .. })),
            "{url}"
        );
    }
}
