//! The Foojay responses under `tests/fixtures/foojay` follow the documented shape of the
//! Disco API v3 `packages` and `ids` endpoints, trimmed to the fields the adapter reads. They
//! were written by hand: the API host was not reachable from the sandbox this was developed
//! in, so the ids, links and digests in them are not Foojay's.

use super::*;
use crate::testing::{Mock, fixture};

const ORIGIN: Origin<'_> = Origin {
    id: "foojay-disco",
    variant: Some("zulu"),
};
const PACKAGES: &str = "/api.foojay.io/disco/v3.0/packages";
const ID: &str = "4f1d5f9a8c1e4b2c9a7e0d3b5c6a7f80";

fn config() -> FoojayConfig {
    FoojayConfig {
        api_url: DEFAULT_API.to_owned(),
        distro: "zulu".to_owned(),
        features: vec![21],
        platforms: Platforms(vec!["linux-x64".to_owned()]),
        package_type: "jdk".to_owned(),
        latest: "all_of_version".to_owned(),
        include_ea: false,
    }
}

/// A server that lists the packages but knows nothing about them yet.
fn mock_packages() -> Mock {
    let mock = Mock::start();
    mock.serve_query(
        PACKAGES,
        &[
            ("distro", "zulu"),
            ("version", "21"),
            ("operating_system", "linux"),
            ("architecture", "x64"),
            ("lib_c_type", "glibc"),
            ("release_status", "ga"),
        ],
        fixture("foojay/packages-zulu-21-linux-x64.json"),
    );
    mock
}

fn mock() -> Mock {
    let mock = mock_packages();
    mock.serve(
        &format!("/api.foojay.io/disco/v3.0/ids/{ID}"),
        fixture(&format!("foojay/ids-{ID}.json")),
    );
    mock
}

#[test]
fn reads_the_package_and_its_checksum_from_the_two_endpoints() {
    let mock = mock();
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert!(discovery.warnings.is_empty(), "{:?}", discovery.warnings);
    assert_eq!(discovery.candidates.len(), 1, "{:?}", discovery.candidates);
    let c = &discovery.candidates[0];
    assert_eq!(c.source, "foojay-disco");
    assert_eq!(c.variant.as_deref(), Some("zulu"));
    assert_eq!(c.version, "21.0.5+11");
    assert_eq!(c.target, Target::Platform(Platform::LinuxX64));
    assert_eq!(c.tags, ["lts", "ga"]);
    assert_eq!(c.archive, jtm_security::ArchiveKind::TarGz);
    assert_eq!(c.size, Some(211_091_301));
    assert_eq!(c.distribution_version.as_deref(), Some("21.38.21"));
    assert_eq!(
        c.url,
        "https://cdn.azul.com/zulu/bin/zulu21.38.21-ca-jdk21.0.5-linux_x64.tar.gz"
    );
    assert_eq!(c.signature_url, None);
    let hash = c.hash.as_ref().unwrap();
    assert_eq!(hash.algorithm, HashAlgorithm::Sha256);
    assert_eq!(hash.hex, "5".repeat(64));
    assert!(
        hash.origin.ends_with(".tar.gz.sha256.txt"),
        "{}",
        hash.origin
    );
}

#[test]
fn packages_for_another_c_library_or_with_javafx_are_not_taken() {
    let mock = mock();
    config().discover(&ORIGIN, &mock.context()).unwrap();
    // Only the one good package was asked about: not the .deb, the musl build or the JavaFX
    // bundle that the same response listed.
    let details: Vec<String> = mock
        .requested()
        .into_iter()
        .filter(|r| r.contains("/ids/"))
        .collect();
    assert_eq!(details, [format!("/api.foojay.io/disco/v3.0/ids/{ID}")]);
}

#[test]
fn musl_is_requested_for_the_musl_platform() {
    let mock = Mock::start();
    mock.serve_query(
        PACKAGES,
        &[("operating_system", "linux"), ("lib_c_type", "musl")],
        r#"{"result": []}"#,
    );
    let musl = FoojayConfig {
        platforms: Platforms(vec!["linux-musl-x64".to_owned()]),
        ..config()
    };
    let discovery = musl.discover(&ORIGIN, &mock.context()).unwrap();
    assert!(discovery.candidates.is_empty());
    assert_eq!(mock.requested().len(), 1);
}

#[test]
fn windows_and_macos_packages_do_not_need_a_c_library() {
    let mock = Mock::start();
    mock.serve_query(
        PACKAGES,
        &[("operating_system", "windows"), ("architecture", "aarch64")],
        r#"{"result":[{"id":"abc123","java_version":"21.0.5+11","release_status":"ga",
        "term_of_support":"lts","operating_system":"windows","lib_c_type":"c_std_lib",
        "architecture":"aarch64","package_type":"jdk","filename":"zulu-win.zip","size":5}]}"#,
    );
    mock.serve(
        "/api.foojay.io/disco/v3.0/ids/abc123",
        r#"{"result":[{"direct_download_uri":"https://cdn.azul.com/zulu-win.zip",
        "checksum":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "checksum_type":"SHA-256","signature_uri":"https://cdn.azul.com/zulu-win.zip.sig"}]}"#,
    );
    let windows = FoojayConfig {
        platforms: Platforms(vec!["windows-aarch64".to_owned()]),
        ..config()
    };
    let discovery = windows.discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(discovery.candidates.len(), 1, "{:?}", discovery.warnings);
    let c = &discovery.candidates[0];
    assert_eq!(c.archive, jtm_security::ArchiveKind::Zip);
    assert_eq!(c.hash.as_ref().unwrap().hex, "a".repeat(64));
    assert_eq!(
        c.signature_url.as_deref(),
        Some("https://cdn.azul.com/zulu-win.zip.sig")
    );
}

#[test]
fn a_package_without_a_usable_checksum_is_dropped_with_a_warning() {
    let mock = mock_packages();
    mock.serve(
        &format!("/api.foojay.io/disco/v3.0/ids/{ID}"),
        r#"{"result":[{"direct_download_uri":"https://cdn.azul.com/a.tar.gz",
        "checksum":"d41d8cd98f00b204e9800998ecf8427e","checksum_type":"md5"}]}"#,
    );
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert!(discovery.candidates.is_empty());
    assert_eq!(discovery.warnings.len(), 1);
    assert!(
        discovery.warnings[0].contains("md5"),
        "{:?}",
        discovery.warnings
    );
}

#[test]
fn a_package_whose_details_are_gone_is_dropped_with_a_warning() {
    let mock = Mock::start();
    mock.serve_query(
        PACKAGES,
        &[("operating_system", "linux")],
        fixture("foojay/packages-zulu-21-linux-x64.json"),
    );
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert!(discovery.candidates.is_empty());
    assert_eq!(discovery.warnings.len(), 1);
}

#[test]
fn a_download_link_that_is_not_https_is_dropped() {
    let mock = mock_packages();
    mock.serve(
        &format!("/api.foojay.io/disco/v3.0/ids/{ID}"),
        r#"{"result":[{"direct_download_uri":"http://cdn.azul.com/a.tar.gz",
        "checksum":"5555555555555555555555555555555555555555555555555555555555555555",
        "checksum_type":"sha256"}]}"#,
    );
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert!(discovery.candidates.is_empty());
    assert_eq!(discovery.warnings.len(), 1);
}

#[test]
fn a_package_id_that_is_not_a_plain_token_is_never_requested() {
    let mock = Mock::start();
    mock.serve_query(
        PACKAGES,
        &[("operating_system", "linux")],
        r#"{"result":[{"id":"../../admin","java_version":"21","release_status":"ga",
        "operating_system":"linux","lib_c_type":"glibc","architecture":"x64","package_type":"jdk",
        "filename":"a.tar.gz"}]}"#,
    );
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert!(discovery.candidates.is_empty());
    assert_eq!(discovery.warnings.len(), 1);
    assert_eq!(mock.requested().len(), 1);
}

#[test]
fn early_access_builds_are_a_separate_request_with_the_ea_tag() {
    let mock = mock();
    mock.serve_query(
        PACKAGES,
        &[("release_status", "ea"), ("operating_system", "linux")],
        r#"{"result":[{"id":"eaid1","java_version":"26-ea+5","release_status":"ea",
        "term_of_support":"sts","operating_system":"linux","lib_c_type":"glibc",
        "architecture":"x64","package_type":"jdk","filename":"ea.tar.gz"}]}"#,
    );
    mock.serve(
        "/api.foojay.io/disco/v3.0/ids/eaid1",
        r#"{"result":[{"direct_download_uri":"https://cdn.azul.com/ea.tar.gz",
        "checksum":"5555555555555555555555555555555555555555555555555555555555555555",
        "checksum_type":"sha256"}]}"#,
    );
    let with_ea = FoojayConfig {
        include_ea: true,
        ..config()
    };
    let discovery = with_ea.discover(&ORIGIN, &mock.context()).unwrap();
    let ea = discovery
        .candidates
        .iter()
        .find(|c| c.version == "26-ea+5")
        .unwrap();
    assert_eq!(ea.tags, ["ea"]);
}

#[test]
fn a_response_of_the_wrong_shape_fails_the_run() {
    let mock = Mock::start();
    mock.serve(PACKAGES, r#"[{"id": 1}]"#);
    let err = config().discover(&ORIGIN, &mock.context()).unwrap_err();
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
}

#[test]
fn bad_settings_are_rejected_when_the_file_loads() {
    assert_eq!(config().validate(), Ok(()));
    let bad = |c: FoojayConfig| c.validate().unwrap_err();

    let message = bad(FoojayConfig {
        api_url: "ftp://api.foojay.io".to_owned(),
        ..config()
    });
    assert!(message.contains("https"), "{message}");

    let message = bad(FoojayConfig {
        distro: "zulu&evil=1".to_owned(),
        ..config()
    });
    assert!(message.contains("distro"), "{message}");

    let message = bad(FoojayConfig {
        features: Vec::new(),
        ..config()
    });
    assert!(message.contains("features"), "{message}");

    let message = bad(FoojayConfig {
        platforms: Platforms(vec!["any".to_owned()]),
        ..config()
    });
    assert!(message.contains("platform"), "{message}");
}
