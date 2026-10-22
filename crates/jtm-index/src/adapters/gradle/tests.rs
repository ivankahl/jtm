use super::*;
use crate::testing::{Mock, fixture};

const LISTING: &str = "/services.gradle.org/versions/all";
const ORIGIN: Origin<'_> = Origin {
    id: "gradle-checksum",
    variant: None,
};

fn config(hash_from: GradleHash, include_rc: bool) -> GradleConfig {
    GradleConfig {
        versions_url: DEFAULT_VERSIONS_URL.to_owned(),
        hash_from,
        include_rc,
    }
}

fn mock_with_listing() -> Mock {
    let mock = Mock::start();
    mock.serve(LISTING, fixture("gradle/versions-all.json"));
    mock
}

fn versions(discovery: &Discovery) -> Vec<&str> {
    discovery
        .candidates
        .iter()
        .map(|c| c.version.as_str())
        .collect()
}

#[test]
fn lists_releases_and_release_candidates_from_the_recorded_listing() {
    let mock = mock_with_listing();
    let discovery = config(GradleHash::VersionsApi, true)
        .discover(&ORIGIN, &mock.context())
        .unwrap();
    // The snapshot, the nightly, the broken build and the milestone are all skipped.
    assert_eq!(
        versions(&discovery),
        ["9.8.0-rc-3", "9.8.2", "8.14.6", "8.10.2", "0.7"]
    );
    assert!(discovery.warnings.is_empty(), "{:?}", discovery.warnings);
}

#[test]
fn candidates_carry_the_download_url_the_digest_and_the_rc_tag() {
    let mock = mock_with_listing();
    let discovery = config(GradleHash::VersionsApi, true)
        .discover(&ORIGIN, &mock.context())
        .unwrap();
    let release = discovery
        .candidates
        .iter()
        .find(|c| c.version == "8.10.2")
        .unwrap();
    assert_eq!(release.source, "gradle-checksum");
    assert_eq!(release.variant, None);
    assert_eq!(release.target, Target::Any);
    assert_eq!(release.archive, ArchiveKind::Zip);
    assert_eq!(
        release.url,
        "https://services.gradle.org/distributions/gradle-8.10.2-bin.zip"
    );
    assert!(release.tags.is_empty());
    let hash = release.hash.as_ref().unwrap();
    assert_eq!(hash.algorithm, HashAlgorithm::Sha256);
    assert_eq!(
        hash.hex,
        "31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26"
    );

    let rc = discovery
        .candidates
        .iter()
        .find(|c| c.version == "9.8.0-rc-3")
        .unwrap();
    assert_eq!(rc.tags, ["rc"]);
}

#[test]
fn release_candidates_can_be_left_out() {
    let mock = mock_with_listing();
    let discovery = config(GradleHash::VersionsApi, false)
        .discover(&ORIGIN, &mock.context())
        .unwrap();
    assert_eq!(versions(&discovery), ["9.8.2", "8.14.6", "8.10.2", "0.7"]);
}

#[test]
fn the_checksum_url_mode_reads_each_sha256_file() {
    let mock = mock_with_listing();
    // Gradle's `.sha256` files hold the bare digest and no newline.
    let digest = "1111111111111111111111111111111111111111111111111111111111111111";
    for version in ["9.8.2", "8.14.6", "8.10.2", "0.7"] {
        mock.serve(
            &format!("/services.gradle.org/distributions/gradle-{version}-bin.zip.sha256"),
            digest,
        );
    }
    let discovery = config(GradleHash::ChecksumUrl, false)
        .discover(&ORIGIN, &mock.context())
        .unwrap();
    assert_eq!(versions(&discovery), ["9.8.2", "8.14.6", "8.10.2", "0.7"]);
    for candidate in &discovery.candidates {
        let hash = candidate.hash.as_ref().unwrap();
        assert_eq!(hash.hex, digest);
        assert!(hash.origin.ends_with(".zip.sha256"), "{}", hash.origin);
    }
}

#[test]
fn a_missing_or_malformed_sha256_file_skips_that_version_with_a_warning() {
    let mock = mock_with_listing();
    let digest = "2222222222222222222222222222222222222222222222222222222222222222";
    mock.serve(
        "/services.gradle.org/distributions/gradle-9.8.2-bin.zip.sha256",
        digest,
    );
    mock.serve(
        "/services.gradle.org/distributions/gradle-8.14.6-bin.zip.sha256",
        "<html>not a digest</html>",
    );
    // 8.10.2 and 0.7 answer 404.
    let discovery = config(GradleHash::ChecksumUrl, false)
        .discover(&ORIGIN, &mock.context())
        .unwrap();
    assert_eq!(versions(&discovery), ["9.8.2"]);
    assert_eq!(discovery.warnings.len(), 3, "{:?}", discovery.warnings);
    assert!(discovery.warnings.iter().any(|w| w.contains("8.14.6")));
}

#[test]
fn an_entry_with_a_foreign_download_url_is_dropped() {
    let mock = Mock::start();
    mock.serve(
        LISTING,
        r#"[{"version":"1.0","downloadUrl":"http://evil.test/g.zip","checksum":
        "3333333333333333333333333333333333333333333333333333333333333333"},
        {"version":"2.0","downloadUrl":"https://services.gradle.org/distributions/gradle-2.0-bin.zip",
         "checksum":"3333333333333333333333333333333333333333333333333333333333333333"}]"#,
    );
    let discovery = config(GradleHash::VersionsApi, true)
        .discover(&ORIGIN, &mock.context())
        .unwrap();
    assert_eq!(versions(&discovery), ["2.0"]);
    assert_eq!(discovery.warnings.len(), 1);
}

#[test]
fn a_listing_of_the_wrong_shape_fails_the_run() {
    let mock = Mock::start();
    mock.serve(LISTING, r#"{"versions": []}"#);
    let err = config(GradleHash::VersionsApi, true)
        .discover(&ORIGIN, &mock.context())
        .unwrap_err();
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
}

#[test]
fn an_unreachable_listing_fails_the_run() {
    let mock = Mock::start();
    mock.status(LISTING, 503);
    let err = config(GradleHash::VersionsApi, true)
        .discover(&ORIGIN, &mock.context())
        .unwrap_err();
    assert_eq!(err.code().as_str(), "E_NETWORK");
}
