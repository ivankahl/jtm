use super::*;
use crate::testing::{Mock, fixture};

const LISTING: &str = "https://archive.apache.org/dist/maven/maven-3/";
const ORIGIN: Origin<'_> = Origin {
    id: "apache-dist",
    variant: None,
};
const SHA512_3_9_9: &str = "a555254d6b53d267965a3404ecb14e53c3827c09c3b94b5678835887ab404556\
                            bfaf78dcfe03ba76fa2508649dca8531c74bca4d5846513522404d48e8c4ac8b";

fn config() -> ApacheConfig {
    ApacheConfig {
        listings: vec![LISTING.to_owned()],
        artifact: "binaries/apache-maven-{version}-bin.tar.gz".to_owned(),
        hash: "sha512".to_owned(),
        signature_suffix: ".asc".to_owned(),
        version_pattern: None,
    }
}

fn mock() -> Mock {
    let mock = Mock::start();
    mock.serve(
        "/archive.apache.org/dist/maven/maven-3/",
        fixture("apache/maven-3-listing.html"),
    );
    mock.serve(
        "/archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz.sha512",
        fixture("apache/apache-maven-3.9.9-bin.tar.gz.sha512"),
    );
    mock
}

#[test]
fn the_recorded_directory_index_yields_only_version_directories() {
    let names: Vec<String> = directory_names(&fixture("apache/maven-3-listing.html")).collect();
    assert_eq!(names.len(), 50, "{names:?}");
    assert_eq!(names.first().map(String::as_str), Some("3.0.4"));
    assert!(names.contains(&"3.9.9".to_owned()));
    assert!(names.contains(&"3.1.0-alpha-1".to_owned()));
    // Sort links, the parent directory and the link to the download server are not versions.
    for name in &names {
        assert!(name.starts_with('3'), "{name}");
    }
}

#[test]
fn links_that_leave_the_directory_are_ignored() {
    let html = r#"<a href="../">..</a><a href="/etc/">x</a><a href="a/b/">x</a>
        <a href="https://evil.test/">x</a><a href="?C=N/">x</a><a href="./">x</a><a href="%2e%2e/">x</a>
        <a href='1.0/'>single quotes are not Apache's</a><a href="1.1/">ok</a>"#;
    let names: Vec<String> = directory_names(html).collect();
    assert_eq!(names, ["1.1"]);
}

#[test]
fn builds_the_candidate_from_the_recorded_sidecar() {
    let mock = mock();
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(discovery.candidates.len(), 1, "{:?}", discovery.candidates);
    let candidate = &discovery.candidates[0];
    assert_eq!(candidate.source, "apache-dist");
    assert_eq!(candidate.version, "3.9.9");
    assert_eq!(candidate.target, Target::Any);
    assert_eq!(candidate.archive, jtm_security::ArchiveKind::TarGz);
    assert_eq!(
        candidate.url,
        "https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz"
    );
    assert_eq!(
        candidate.signature_url.as_deref(),
        Some(
            "https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/\
             apache-maven-3.9.9-bin.tar.gz.asc"
        )
    );
    let hash = candidate.hash.as_ref().unwrap();
    assert_eq!(hash.algorithm, HashAlgorithm::Sha512);
    assert_eq!(hash.hex, SHA512_3_9_9);
    assert!(hash.origin.ends_with(".tar.gz.sha512"), "{}", hash.origin);
}

#[test]
fn versions_without_a_sidecar_are_skipped_with_a_warning_each() {
    let mock = mock();
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    // 49 of the 50 recorded versions answer 404 for their .sha512 here.
    assert_eq!(discovery.warnings.len(), 49);
    assert!(discovery.warnings.iter().all(|w| w.contains("apache-dist")));
}

#[test]
fn the_version_pattern_narrows_what_is_requested() {
    let mock = mock();
    let narrowed = ApacheConfig {
        version_pattern: Some(r"^3\.9\.9$".to_owned()),
        ..config()
    };
    let discovery = narrowed.discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(discovery.candidates.len(), 1);
    assert!(discovery.warnings.is_empty());
    let requested = mock.requested();
    assert_eq!(requested.len(), 2, "{requested:?}");
}

#[test]
fn a_sidecar_for_another_algorithm_is_not_accepted() {
    let mock = Mock::start();
    mock.serve(
        "/archive.apache.org/dist/maven/maven-3/",
        r#"<a href="1.0/">1.0/</a>"#,
    );
    // A SHA-1 where a SHA-512 is expected.
    mock.serve(
        "/archive.apache.org/dist/maven/maven-3/1.0/binaries/apache-maven-1.0-bin.tar.gz.sha512",
        "0b7641f3bf34a49f7350eafe39de4c97f4126991",
    );
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert!(discovery.candidates.is_empty());
    assert_eq!(discovery.warnings.len(), 1);
}

#[test]
fn signatures_can_be_left_out() {
    let mock = mock();
    let unsigned = ApacheConfig {
        signature_suffix: String::new(),
        version_pattern: Some(r"^3\.9\.9$".to_owned()),
        ..config()
    };
    let discovery = unsigned.discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(discovery.candidates[0].signature_url, None);
}

#[test]
fn several_listings_are_all_read() {
    let mock = mock();
    mock.serve(
        "/archive.apache.org/dist/maven/maven-4/",
        r#"<a href="4.0.0-rc-3/">4.0.0-rc-3/</a>"#,
    );
    mock.serve(
        "/archive.apache.org/dist/maven/maven-4/4.0.0-rc-3/binaries/apache-maven-4.0.0-rc-3-bin.tar.gz.sha512",
        format!("{SHA512_3_9_9}  apache-maven-4.0.0-rc-3-bin.tar.gz\n"),
    );
    let both = ApacheConfig {
        listings: vec![
            LISTING.to_owned(),
            "https://archive.apache.org/dist/maven/maven-4".to_owned(),
        ],
        version_pattern: Some(r"^(3\.9\.9|4\..*)$".to_owned()),
        ..config()
    };
    let discovery = both.discover(&ORIGIN, &mock.context()).unwrap();
    let versions: Vec<&str> = discovery
        .candidates
        .iter()
        .map(|c| c.version.as_str())
        .collect();
    assert_eq!(versions, ["3.9.9", "4.0.0-rc-3"]);
}

#[test]
fn a_version_listed_twice_is_read_once() {
    let mock = Mock::start();
    mock.serve(
        "/archive.apache.org/dist/maven/maven-3/",
        r#"<a href="3.9.9/">3.9.9/</a><a href="3.9.9/">again</a>"#,
    );
    mock.serve(
        "/archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.tar.gz.sha512",
        fixture("apache/apache-maven-3.9.9-bin.tar.gz.sha512"),
    );
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(discovery.candidates.len(), 1);
}

#[test]
fn a_missing_listing_fails_the_run() {
    let mock = Mock::start();
    let err = config().discover(&ORIGIN, &mock.context()).unwrap_err();
    assert_eq!(err.code().as_str(), "E_NETWORK");
}

#[test]
fn bad_settings_are_rejected_when_the_file_loads() {
    assert_eq!(config().validate(), Ok(()));
    let bad = |c: ApacheConfig| c.validate().unwrap_err();

    let message = bad(ApacheConfig {
        listings: Vec::new(),
        ..config()
    });
    assert!(message.contains("listings"), "{message}");

    let message = bad(ApacheConfig {
        listings: vec!["http://archive.apache.org/dist/".to_owned()],
        ..config()
    });
    assert!(message.contains("https"), "{message}");

    let message = bad(ApacheConfig {
        artifact: "{versoin}/x.tar.gz".to_owned(),
        ..config()
    });
    assert!(message.contains("versoin"), "{message}");

    let message = bad(ApacheConfig {
        artifact: "../{version}/x.tar.gz".to_owned(),
        ..config()
    });
    assert!(message.contains("relative"), "{message}");

    let message = bad(ApacheConfig {
        artifact: "{version}/x.dmg".to_owned(),
        ..config()
    });
    assert!(message.contains("zip"), "{message}");

    let message = bad(ApacheConfig {
        hash: "md5".to_owned(),
        ..config()
    });
    assert!(message.contains("md5"), "{message}");

    let message = bad(ApacheConfig {
        version_pattern: Some("(".to_owned()),
        ..config()
    });
    assert!(message.contains("version_pattern"), "{message}");

    let message = bad(ApacheConfig {
        signature_suffix: "asc".to_owned(),
        ..config()
    });
    assert!(message.contains("signature_suffix"), "{message}");
}
