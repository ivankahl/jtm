//! The Adoptium API responses under `tests/fixtures/adoptium` follow the documented shape of
//! `/v3/info/available_releases` and `/v3/assets/feature_releases`, trimmed to the fields the
//! adapter reads. They were written by hand: the API host was not reachable from the sandbox
//! this was developed in, so the digests in them are not Adoptium's.

use super::*;
use crate::testing::{Mock, fixture};

const ORIGIN: Origin<'_> = Origin {
    id: "adoptium-api",
    variant: Some("temurin"),
};
const INFO: &str = "/api.adoptium.net/v3/info/available_releases";
const RELEASES_21: &str = "/api.adoptium.net/v3/assets/feature_releases/21/ga";

fn config() -> AdoptiumConfig {
    AdoptiumConfig {
        api_url: DEFAULT_API.to_owned(),
        features: Some(vec![21]),
        platforms: Platforms(vec!["linux-x64".to_owned()]),
        image_type: "jdk".to_owned(),
        jvm_impl: "hotspot".to_owned(),
        vendor: "eclipse".to_owned(),
        include_ea: false,
        max_pages: 5,
    }
}

fn mock() -> Mock {
    let mock = Mock::start();
    mock.serve(INFO, fixture("adoptium/available_releases.json"));
    mock.serve_query(
        RELEASES_21,
        &[("os", "linux"), ("architecture", "x64"), ("page", "0")],
        fixture("adoptium/feature_releases-21-ga-linux-x64.json"),
    );
    mock
}

#[test]
fn lists_the_packages_of_each_release_with_their_sha256() {
    let mock = mock();
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert!(discovery.warnings.is_empty(), "{:?}", discovery.warnings);
    // Each release also lists a Windows package and a JRE, which the query did not ask for.
    let versions: Vec<&str> = discovery
        .candidates
        .iter()
        .map(|c| c.version.as_str())
        .collect();
    assert_eq!(versions, ["21.0.5+11", "21.0.4+7"]);
}

#[test]
fn a_candidate_carries_everything_the_api_knows() {
    let mock = mock();
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    let c = &discovery.candidates[0];
    assert_eq!(c.source, "adoptium-api");
    assert_eq!(c.variant.as_deref(), Some("temurin"));
    assert_eq!(c.target, Target::Platform(Platform::LinuxX64));
    assert_eq!(c.tags, ["lts", "ga"]);
    assert_eq!(c.archive, jtm_security::ArchiveKind::TarGz);
    assert_eq!(c.size, Some(206_102_334));
    assert_eq!(
        c.url,
        "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.5%2B11/\
         OpenJDK21U-jdk_x64_linux_hotspot_21.0.5_11.tar.gz"
    );
    assert_eq!(
        c.signature_url.as_deref(),
        Some(format!("{}.sig", c.url).as_str())
    );
    let hash = c.hash.as_ref().unwrap();
    assert_eq!(hash.algorithm, HashAlgorithm::Sha256);
    assert!(hash.hex.starts_with("553a1c7c"), "{}", hash.hex);
    assert!(
        hash.origin.ends_with(".tar.gz.sha256.txt"),
        "{}",
        hash.origin
    );
}

#[test]
fn the_request_carries_the_configured_filters() {
    let mock = mock();
    config().discover(&ORIGIN, &mock.context()).unwrap();
    let requests = mock.requested();
    assert_eq!(requests.len(), 2, "{requests:?}");
    let query = &requests[1];
    for expected in [
        "architecture=x64",
        "os=linux",
        "image_type=jdk",
        "jvm_impl=hotspot",
        "vendor=eclipse",
        "page=0",
    ] {
        assert!(query.contains(expected), "{expected} missing from {query}");
    }
}

#[test]
fn features_default_to_every_release_and_only_lts_ones_are_tagged() {
    let mock = Mock::start();
    mock.serve(INFO, fixture("adoptium/available_releases.json"));
    mock.serve(
        "/api.adoptium.net/v3/assets/feature_releases/24/ga",
        r#"[{"release_type":"ga","version_data":{"major":24,"minor":0,"security":1,"build":9},
            "binaries":[{"os":"linux","architecture":"x64","image_type":"jdk","jvm_impl":"hotspot",
            "package":{"name":"a.tar.gz","link":"https://github.com/a.tar.gz",
            "checksum":"3333333333333333333333333333333333333333333333333333333333333333"}}]}]"#,
    );
    let all = AdoptiumConfig {
        features: None,
        ..config()
    };
    let discovery = all.discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(discovery.candidates.len(), 1);
    assert_eq!(discovery.candidates[0].version, "24.0.1+9");
    assert_eq!(discovery.candidates[0].tags, ["ga"]);
    // Nine feature releases are known; each was asked for.
    assert_eq!(mock.requested().len(), 1 + 9);
}

#[test]
fn versions_are_written_like_java_prints_them() {
    let data = |major, minor, security, patch, build| VersionData {
        major,
        minor,
        security,
        patch,
        build,
        respin: 0,
    };
    assert_eq!(
        java_version(&data(21, 0, 5, 0, Some(11)), false),
        "21.0.5+11"
    );
    assert_eq!(
        java_version(&data(8, 0, 432, 0, Some(6)), false),
        "8.0.432+6"
    );
    assert_eq!(java_version(&data(21, 0, 0, 0, Some(35)), false), "21+35");
    assert_eq!(
        java_version(&data(17, 0, 13, 1, Some(2)), false),
        "17.0.13.1+2"
    );
    assert_eq!(java_version(&data(26, 0, 0, 0, Some(5)), true), "26-ea+5");
    assert_eq!(java_version(&data(21, 0, 5, 0, None), false), "21.0.5");
    // A re-spin of a build is a different archive and gets its own version.
    let respun = VersionData {
        respin: 1,
        ..data(17, 0, 9, 0, Some(9))
    };
    assert_eq!(java_version(&respun, false), "17.0.9+9.1");
    // The result is a version the java scheme accepts.
    for version in [
        "21.0.5+11",
        "8.0.432+6",
        "21+35",
        "17.0.13.1+2",
        "26-ea+5",
        "17.0.9+9.1",
    ] {
        assert!(
            jtm_plugin::VersionScheme::Java.parse(version).is_ok(),
            "{version}"
        );
    }
}

#[test]
fn a_respin_is_a_separate_version_from_the_build_it_replaces() {
    let mock = Mock::start();
    mock.serve(INFO, fixture("adoptium/available_releases.json"));
    let release = |respin: u32| {
        format!(
            r#"{{"release_type":"ga","version_data":{{"major":21,"minor":0,"security":9,"build":9,
            "adopt_build_number":{respin}}},
            "binaries":[{{"os":"linux","architecture":"x64","image_type":"jdk","jvm_impl":"hotspot",
            "package":{{"name":"a.tar.gz","link":"https://github.com/a{respin}.tar.gz",
            "checksum":"3333333333333333333333333333333333333333333333333333333333333333"}}}}]}}"#
        )
    };
    mock.serve(RELEASES_21, format!("[{},{}]", release(1), release(0)));
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    let versions: Vec<&str> = discovery
        .candidates
        .iter()
        .map(|c| c.version.as_str())
        .collect();
    assert_eq!(versions, ["21.0.9+9.1", "21.0.9+9"]);
}

#[test]
fn early_access_builds_are_listed_on_request_with_the_ea_tag() {
    let mock = mock();
    mock.serve(
        "/api.adoptium.net/v3/assets/feature_releases/21/ea",
        r#"[{"release_type":"ea","version_data":{"major":21,"minor":0,"security":6,"build":3},
            "binaries":[{"os":"linux","architecture":"x64","image_type":"jdk","jvm_impl":"hotspot",
            "package":{"name":"a.tar.gz","link":"https://github.com/ea.tar.gz",
            "checksum":"3333333333333333333333333333333333333333333333333333333333333333"}}]}]"#,
    );
    let with_ea = AdoptiumConfig {
        include_ea: true,
        ..config()
    };
    let discovery = with_ea.discover(&ORIGIN, &mock.context()).unwrap();
    let ea = discovery
        .candidates
        .iter()
        .find(|c| c.tags.contains(&"ea".to_owned()))
        .unwrap();
    assert_eq!(ea.version, "21.0.6-ea+3");
    assert_eq!(ea.tags, ["lts", "ea"]);

    let without = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert!(
        without
            .candidates
            .iter()
            .all(|c| c.tags.contains(&"ga".to_owned()))
    );
}

#[test]
fn pages_are_followed_until_a_short_page() {
    let mock = Mock::start();
    mock.serve(INFO, fixture("adoptium/available_releases.json"));
    let release = |build: u32| {
        format!(
            r#"{{"release_type":"ga","version_data":{{"major":21,"minor":0,"security":{build},"build":1}},
            "binaries":[{{"os":"linux","architecture":"x64","image_type":"jdk","jvm_impl":"hotspot",
            "package":{{"name":"a.tar.gz","link":"https://github.com/a{build}.tar.gz",
            "checksum":"3333333333333333333333333333333333333333333333333333333333333333"}}}}]}}"#
        )
    };
    let page = |range: std::ops::Range<u32>| {
        format!("[{}]", range.map(release).collect::<Vec<_>>().join(","))
    };
    mock.serve_query(RELEASES_21, &[("page", "0")], page(1..21));
    mock.serve_query(RELEASES_21, &[("page", "1")], page(21..24));
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(discovery.candidates.len(), 23);
    let pages = mock
        .requested()
        .iter()
        .filter(|r| r.contains("feature_releases"))
        .count();
    assert_eq!(pages, 2);
}

#[test]
fn the_page_bound_stops_a_runaway_listing_with_a_warning() {
    let mock = Mock::start();
    mock.serve(INFO, fixture("adoptium/available_releases.json"));
    let release = r#"{"release_type":"ga","version_data":{"major":21,"minor":0,"security":1,"build":1},"binaries":[]}"#;
    let full_page = format!("[{}]", vec![release; PAGE_SIZE].join(","));
    mock.serve(RELEASES_21, full_page);
    let bounded = AdoptiumConfig {
        max_pages: 3,
        ..config()
    };
    let discovery = bounded.discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(discovery.warnings.len(), 1);
    assert!(discovery.warnings[0].contains("stopped after 3 pages"));
    assert_eq!(
        mock.requested()
            .iter()
            .filter(|r| r.contains("feature_releases"))
            .count(),
        3
    );
}

#[test]
fn a_package_the_api_answers_for_another_platform_is_ignored() {
    let mock = Mock::start();
    mock.serve(INFO, fixture("adoptium/available_releases.json"));
    mock.serve(
        RELEASES_21,
        r#"[{"release_type":"ga","version_data":{"major":21,"minor":0,"security":5,"build":11},
        "binaries":[{"os":"windows","architecture":"x64","image_type":"jdk","jvm_impl":"hotspot",
        "package":{"name":"a.zip","link":"https://github.com/a.zip",
        "checksum":"3333333333333333333333333333333333333333333333333333333333333333"}}]}]"#,
    );
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert!(discovery.candidates.is_empty());
}

#[test]
fn packages_without_a_usable_sha256_or_archive_are_dropped_with_a_warning() {
    let mock = Mock::start();
    mock.serve(INFO, fixture("adoptium/available_releases.json"));
    mock.serve(
        RELEASES_21,
        r#"[{"release_type":"ga","version_data":{"major":21,"minor":0,"security":5,"build":11},
        "binaries":[
          {"os":"linux","architecture":"x64","image_type":"jdk","jvm_impl":"hotspot",
           "package":{"name":"a.tar.gz","link":"https://github.com/a.tar.gz","checksum":"short"}},
          {"os":"linux","architecture":"x64","image_type":"jdk","jvm_impl":"hotspot",
           "package":{"name":"a.pkg","link":"https://github.com/a.pkg",
           "checksum":"3333333333333333333333333333333333333333333333333333333333333333"}},
          {"os":"linux","architecture":"x64","image_type":"jdk","jvm_impl":"hotspot",
           "package":{"name":"b.tar.gz","link":"http://github.com/b.tar.gz",
           "checksum":"3333333333333333333333333333333333333333333333333333333333333333"}}]}]"#,
    );
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert!(discovery.candidates.is_empty());
    // The checksum and the http link are reported; the installer is quietly not an archive.
    assert_eq!(discovery.warnings.len(), 2, "{:?}", discovery.warnings);
}

#[test]
fn a_response_of_the_wrong_shape_fails_the_run() {
    let mock = Mock::start();
    mock.serve(INFO, fixture("adoptium/available_releases.json"));
    mock.serve(RELEASES_21, r#"{"message": "rate limited"}"#);
    let err = config().discover(&ORIGIN, &mock.context()).unwrap_err();
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
}

#[test]
fn an_unreachable_api_fails_the_run() {
    let mock = Mock::start();
    mock.status(INFO, 502);
    let err = config().discover(&ORIGIN, &mock.context()).unwrap_err();
    assert_eq!(err.code().as_str(), "E_NETWORK");
}

#[test]
fn every_platform_maps_to_the_apis_names() {
    let names: Vec<_> = Platform::ALL.iter().map(|p| api_names(*p)).collect();
    assert_eq!(
        names,
        [
            ("windows", "x64"),
            ("windows", "aarch64"),
            ("mac", "x64"),
            ("mac", "aarch64"),
            ("linux", "x64"),
            ("linux", "aarch64"),
            ("alpine-linux", "x64"),
        ]
    );
}

#[test]
fn bad_settings_are_rejected_when_the_file_loads() {
    assert_eq!(config().validate(), Ok(()));
    let bad = |c: AdoptiumConfig| c.validate().unwrap_err();

    let message = bad(AdoptiumConfig {
        api_url: "http://api.adoptium.net".to_owned(),
        ..config()
    });
    assert!(message.contains("https"), "{message}");

    let message = bad(AdoptiumConfig {
        platforms: Platforms(vec!["linux-sparc".to_owned()]),
        ..config()
    });
    assert!(message.contains("linux-sparc"), "{message}");

    let message = bad(AdoptiumConfig {
        vendor: "eclipse&os=evil".to_owned(),
        ..config()
    });
    assert!(message.contains("vendor"), "{message}");

    let message = bad(AdoptiumConfig {
        features: Some(Vec::new()),
        ..config()
    });
    assert!(message.contains("features"), "{message}");

    let message = bad(AdoptiumConfig {
        max_pages: 0,
        ..config()
    });
    assert!(message.contains("max_pages"), "{message}");
}
