//! The release listings under `tests/fixtures/github` follow the documented shape of
//! `GET /repos/{owner}/{repo}/releases`, trimmed to the fields the adapter reads. They were
//! written by hand: the API host was not reachable from the sandbox this was developed in, so
//! the digests in them are not the projects'.

use super::*;
use crate::testing::{Mock, fixture};
use jtm_core::Platform;

const ORIGIN: Origin<'_> = Origin {
    id: "github-release",
    variant: None,
};
const KOTLIN: &str = "/api.github.com/repos/JetBrains/kotlin/releases";
const TEMURIN_21: &str = "/api.github.com/repos/adoptium/temurin21-binaries/releases";

fn kotlin() -> GithubConfig {
    GithubConfig {
        api_url: DEFAULT_API.to_owned(),
        repo: "JetBrains/kotlin".to_owned(),
        features: None,
        tag_pattern: r"v(?P<version>\d+\.\d+\.\d+(?:-[A-Za-z0-9]+)?)".to_owned(),
        version: "{version}".to_owned(),
        assets: BTreeMap::from([("any".to_owned(), "kotlin-compiler-{version}.zip".to_owned())]),
        hash_from: HashFrom::Digest,
        sidecar_suffix: None,
        signature_suffix: None,
        include_prereleases: false,
        tags: Vec::new(),
        prerelease_tags: Vec::new(),
        max_pages: 3,
    }
}

fn temurin() -> GithubConfig {
    GithubConfig {
        repo: "adoptium/temurin{feature}-binaries".to_owned(),
        features: Some(vec![21]),
        tag_pattern: r"jdk-(?P<version>\d+(?:\.\d+)*)\+(?P<build>\d+)".to_owned(),
        version: "{version}+{build}".to_owned(),
        assets: BTreeMap::from([
            (
                "linux-x64".to_owned(),
                "OpenJDK{feature}U-jdk_x64_linux_hotspot_{version}_{build}.tar.gz".to_owned(),
            ),
            (
                "windows-x64".to_owned(),
                "OpenJDK{feature}U-jdk_x64_windows_hotspot_{version}_{build}.zip".to_owned(),
            ),
        ]),
        hash_from: HashFrom::Sidecar,
        sidecar_suffix: Some(".sha256.txt".to_owned()),
        signature_suffix: Some(".sig".to_owned()),
        ..kotlin()
    }
}

fn mock_kotlin() -> Mock {
    let mock = Mock::start();
    mock.serve(KOTLIN, fixture("github/kotlin-releases.json"));
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
fn takes_the_asset_digest_github_records() {
    let mock = mock_kotlin();
    let discovery = kotlin().discover(&ORIGIN, &mock.context()).unwrap();
    // The pre-release, the draft and the tag that is not a version are left out; 2.0.21 has an
    // asset without a digest, which is reported rather than guessed.
    assert_eq!(versions(&discovery), ["2.1.0"]);
    assert_eq!(discovery.warnings.len(), 1, "{:?}", discovery.warnings);
    assert!(discovery.warnings[0].contains("2.0.21"));

    let c = &discovery.candidates[0];
    assert_eq!(c.source, "github-release");
    assert_eq!(c.target, Target::Any);
    assert_eq!(c.archive, jtm_security::ArchiveKind::Zip);
    assert_eq!(c.size, Some(80_000_001));
    assert!(c.tags.is_empty());
    assert_eq!(
        c.url,
        "https://github.com/JetBrains/kotlin/releases/download/v2.1.0/kotlin-compiler-2.1.0.zip"
    );
    let hash = c.hash.as_ref().unwrap();
    assert_eq!(hash.algorithm, HashAlgorithm::Sha256);
    assert_eq!(hash.hex, "6".repeat(64));
}

#[test]
fn pre_releases_are_opt_in_and_can_be_tagged() {
    let mock = mock_kotlin();
    let config = GithubConfig {
        include_prereleases: true,
        tags: vec!["stable".to_owned()],
        prerelease_tags: vec!["rc".to_owned()],
        ..kotlin()
    };
    let discovery = config.discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(versions(&discovery), ["2.1.0", "2.2.0-RC"]);
    assert_eq!(discovery.candidates[0].tags, ["stable"]);
    assert_eq!(discovery.candidates[1].tags, ["stable", "rc"]);
}

#[test]
fn a_sidecar_file_supplies_the_digest_and_a_signature_asset_the_signature() {
    let mock = Mock::start();
    mock.serve(TEMURIN_21, fixture("github/temurin21-releases.json"));
    let sidecar = "/github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.5%2B11/\
                   OpenJDK21U-jdk_x64_linux_hotspot_21.0.5_11.tar.gz.sha256.txt";
    mock.serve(
        sidecar,
        format!(
            "{}  OpenJDK21U-jdk_x64_linux_hotspot_21.0.5_11.tar.gz\n",
            "b".repeat(64)
        ),
    );
    let discovery = temurin().discover(&ORIGIN, &mock.context()).unwrap();
    // The Windows asset has a sidecar asset too, but the server has no file behind it.
    assert_eq!(discovery.candidates.len(), 1, "{:?}", discovery.warnings);
    let c = &discovery.candidates[0];
    assert_eq!(c.version, "21.0.5+11");
    assert_eq!(c.target, Target::Platform(Platform::LinuxX64));
    assert_eq!(c.archive, jtm_security::ArchiveKind::TarGz);
    let hash = c.hash.as_ref().unwrap();
    assert_eq!(hash.hex, "b".repeat(64));
    assert!(hash.origin.ends_with(".sha256.txt"), "{}", hash.origin);
    assert_eq!(
        c.signature_url.as_deref(),
        Some(format!("{}.sig", c.url).as_str())
    );
    assert_eq!(discovery.warnings.len(), 1);
    assert!(discovery.warnings[0].contains("windows-x64"));
}

#[test]
fn each_feature_release_is_its_own_repository() {
    let mock = Mock::start();
    mock.serve(TEMURIN_21, "[]");
    let config = GithubConfig {
        features: Some(vec![21, 17]),
        ..temurin()
    };
    let discovery = config.discover(&ORIGIN, &mock.context()).unwrap();
    assert!(discovery.candidates.is_empty());
    // temurin17-binaries does not exist on the mock server; that is a warning, not a failure.
    assert_eq!(discovery.warnings.len(), 1, "{:?}", discovery.warnings);
    assert!(discovery.warnings[0].contains("temurin17-binaries"));
}

#[test]
fn a_tag_can_be_rewritten_into_a_version_with_the_named_groups() {
    let mock = Mock::start();
    mock.serve(
        "/api.github.com/repos/adoptium/temurin8-binaries/releases",
        r#"[{"tag_name":"jdk8u432-b06","assets":[
        {"name":"OpenJDK8U-jdk_x64_linux_hotspot_8u432b06.tar.gz","size":9,
         "digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
         "browser_download_url":"https://github.com/adoptium/temurin8-binaries/x.tar.gz"}]}]"#,
    );
    let config = GithubConfig {
        features: Some(vec![8]),
        tag_pattern: r"jdk8u(?P<update>\d+)-b(?P<pad>0*)(?P<build>\d+)".to_owned(),
        version: "8.0.{update}+{build}".to_owned(),
        assets: BTreeMap::from([(
            "linux-x64".to_owned(),
            "OpenJDK{feature}U-jdk_x64_linux_hotspot_8u{update}b{pad}{build}.tar.gz".to_owned(),
        )]),
        hash_from: HashFrom::Digest,
        sidecar_suffix: None,
        signature_suffix: None,
        ..temurin()
    };
    let discovery = config.discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(versions(&discovery), ["8.0.432+6"]);
}

#[test]
fn the_tag_pattern_must_match_the_whole_tag() {
    let mock = Mock::start();
    mock.serve(
        KOTLIN,
        r#"[{"tag_name":"xv2.1.0","assets":[{"name":"kotlin-compiler-2.1.0.zip","size":1,
        "digest":"sha256:6666666666666666666666666666666666666666666666666666666666666666",
        "browser_download_url":"https://github.com/a.zip"}]},
        {"tag_name":"v2.1.0-rc-1-extra!","assets":[]}]"#,
    );
    let discovery = kotlin().discover(&ORIGIN, &mock.context()).unwrap();
    assert!(discovery.candidates.is_empty());
    assert!(discovery.warnings.is_empty());
}

#[test]
fn the_token_goes_to_the_api_but_not_to_the_checksum_download() {
    let mock = Mock::start();
    mock.serve(TEMURIN_21, fixture("github/temurin21-releases.json"));
    mock.serve(
        "/github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.5%2B11/\
         OpenJDK21U-jdk_x64_linux_hotspot_21.0.5_11.tar.gz.sha256.txt",
        "b".repeat(64),
    );
    let ctx = mock.context().with_github_token(Some("tok".to_owned()));
    temurin().discover(&ORIGIN, &ctx).unwrap();
    let requests = mock.requests();
    let api = requests
        .iter()
        .find(|r| r.url.path().ends_with("/releases"))
        .unwrap();
    assert_eq!(
        api.headers
            .get("authorization")
            .map(|v| v.to_str().unwrap()),
        Some("Bearer tok")
    );
    let download = requests
        .iter()
        .find(|r| r.url.path().ends_with(".sha256.txt"))
        .unwrap();
    assert!(download.headers.get("authorization").is_none());
}

#[test]
fn releases_are_paged_until_a_short_page() {
    let mock = Mock::start();
    let release = r#"{"tag_name":"nope","assets":[]}"#;
    let full = format!("[{}]", vec![release; PER_PAGE].join(","));
    mock.serve_query(KOTLIN, &[("page", "1")], full);
    mock.serve_query(KOTLIN, &[("page", "2")], format!("[{release}]"));
    kotlin().discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(mock.requested().len(), 2);
}

#[test]
fn the_page_bound_stops_a_runaway_listing_with_a_warning() {
    let mock = Mock::start();
    let release = r#"{"tag_name":"nope","assets":[]}"#;
    mock.serve(KOTLIN, format!("[{}]", vec![release; PER_PAGE].join(",")));
    let discovery = kotlin().discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(mock.requested().len(), 3);
    assert!(discovery.warnings[0].contains("stopped after 3 pages"));
}

#[test]
fn rate_limiting_fails_the_run() {
    let mock = Mock::start();
    mock.status(KOTLIN, 403);
    let err = kotlin().discover(&ORIGIN, &mock.context()).unwrap_err();
    assert_eq!(err.code().as_str(), "E_NETWORK");
}

#[test]
fn a_response_of_the_wrong_shape_fails_the_run() {
    let mock = Mock::start();
    mock.serve(KOTLIN, r#"{"message":"Bad credentials"}"#);
    let err = kotlin().discover(&ORIGIN, &mock.context()).unwrap_err();
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
}

#[test]
fn bad_settings_are_rejected_when_the_file_loads() {
    assert_eq!(kotlin().validate(), Ok(()));
    assert_eq!(temurin().validate(), Ok(()));
    let bad = |c: GithubConfig| c.validate().unwrap_err();

    let message = bad(GithubConfig {
        api_url: "http://api.github.com".to_owned(),
        ..kotlin()
    });
    assert!(message.contains("https"), "{message}");

    let message = bad(GithubConfig {
        repo: "JetBrains".to_owned(),
        ..kotlin()
    });
    assert!(message.contains("owner/name"), "{message}");

    let message = bad(GithubConfig {
        repo: "../kotlin/x".to_owned(),
        ..kotlin()
    });
    assert!(message.contains("owner/name"), "{message}");

    let message = bad(GithubConfig {
        features: None,
        ..temurin()
    });
    assert!(message.contains("features"), "{message}");

    let message = bad(GithubConfig {
        features: Some(vec![21]),
        ..kotlin()
    });
    assert!(message.contains("features"), "{message}");

    let message = bad(GithubConfig {
        tag_pattern: "v(".to_owned(),
        ..kotlin()
    });
    assert!(message.contains("tag_pattern"), "{message}");

    let message = bad(GithubConfig {
        version: "{versoin}".to_owned(),
        ..kotlin()
    });
    assert!(message.contains("versoin"), "{message}");

    let message = bad(GithubConfig {
        assets: BTreeMap::from([("beos-x64".to_owned(), "a.zip".to_owned())]),
        ..kotlin()
    });
    assert!(message.contains("beos-x64"), "{message}");

    let message = bad(GithubConfig {
        assets: BTreeMap::from([("any".to_owned(), "k-{build}.zip".to_owned())]),
        ..kotlin()
    });
    assert!(message.contains("build"), "{message}");

    let message = bad(GithubConfig {
        assets: BTreeMap::new(),
        ..kotlin()
    });
    assert!(message.contains("assets"), "{message}");

    let message = bad(GithubConfig {
        hash_from: HashFrom::Sidecar,
        ..kotlin()
    });
    assert!(message.contains("sidecar_suffix"), "{message}");

    let message = bad(GithubConfig {
        sidecar_suffix: Some(".sha256".to_owned()),
        ..kotlin()
    });
    assert!(message.contains("sidecar_suffix"), "{message}");

    let message = bad(GithubConfig {
        signature_suffix: Some("sig".to_owned()),
        ..kotlin()
    });
    assert!(message.contains("signature_suffix"), "{message}");

    let message = bad(GithubConfig {
        prerelease_tags: vec!["No Good".to_owned()],
        ..kotlin()
    });
    assert!(message.contains("tag"), "{message}");

    let message = bad(GithubConfig {
        max_pages: 0,
        ..kotlin()
    });
    assert!(message.contains("max_pages"), "{message}");
}
