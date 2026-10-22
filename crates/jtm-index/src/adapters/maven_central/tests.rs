use super::*;
use crate::testing::{Mock, fixture};

const BASE: &str = "/repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-cli";
const SHA1_3_3_5: &str = "0b7641f3bf34a49f7350eafe39de4c97f4126991";
const ORIGIN: Origin<'_> = Origin {
    id: "maven-central",
    variant: None,
};

fn config() -> MavenCentralConfig {
    MavenCentralConfig {
        repository: DEFAULT_REPOSITORY.to_owned(),
        group: "org.springframework.boot".to_owned(),
        artifact: "spring-boot-cli".to_owned(),
        classifier: Some("bin".to_owned()),
        extension: "tar.gz".to_owned(),
        hashes: vec!["sha256".to_owned(), "sha1".to_owned()],
        signature: true,
        version_pattern: Some(r"^3\.3\.5$".to_owned()),
    }
}

fn mock() -> Mock {
    let mock = Mock::start();
    mock.serve(
        &format!("{BASE}/maven-metadata.xml"),
        fixture("maven-central/maven-metadata.xml"),
    );
    // Central publishes no .sha256 for this artifact (404 here), only the .sha1 recorded.
    mock.serve(
        &format!("{BASE}/3.3.5/spring-boot-cli-3.3.5-bin.tar.gz.sha1"),
        fixture("maven-central/spring-boot-cli-3.3.5-bin.tar.gz.sha1"),
    );
    mock
}

#[test]
fn the_recorded_metadata_lists_every_version_once() {
    let versions = metadata_versions(&fixture("maven-central/maven-metadata.xml"));
    assert!(versions.len() > 100, "{}", versions.len());
    assert_eq!(versions.first().map(String::as_str), Some("1.0.0.RELEASE"));
    assert!(versions.contains(&"3.3.5".to_owned()));
    let mut sorted = versions.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), versions.len());
}

#[test]
fn only_versions_inside_the_versions_element_count() {
    let xml = "<metadata><versioning><latest>9.9</latest><release>9.9</release>\
               <versions><version>1.0</version> <version>1.1</version><version>1.0</version>\
               </versions></versioning><version>8.8</version></metadata>";
    assert_eq!(metadata_versions(xml), ["1.0", "1.1"]);
    assert!(metadata_versions("<metadata/>").is_empty());
    assert!(metadata_versions("<versions><version>1.0").is_empty());
}

#[test]
fn builds_the_candidate_from_the_recorded_sha1() {
    let mock = mock();
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(discovery.candidates.len(), 1, "{:?}", discovery.warnings);
    let candidate = &discovery.candidates[0];
    assert_eq!(candidate.version, "3.3.5");
    assert_eq!(candidate.target, Target::Any);
    assert_eq!(candidate.archive, jtm_security::ArchiveKind::TarGz);
    assert_eq!(
        candidate.url,
        "https://repo.maven.apache.org/maven2/org/springframework/boot/spring-boot-cli/3.3.5/\
         spring-boot-cli-3.3.5-bin.tar.gz"
    );
    assert_eq!(
        candidate.signature_url.as_deref(),
        Some(format!("{}.asc", candidate.url).as_str())
    );
    let hash = candidate.hash.as_ref().unwrap();
    assert_eq!(hash.algorithm, HashAlgorithm::Sha1);
    assert_eq!(hash.hex, SHA1_3_3_5);
}

#[test]
fn the_strongest_published_checksum_wins() {
    let mock = mock();
    let sha256 = "4444444444444444444444444444444444444444444444444444444444444444";
    mock.serve(
        &format!("{BASE}/3.3.5/spring-boot-cli-3.3.5-bin.tar.gz.sha256"),
        sha256,
    );
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    let hash = discovery.candidates[0].hash.as_ref().unwrap();
    assert_eq!(hash.algorithm, HashAlgorithm::Sha256);
    assert_eq!(hash.hex, sha256);
}

#[test]
fn an_unparsable_checksum_falls_back_to_the_next_algorithm() {
    let mock = mock();
    mock.serve(
        &format!("{BASE}/3.3.5/spring-boot-cli-3.3.5-bin.tar.gz.sha256"),
        "<html>not a digest</html>",
    );
    let discovery = config().discover(&ORIGIN, &mock.context()).unwrap();
    let hash = discovery.candidates[0].hash.as_ref().unwrap();
    assert_eq!(hash.algorithm, HashAlgorithm::Sha1);
}

#[test]
fn versions_without_any_checksum_are_skipped_with_a_warning() {
    let mock = mock();
    let wider = MavenCentralConfig {
        version_pattern: Some(r"^3\.3\.[45]$".to_owned()),
        ..config()
    };
    let discovery = wider.discover(&ORIGIN, &mock.context()).unwrap();
    assert_eq!(discovery.candidates.len(), 1);
    assert_eq!(discovery.warnings.len(), 1);
    assert!(
        discovery.warnings[0].contains("3.3.4"),
        "{:?}",
        discovery.warnings
    );
}

#[test]
fn versions_that_are_not_plain_path_segments_are_never_requested() {
    let mock = Mock::start();
    mock.serve(
        &format!("{BASE}/maven-metadata.xml"),
        "<versions><version>../../evil</version><version>1.0+x</version></versions>",
    );
    let open = MavenCentralConfig {
        version_pattern: None,
        ..config()
    };
    let discovery = open.discover(&ORIGIN, &mock.context()).unwrap();
    assert!(discovery.candidates.is_empty());
    assert_eq!(discovery.warnings.len(), 2);
    assert_eq!(mock.requested().len(), 1, "{:?}", mock.requested());
}

#[test]
fn the_signature_can_be_left_out_and_there_may_be_no_classifier() {
    let mock = Mock::start();
    mock.serve(
        &format!("{BASE}/maven-metadata.xml"),
        "<versions><version>1.0</version></versions>",
    );
    mock.serve(
        &format!("{BASE}/1.0/spring-boot-cli-1.0.zip.sha1"),
        SHA1_3_3_5,
    );
    let plain = MavenCentralConfig {
        classifier: None,
        extension: "zip".to_owned(),
        hashes: vec!["sha1".to_owned()],
        signature: false,
        version_pattern: None,
        ..config()
    };
    let discovery = plain.discover(&ORIGIN, &mock.context()).unwrap();
    let candidate = &discovery.candidates[0];
    assert!(candidate.url.ends_with("/1.0/spring-boot-cli-1.0.zip"));
    assert_eq!(candidate.archive, jtm_security::ArchiveKind::Zip);
    assert_eq!(candidate.signature_url, None);
}

#[test]
fn metadata_without_versions_is_an_error() {
    let mock = Mock::start();
    mock.serve(
        &format!("{BASE}/maven-metadata.xml"),
        "<metadata></metadata>",
    );
    let err = config().discover(&ORIGIN, &mock.context()).unwrap_err();
    assert_eq!(err.code().as_str(), "E_INDEX_INVALID");
}

#[test]
fn rate_limiting_fails_the_run_rather_than_dropping_versions() {
    let mock = Mock::start();
    mock.status(&format!("{BASE}/maven-metadata.xml"), 429);
    let err = config().discover(&ORIGIN, &mock.context()).unwrap_err();
    assert_eq!(err.code().as_str(), "E_NETWORK");
}

#[test]
fn bad_settings_are_rejected_when_the_file_loads() {
    assert_eq!(config().validate(), Ok(()));
    let bad = |c: MavenCentralConfig| c.validate().unwrap_err();

    let message = bad(MavenCentralConfig {
        repository: "http://repo.example/".to_owned(),
        ..config()
    });
    assert!(message.contains("https"), "{message}");

    let message = bad(MavenCentralConfig {
        group: "org/evil".to_owned(),
        ..config()
    });
    assert!(message.contains("group"), "{message}");

    let message = bad(MavenCentralConfig {
        artifact: "../x".to_owned(),
        ..config()
    });
    assert!(message.contains("artifact"), "{message}");

    let message = bad(MavenCentralConfig {
        classifier: Some("a b".to_owned()),
        ..config()
    });
    assert!(message.contains("classifier"), "{message}");

    let message = bad(MavenCentralConfig {
        extension: "jar".to_owned(),
        ..config()
    });
    assert!(message.contains("extension"), "{message}");

    let message = bad(MavenCentralConfig {
        hashes: Vec::new(),
        ..config()
    });
    assert!(message.contains("hashes"), "{message}");

    let message = bad(MavenCentralConfig {
        hashes: vec!["md5".to_owned()],
        ..config()
    });
    assert!(message.contains("md5"), "{message}");

    let message = bad(MavenCentralConfig {
        version_pattern: Some("[".to_owned()),
        ..config()
    });
    assert!(message.contains("version_pattern"), "{message}");
}
