use super::*;

const SHA256: &str = "31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26";
const SHA1: &str = "0b7641f3bf34a49f7350eafe39de4c97f4126991";

fn candidate() -> Candidate {
    Candidate {
        source: "vendor-api".to_owned(),
        variant: Some("temurin".to_owned()),
        version: "21.0.5+11".to_owned(),
        target: Target::Platform(Platform::LinuxX64),
        tags: vec!["lts".to_owned(), "ga".to_owned()],
        url: "https://example.test/jdk-21.0.5.tar.gz".to_owned(),
        archive: ArchiveKind::TarGz,
        size: Some(1234),
        hash: None,
        signature_url: None,
        distribution_version: None,
    }
}

#[test]
fn a_well_formed_candidate_passes() {
    assert_eq!(candidate().check(), Ok(()));
}

#[test]
fn urls_must_be_https_printable_and_bounded() {
    for bad in [
        "http://example.test/a.zip",
        "ftp://example.test/a.zip",
        "file:///etc/passwd",
        "https://",
        "https:///a.zip",
        "https://example.test/a b.zip",
        "https://example.test/\u{e9}.zip",
        "javascript:alert(1)",
    ] {
        let mut c = candidate();
        c.url = bad.to_owned();
        assert!(c.check().is_err(), "{bad} should be refused");
    }
    let mut long = candidate();
    long.url = format!("https://example.test/{}", "a".repeat(MAX_URL_LEN));
    assert!(long.check().is_err());
}

#[test]
fn the_signature_url_is_held_to_the_same_rules() {
    let mut c = candidate();
    c.signature_url = Some("http://example.test/a.asc".to_owned());
    assert!(c.check().is_err());
    c.signature_url = Some("https://example.test/a.asc".to_owned());
    assert_eq!(c.check(), Ok(()));
}

#[test]
fn versions_names_and_sizes_are_checked() {
    let mut c = candidate();
    c.version = "21 && rm -rf".to_owned();
    assert!(c.check().is_err());

    let mut c = candidate();
    c.variant = Some("Temurin".to_owned());
    assert!(c.check().is_err());

    let mut c = candidate();
    c.tags = vec!["has space".to_owned()];
    assert!(c.check().is_err());

    let mut c = candidate();
    c.size = Some(0);
    assert!(c.check().is_err());
}

#[test]
fn the_distribution_version_is_held_to_the_version_rules() {
    let mut c = candidate();
    c.distribution_version = Some("21.38.21".to_owned());
    assert_eq!(c.check(), Ok(()));
    c.distribution_version = Some("21.38 \"quoted\"".to_owned());
    assert!(c.check().is_err());
}

#[test]
fn discovery_drops_bad_candidates_with_a_warning() {
    let mut discovery = Discovery::default();
    discovery.push(candidate());
    let mut bad = candidate();
    bad.url = "http://example.test/a.zip".to_owned();
    discovery.push(bad);
    assert_eq!(discovery.candidates.len(), 1);
    assert_eq!(discovery.warnings.len(), 1);
    assert!(discovery.warnings[0].contains("vendor-api"));
    assert!(discovery.warnings[0].contains("21.0.5+11"));
}

#[test]
fn targets_round_trip_through_their_names() {
    assert_eq!(Target::parse("any"), Some(Target::Any));
    for platform in Platform::ALL {
        let target = Target::Platform(*platform);
        assert_eq!(Target::parse(target.as_str()), Some(target));
    }
    assert_eq!(Target::parse("linux-musl-aarch64"), None);
    assert_eq!(Target::parse(""), None);
}

#[test]
fn hash_algorithms_are_parsed_as_vendors_spell_them() {
    assert_eq!(HashAlgorithm::parse("SHA-256"), Some(HashAlgorithm::Sha256));
    assert_eq!(HashAlgorithm::parse("sha256"), Some(HashAlgorithm::Sha256));
    assert_eq!(HashAlgorithm::parse("sha_512"), Some(HashAlgorithm::Sha512));
    assert_eq!(HashAlgorithm::parse("SHA1"), Some(HashAlgorithm::Sha1));
    assert_eq!(HashAlgorithm::parse("md5"), None);
    assert_eq!(HashAlgorithm::parse("sha3_256"), None);
}

#[test]
fn claimed_hashes_are_normalised_and_length_checked() {
    let claim = ClaimedHash::new(HashAlgorithm::Sha256, &SHA256.to_uppercase(), "x").unwrap();
    assert_eq!(claim.hex, SHA256);
    assert!(ClaimedHash::new(HashAlgorithm::Sha256, SHA1, "x").is_none());
    assert!(ClaimedHash::new(HashAlgorithm::Sha1, SHA256, "x").is_none());
    let not_hex = "g".repeat(64);
    assert!(ClaimedHash::new(HashAlgorithm::Sha256, &not_hex, "x").is_none());
}

#[test]
fn archives_are_recognised_by_extension() {
    assert_eq!(archive_from_name("a-1.0-bin.zip"), Some(ArchiveKind::Zip));
    assert_eq!(archive_from_name("A.TAR.GZ"), Some(ArchiveKind::TarGz));
    assert_eq!(archive_from_name("a.tgz"), Some(ArchiveKind::TarGz));
    assert_eq!(archive_from_name("a.tar.xz"), Some(ArchiveKind::TarXz));
    assert_eq!(archive_from_name("a.msi"), None);
    assert_eq!(archive_from_name("a.pkg"), None);
    assert_eq!(archive_from_name("a.tar.gz.sha256"), None);
}

#[test]
fn checksum_files_in_every_published_form() {
    let sha256 = HashAlgorithm::Sha256;
    // A bare digest, as Gradle and Maven Central publish it, with and without a newline.
    assert_eq!(
        parse_checksum_file(SHA256, sha256, None).as_deref(),
        Some(SHA256)
    );
    assert_eq!(
        parse_checksum_file(&format!("{SHA256}\n"), sha256, None).as_deref(),
        Some(SHA256)
    );
    // `sha256sum` output, text and binary mode.
    assert_eq!(
        parse_checksum_file(&format!("{SHA256}  OpenJDK.tar.gz\n"), sha256, None).as_deref(),
        Some(SHA256)
    );
    assert_eq!(
        parse_checksum_file(&format!("{SHA256} *OpenJDK.tar.gz"), sha256, None).as_deref(),
        Some(SHA256)
    );
    // BSD style.
    assert_eq!(
        parse_checksum_file(&format!("SHA256 (OpenJDK.tar.gz) = {SHA256}"), sha256, None)
            .as_deref(),
        Some(SHA256)
    );
    // Upper case, split into groups of hex digits across spaces.
    let (a, b) = SHA1.split_at(20);
    assert_eq!(
        parse_checksum_file(
            &format!("{} {}", a.to_uppercase(), b.to_uppercase()),
            HashAlgorithm::Sha1,
            None
        )
        .as_deref(),
        Some(SHA1)
    );
}

#[test]
fn a_digest_listed_for_another_file_is_not_a_claim_for_this_one() {
    let sha256 = HashAlgorithm::Sha256;
    let other = "9".repeat(64);
    let wanted = Some("tool-1.0.zip");
    // The wrong file, in each spelling.
    assert_eq!(
        parse_checksum_file(&format!("{SHA256}  tool-2.0.zip"), sha256, wanted),
        None
    );
    assert_eq!(
        parse_checksum_file(&format!("{SHA256} *tool-2.0.zip"), sha256, wanted),
        None
    );
    assert_eq!(
        parse_checksum_file(&format!("SHA256 (tool-2.0.zip) = {SHA256}"), sha256, wanted),
        None
    );
    // The right file, in each spelling, including a path in front of the name.
    for line in [
        format!("{SHA256}  tool-1.0.zip"),
        format!("{SHA256} *tool-1.0.zip"),
        format!("{SHA256}  ./dist/tool-1.0.zip"),
        format!("SHA256 (tool-1.0.zip) = {SHA256}"),
        SHA256.to_owned(),
    ] {
        assert_eq!(
            parse_checksum_file(&line, sha256, wanted).as_deref(),
            Some(SHA256),
            "{line}"
        );
    }
    // A file listing several artifacts yields the line for the one asked about.
    let several = format!("{other}  tool-2.0.zip\n{SHA256}  tool-1.0.zip\n");
    assert_eq!(
        parse_checksum_file(&several, sha256, wanted).as_deref(),
        Some(SHA256)
    );
    assert_eq!(
        parse_checksum_file(&several, sha256, None).as_deref(),
        Some(other.as_str())
    );
    assert_eq!(
        parse_checksum_file(&several, sha256, Some("tool-3.0.zip")),
        None
    );
}

#[test]
fn a_hex_looking_file_name_is_not_part_of_the_digest() {
    let text = format!("{SHA256}  deadbeef");
    assert_eq!(
        parse_checksum_file(&text, HashAlgorithm::Sha256, None).as_deref(),
        Some(SHA256)
    );
}

#[test]
fn anything_else_is_not_a_digest() {
    let sha256 = HashAlgorithm::Sha256;
    assert_eq!(parse_checksum_file("", sha256, None), None);
    assert_eq!(parse_checksum_file("\n\n", sha256, None), None);
    assert_eq!(
        parse_checksum_file("<html>404 Not Found</html>", sha256, None),
        None
    );
    // The wrong algorithm for the file.
    assert_eq!(parse_checksum_file(SHA1, sha256, None), None);
    assert_eq!(parse_checksum_file(SHA256, HashAlgorithm::Sha1, None), None);
    // Too long.
    assert_eq!(
        parse_checksum_file(&format!("{SHA256}ab"), sha256, None),
        None
    );
    assert_eq!(
        parse_checksum_file(&format!("SHA256 (f) = {SHA256}ab"), sha256, None),
        None
    );
}

#[test]
fn the_recorded_sha512_sidecar_parses() {
    let text = include_str!("../../tests/fixtures/apache/apache-maven-3.9.9-bin.tar.gz.sha512");
    let digest = parse_checksum_file(text, HashAlgorithm::Sha512, None).unwrap();
    assert!(digest.starts_with("a555254d6b53d267"), "{digest}");
}
