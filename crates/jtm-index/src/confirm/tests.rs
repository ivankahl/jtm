use std::collections::BTreeMap;

use jtm_security::ArchiveKind;
use jtm_security::time::Timestamp;

use super::*;
use crate::candidate::ClaimedHash;
use crate::error::Reason;
use crate::testing::{Mock, TestKey, client};

/// The bytes every test artifact consists of, and their digests: the FIPS 180 vectors for
/// "abc", so the expected values come from the standard and not from the code under test.
const BODY: &[u8] = b"abc";
const SHA1: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
const SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const SHA512: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                      2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
const OTHER_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// A `sources.toml` listing `(id, role, extra settings)`. Every source uses the Gradle
/// adapter, which these tests never run: only the roles and flags matter here.
fn sources(specs: &[(&str, &str, &str)]) -> SourcesFile {
    let mut text = "schema = 1\n".to_owned();
    for (id, role, extra) in specs {
        text.push_str(&format!(
            "[[source]]\nid = \"{id}\"\nadapter = \"gradle\"\nrole = \"{role}\"\n{extra}\n"
        ));
    }
    SourcesFile::parse("sources.toml", &text).unwrap()
}

/// A candidate for version 1.0.0 with the claim `hash`, served from `/<path>`.
fn candidate(source: &str, hash: Option<(HashAlgorithm, &str)>) -> Candidate {
    Candidate {
        source: source.to_owned(),
        variant: None,
        version: "1.0.0".to_owned(),
        target: Target::Any,
        tags: vec!["ga".to_owned()],
        url: "https://vendor.test/a.zip".to_owned(),
        archive: ArchiveKind::Zip,
        size: None,
        hash: hash.map(|(algorithm, hex)| {
            ClaimedHash::new(algorithm, hex, &format!("{source}-file")).unwrap()
        }),
        signature_url: None,
        distribution_version: None,
    }
}

struct World {
    mock: Mock,
}

impl World {
    /// A vendor serving `BODY` at `/a.zip`.
    fn new() -> World {
        World::serving(BODY)
    }

    /// A vendor serving `body` at `/a.zip`.
    fn serving(body: impl Into<Vec<u8>>) -> World {
        let world = World {
            mock: Mock::start(),
        };
        world.mock.serve("/vendor/a.zip", body);
        world
    }

    /// A vendor that has taken `/a.zip` down.
    fn without_the_artifact() -> World {
        let world = World {
            mock: Mock::start(),
        };
        world.mock.status("/vendor/a.zip", 404);
        world
    }

    fn ctx(&self) -> Context {
        Context::new(client()).with_mirrors(BTreeMap::from([(
            "https://vendor.test/".to_owned(),
            self.mock.url("/vendor/"),
        )]))
    }

    fn confirm(
        &self,
        sources: &SourcesFile,
        keyrings: BTreeMap<String, Keyring>,
        candidates: Vec<Candidate>,
    ) -> Result<Confirmed> {
        Confirmer::new(&self.ctx(), sources, keyrings, Options::default()).confirm(candidates)
    }

    fn downloads(&self) -> usize {
        self.mock
            .requested()
            .iter()
            .filter(|p| p.ends_with("/a.zip"))
            .count()
    }
}

fn keyrings(source: &str, key: &TestKey) -> BTreeMap<String, Keyring> {
    BTreeMap::from([(
        source.to_owned(),
        Keyring::parse("test keys", key.public_armored().as_bytes()).unwrap(),
    )])
}

fn rejections(error: Error) -> Vec<Reason> {
    match error {
        Error::Rejected { rejections } => rejections.into_iter().map(|r| r.reason).collect(),
        other => panic!("expected a rejection, got {other}"),
    }
}

fn two_sources() -> SourcesFile {
    sources(&[("src-a", "primary", ""), ("src-b", "confirm", "")])
}

// ---------------------------------------------------------------------------------------------
// Two independent sources
// ---------------------------------------------------------------------------------------------

#[test]
fn two_sources_that_agree_with_the_download_confirm_the_entry() {
    let world = World::new();
    let confirmed = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![
                candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
            ],
        )
        .unwrap();
    assert!(confirmed.warnings.is_empty(), "{:?}", confirmed.warnings);
    let [entry] = confirmed.entries.as_slice() else {
        panic!("expected one entry: {:?}", confirmed.entries);
    };
    assert_eq!(entry.sha256, SHA256);
    assert_eq!(entry.size, 3);
    assert_eq!(entry.version, "1.0.0");
    assert_eq!(entry.target, Target::Any);
    assert_eq!(entry.url, "https://vendor.test/a.zip");
    assert_eq!(entry.tags, ["ga"]);
    assert_eq!(entry.provenance.confirmation, Confirmation::Independent);
    assert_eq!(entry.provenance.sources, ["src-a", "src-b"]);
    assert_eq!(entry.provenance.labels(), ["src-a", "src-b"]);
}

#[test]
fn a_sha512_claim_and_a_sha256_claim_confirm_each_other_through_the_download() {
    let world = World::new();
    let confirmed = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![
                candidate("src-a", Some((HashAlgorithm::Sha512, SHA512))),
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
            ],
        )
        .unwrap();
    // The SHA-256 in the entry is the generator's own, whatever the vendors published.
    assert_eq!(confirmed.entries[0].sha256, SHA256);
    assert_eq!(
        confirmed.entries[0].provenance.confirmation,
        Confirmation::Independent
    );
    let algorithms: Vec<_> = confirmed.entries[0]
        .provenance
        .claims
        .iter()
        .map(|c| (c.source.as_str(), c.algorithm))
        .collect();
    assert_eq!(
        algorithms,
        [
            ("src-a", HashAlgorithm::Sha512),
            ("src-b", HashAlgorithm::Sha256)
        ]
    );
}

#[test]
fn sources_that_disagree_fail_the_run_before_anything_is_downloaded() {
    let world = World::new();
    let error = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![
                candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", Some((HashAlgorithm::Sha256, OTHER_SHA256))),
            ],
        )
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_HASH_MISMATCH");
    let reasons = rejections(error);
    let [Reason::SourcesDisagree { algorithm, claims }] = reasons.as_slice() else {
        panic!("{reasons:?}");
    };
    assert_eq!(*algorithm, HashAlgorithm::Sha256);
    assert_eq!(
        claims,
        &[
            ("src-a".to_owned(), SHA256.to_owned()),
            ("src-b".to_owned(), OTHER_SHA256.to_owned())
        ]
    );
    assert_eq!(world.downloads(), 0);
}

#[test]
fn a_download_that_differs_from_what_both_sources_say_fails_the_run() {
    let world = World::serving(b"a different archive".to_vec());
    let error = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![
                candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
            ],
        )
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_HASH_MISMATCH");
    let reasons = rejections(error);
    assert!(
        matches!(&reasons[0], Reason::ClaimMismatch { claimed, .. } if claimed == SHA256),
        "{reasons:?}"
    );
}

#[test]
fn every_claim_is_held_against_the_download_including_a_corroborating_sha1() {
    let world = World::new();
    let wrong_sha1 = "0".repeat(40);
    let three = sources(&[
        ("src-a", "primary", ""),
        ("src-b", "confirm", ""),
        ("src-c", "confirm", ""),
    ]);
    let error = world
        .confirm(
            &three,
            BTreeMap::new(),
            vec![
                candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-c", Some((HashAlgorithm::Sha1, &wrong_sha1))),
            ],
        )
        .unwrap_err();
    let reasons = rejections(error);
    assert!(
        matches!(
            &reasons[0],
            Reason::ClaimMismatch {
                source_id,
                algorithm: HashAlgorithm::Sha1,
                ..
            } if source_id == "src-c"
        ),
        "{reasons:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// Too little evidence
// ---------------------------------------------------------------------------------------------

#[test]
fn one_source_alone_is_not_enough() {
    let world = World::new();
    let error = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![candidate("src-a", Some((HashAlgorithm::Sha256, SHA256)))],
        )
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_INDEX_INVALID");
    let reasons = rejections(error);
    assert!(
        matches!(&reasons[0], Reason::NotConfirmed { message } if message.contains("src-a")),
        "{reasons:?}"
    );
    assert_eq!(world.downloads(), 0, "refused before any bytes are fetched");
}

#[test]
fn sha1_never_confirms_anything_on_its_own() {
    let world = World::new();
    // Two sources, but both only publish SHA-1.
    let error = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![
                candidate("src-a", Some((HashAlgorithm::Sha1, SHA1))),
                candidate("src-b", Some((HashAlgorithm::Sha1, SHA1))),
            ],
        )
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_INDEX_INVALID");
    // One strong source plus one SHA-1 source is still one independent opinion.
    let error = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![
                candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", Some((HashAlgorithm::Sha1, SHA1))),
            ],
        )
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_INDEX_INVALID");
    assert_eq!(world.downloads(), 0);
}

#[test]
fn the_same_source_listed_twice_is_still_one_source() {
    let world = World::new();
    let confirmed = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![
                candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", None),
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", Some((HashAlgorithm::Sha512, SHA512))),
            ],
        )
        .unwrap();
    // src-b's claims are one source's, and `src-b` is listed once in the provenance.
    assert_eq!(confirmed.entries[0].provenance.sources, ["src-a", "src-b"]);

    let only_a = sources(&[("src-a", "primary", "")]);
    let error = world
        .confirm(
            &only_a,
            BTreeMap::new(),
            vec![
                candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-a", Some((HashAlgorithm::Sha512, SHA512))),
            ],
        )
        .unwrap_err();
    // Two candidates of the primary for one artifact are ambiguous, not two opinions.
    assert!(
        matches!(rejections(error)[0], Reason::AmbiguousPrimary { .. }),
        "ambiguous"
    );
}

#[test]
fn a_source_with_no_claim_adds_nothing() {
    let world = World::new();
    let error = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![
                candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", None),
            ],
        )
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_INDEX_INVALID");
}

// ---------------------------------------------------------------------------------------------
// Source plus the generator's own download
// ---------------------------------------------------------------------------------------------

fn sole() -> SourcesFile {
    sources(&[("foojay-x", "primary", "sole_source = true")])
}

#[test]
fn a_sole_source_is_confirmed_by_the_download_and_the_provenance_says_so() {
    let world = World::new();
    let confirmed = world
        .confirm(
            &sole(),
            BTreeMap::new(),
            vec![candidate("foojay-x", Some((HashAlgorithm::Sha256, SHA256)))],
        )
        .unwrap();
    let provenance = &confirmed.entries[0].provenance;
    assert_eq!(provenance.confirmation, Confirmation::SourceAndComputed);
    assert_eq!(provenance.labels(), ["foojay-x", "computed:sha256"]);
    assert_eq!(confirmed.entries[0].sha256, SHA256);
}

#[test]
fn a_sole_source_still_has_to_match_the_download() {
    let world = World::new();
    let error = world
        .confirm(
            &sole(),
            BTreeMap::new(),
            vec![candidate(
                "foojay-x",
                Some((HashAlgorithm::Sha256, OTHER_SHA256)),
            )],
        )
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_HASH_MISMATCH");
}

#[test]
fn a_sole_source_needs_a_strong_claim_not_sha1_or_nothing() {
    let world = World::new();
    for claim in [Some((HashAlgorithm::Sha1, SHA1)), None] {
        let error = world
            .confirm(&sole(), BTreeMap::new(), vec![candidate("foojay-x", claim)])
            .unwrap_err();
        assert_eq!(error.code().as_str(), "E_INDEX_INVALID");
    }
}

#[test]
fn without_the_sole_source_flag_one_source_and_a_download_are_not_enough() {
    let world = World::new();
    let plain = sources(&[("foojay-x", "primary", "")]);
    let error = world
        .confirm(
            &plain,
            BTreeMap::new(),
            vec![candidate("foojay-x", Some((HashAlgorithm::Sha256, SHA256)))],
        )
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_INDEX_INVALID");
}

// ---------------------------------------------------------------------------------------------
// Vendor signatures
// ---------------------------------------------------------------------------------------------

fn signed_candidate(source: &str, hash: Option<(HashAlgorithm, &str)>) -> Candidate {
    let mut c = candidate(source, hash);
    c.signature_url = Some("https://vendor.test/a.zip.asc".to_owned());
    c
}

#[test]
fn one_source_and_a_valid_vendor_signature_confirm_the_entry() {
    let world = World::new();
    let key = TestKey::primary("Vendor <v@example.test>");
    world
        .mock
        .serve("/vendor/a.zip.asc", key.armored_signature(BODY));
    let confirmed = world
        .confirm(
            &sources(&[("src-a", "primary", "")]),
            keyrings("src-a", &key),
            vec![signed_candidate(
                "src-a",
                Some((HashAlgorithm::Sha256, SHA256)),
            )],
        )
        .unwrap();
    let provenance = &confirmed.entries[0].provenance;
    assert_eq!(provenance.confirmation, Confirmation::SourceAndSignature);
    assert_eq!(provenance.labels(), ["src-a", "signature:pgp"]);
    let [signature] = provenance.signatures.as_slice() else {
        panic!("{:?}", provenance.signatures);
    };
    assert_eq!(signature.source, "src-a");
    assert_eq!(signature.url, "https://vendor.test/a.zip.asc");
    assert_eq!(
        signature.status,
        SignatureStatus::Verified {
            fingerprint: key.fingerprint()
        }
    );
}

#[test]
fn a_sha1_claim_and_a_valid_signature_confirm_the_entry() {
    // The Maven Central shape: only a SHA-1 is published, the signature carries the weight.
    let world = World::new();
    let key = TestKey::primary("Vendor <v@example.test>");
    world
        .mock
        .serve("/vendor/a.zip.asc", key.armored_signature(BODY));
    let confirmed = world
        .confirm(
            &sources(&[("src-a", "primary", "")]),
            keyrings("src-a", &key),
            vec![signed_candidate("src-a", Some((HashAlgorithm::Sha1, SHA1)))],
        )
        .unwrap();
    assert_eq!(
        confirmed.entries[0].provenance.confirmation,
        Confirmation::SourceAndSignature
    );
    assert_eq!(confirmed.entries[0].sha256, SHA256);
}

#[test]
fn a_signature_without_any_hash_claim_is_not_enough() {
    let world = World::new();
    let key = TestKey::primary("Vendor <v@example.test>");
    world
        .mock
        .serve("/vendor/a.zip.asc", key.armored_signature(BODY));
    let error = world
        .confirm(
            &sources(&[("src-a", "primary", "")]),
            keyrings("src-a", &key),
            vec![signed_candidate("src-a", None)],
        )
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_INDEX_INVALID");
}

#[test]
fn a_signature_that_does_not_hold_fails_the_run_even_when_two_sources_agree() {
    let world = World::new();
    let key = TestKey::primary("Vendor <v@example.test>");
    world.mock.serve(
        "/vendor/a.zip.asc",
        key.armored_signature(b"some other file"),
    );
    let error = world
        .confirm(
            &two_sources(),
            keyrings("src-a", &key),
            vec![
                signed_candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
            ],
        )
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_SIGNATURE_INVALID");
}

#[test]
fn a_signature_that_is_not_a_signature_fails_the_run() {
    let world = World::new();
    let key = TestKey::primary("Vendor <v@example.test>");
    world.mock.serve("/vendor/a.zip.asc", "<html>oops</html>");
    let error = world
        .confirm(
            &two_sources(),
            keyrings("src-a", &key),
            vec![
                signed_candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
            ],
        )
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_SIGNATURE_INVALID");
}

#[test]
fn a_signature_by_an_unknown_key_is_recorded_but_proves_nothing() {
    let world = World::new();
    let trusted = TestKey::primary("Trusted <t@example.test>");
    let stranger = TestKey::primary("Stranger <s@example.test>");
    world
        .mock
        .serve("/vendor/a.zip.asc", stranger.armored_signature(BODY));

    // Two sources agree, so the entry stands; the signature is noted as unverified.
    let confirmed = world
        .confirm(
            &two_sources(),
            keyrings("src-a", &trusted),
            vec![
                signed_candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
            ],
        )
        .unwrap();
    let provenance = &confirmed.entries[0].provenance;
    assert_eq!(provenance.confirmation, Confirmation::Independent);
    assert!(matches!(
        provenance.signatures[0].status,
        SignatureStatus::Unverified { .. }
    ));
    assert_eq!(provenance.labels(), ["src-a", "src-b"]);

    // With one source it cannot stand in for a second opinion.
    let error = world
        .confirm(
            &sources(&[("src-a", "primary", "")]),
            keyrings("src-a", &trusted),
            vec![signed_candidate(
                "src-a",
                Some((HashAlgorithm::Sha256, SHA256)),
            )],
        )
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_INDEX_INVALID");
}

#[test]
fn a_source_without_signing_keys_cannot_verify_its_signatures() {
    let world = World::new();
    let key = TestKey::primary("Vendor <v@example.test>");
    world
        .mock
        .serve("/vendor/a.zip.asc", key.armored_signature(BODY));
    // No keyring for src-a: refused up front, with the reason spelled out.
    let error = world
        .confirm(
            &sources(&[("src-a", "primary", "")]),
            BTreeMap::new(),
            vec![signed_candidate(
                "src-a",
                Some((HashAlgorithm::Sha256, SHA256)),
            )],
        )
        .unwrap_err();
    let reasons = rejections(error);
    assert!(
        matches!(&reasons[0], Reason::NotConfirmed { message } if message.contains("signing_keys")),
        "{reasons:?}"
    );
}

#[test]
fn a_signature_the_vendor_does_not_publish_is_recorded_as_missing() {
    let world = World::new();
    world.mock.status("/vendor/a.zip.asc", 404);
    let key = TestKey::primary("Vendor <v@example.test>");
    let confirmed = world
        .confirm(
            &two_sources(),
            keyrings("src-a", &key),
            vec![
                signed_candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
            ],
        )
        .unwrap();
    assert_eq!(
        confirmed.entries[0].provenance.signatures[0].status,
        SignatureStatus::NotPublished
    );
}

// ---------------------------------------------------------------------------------------------
// Sizes, limits and the shape of the input
// ---------------------------------------------------------------------------------------------

#[test]
fn a_claimed_size_must_match_the_download() {
    let world = World::new();
    let mut a = candidate("src-a", Some((HashAlgorithm::Sha256, SHA256)));
    a.size = Some(3);
    let mut b = candidate("src-b", Some((HashAlgorithm::Sha256, SHA256)));
    b.size = Some(2);
    let error = world
        .confirm(&two_sources(), BTreeMap::new(), vec![a.clone(), b])
        .unwrap_err();
    let reasons = rejections(error);
    assert!(
        matches!(
            &reasons[0],
            Reason::SizeMismatch {
                source_id,
                claimed: 2,
                measured: 3
            } if source_id == "src-b"
        ),
        "{reasons:?}"
    );

    a.size = Some(3);
    let confirmed = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![a, candidate("src-b", Some((HashAlgorithm::Sha256, SHA256)))],
        )
        .unwrap();
    assert_eq!(confirmed.entries[0].size, 3);
}

#[test]
fn a_download_larger_than_the_cap_is_aborted() {
    let world = World::serving(vec![b'x'; 5000]);
    let ctx = world.ctx();
    let options = Options {
        max_artifact_bytes: 1000,
    };
    let error = Confirmer::new(&ctx, &two_sources(), BTreeMap::new(), options)
        .confirm(vec![
            candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
            candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
        ])
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_SIZE_EXCEEDED");
}

#[test]
fn an_artifact_the_vendor_no_longer_serves_fails_the_run() {
    let world = World::without_the_artifact();
    let error = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![
                candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
            ],
        )
        .unwrap_err();
    assert_eq!(error.code().as_str(), "E_NETWORK");
}

#[test]
fn two_primary_candidates_for_one_artifact_are_ambiguous() {
    let world = World::new();
    let mut other = candidate("src-a", Some((HashAlgorithm::Sha256, SHA256)));
    other.url = "https://vendor.test/b.zip".to_owned();
    let error = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![
                candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                other,
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
            ],
        )
        .unwrap_err();
    let reasons = rejections(error);
    assert!(
        matches!(&reasons[0], Reason::AmbiguousPrimary { urls } if urls.len() == 2),
        "{reasons:?}"
    );
    assert_eq!(world.downloads(), 0);
}

#[test]
fn an_exact_duplicate_from_the_primary_is_harmless() {
    let world = World::new();
    let a = candidate("src-a", Some((HashAlgorithm::Sha256, SHA256)));
    let confirmed = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![
                a.clone(),
                a,
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
            ],
        )
        .unwrap();
    assert_eq!(confirmed.entries.len(), 1);
}

#[test]
fn a_candidate_from_a_source_that_is_not_listed_is_refused() {
    let world = World::new();
    let error = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![candidate("ghost", Some((HashAlgorithm::Sha256, SHA256)))],
        )
        .unwrap_err();
    assert!(
        matches!(&rejections(error)[0], Reason::UnknownSource { source_id } if source_id == "ghost")
    );
}

#[test]
fn what_only_a_confirming_source_knows_is_reported_not_published() {
    let world = World::new();
    let mut extra = candidate("src-b", Some((HashAlgorithm::Sha256, SHA256)));
    extra.version = "0.9.0".to_owned();
    let confirmed = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![
                candidate("src-a", Some((HashAlgorithm::Sha256, SHA256))),
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
                extra,
            ],
        )
        .unwrap();
    assert_eq!(confirmed.entries.len(), 1);
    assert_eq!(confirmed.warnings.len(), 1);
    assert!(
        confirmed.warnings[0].contains("0.9.0"),
        "{:?}",
        confirmed.warnings
    );
    assert!(
        confirmed.warnings[0].contains("src-b"),
        "{:?}",
        confirmed.warnings
    );
}

#[test]
fn every_problem_is_reported_together_and_nothing_is_published() {
    let world = World::new();
    let mut second = candidate("src-a", Some((HashAlgorithm::Sha256, SHA256)));
    second.version = "2.0.0".to_owned();
    let mut third = candidate("src-a", Some((HashAlgorithm::Sha256, SHA256)));
    third.version = "3.0.0".to_owned();
    let mut third_b = candidate("src-b", Some((HashAlgorithm::Sha256, OTHER_SHA256)));
    third_b.version = "3.0.0".to_owned();
    let mut good = candidate("src-a", Some((HashAlgorithm::Sha256, SHA256)));
    good.version = "1.0.0".to_owned();
    let error = world
        .confirm(
            &two_sources(),
            BTreeMap::new(),
            vec![
                good,
                candidate("src-b", Some((HashAlgorithm::Sha256, SHA256))),
                second,
                third,
                third_b,
            ],
        )
        .unwrap_err();
    let Error::Rejected { rejections } = error else {
        panic!("expected a rejection");
    };
    let versions: Vec<_> = rejections.iter().map(|r| r.version.as_str()).collect();
    assert_eq!(versions, ["2.0.0", "3.0.0"]);
    assert_eq!(
        world.downloads(),
        0,
        "the good entry was not fetched either"
    );
}

#[test]
fn entries_come_out_in_a_stable_order_with_a_fetch_time() {
    let world = World::new();
    let mut candidates = Vec::new();
    for version in ["2.0.0", "1.0.0", "10.0.0"] {
        for source in ["src-b", "src-a"] {
            let mut c = candidate(source, Some((HashAlgorithm::Sha256, SHA256)));
            c.version = version.to_owned();
            candidates.push(c);
        }
    }
    let confirmed = world
        .confirm(&two_sources(), BTreeMap::new(), candidates)
        .unwrap();
    let versions: Vec<_> = confirmed
        .entries
        .iter()
        .map(|e| e.version.as_str())
        .collect();
    assert_eq!(versions, ["1.0.0", "10.0.0", "2.0.0"]);
    for entry in &confirmed.entries {
        let fetched = Timestamp::parse(&entry.provenance.fetched_at).unwrap();
        let age = Timestamp::now().unix() - fetched.unix();
        assert!((0..60).contains(&age), "fetched {age}s ago");
    }
}

#[test]
fn variants_and_platforms_are_confirmed_separately() {
    let world = World::new();
    let both = sources(&[
        ("src-a", "primary", "variant = \"one\""),
        ("src-b", "confirm", "variant = \"one\""),
        ("src-c", "primary", "variant = \"two\"\nsole_source = true"),
    ]);
    let mut candidates = Vec::new();
    for source in ["src-a", "src-b"] {
        let mut c = candidate(source, Some((HashAlgorithm::Sha256, SHA256)));
        c.variant = Some("one".to_owned());
        candidates.push(c);
    }
    let mut c = candidate("src-c", Some((HashAlgorithm::Sha256, SHA256)));
    c.variant = Some("two".to_owned());
    candidates.push(c);
    let confirmed = world.confirm(&both, BTreeMap::new(), candidates).unwrap();
    let got: Vec<_> = confirmed
        .entries
        .iter()
        .map(|e| (e.variant.as_deref(), e.provenance.confirmation))
        .collect();
    assert_eq!(
        got,
        [
            (Some("one"), Confirmation::Independent),
            (Some("two"), Confirmation::SourceAndComputed)
        ]
    );
}

#[test]
fn provenance_serialises_for_the_index_writer() {
    let world = World::new();
    let confirmed = world
        .confirm(
            &sole(),
            BTreeMap::new(),
            vec![candidate("foojay-x", Some((HashAlgorithm::Sha256, SHA256)))],
        )
        .unwrap();
    let json = serde_json::to_value(&confirmed.entries[0].provenance).unwrap();
    assert_eq!(json["confirmation"], "source-and-computed");
    assert_eq!(json["sources"][0], "foojay-x");
    assert_eq!(json["claims"][0]["algorithm"], "sha256");
    assert_eq!(json["claims"][0]["source"], "foojay-x");
}

// ---------------------------------------------------------------------------------------------
// Keyrings from disk
// ---------------------------------------------------------------------------------------------

#[test]
fn keyrings_are_read_from_the_files_each_source_names() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("keys")).unwrap();
    let first = TestKey::primary("First <a@example.test>");
    let second = TestKey::primary("Second <b@example.test>");
    std::fs::write(dir.path().join("keys/first.asc"), first.public_armored()).unwrap();
    std::fs::write(dir.path().join("keys/second.asc"), second.public_armored()).unwrap();
    let file = sources(&[
        (
            "src-a",
            "primary",
            "signing_keys = [\"keys/first.asc\", \"keys/second.asc\"]",
        ),
        ("src-b", "confirm", ""),
    ]);
    let rings = Confirmer::load_keyrings(dir.path(), &file).unwrap();
    assert_eq!(rings.keys().collect::<Vec<_>>(), ["src-a"]);
    assert_eq!(rings["src-a"].len(), 2);
}

#[test]
fn a_missing_or_empty_key_file_fails_loading() {
    let dir = tempfile::tempdir().unwrap();
    let file = sources(&[("src-a", "primary", "signing_keys = [\"keys/missing.asc\"]")]);
    let error = Confirmer::load_keyrings(dir.path(), &file).unwrap_err();
    assert_eq!(error.code().as_str(), "E_PLUGIN_INVALID");
    assert!(error.to_string().contains("missing.asc"), "{error}");

    std::fs::create_dir(dir.path().join("keys")).unwrap();
    std::fs::write(dir.path().join("keys/missing.asc"), "no keys\n").unwrap();
    let error = Confirmer::load_keyrings(dir.path(), &file).unwrap_err();
    assert!(error.to_string().contains("no PGP public key"), "{error}");
}
