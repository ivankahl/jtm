use super::*;
use jtm_security::testing::TestKey;

const NOW: Timestamp = Timestamp::from_unix(1_800_000_000);
const IN_30_DAYS: &str = "2027-01-17T08:00:00Z";
const IN_120_DAYS: &str = "2027-05-17T08:00:00Z";
const EXPIRED: &str = "2026-01-01T00:00:00Z";

fn ts(text: &str) -> Timestamp {
    Timestamp::parse(text).unwrap()
}

struct Roots {
    keys: [TestKey; 3],
}

impl Roots {
    fn new() -> Roots {
        Roots {
            keys: [
                TestKey::generate(),
                TestKey::generate(),
                TestKey::generate(),
            ],
        }
    }

    fn public(&self) -> Vec<String> {
        self.keys.iter().map(TestKey::public_str).collect()
    }

    /// Two plugins, both anchored on the three roots at 2 of 3.
    fn first_party(&self) -> Vec<FirstParty> {
        ["alpha", "beta"]
            .into_iter()
            .map(|name| FirstParty {
                plugin: name.to_owned(),
                keys: self.public(),
                threshold: 2,
            })
            .collect()
    }

    /// Co-signatures from the given roots, concatenated into one `.minisig` file.
    fn sign(&self, data: &[u8], signers: &[usize]) -> Vec<u8> {
        signers
            .iter()
            .flat_map(|i| self.keys[*i].sign(data))
            .collect()
    }
}

/// A change to a valid spec that makes it invalid.
type Change = Box<dyn Fn(&mut BuildSpec)>;

fn spec(index_key: &TestKey, expires: &str) -> BuildSpec {
    BuildSpec {
        sequence: 8,
        threshold: 1,
        keys: vec![(index_key.public_str(), ts(expires))],
        scope: None,
        previous_sequence: None,
    }
}

/// A built `keys.json` for the two test plugins and its signature by roots 0 and 1.
fn signed(roots: &Roots) -> (Vec<u8>, Vec<u8>) {
    let bytes = build(
        &spec(&TestKey::generate(), IN_30_DAYS),
        &roots.first_party(),
        NOW,
    )
    .unwrap();
    let sigs = roots.sign(&bytes, &[0, 1]);
    (bytes, sigs)
}

fn raw_keys_file(keys: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({
        "format": 1, "sequence": 9, "threshold": 1, "keys": keys
    }))
    .unwrap()
}

#[test]
fn build_lists_the_index_key_for_every_first_party_plugin() {
    let roots = Roots::new();
    let index = TestKey::generate();
    let bytes = build(&spec(&index, IN_30_DAYS), &roots.first_party(), NOW).unwrap();

    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["format"], 1);
    assert_eq!(value["sequence"], 8);
    assert_eq!(value["threshold"], 1);
    assert_eq!(value["keys"][0]["key"], index.public_str());
    assert_eq!(
        value["keys"][0]["scope"],
        serde_json::json!(["alpha", "beta"])
    );
    assert_eq!(value["keys"][0]["expires"], IN_30_DAYS);
    assert!(bytes.ends_with(b"}\n"), "ends with a single newline");
}

#[test]
fn built_file_signed_by_two_roots_passes_the_client_loader() {
    let roots = Roots::new();
    let (bytes, sigs) = signed(&roots);
    let report = verify(&bytes, &sigs, &VerifySpec::new(roots.first_party()), NOW).unwrap();
    assert_eq!(report.sequence, 8);
    assert_eq!(report.plugins, vec!["alpha", "beta"]);
    assert_eq!(report.signers.len(), 2);
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    assert_eq!(report.sha256, jtm_security::sha256_hex(&bytes));
}

#[test]
fn build_scope_can_name_a_subset_of_the_first_party_plugins() {
    let roots = Roots::new();
    let mut s = spec(&TestKey::generate(), IN_30_DAYS);
    s.scope = Some(vec!["beta".to_owned()]);
    let bytes = build(&s, &roots.first_party(), NOW).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["keys"][0]["scope"], serde_json::json!(["beta"]));
}

/// There is no marketplace any more (ADR 0002), so its scope is not special.
#[test]
fn build_scope_cannot_name_the_marketplace() {
    let roots = Roots::new();
    let mut s = spec(&TestKey::generate(), IN_30_DAYS);
    s.scope = Some(vec!["marketplace".to_owned(), "alpha".to_owned()]);
    let err = build(&s, &roots.first_party(), NOW).unwrap_err();
    assert!(
        err.to_string()
            .contains("`marketplace` is not a first-party plugin"),
        "{err}"
    );
}

#[test]
fn verify_warns_about_a_key_scoped_to_the_marketplace() {
    let roots = Roots::new();
    let raw = raw_keys_file(serde_json::json!([
        { "key": TestKey::generate().public_str(), "scope": ["alpha", "beta", "marketplace"], "expires": IN_30_DAYS }
    ]));
    let report = verify(
        &raw,
        &roots.sign(&raw, &[0, 1]),
        &VerifySpec::new(roots.first_party()),
        NOW,
    )
    .unwrap();
    let all = report.warnings.join("\n");
    assert!(all.contains("marketplace"), "{all}");
}

#[test]
fn signers_are_reported_across_every_plugin() {
    let roots = Roots::new();
    let (bytes, _) = signed(&roots);
    let sigs = roots.sign(&bytes, &[0, 1, 2]);
    let report = verify(&bytes, &sigs, &VerifySpec::new(roots.first_party()), NOW).unwrap();
    assert_eq!(report.signers.len(), 3);
}

#[test]
fn failures_have_error_codes_and_messages_without_them() {
    let roots = Roots::new();
    let err = build(
        &BuildSpec {
            sequence: 0,
            ..spec(&TestKey::generate(), IN_30_DAYS)
        },
        &roots.first_party(),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.code(), "E_USAGE");
    let (bytes, _) = signed(&roots);
    let err = verify(
        &bytes,
        &roots.sign(&bytes, &[1]),
        &VerifySpec::new(roots.first_party()),
        NOW,
    )
    .unwrap_err();
    assert!(err.to_string().starts_with("E_SIGNATURE_INVALID: "));
    assert!(
        !err.message().contains("E_SIGNATURE_INVALID"),
        "{}",
        err.message()
    );
}

#[test]
fn build_refuses_a_scope_naming_a_plugin_that_is_not_first_party() {
    let roots = Roots::new();
    let mut s = spec(&TestKey::generate(), IN_30_DAYS);
    s.scope = Some(vec!["acme-flyway".to_owned()]);
    let err = build(&s, &roots.first_party(), NOW).unwrap_err();
    assert!(err.to_string().contains("acme-flyway"), "{err}");
    assert_eq!(err.exit_code(), 2);
}

#[test]
fn build_refuses_bad_inputs() {
    let roots = Roots::new();
    let fp = roots.first_party();
    let index = TestKey::generate();
    let cases: Vec<(&str, Change)> = vec![
        ("sequence 0", Box::new(|s| s.sequence = 0)),
        (
            "threshold above the key count",
            Box::new(|s| s.threshold = 2),
        ),
        ("threshold 0", Box::new(|s| s.threshold = 0)),
        ("no keys", Box::new(|s| s.keys.clear())),
        (
            "duplicate key",
            Box::new(|s| s.keys.push(s.keys[0].clone())),
        ),
        (
            "malformed key",
            Box::new(|s| s.keys[0].0 = "not-a-key".to_owned()),
        ),
        ("empty scope", Box::new(|s| s.scope = Some(Vec::new()))),
    ];
    for (name, change) in cases {
        let mut s = spec(&index, IN_30_DAYS);
        change(&mut s);
        let err = build(&s, &fp, NOW).expect_err(name);
        assert_eq!(err.exit_code(), 2, "{name}");
    }
}

#[test]
fn build_requires_a_sequence_above_the_published_one() {
    let roots = Roots::new();
    let mut s = spec(&TestKey::generate(), IN_30_DAYS);
    s.previous_sequence = Some(7);
    build(&s, &roots.first_party(), NOW).unwrap();
    s.previous_sequence = Some(8);
    let err = build(&s, &roots.first_party(), NOW).unwrap_err();
    assert!(err.to_string().contains("sequence"), "{err}");
}

#[test]
fn build_refuses_an_expiry_in_the_past_or_beyond_ninety_days() {
    let roots = Roots::new();
    let fp = roots.first_party();
    let index = TestKey::generate();
    let err = build(&spec(&index, EXPIRED), &fp, NOW).unwrap_err();
    assert!(err.to_string().contains("expire"), "{err}");
    let err = build(&spec(&index, IN_120_DAYS), &fp, NOW).unwrap_err();
    assert!(err.to_string().contains("90 days"), "{err}");
}

#[test]
fn build_refuses_to_delegate_to_a_root_key() {
    let roots = Roots::new();
    let err = build(&spec(&roots.keys[1], IN_30_DAYS), &roots.first_party(), NOW).unwrap_err();
    assert!(err.to_string().contains("root key"), "{err}");
}

#[test]
fn verify_refuses_one_root_signature_when_two_are_needed() {
    let roots = Roots::new();
    let (bytes, _) = signed(&roots);
    let one = roots.sign(&bytes, &[1]);
    let err = verify(&bytes, &one, &VerifySpec::new(roots.first_party()), NOW).unwrap_err();
    assert_eq!(err.code(), "E_SIGNATURE_INVALID");
    assert_eq!(err.exit_code(), 5);
}

#[test]
fn verify_refuses_a_signature_by_keys_that_are_not_roots() {
    let roots = Roots::new();
    let (bytes, _) = signed(&roots);
    let sigs = [
        TestKey::generate().sign(&bytes),
        TestKey::generate().sign(&bytes),
    ]
    .concat();
    let err = verify(&bytes, &sigs, &VerifySpec::new(roots.first_party()), NOW).unwrap_err();
    assert_eq!(err.code(), "E_KEY_UNTRUSTED");
    assert_eq!(err.exit_code(), 7);
}

#[test]
fn verify_refuses_a_file_edited_after_signing() {
    let roots = Roots::new();
    let (bytes, sigs) = signed(&roots);
    let edited = String::from_utf8(bytes)
        .unwrap()
        .replace("\"sequence\": 8", "\"sequence\": 9");
    let err = verify(
        edited.as_bytes(),
        &sigs,
        &VerifySpec::new(roots.first_party()),
        NOW,
    )
    .unwrap_err();
    assert_eq!(err.code(), "E_SIGNATURE_INVALID");
}

#[test]
fn verify_refuses_legacy_signatures() {
    let roots = Roots::new();
    let (bytes, _) = signed(&roots);
    let sigs = [
        roots.keys[0].sign_legacy(&bytes),
        roots.keys[1].sign_legacy(&bytes),
    ]
    .concat();
    let err = verify(&bytes, &sigs, &VerifySpec::new(roots.first_party()), NOW).unwrap_err();
    assert!(err.to_string().contains("legacy"), "{err}");
}

#[test]
fn verify_requires_a_sequence_above_the_published_one() {
    let roots = Roots::new();
    let (bytes, sigs) = signed(&roots);
    let mut v = VerifySpec::new(roots.first_party());
    v.previous_sequence = Some(7);
    verify(&bytes, &sigs, &v, NOW).unwrap();
    v.previous_sequence = Some(8);
    let err = verify(&bytes, &sigs, &v, NOW).unwrap_err();
    assert_eq!(err.code(), "E_INDEX_ROLLBACK");
}

#[test]
fn verify_refuses_a_file_whose_keys_have_all_expired() {
    let roots = Roots::new();
    let (bytes, sigs) = signed(&roots);
    let later = ts("2027-02-01T00:00:00Z");
    let err = verify(&bytes, &sigs, &VerifySpec::new(roots.first_party()), later).unwrap_err();
    assert_eq!(err.code(), "E_INDEX_EXPIRED");
}

#[test]
fn verify_warns_about_a_key_that_expired_or_outlives_ninety_days() {
    let roots = Roots::new();
    let raw = raw_keys_file(serde_json::json!([
        { "key": TestKey::generate().public_str(), "scope": ["alpha", "beta"], "expires": "2027-12-01T00:00:00Z" },
        { "key": TestKey::generate().public_str(), "scope": ["alpha", "beta"], "expires": EXPIRED },
    ]));
    let report = verify(
        &raw,
        &roots.sign(&raw, &[0, 1]),
        &VerifySpec::new(roots.first_party()),
        ts("2027-06-01T00:00:00Z"),
    )
    .unwrap();
    let all = report.warnings.join("\n");
    assert!(all.contains("90 days"), "{all}");
    assert!(all.contains("already expired"), "{all}");
}

#[test]
fn verify_refuses_an_index_key_that_is_a_root_key() {
    let roots = Roots::new();
    let raw = raw_keys_file(serde_json::json!([
        { "key": roots.keys[2].public_str(), "scope": ["alpha", "beta"], "expires": IN_30_DAYS }
    ]));
    let err = verify(
        &raw,
        &roots.sign(&raw, &[0, 1]),
        &VerifySpec::new(roots.first_party()),
        NOW,
    )
    .unwrap_err();
    assert!(err.to_string().contains("root key"), "{err}");
}

#[test]
fn verify_warns_about_scope_outside_the_first_party_plugins() {
    let roots = Roots::new();
    let raw = raw_keys_file(serde_json::json!([
        { "key": TestKey::generate().public_str(), "scope": ["alpha", "acme-flyway"], "expires": IN_30_DAYS }
    ]));
    let report = verify(
        &raw,
        &roots.sign(&raw, &[0, 1]),
        &VerifySpec::new(roots.first_party()),
        NOW,
    )
    .unwrap();
    let all = report.warnings.join("\n");
    assert!(all.contains("acme-flyway"), "{all}");
    assert!(
        all.contains("beta"),
        "a first-party plugin no key covers: {all}"
    );
}

#[test]
fn verify_checks_the_file_against_every_first_party_manifest() {
    let roots = Roots::new();
    let other = Roots::new();
    let mut fp = roots.first_party();
    fp[1].keys = other.public();
    let (bytes, sigs) = signed(&roots);
    let err = verify(&bytes, &sigs, &VerifySpec::new(fp), NOW).unwrap_err();
    assert!(err.to_string().contains("beta"), "{err}");
}

#[test]
fn root_override_replaces_every_manifest_anchor() {
    let roots = Roots::new();
    let new_roots = Roots::new();
    let (bytes, old_only) = signed(&roots);
    let mut v = VerifySpec::new(roots.first_party());
    v.roots = Some((new_roots.public(), 2));
    // Signed only by the old roots: the new roots do not accept it.
    assert!(verify(&bytes, &old_only, &v, NOW).is_err());
    // Cross-signed by two old and two new roots, as a root rotation publishes: both the new
    // roots (the override) and the old roots (the manifests) accept it.
    let cross = [old_only, new_roots.sign(&bytes, &[1, 2])].concat();
    verify(&bytes, &cross, &v, NOW).unwrap();
    verify(&bytes, &cross, &VerifySpec::new(roots.first_party()), NOW).unwrap();
}

fn manifest(name: &str, key: &str) -> String {
    format!(
        "schema = 1\nname = \"{name}\"\ndisplay_name = \"{name}\"\ndescription = \"d\"\n\
         homepage = \"https://example.org\"\nlicense = \"MIT\"\nmin_jtm = \"0.1.0\"\n\
         [versions]\nscheme = \"semver-loose\"\n\
         [index]\nurl = \"https://example.org/{{os}}-{{arch}}.json\"\n\
         signing_keys = [\"{key}\"]\nformat = 1\n\
         [layout]\nbin_dirs = [\"bin\"]\n"
    )
}

#[test]
fn first_party_manifests_are_read_from_a_directory() {
    let dir = tempfile::tempdir().unwrap();
    let key = TestKey::generate().public_str();
    for name in ["zed", "alpha"] {
        std::fs::create_dir(dir.path().join(name)).unwrap();
        std::fs::write(
            dir.path().join(name).join("plugin.toml"),
            manifest(name, &key),
        )
        .unwrap();
    }
    std::fs::write(dir.path().join("README.md"), "not a plugin").unwrap();
    let found = load_first_party(dir.path()).unwrap();
    assert_eq!(
        found.iter().map(|f| f.plugin.as_str()).collect::<Vec<_>>(),
        ["alpha", "zed"]
    );
    assert_eq!(found[0].keys, vec![key]);
    assert_eq!(found[0].threshold, 1);
}

#[test]
fn an_empty_or_missing_plugin_directory_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(load_first_party(dir.path()).unwrap_err().exit_code(), 2);
    assert_eq!(
        load_first_party(&dir.path().join("missing"))
            .unwrap_err()
            .exit_code(),
        4
    );
}

#[test]
fn shipped_manifests_agree_on_one_root_set() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../jtm-cli/plugins");
    let found = load_first_party(&dir).unwrap();
    assert!(found.len() >= 5);
    for fp in &found {
        assert_eq!(fp.keys, found[0].keys, "{} differs", fp.plugin);
        assert_eq!(fp.threshold, found[0].threshold, "{} differs", fp.plugin);
    }
    assert_eq!(found[0].keys.len(), 1);
    assert_eq!(found[0].threshold, 1);
}
