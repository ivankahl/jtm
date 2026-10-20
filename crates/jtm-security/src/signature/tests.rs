use super::*;
use crate::key::{Scope, TrustedKey};
use crate::testing::TestKey;

const DATA: &[u8] = br#"{"format":1,"plugin":"demo"}"#;
const NOW: Timestamp = Timestamp::from_unix(1_800_000_000);

fn subject() -> Subject<'static> {
    Subject {
        file: "demo-linux-x64.json",
        plugin: "demo",
    }
}

fn group(keys: &[&TestKey], scope: &[&str], threshold: u32) -> KeyGroup {
    KeyGroup {
        origin: "test keys".into(),
        keys: keys
            .iter()
            .map(|k| TrustedKey {
                key: k.public(),
                scope: Scope::plugins(scope.iter().copied()).unwrap(),
                expires: None,
            })
            .collect(),
        threshold,
    }
}

fn ring(groups: Vec<KeyGroup>) -> Keyring {
    Keyring { groups }
}

#[test]
fn valid_signature_verifies() {
    let key = TestKey::generate();
    let sig = key.sign(DATA);
    let verified = verify(
        DATA,
        &sig,
        &ring(vec![group(&[&key], &["demo"], 1)]),
        subject(),
        NOW,
    )
    .unwrap();
    assert_eq!(verified.signers, vec![key.public().id()]);
    assert_eq!(verified.group, "test keys");
}

#[test]
fn wrong_key_is_untrusted() {
    let signer = TestKey::generate();
    let trusted = TestKey::generate();
    let sig = signer.sign(DATA);
    let err = verify(
        DATA,
        &sig,
        &ring(vec![group(&[&trusted], &["demo"], 1)]),
        subject(),
        NOW,
    )
    .unwrap_err();
    match err {
        Error::KeyUntrusted {
            key_id, resolve, ..
        } => {
            assert_eq!(key_id, signer.public().id().to_string());
            assert_eq!(resolve, "jtm trust add <public key> --scope demo");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn tampered_byte_is_invalid() {
    let key = TestKey::generate();
    let sig = key.sign(DATA);
    let keyring = ring(vec![group(&[&key], &["demo"], 1)]);
    for i in [0, DATA.len() / 2, DATA.len() - 1] {
        let mut tampered = DATA.to_vec();
        tampered[i] ^= 0x01;
        let err = verify(&tampered, &sig, &keyring, subject(), NOW).unwrap_err();
        assert!(
            matches!(err, Error::SignatureInvalid { .. }),
            "byte {i}: {err:?}"
        );
    }
}

#[test]
fn truncated_data_is_invalid() {
    let key = TestKey::generate();
    let sig = key.sign(DATA);
    let keyring = ring(vec![group(&[&key], &["demo"], 1)]);
    for len in [0, 1, DATA.len() - 1] {
        let err = verify(&DATA[..len], &sig, &keyring, subject(), NOW).unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid { .. }), "{len}");
    }
}

#[test]
fn truncated_or_corrupt_signature_file_is_invalid() {
    let key = TestKey::generate();
    let sig = key.sign(DATA);
    let keyring = ring(vec![group(&[&key], &["demo"], 1)]);
    let text = String::from_utf8(sig.clone()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let mut cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        sig[..sig.len() / 2].to_vec(),
        lines[..3].join("\n").into_bytes(),
        vec![0xff, 0xfe],
        lines[1..].join("\n").into_bytes(),
    ];
    // A flipped bit in the global signature, which covers the trusted comment.
    let mut global = lines.clone();
    let flipped = flip_base64(lines[3]);
    global[3] = &flipped;
    cases.push(global.join("\n").into_bytes());
    // A changed trusted comment.
    let mut comment = lines.clone();
    comment[2] = "trusted comment: something else";
    cases.push(comment.join("\n").into_bytes());
    for (i, bad) in cases.iter().enumerate() {
        let err = verify(DATA, bad, &keyring, subject(), NOW).unwrap_err();
        assert!(
            matches!(err, Error::SignatureInvalid { .. }),
            "case {i}: {err:?}"
        );
    }
}

#[test]
fn out_of_scope_key_is_untrusted() {
    let key = TestKey::generate();
    let sig = key.sign(DATA);
    let err = verify(
        DATA,
        &sig,
        &ring(vec![group(&[&key], &["other"], 1)]),
        subject(),
        NOW,
    )
    .unwrap_err();
    assert!(matches!(err, Error::KeyUntrusted { .. }), "{err:?}");
}

#[test]
fn expired_key_is_rejected() {
    let key = TestKey::generate();
    let sig = key.sign(DATA);
    let mut expiring = group(&[&key], &["demo"], 1);
    expiring.keys[0].expires = Some(Timestamp::from_unix(NOW.unix() + 1));
    verify(DATA, &sig, &ring(vec![expiring.clone()]), subject(), NOW).unwrap();
    expiring.keys[0].expires = Some(NOW);
    let err = verify(DATA, &sig, &ring(vec![expiring]), subject(), NOW).unwrap_err();
    assert!(matches!(err, Error::SignatureInvalid { .. }), "{err:?}");
    assert!(err.to_string().contains("expired"), "{err}");
}

#[test]
fn threshold_two_needs_two_distinct_keys() {
    let (a, b, c) = (
        TestKey::generate(),
        TestKey::generate(),
        TestKey::generate(),
    );
    let keyring = ring(vec![group(&[&a, &b, &c], &["demo"], 2)]);

    let one = a.sign(DATA);
    let err = verify(DATA, &one, &keyring, subject(), NOW).unwrap_err();
    assert!(err.to_string().contains("needs 2 signatures"), "{err}");

    let same_twice = [a.sign(DATA), a.sign(DATA)].concat();
    assert!(verify(DATA, &same_twice, &keyring, subject(), NOW).is_err());

    let two = [a.sign(DATA), c.sign(DATA)].concat();
    let verified = verify(DATA, &two, &keyring, subject(), NOW).unwrap();
    assert_eq!(verified.signers.len(), 2);
}

#[test]
fn any_group_can_accept() {
    let (a, b, user) = (
        TestKey::generate(),
        TestKey::generate(),
        TestKey::generate(),
    );
    let keyring = ring(vec![
        group(&[&a, &b], &["demo"], 2),
        KeyGroup {
            origin: "user trust store".into(),
            ..group(&[&user], &["demo"], 1)
        },
    ]);
    let verified = verify(DATA, &user.sign(DATA), &keyring, subject(), NOW).unwrap();
    assert_eq!(verified.group, "user trust store");
}

#[test]
fn a_bad_extra_signature_does_not_mask_tampering() {
    let (a, b) = (TestKey::generate(), TestKey::generate());
    let keyring = ring(vec![group(&[&a, &b], &["demo"], 2)]);
    let mut tampered = DATA.to_vec();
    tampered[0] ^= 1;
    let sig = [a.sign(DATA), b.sign(DATA)].concat();
    let err = verify(&tampered, &sig, &keyring, subject(), NOW).unwrap_err();
    assert!(err.to_string().contains("tampered"), "{err}");
}

#[test]
fn legacy_signatures_are_refused() {
    let key = TestKey::generate();
    let sig = key.sign_legacy(DATA);
    let err = verify(
        DATA,
        &sig,
        &ring(vec![group(&[&key], &["demo"], 1)]),
        subject(),
        NOW,
    )
    .unwrap_err();
    assert!(matches!(err, Error::SignatureInvalid { .. }), "{err:?}");
    // The file is not called tampered with: the legacy format is refused by policy.
    assert!(err.to_string().contains("legacy"), "{err}");
    assert!(!err.to_string().contains("tampered"), "{err}");
}

#[test]
fn signature_file_limits() {
    let key = TestKey::generate();
    let keyring = ring(vec![group(&[&key], &["demo"], 1)]);
    let many = key.sign(DATA).repeat(MAX_SIGNATURES + 1);
    assert!(verify(DATA, &many, &keyring, subject(), NOW).is_err());
    let huge = vec![b'a'; MAX_SIGNATURE_FILE + 1];
    assert!(verify(DATA, &huge, &keyring, subject(), NOW).is_err());
    let crlf = String::from_utf8(key.sign(DATA))
        .unwrap()
        .replace('\n', "\r\n");
    verify(DATA, crlf.as_bytes(), &keyring, subject(), NOW).unwrap();
}

fn flip_base64(line: &str) -> String {
    let mut chars: Vec<char> = line.chars().collect();
    chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
    chars.into_iter().collect()
}
