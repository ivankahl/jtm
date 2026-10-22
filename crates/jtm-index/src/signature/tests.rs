use std::io::Cursor;

use pgp::composed::ArmorOptions;
use pgp::crypto::hash::HashAlgorithm;

use super::*;
use crate::testing::TestKey;

const DATA: &[u8] = b"the bytes of an archive";

fn keyring(keys: &[&TestKey]) -> Keyring {
    let text: String = keys.iter().map(|k| k.public_armored()).collect();
    Keyring::parse("test keys", text.as_bytes()).unwrap()
}

fn verify(keyring: &Keyring, signature: &[u8], data: &[u8]) -> Verification {
    keyring.verify(signature, &mut Cursor::new(data))
}

#[test]
fn a_signature_by_a_trusted_primary_key_verifies() {
    let key = TestKey::primary("Release Manager <rm@example.test>");
    let ring = keyring(&[&key]);
    let result = verify(&ring, &key.armored_signature(DATA), DATA);
    assert_eq!(
        result,
        Verification::Valid {
            fingerprint: key.fingerprint()
        }
    );
}

#[test]
fn a_binary_signature_verifies_like_an_armored_one() {
    let key = TestKey::primary("Release Manager <rm@example.test>");
    let ring = keyring(&[&key]);
    assert!(matches!(
        verify(&ring, &key.binary_signature(DATA), DATA),
        Verification::Valid { .. }
    ));
}

#[test]
fn a_signature_made_by_a_signing_subkey_verifies() {
    let key = TestKey::with_signing_subkey("Release Manager <rm@example.test>");
    let ring = keyring(&[&key]);
    // The subkey has its own fingerprint, which is the one reported.
    let Verification::Valid { fingerprint } = verify(&ring, &key.armored_signature(DATA), DATA)
    else {
        panic!("a subkey signature should verify");
    };
    assert_ne!(fingerprint, key.fingerprint());
    assert_eq!(fingerprint.len(), 40);
}

#[test]
fn the_right_key_is_found_among_several() {
    let first = TestKey::primary("First <a@example.test>");
    let second = TestKey::primary("Second <b@example.test>");
    let ring = keyring(&[&first, &second]);
    assert_eq!(ring.len(), 2);
    assert_eq!(
        verify(&ring, &second.armored_signature(DATA), DATA),
        Verification::Valid {
            fingerprint: second.fingerprint()
        }
    );
}

#[test]
fn a_signature_over_other_bytes_is_invalid() {
    let key = TestKey::primary("Release Manager <rm@example.test>");
    let ring = keyring(&[&key]);
    let result = verify(&ring, &key.armored_signature(DATA), b"tampered archive");
    assert!(matches!(result, Verification::Invalid(_)), "{result:?}");
}

#[test]
fn a_signature_by_a_key_outside_the_keyring_is_unknown_not_valid() {
    let trusted = TestKey::primary("Trusted <t@example.test>");
    let stranger = TestKey::primary("Stranger <s@example.test>");
    let ring = keyring(&[&trusted]);
    let result = verify(&ring, &stranger.armored_signature(DATA), DATA);
    assert!(matches!(result, Verification::UnknownKey(_)), "{result:?}");
}

#[test]
fn an_empty_keyring_verifies_nothing() {
    let key = TestKey::primary("Release Manager <rm@example.test>");
    let ring = Keyring::default();
    assert!(ring.is_empty());
    let result = verify(&ring, &key.armored_signature(DATA), DATA);
    assert!(matches!(result, Verification::UnknownKey(_)), "{result:?}");
}

#[test]
fn bytes_that_are_not_a_signature_are_invalid() {
    let key = TestKey::primary("Release Manager <rm@example.test>");
    let ring = keyring(&[&key]);
    for junk in [
        &b"<html>404 not found</html>"[..],
        b"",
        b"-----BEGIN PGP SIGNATURE-----\n\nnot base64!\n-----END PGP SIGNATURE-----\n",
    ] {
        let result = verify(&ring, junk, DATA);
        assert!(matches!(result, Verification::Invalid(_)), "{result:?}");
    }
}

#[test]
fn a_signature_with_a_weak_hash_is_set_aside_rather_than_trusted() {
    let key = TestKey::rsa("Release Manager <rm@example.test>");
    let ring = keyring(&[&key]);
    let strong = verify(&ring, &key.armored_signature(DATA), DATA);
    assert!(matches!(strong, Verification::Valid { .. }), "{strong:?}");
    let weak = key
        .sign(DATA, HashAlgorithm::Sha1)
        .to_armored_bytes(ArmorOptions::default())
        .unwrap();
    let result = verify(&ring, &weak, DATA);
    assert!(matches!(result, Verification::Unsupported(_)), "{result:?}");
}

#[test]
fn a_keys_file_may_hold_prose_and_many_blocks() {
    let first = TestKey::primary("First <a@example.test>");
    let second = TestKey::primary("Second <b@example.test>");
    let text = format!(
        "This file contains the public keys used to sign releases.\n\npub  ed25519 2026-01-01\nuid First\n\n{}\nuid Second\n\n{}\n",
        first.public_armored(),
        second.public_armored()
    );
    let ring = Keyring::parse("KEYS", text.as_bytes()).unwrap();
    assert_eq!(ring.len(), 2);
    assert_eq!(ring.fingerprints(), {
        let mut both = vec![first.fingerprint(), second.fingerprint()];
        both.sort();
        both
    });
}

#[test]
fn a_keys_file_without_keys_is_refused() {
    for text in ["", "no keys here\n"] {
        let message = Keyring::parse("KEYS", text.as_bytes()).unwrap_err();
        assert!(message.contains("KEYS"), "{message}");
        assert!(message.contains("no PGP public key"), "{message}");
    }
}

#[test]
fn a_block_that_does_not_parse_refuses_the_whole_file() {
    let good = TestKey::primary("Good <g@example.test>");
    let text = format!(
        "{}\n-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----\n",
        good.public_armored()
    );
    let message = Keyring::parse("KEYS", text.as_bytes()).unwrap_err();
    assert!(message.contains("KEYS"), "{message}");
}

#[test]
fn a_secret_key_in_the_file_is_not_taken_for_a_public_one() {
    let key = TestKey::primary("Oops <o@example.test>");
    let secret = key
        .secret
        .to_armored_string(ArmorOptions::default())
        .unwrap();
    assert!(Keyring::parse("KEYS", secret.as_bytes()).is_err());
}
