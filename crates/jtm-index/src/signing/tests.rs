use jtm_security::signature::{self, Subject};
use jtm_security::{KeyGroup, Keyring, PublicKey, Scope, Timestamp, TrustedKey};

use super::*;

const NOW: Timestamp = Timestamp::from_unix(1_800_000_000);

/// A secret key file as `minisign -G` writes it, and the matching public key line.
struct Generated {
    secret_file: String,
    public: String,
}

fn generate(password: Option<&str>) -> Generated {
    let pair = match password {
        Some(password) => {
            minisign::KeyPair::generate_encrypted_keypair(Some(password.to_owned())).unwrap()
        }
        None => minisign::KeyPair::generate_unencrypted_keypair().unwrap(),
    };
    Generated {
        secret_file: pair.sk.to_box(Some("jtm test key")).unwrap().into_string(),
        public: pair.pk.to_base64(),
    }
}

fn keyring(public: &str) -> Keyring {
    Keyring::new().with(KeyGroup {
        origin: "test".to_owned(),
        keys: vec![TrustedKey {
            key: PublicKey::parse(public).unwrap(),
            scope: Scope::plugins(["demo"]).unwrap(),
            expires: None,
        }],
        threshold: 1,
    })
}

fn verify(data: &[u8], signature: &[u8], public: &str) -> jtm_security::Result<()> {
    let subject = Subject {
        file: "demo-any.json",
        plugin: "demo",
    };
    signature::verify(data, signature, &keyring(public), subject, NOW).map(|_| ())
}

#[test]
fn a_signature_verifies_with_the_client_verifier() {
    let key = generate(None);
    let signer = Signer::from_secret_key(&key.secret_file, None).unwrap();
    let signature = signer
        .sign("demo-any.json", b"{\"format\":1}", NOW)
        .unwrap();
    verify(b"{\"format\":1}", &signature, &key.public).unwrap();
}

#[test]
fn a_signature_does_not_cover_other_bytes() {
    let key = generate(None);
    let signer = Signer::from_secret_key(&key.secret_file, None).unwrap();
    let signature = signer.sign("demo-any.json", b"original", NOW).unwrap();
    let err = verify(b"tampered", &signature, &key.public).unwrap_err();
    assert!(matches!(err, jtm_security::Error::SignatureInvalid { .. }));
}

#[test]
fn a_signature_by_another_key_is_not_accepted() {
    let signer = Signer::from_secret_key(&generate(None).secret_file, None).unwrap();
    let signature = signer.sign("demo-any.json", b"data", NOW).unwrap();
    let err = verify(b"data", &signature, &generate(None).public).unwrap_err();
    assert!(matches!(err, jtm_security::Error::KeyUntrusted { .. }));
}

#[test]
fn the_signature_is_the_pre_hashed_kind_the_client_requires() {
    let key = generate(None);
    let signer = Signer::from_secret_key(&key.secret_file, None).unwrap();
    let signature = String::from_utf8(signer.sign("demo-any.json", b"data", NOW).unwrap()).unwrap();
    let parsed = minisign::SignatureBox::from_string(&signature).unwrap();
    assert!(parsed.is_prehashed());
}

#[test]
fn the_trusted_comment_names_the_file_and_the_time() {
    let signer = Signer::from_secret_key(&generate(None).secret_file, None).unwrap();
    let signature = String::from_utf8(signer.sign("demo-any.json", b"data", NOW).unwrap()).unwrap();
    let parsed = minisign::SignatureBox::from_string(&signature).unwrap();
    assert_eq!(
        parsed.trusted_comment().unwrap(),
        "timestamp:1800000000\tfile:demo-any.json"
    );
}

#[test]
fn the_public_key_is_the_one_the_secret_key_belongs_to() {
    let key = generate(None);
    let signer = Signer::from_secret_key(&key.secret_file, None).unwrap();
    assert_eq!(signer.public_key().as_str(), key.public);
}

#[test]
fn an_encrypted_key_opens_with_its_password() {
    let key = generate(Some("correct horse"));
    let signer =
        Signer::from_secret_key(&key.secret_file, Some("correct horse".to_owned())).unwrap();
    let signature = signer.sign("demo-any.json", b"data", NOW).unwrap();
    verify(b"data", &signature, &key.public).unwrap();
}

#[test]
fn an_encrypted_key_without_its_password_is_refused() {
    let key = generate(Some("correct horse"));
    let err = Signer::from_secret_key(&key.secret_file, None).unwrap_err();
    assert!(err.to_string().contains("password"), "{err}");
    assert_eq!(err.code(), jtm_core::ErrorCode::Usage);
}

#[test]
fn a_wrong_password_is_refused_without_repeating_it() {
    let key = generate(Some("correct horse"));
    let err =
        Signer::from_secret_key(&key.secret_file, Some("battery staple".to_owned())).unwrap_err();
    let message = err.to_string();
    assert!(!message.contains("battery staple"), "{message}");
    assert!(!message.contains("correct horse"), "{message}");
    assert_eq!(err.code(), jtm_core::ErrorCode::Usage);
}

#[test]
fn a_password_for_an_unencrypted_key_is_refused() {
    // Silently ignoring a password would hide that the secret in CI is not what the
    // maintainer thinks it is.
    let key = generate(None);
    let err = Signer::from_secret_key(&key.secret_file, Some("unneeded".to_owned())).unwrap_err();
    assert!(err.to_string().contains("not password-protected"), "{err}");
    assert!(!err.to_string().contains("unneeded"), "{err}");
}

#[test]
fn text_that_is_not_a_secret_key_is_refused_without_echoing_it() {
    let err = Signer::from_secret_key("PRIVATE-MARKER-123 is not a key", None).unwrap_err();
    assert!(!err.to_string().contains("PRIVATE-MARKER-123"), "{err}");
    assert_eq!(err.code(), jtm_core::ErrorCode::Usage);
}

#[test]
fn a_public_key_is_not_accepted_as_a_secret_key() {
    let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    let public_file = pair.pk.to_box().unwrap().into_string();
    assert!(Signer::from_secret_key(&public_file, None).is_err());
}

#[test]
fn debug_output_shows_the_public_key_and_never_the_secret() {
    let key = generate(None);
    let signer = Signer::from_secret_key(&key.secret_file, None).unwrap();
    let shown = format!("{signer:?}");
    assert!(shown.contains(&key.public), "{shown}");
    // The second line of the file is the secret key's base64.
    let secret_line = key.secret_file.lines().nth(1).unwrap();
    assert!(!shown.contains(secret_line), "{shown}");
}

#[test]
fn an_ephemeral_signer_signs_for_validation_only() {
    let signer = Signer::ephemeral().unwrap();
    let signature = signer.sign("demo-any.json", b"data", NOW).unwrap();
    verify(b"data", &signature, signer.public_key().as_str()).unwrap();
}
