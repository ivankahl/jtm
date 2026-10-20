//! Key generation and signing for tests. Keys are generated fresh in every test, so no secret
//! key is ever checked in. Compiled only for this crate's tests and the `testing` feature.

#![allow(clippy::expect_used, clippy::missing_panics_doc)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::key::PublicKey;

/// A freshly generated minisign key pair.
pub struct TestKey {
    pair: minisign::KeyPair,
}

impl std::fmt::Debug for TestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("TestKey").field(&self.public_str()).finish()
    }
}

impl TestKey {
    pub fn generate() -> TestKey {
        TestKey {
            pair: minisign::KeyPair::generate_unencrypted_keypair().expect("generate a key pair"),
        }
    }

    /// The public key as its base64 line.
    pub fn public_str(&self) -> String {
        self.pair.pk.to_base64()
    }

    pub fn public(&self) -> PublicKey {
        PublicKey::parse(&self.public_str()).expect("a generated key parses")
    }

    /// A `.minisig` file for `data`, ending in a newline so files can be concatenated.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        minisign::sign(
            Some(&self.pair.pk),
            &self.pair.sk,
            data,
            Some("timestamp:0\tfile:test"),
            Some("signature from a jtm test key"),
        )
        .expect("sign")
        .to_bytes()
    }

    /// A signature claiming the legacy algorithm, which signs raw bytes instead of a hash.
    pub fn sign_legacy(&self, data: &[u8]) -> Vec<u8> {
        let text = String::from_utf8(self.sign(data)).expect("signatures are text");
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        let mut bytes = STANDARD.decode(&lines[1]).expect("base64");
        bytes[1] = b'd';
        lines[1] = STANDARD.encode(bytes);
        let mut out = lines.join("\n");
        out.push('\n');
        out.into_bytes()
    }
}
