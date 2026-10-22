//! Helpers shared by the unit tests. Nothing here touches the real network: upstreams are
//! `wiremock` servers answering with the responses recorded under `tests/fixtures`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use pgp::composed::{
    ArmorOptions, DetachedSignature, EncryptionCaps, KeyType, SecretKeyParamsBuilder,
    SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::ser::Serialize;
use pgp::types::{KeyDetails, Password};

use jtm_fetch::{Client, ClientOptions, RetryPolicy};
use tokio::runtime::Runtime;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock as Route, MockServer, ResponseTemplate};

use crate::context::Context;

/// A mock server and the runtime it runs on. The blocking client must be used outside the
/// runtime, so tests call it directly and only use the runtime to set up mocks.
pub(crate) struct Mock {
    rt: Runtime,
    pub(crate) server: MockServer,
}

impl Mock {
    pub(crate) fn start() -> Mock {
        let rt = Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        Mock { rt, server }
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server.uri())
    }

    pub(crate) fn mount(&self, route: Route) {
        self.rt.block_on(route.mount(&self.server));
    }

    /// Answers `GET path` with `body`.
    pub(crate) fn serve(&self, at: &str, body: impl Into<Vec<u8>>) {
        self.mount(
            Route::given(method("GET"))
                .and(path(at))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(body.into())),
        );
    }

    /// Answers `GET path?key=value` with `body`.
    pub(crate) fn serve_query(&self, at: &str, query: &[(&str, &str)], body: impl Into<Vec<u8>>) {
        let mut route = Route::given(method("GET")).and(path(at));
        for (key, value) in query {
            route = route.and(query_param(*key, *value));
        }
        self.mount(route.respond_with(ResponseTemplate::new(200).set_body_bytes(body.into())));
    }

    pub(crate) fn status(&self, at: &str, status: u16) {
        self.mount(
            Route::given(method("GET"))
                .and(path(at))
                .respond_with(ResponseTemplate::new(status)),
        );
    }

    /// The paths and queries requested so far, in order.
    pub(crate) fn requested(&self) -> Vec<String> {
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
            .iter()
            .map(|r| match r.url.query() {
                Some(q) => format!("{}?{q}", r.url.path()),
                None => r.url.path().to_owned(),
            })
            .collect()
    }

    pub(crate) fn requests(&self) -> Vec<wiremock::Request> {
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
    }

    /// A context whose client talks plain http, with no waits between retries, and which
    /// sends every request meant for a vendor host in [`VENDOR_HOSTS`] to this server under
    /// `/<host>/`. The URLs in configs and candidates stay the real, https ones.
    pub(crate) fn context(&self) -> Context {
        let mirrors = VENDOR_HOSTS
            .iter()
            .map(|host| (format!("https://{host}/"), self.url(&format!("/{host}/"))))
            .collect();
        Context::new(client()).with_mirrors(mirrors)
    }
}

/// The hosts the adapters query by default, and the ones the fixtures were recorded from.
pub(crate) const VENDOR_HOSTS: &[&str] = &[
    "api.adoptium.net",
    "api.foojay.io",
    "api.github.com",
    "archive.apache.org",
    "downloads.apache.org",
    "github.com",
    "repo.maven.apache.org",
    "services.gradle.org",
];

pub(crate) fn client() -> Client {
    Client::new(ClientOptions {
        allow_http: true,
        retry: RetryPolicy {
            retries: 0,
            backoff: Duration::ZERO,
        },
        read_timeout: Duration::from_secs(5),
        ..ClientOptions::new("0.0.0-test")
    })
    .unwrap()
}

/// The text of a recorded response under `tests/fixtures`.
pub(crate) fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))
}

/// A key made for the test, so no key material is ever checked in or fetched.
pub(crate) struct TestKey {
    pub(crate) secret: SignedSecretKey,
}

impl TestKey {
    /// A key that certifies and signs with its primary key.
    pub(crate) fn primary(user: &str) -> TestKey {
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id(user.into())
            .build()
            .unwrap();
        TestKey {
            secret: params.generate(rand::thread_rng()).unwrap(),
        }
    }

    /// An RSA key, the only kind the library will sign with SHA-1 (it refuses weak hashes for
    /// Ed25519). Slow to generate, so only the weak-hash test uses it.
    pub(crate) fn rsa(user: &str) -> TestKey {
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Rsa(2048))
            .can_certify(true)
            .can_sign(true)
            .primary_user_id(user.into())
            .build()
            .unwrap();
        TestKey {
            secret: params.generate(rand::thread_rng()).unwrap(),
        }
    }

    /// A key that certifies only, with a separate signing subkey, as most release keys are.
    pub(crate) fn with_signing_subkey(user: &str) -> TestKey {
        let subkey = SubkeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_sign(true)
            .can_encrypt(EncryptionCaps::None)
            .build()
            .unwrap();
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(false)
            .primary_user_id(user.into())
            .subkeys(vec![subkey])
            .build()
            .unwrap();
        TestKey {
            secret: params.generate(rand::thread_rng()).unwrap(),
        }
    }

    pub(crate) fn public_armored(&self) -> String {
        SignedPublicKey::from(self.secret.clone())
            .to_armored_string(ArmorOptions::default())
            .unwrap()
    }

    pub(crate) fn fingerprint(&self) -> String {
        format!("{:X}", self.secret.fingerprint())
    }

    pub(crate) fn sign(&self, data: &[u8], hash: HashAlgorithm) -> DetachedSignature {
        match self.secret.secret_subkeys.first() {
            Some(subkey) => DetachedSignature::sign_binary_data(
                rand::thread_rng(),
                &subkey.key,
                &Password::empty(),
                hash,
                data,
            ),
            None => DetachedSignature::sign_binary_data(
                rand::thread_rng(),
                &self.secret.primary_key,
                &Password::empty(),
                hash,
                data,
            ),
        }
        .unwrap()
    }

    pub(crate) fn armored_signature(&self, data: &[u8]) -> Vec<u8> {
        self.sign(data, HashAlgorithm::Sha256)
            .to_armored_bytes(ArmorOptions::default())
            .unwrap()
    }

    pub(crate) fn binary_signature(&self, data: &[u8]) -> Vec<u8> {
        self.sign(data, HashAlgorithm::Sha256).to_bytes().unwrap()
    }
}

/// A minisign key pair made for the test.
pub(crate) struct MinisignKey {
    /// The contents of the `minisign.key` file.
    pub(crate) secret_file: String,
    /// The public key line.
    pub(crate) public: String,
}

pub(crate) fn minisign_key() -> MinisignKey {
    let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    MinisignKey {
        secret_file: pair.sk.to_box(Some("jtm test key")).unwrap().into_string(),
        public: pair.pk.to_base64(),
    }
}

/// A confirmed entry for `version` with the digest `ab` repeated, served from vendor.test.
pub(crate) fn confirmed_entry(
    variant: Option<&str>,
    version: &str,
    target: crate::candidate::Target,
) -> crate::confirm::ConfirmedEntry {
    use crate::confirm::{ClaimRecord, Confirmation, ConfirmedEntry, Provenance};
    ConfirmedEntry {
        variant: variant.map(str::to_owned),
        version: version.to_owned(),
        target,
        tags: vec!["ga".to_owned()],
        url: format!("https://vendor.test/{version}.zip"),
        archive: jtm_security::ArchiveKind::Zip,
        size: 1234,
        sha256: "ab".repeat(32),
        distribution_version: None,
        provenance: Provenance {
            confirmation: Confirmation::Independent,
            sources: vec!["src-a".to_owned(), "src-b".to_owned()],
            claims: vec![ClaimRecord {
                source: "src-a".to_owned(),
                algorithm: crate::HashAlgorithm::Sha256,
                origin: "https://x.test/sum".to_owned(),
            }],
            signatures: Vec::new(),
            fetched_at: "2026-10-19T02:00:00Z".to_owned(),
        },
    }
}
