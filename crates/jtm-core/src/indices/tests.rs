use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

use jtm_security::testing::TestKey;
use serde_json::json;

use super::*;
use crate::platform::Os;

const NOW: Timestamp = Timestamp::from_unix(1_800_000_000);
const FUTURE: &str = "2027-06-01T00:00:00Z";
const PAST: &str = "2027-01-01T00:00:00Z";
const REMOTE: &str = "https://index.example.test/demo-{os}-{arch}.json";
const REMOTE_EXPANDED: &str = "https://index.example.test/demo-linux-x64.json";

/// An in-memory network that counts requests.
#[derive(Default)]
struct FakeNet {
    files: HashMap<String, Vec<u8>>,
    fail: bool,
    requests: RefCell<Vec<String>>,
}

impl FakeNet {
    fn serve(&mut self, url: &str, (data, sig): (Vec<u8>, Vec<u8>)) {
        self.files.insert(url.to_owned(), data);
        self.files.insert(format!("{url}.minisig"), sig);
    }
}

impl Fetcher for FakeNet {
    fn fetch(&self, url: &str) -> Result<Option<Vec<u8>>> {
        self.requests.borrow_mut().push(url.to_owned());
        if self.fail {
            return Err(JtmError::Network {
                url: url.to_owned(),
                message: "connection refused".into(),
                source: None,
            });
        }
        Ok(self.files.get(url).cloned())
    }
}

struct Fixture {
    _home: tempfile::TempDir,
    dirs: Dirs,
    key: TestKey,
    keyring: Keyring,
    mirrors: BTreeMap<String, String>,
}

impl Fixture {
    fn new() -> Fixture {
        let home = tempfile::tempdir().unwrap();
        let os = Os::host().unwrap();
        let dirs = Dirs::resolve(os, Some(home.path()), None, &|_| None).unwrap();
        let key = TestKey::generate();
        let anchors = TrustAnchors::preapproved("demo", &[key.public_str()], 1).unwrap();
        let keyring = jtm_security::plugin_keyring(&anchors, None, &TrustState::default());
        Fixture {
            _home: home,
            dirs,
            key,
            keyring,
            mirrors: BTreeMap::new(),
        }
    }

    fn signed(&self, sequence: u64, expires: &str) -> (Vec<u8>, Vec<u8>) {
        let data = serde_json::to_vec(&json!({
            "format": 1,
            "plugin": "demo",
            "platform": "linux-x64",
            "sequence": sequence,
            "generated": "2026-01-01T00:00:00Z",
            "expires": expires,
            "entries": [{
                "variant": "default",
                "version": format!("1.{sequence}.0"),
                "url": "https://example.test/demo.zip",
                "archive": "zip",
                "size": 1,
                "sha256": "0".repeat(64)
            }]
        }))
        .unwrap();
        let sig = self.key.sign(&data);
        (data, sig)
    }

    fn write(&self, path: &Path, (data, sig): (Vec<u8>, Vec<u8>)) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, data).unwrap();
        fs::write(signature_path(path), sig).unwrap();
    }

    fn cache(&self) -> PathBuf {
        cache_path(&self.dirs, "demo", "linux-x64")
    }

    fn load(
        &self,
        embedded: &[EmbeddedIndex],
        net: Option<&FakeNet>,
        override_url: Option<&str>,
        options: LoadOptions,
    ) -> Result<PluginIndex> {
        let loader = IndexLoader {
            dirs: &self.dirs,
            embedded,
            embedded_keys: &[],
            fetcher: net.map(|n| n as &dyn Fetcher),
            mirrors: &self.mirrors,
        };
        let sources = IndexSources {
            plugin: "demo",
            platform: "linux-x64",
            remote_url: REMOTE,
            override_url,
        };
        loader.load(&sources, &self.keyring, &options)
    }

    fn state(&self) -> TrustState {
        TrustState::load(&trust_path(&self.dirs)).unwrap()
    }
}

fn options() -> LoadOptions {
    LoadOptions {
        refresh: false,
        offline: false,
        policy: ExpiryPolicy::RemoteOnly,
        now: NOW,
    }
}

fn refresh() -> LoadOptions {
    LoadOptions {
        refresh: true,
        ..options()
    }
}

fn leak(bytes: Vec<u8>) -> &'static [u8] {
    Box::leak(bytes.into_boxed_slice())
}

fn embedded((data, sig): (Vec<u8>, Vec<u8>)) -> EmbeddedIndex {
    EmbeddedIndex {
        plugin: "demo",
        platform: "linux-x64",
        data: leak(data),
        signature: leak(sig),
    }
}

#[test]
fn embedded_snapshot_works_offline_and_is_recorded() {
    let f = Fixture::new();
    let snapshot = [embedded(f.signed(3, FUTURE))];
    let offline = LoadOptions {
        offline: true,
        ..options()
    };
    let loaded = f.load(&snapshot, None, None, offline).unwrap();
    assert_eq!(loaded.index.sequence, 3);
    assert_eq!(loaded.source, SourceKind::Embedded);
    assert!(loaded.warnings.is_empty());
    let seen = f.state();
    let seen = seen.seen_index("demo", "linux-x64").unwrap();
    assert_eq!(seen.sequence, 3);
    assert_eq!(seen.source, Some(SourceKind::Embedded));
    assert!(!f.cache().exists(), "the embedded copy is not cached");
}

#[test]
fn mixed_valid_and_invalid_copies_resolve_to_the_highest_valid_one() {
    let f = Fixture::new();
    // The cache holds a tampered copy with a high sequence.
    let (mut data, sig) = f.signed(9, FUTURE);
    let n = data.len() - 5;
    data[n] ^= 1;
    f.write(&f.cache(), (data, sig));
    let snapshot = [embedded(f.signed(3, FUTURE))];
    let mut net = FakeNet::default();
    net.serve(REMOTE_EXPANDED, f.signed(7, FUTURE));

    let loaded = f.load(&snapshot, Some(&net), None, refresh()).unwrap();
    assert_eq!(loaded.index.sequence, 7);
    assert_eq!(loaded.source, SourceKind::Remote);
    assert_eq!(loaded.origin, REMOTE_EXPANDED);
    assert!(
        loaded
            .warnings
            .iter()
            .any(|w| w.code == "W_INDEX_COPY_REJECTED"),
        "{:?}",
        loaded.warnings
    );

    // The verified remote copy replaced the tampered cache, and later loads use it.
    let again = f
        .load(
            &snapshot,
            None,
            None,
            LoadOptions {
                offline: true,
                ..options()
            },
        )
        .unwrap();
    assert_eq!(again.index.sequence, 7);
    assert_eq!(again.source, SourceKind::Cache);
    assert!(again.warnings.is_empty(), "{:?}", again.warnings);
}

#[test]
fn local_copies_are_used_without_touching_the_network() {
    let f = Fixture::new();
    f.write(&f.cache(), f.signed(5, FUTURE));
    let net = FakeNet::default();
    let loaded = f.load(&[], Some(&net), None, options()).unwrap();
    assert_eq!(loaded.index.sequence, 5);
    assert!(net.requests.borrow().is_empty());
}

#[test]
fn the_network_is_used_when_nothing_is_local() {
    let f = Fixture::new();
    let mut net = FakeNet::default();
    net.serve(REMOTE_EXPANDED, f.signed(2, FUTURE));
    let loaded = f.load(&[], Some(&net), None, options()).unwrap();
    assert_eq!(loaded.index.sequence, 2);
    assert_eq!(
        *net.requests.borrow(),
        vec![
            REMOTE_EXPANDED.to_owned(),
            format!("{REMOTE_EXPANDED}.minisig")
        ]
    );
    assert!(f.cache().exists());
}

#[test]
fn a_missing_remote_signature_is_a_failure_not_a_skip() {
    let f = Fixture::new();
    let mut net = FakeNet::default();
    let (data, _) = f.signed(2, FUTURE);
    net.files.insert(REMOTE_EXPANDED.to_owned(), data);
    let err = f.load(&[], Some(&net), None, options()).unwrap_err();
    assert_eq!(err.code(), "E_SIGNATURE_INVALID");
    assert!(!f.cache().exists(), "nothing unverified is cached");
}

#[test]
fn local_override_is_a_mirror_and_expiry_only_warns() {
    let f = Fixture::new();
    let mirror_dir = f.dirs.data.join("mirror");
    let path = mirror_dir.join("demo-linux-x64.json");
    f.write(&path, f.signed(6, PAST));
    let template = mirror_dir.join("demo-{os}-{arch}.json");
    // `file:///C:/...` on Windows, `file:///tmp/...` elsewhere.
    let slashed = template.display().to_string().replace('\\', "/");
    let url = format!("file://{}{slashed}", if cfg!(windows) { "/" } else { "" });
    let net = FakeNet::default();
    let loaded = f.load(&[], Some(&net), Some(&url), refresh()).unwrap();
    assert_eq!(loaded.index.sequence, 6);
    assert_eq!(loaded.source, SourceKind::Mirror);
    assert_eq!(loaded.warnings[0].code, "W_INDEX_EXPIRED");
    assert!(
        net.requests.borrow().is_empty(),
        "the override replaces the remote"
    );

    let enforce = LoadOptions {
        policy: ExpiryPolicy::Enforce,
        ..refresh()
    };
    let err = f
        .load(
            &[],
            Some(&net),
            Some(&template.display().to_string()),
            enforce,
        )
        .unwrap_err();
    assert_eq!(err.code(), "E_INDEX_EXPIRED");
}

#[test]
fn https_override_replaces_the_remote() {
    let f = Fixture::new();
    let mirror = "https://mirror.example.test/demo-{os}-{arch}.json";
    let mut net = FakeNet::default();
    net.serve(
        "https://mirror.example.test/demo-linux-x64.json",
        f.signed(4, PAST),
    );
    let loaded = f.load(&[], Some(&net), Some(mirror), refresh()).unwrap();
    assert_eq!(loaded.source, SourceKind::Mirror);
    assert_eq!(loaded.warnings[0].code, "W_INDEX_EXPIRED");
    assert!(!net.requests.borrow().iter().any(|u| u == REMOTE_EXPANDED));

    // The cached mirror copy keeps the mirror's expiry policy.
    let again = f
        .load(
            &[],
            None,
            Some(mirror),
            LoadOptions {
                offline: true,
                ..options()
            },
        )
        .unwrap();
    assert_eq!(again.source, SourceKind::Cache);
    assert_eq!(again.warnings[0].code, "W_INDEX_EXPIRED");
}

#[test]
fn expired_remote_is_refused() {
    let f = Fixture::new();
    let mut net = FakeNet::default();
    net.serve(REMOTE_EXPANDED, f.signed(4, PAST));
    let err = f.load(&[], Some(&net), None, refresh()).unwrap_err();
    assert_eq!(err.code(), "E_INDEX_EXPIRED");
}

#[test]
fn rollback_is_detected_across_loads() {
    let f = Fixture::new();
    let mut net = FakeNet::default();
    net.serve(REMOTE_EXPANDED, f.signed(8, FUTURE));
    f.load(&[], Some(&net), None, refresh()).unwrap();
    fs::remove_file(f.cache()).unwrap();

    let snapshot = [embedded(f.signed(3, FUTURE))];
    let err = f
        .load(
            &snapshot,
            None,
            None,
            LoadOptions {
                offline: true,
                ..options()
            },
        )
        .unwrap_err();
    assert_eq!(err.code(), "E_INDEX_ROLLBACK");

    let mut old = FakeNet::default();
    old.serve(REMOTE_EXPANDED, f.signed(5, FUTURE));
    let err = f.load(&[], Some(&old), None, refresh()).unwrap_err();
    assert_eq!(err.code(), "E_INDEX_ROLLBACK");
}

#[test]
fn nothing_available_reports_why() {
    let f = Fixture::new();
    let offline = LoadOptions {
        offline: true,
        ..options()
    };
    assert_eq!(
        f.load(&[], None, None, offline).unwrap_err().code(),
        "E_OFFLINE"
    );

    let net = FakeNet::default();
    let err = f.load(&[], Some(&net), None, options()).unwrap_err();
    assert_eq!(err.code(), "E_PLATFORM_UNSUPPORTED");

    let failing = FakeNet {
        fail: true,
        ..FakeNet::default()
    };
    let err = f.load(&[], Some(&failing), None, options()).unwrap_err();
    assert_eq!(err.code(), "E_NETWORK");
}

#[test]
fn a_failed_refresh_falls_back_to_local_copies_with_a_warning() {
    let f = Fixture::new();
    let snapshot = [embedded(f.signed(3, FUTURE))];
    let failing = FakeNet {
        fail: true,
        ..FakeNet::default()
    };
    let loaded = f.load(&snapshot, Some(&failing), None, refresh()).unwrap();
    assert_eq!(loaded.index.sequence, 3);
    assert_eq!(loaded.warnings[0].code, W_INDEX_REFRESH_FAILED);
}

#[test]
fn untrusted_signer_is_exit_seven() {
    let f = Fixture::new();
    let stranger = TestKey::generate();
    let (data, _) = f.signed(3, FUTURE);
    let sig = stranger.sign(&data);
    let snapshot = [embedded((data, sig))];
    let err = f.load(&snapshot, None, None, options()).unwrap_err();
    assert_eq!(err.code(), "E_KEY_UNTRUSTED");
    assert_eq!(err.exit_code(), crate::ExitCode::TrustRequired);
}

#[test]
fn urls_expand_os_and_arch() {
    assert_eq!(
        expand("https://x/j-{os}-{arch}.json", "linux-musl-x64"),
        "https://x/j-linux-musl-x64.json"
    );
    assert_eq!(
        expand("https://x/{os}/{arch}", "macos-aarch64"),
        "https://x/macos/aarch64"
    );
    assert_eq!(local_path("https://x"), None);
    assert_eq!(
        local_path("file:///opt/m.json"),
        Some(PathBuf::from("/opt/m.json"))
    );
    assert_eq!(
        local_path("file:///C:/m.json"),
        Some(PathBuf::from("C:/m.json"))
    );
    assert_eq!(
        local_path("/opt/m.json"),
        Some(PathBuf::from("/opt/m.json"))
    );
}

const KEYS_URL: &str = "https://index.example.test/keys.json";

/// A keys file for `demo` listing `keys`, signed by `anchors`.
fn keys_file(sequence: u64, keys: &[&TestKey], anchors: &[&TestKey]) -> (Vec<u8>, Vec<u8>) {
    let listed: Vec<_> = keys
        .iter()
        .map(|k| json!({ "key": k.public_str(), "scope": ["demo"], "expires": FUTURE }))
        .collect();
    let data = serde_json::to_vec(&json!({
        "format": 1, "sequence": sequence, "threshold": 1, "keys": listed
    }))
    .unwrap();
    let sig = anchors
        .iter()
        .map(|a| a.sign(&data))
        .collect::<Vec<_>>()
        .concat();
    (data, sig)
}

/// An index for `demo` signed by `signer`.
fn index_signed_by(signer: &TestKey, sequence: u64) -> (Vec<u8>, Vec<u8>) {
    let data = serde_json::to_vec(&json!({
        "format": 1,
        "plugin": "demo",
        "platform": "linux-x64",
        "sequence": sequence,
        "generated": "2026-01-01T00:00:00Z",
        "expires": FUTURE,
        "entries": []
    }))
    .unwrap();
    let sig = signer.sign(&data);
    (data, sig)
}

impl Fixture {
    fn loader<'a>(
        &'a self,
        net: Option<&'a FakeNet>,
        embedded_keys: &'a [EmbeddedKeysFile],
    ) -> IndexLoader<'a> {
        IndexLoader {
            dirs: &self.dirs,
            embedded: &[],
            embedded_keys,
            fetcher: net.map(|n| n as &dyn Fetcher),
            mirrors: &self.mirrors,
        }
    }

    /// Builds the keyring for `demo` with `anchors`, then loads the index from `net`.
    fn load_plugin(
        &self,
        anchors: &[String],
        origin: ManifestOrigin,
        net: &FakeNet,
        options: LoadOptions,
    ) -> Result<PluginIndex> {
        let loader = self.loader(Some(net), &[]);
        let keys = PluginKeys {
            plugin: "demo",
            signing_keys: anchors,
            threshold: 1,
            keys_url: Some(KEYS_URL),
            origin,
        };
        let (keyring, mut warnings) = loader.keyring(&keys, &options)?;
        let sources = IndexSources {
            plugin: "demo",
            platform: "linux-x64",
            remote_url: REMOTE,
            override_url: None,
        };
        let mut loaded = loader.load(&sources, &keyring, &options)?;
        warnings.append(&mut loaded.warnings);
        loaded.warnings = warnings;
        Ok(loaded)
    }
}

#[test]
fn a_keys_file_delegates_and_rotates_index_keys_without_prompts() {
    let f = Fixture::new();
    let (root, old, new) = (
        TestKey::generate(),
        TestKey::generate(),
        TestKey::generate(),
    );
    let anchors = [root.public_str()];

    let mut net = FakeNet::default();
    net.serve(KEYS_URL, keys_file(1, &[&old], &[&root]));
    net.serve(REMOTE_EXPANDED, index_signed_by(&old, 1));
    let loaded = f
        .load_plugin(&anchors, ManifestOrigin::Builtin, &net, refresh())
        .unwrap();
    assert_eq!(loaded.index.sequence, 1);
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);

    // The publisher rotates to a new index key.
    net.serve(KEYS_URL, keys_file(2, &[&new], &[&root]));
    net.serve(REMOTE_EXPANDED, index_signed_by(&new, 2));
    let loaded = f
        .load_plugin(&anchors, ManifestOrigin::Builtin, &net, refresh())
        .unwrap();
    assert_eq!(loaded.index.sequence, 2);
    assert_eq!(f.state().keys_file_newest("demo").unwrap().sequence, 2);

    // The retired key no longer verifies anything.
    net.serve(REMOTE_EXPANDED, index_signed_by(&old, 3));
    let loaded = f
        .load_plugin(&anchors, ManifestOrigin::Builtin, &net, refresh())
        .unwrap();
    assert_eq!(
        loaded.index.sequence, 2,
        "the copy signed by the old key is ignored"
    );
    assert!(
        loaded
            .warnings
            .iter()
            .any(|w| w.code == "W_INDEX_COPY_REJECTED"),
        "{:?}",
        loaded.warnings
    );

    // Replaying the old keys file is refused; the cached current one stays in use.
    net.serve(KEYS_URL, keys_file(1, &[&old], &[&root]));
    net.serve(REMOTE_EXPANDED, index_signed_by(&new, 4));
    let loaded = f
        .load_plugin(&anchors, ManifestOrigin::Builtin, &net, refresh())
        .unwrap();
    assert_eq!(loaded.index.sequence, 4);
}

#[test]
fn an_embedded_keys_file_works_offline() {
    let f = Fixture::new();
    let (root, idx) = (TestKey::generate(), TestKey::generate());
    let (data, sig) = keys_file(1, &[&idx], &[&root]);
    let embedded_keys = [EmbeddedKeysFile {
        url: KEYS_URL,
        data: leak(data),
        signature: leak(sig),
    }];
    let loader = f.loader(None, &embedded_keys);
    let keys = PluginKeys {
        plugin: "demo",
        signing_keys: &[root.public_str()],
        threshold: 1,
        keys_url: Some(KEYS_URL),
        origin: ManifestOrigin::Builtin,
    };
    let offline = LoadOptions {
        offline: true,
        ..options()
    };
    let (keyring, warnings) = loader.keyring(&keys, &offline).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    let (data, sig) = index_signed_by(&idx, 1);
    jtm_security::verify(
        &data,
        &sig,
        &keyring,
        jtm_security::Subject {
            file: "demo-linux-x64.json",
            plugin: "demo",
        },
        NOW,
    )
    .unwrap();
}

#[test]
fn a_third_party_plugin_needs_its_key_confirmed() {
    let f = Fixture::new();
    let author = TestKey::generate();
    let anchors = [author.public_str()];
    let mut net = FakeNet::default();
    net.serve(REMOTE_EXPANDED, index_signed_by(&author, 1));

    // `demo` has the shape of a first-party name, but an external manifest's anchors are
    // confirmed, never pre-approved: provenance decides, not the name.
    let err = f
        .load_plugin(&anchors, ManifestOrigin::External, &net, refresh())
        .unwrap_err();
    assert_eq!(err.code(), "E_KEY_UNTRUSTED");
    assert_eq!(err.exit_code(), crate::ExitCode::TrustRequired);
    assert_eq!(
        err.details()["resolve"],
        format!("jtm trust add {} --scope demo", author.public_str())
    );
    assert!(
        net.requests.borrow().is_empty(),
        "nothing is fetched before trust"
    );

    crate::trust::add_key(&f.dirs, &author.public_str(), &["demo".to_owned()], NOW).unwrap();
    let loaded = f
        .load_plugin(&anchors, ManifestOrigin::External, &net, refresh())
        .unwrap();
    assert_eq!(loaded.index.sequence, 1);
}

#[test]
fn a_bad_keys_file_only_drops_its_delegated_keys() {
    let f = Fixture::new();
    let (root, stranger, idx) = (
        TestKey::generate(),
        TestKey::generate(),
        TestKey::generate(),
    );
    let anchors = [root.public_str()];
    let mut net = FakeNet::default();
    // A keys file signed by someone else, delegating to a key it should not.
    net.serve(KEYS_URL, keys_file(1, &[&idx], &[&stranger]));

    net.serve(REMOTE_EXPANDED, index_signed_by(&idx, 1));
    let err = f
        .load_plugin(&anchors, ManifestOrigin::Builtin, &net, refresh())
        .unwrap_err();
    assert_eq!(err.code(), "E_KEY_UNTRUSTED");

    // The anchors can still sign directly, with a warning about the keys file.
    net.serve(REMOTE_EXPANDED, index_signed_by(&root, 1));
    let loaded = f
        .load_plugin(&anchors, ManifestOrigin::Builtin, &net, refresh())
        .unwrap();
    assert_eq!(loaded.warnings[0].code, W_KEYS_FILE_UNAVAILABLE);
    assert!(!keys_cache_path(&f.dirs, "demo").exists());
}

#[test]
fn two_keys_file_copies_at_the_same_sequence_refuse_the_whole_file() {
    let f = Fixture::new();
    let (root, a, b) = (
        TestKey::generate(),
        TestKey::generate(),
        TestKey::generate(),
    );
    let anchors = [root.public_str()];
    let cache_file = keys_cache_path(&f.dirs, "demo");
    let (cached, cached_sig) = keys_file(5, &[&a], &[&root]);
    f.write(&cache_file, (cached.clone(), cached_sig));

    // The network serves different content at the same sequence.
    let mut net = FakeNet::default();
    net.serve(KEYS_URL, keys_file(5, &[&b], &[&root]));
    net.serve(REMOTE_EXPANDED, index_signed_by(&root, 1));
    let loaded = f
        .load_plugin(&anchors, ManifestOrigin::Builtin, &net, refresh())
        .unwrap();
    let warning = loaded
        .warnings
        .iter()
        .find(|w| w.code == W_KEYS_FILE_UNAVAILABLE)
        .expect("the conflict is reported");
    assert!(
        warning.message.contains("differ while claiming sequence 5"),
        "{warning:?}"
    );
    // Neither copy is accepted: nothing is recorded and the cache is left alone.
    assert!(!f.state().keys_files.contains_key("demo"));
    assert_eq!(fs::read(&cache_file).unwrap(), cached);

    // Both copies' delegated keys are dropped; only the anchors verify.
    let loader = f.loader(Some(&net), &[]);
    let keys = PluginKeys {
        plugin: "demo",
        signing_keys: &anchors,
        threshold: 1,
        keys_url: Some(KEYS_URL),
        origin: ManifestOrigin::Builtin,
    };
    let (keyring, warnings) = loader.keyring(&keys, &refresh()).unwrap();
    assert!(warnings.iter().any(|w| w.code == W_KEYS_FILE_UNAVAILABLE));
    let (data, sig) = index_signed_by(&b, 1);
    let err = jtm_security::verify(
        &data,
        &sig,
        &keyring,
        jtm_security::Subject {
            file: "demo-linux-x64.json",
            plugin: "demo",
        },
        NOW,
    )
    .unwrap_err();
    assert!(
        matches!(err, jtm_security::Error::KeyUntrusted { .. }),
        "{err:?}"
    );
}

#[test]
fn a_keys_file_copy_colliding_with_the_record_is_refused() {
    let f = Fixture::new();
    let (root, a, b) = (
        TestKey::generate(),
        TestKey::generate(),
        TestKey::generate(),
    );
    let anchors = [root.public_str()];
    let mut net = FakeNet::default();
    net.serve(KEYS_URL, keys_file(5, &[&a], &[&root]));
    net.serve(REMOTE_EXPANDED, index_signed_by(&a, 1));
    let loaded = f
        .load_plugin(&anchors, ManifestOrigin::Builtin, &net, refresh())
        .unwrap();
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
    assert_eq!(f.state().keys_file_newest("demo").unwrap().sequence, 5);

    // The network now serves a different keys file claiming the recorded sequence.
    net.serve(KEYS_URL, keys_file(5, &[&b], &[&root]));
    net.serve(REMOTE_EXPANDED, index_signed_by(&root, 2));
    let loaded = f
        .load_plugin(&anchors, ManifestOrigin::Builtin, &net, refresh())
        .unwrap();
    let warning = loaded
        .warnings
        .iter()
        .find(|w| w.code == W_KEYS_FILE_UNAVAILABLE)
        .expect("the conflict is reported");
    assert!(
        warning
            .message
            .contains("same as the newest copy already seen"),
        "{warning:?}"
    );
    assert_eq!(f.state().keys_file_newest("demo").unwrap().sequence, 5);
}

#[test]
fn files_over_their_format_limit_are_refused_before_reading() {
    // A signature file over its own 64 KiB limit fails even with small index bytes.
    let f = Fixture::new();
    let (data, sig) = f.signed(1, FUTURE);
    f.write(&f.cache(), (data, sig));
    fs::write(
        signature_path(&f.cache()),
        vec![b'a'; jtm_security::signature::MAX_SIGNATURE_FILE + 1],
    )
    .unwrap();
    let err = f.load(&[], None, None, options()).unwrap_err();
    assert!(
        err.to_string()
            .contains("larger than the limit for a signature file"),
        "{err}"
    );

    // A keys file over its own 1 MiB limit is refused the same way.
    let f = Fixture::new();
    let keys_cache = keys_cache_path(&f.dirs, "demo");
    fs::create_dir_all(keys_cache.parent().unwrap()).unwrap();
    fs::write(
        &keys_cache,
        vec![b'a'; jtm_security::keys_json::MAX_KEYS_FILE + 1],
    )
    .unwrap();
    let anchors = [TestKey::generate().public_str()];
    let mut net = FakeNet::default();
    net.serve(REMOTE_EXPANDED, index_signed_by(&f.key, 1));
    let err = f
        .load_plugin(&anchors, ManifestOrigin::Builtin, &net, options())
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("larger than the limit for a keys file"),
        "{err}"
    );
}

/// `dir` as a `file://` URL ending in a slash, `file:///C:/x/` on Windows.
fn file_url(dir: &Path) -> String {
    let path = dir.display().to_string().replace('\\', "/");
    let slash = if path.starts_with('/') { "" } else { "/" };
    format!("file://{slash}{path}/")
}

const CORP: &str = "https://corp.test/idx/";

#[test]
fn mirrors_apply_to_the_index_the_keys_file_and_their_signatures() {
    let mut f = Fixture::new();
    f.mirrors
        .insert("https://index.example.test/".into(), CORP.into());
    let (root, idx) = (TestKey::generate(), TestKey::generate());
    let mut net = FakeNet::default();
    net.serve(&format!("{CORP}keys.json"), keys_file(1, &[&idx], &[&root]));
    net.serve(
        &format!("{CORP}demo-linux-x64.json"),
        index_signed_by(&idx, 1),
    );

    let loaded = f
        .load_plugin(
            &[root.public_str()],
            ManifestOrigin::Builtin,
            &net,
            refresh(),
        )
        .unwrap();
    assert_eq!(loaded.index.sequence, 1);
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
    assert_eq!(loaded.origin, format!("{CORP}demo-linux-x64.json"));
    // Nothing reached the original host, including the signatures.
    assert_eq!(
        *net.requests.borrow(),
        vec![
            format!("{CORP}keys.json"),
            format!("{CORP}keys.json.minisig"),
            format!("{CORP}demo-linux-x64.json"),
            format!("{CORP}demo-linux-x64.json.minisig"),
        ]
    );
}

#[test]
fn an_expired_index_from_a_rewritten_url_only_warns() {
    // Section 9: expiry is enforced for the canonical remote, and is a warning for a
    // configured mirror, because mirrors go stale by design.
    let mut f = Fixture::new();
    f.mirrors
        .insert("https://index.example.test/".into(), CORP.into());
    let mut net = FakeNet::default();
    net.serve(&format!("{CORP}demo-linux-x64.json"), f.signed(4, PAST));
    let loaded = f.load(&[], Some(&net), None, refresh()).unwrap();
    assert_eq!(loaded.source, SourceKind::Mirror);
    assert_eq!(loaded.warnings[0].code, "W_INDEX_EXPIRED");

    // Without the rewrite the same copy is the canonical remote and is refused.
    let f = Fixture::new();
    let mut net = FakeNet::default();
    net.serve(REMOTE_EXPANDED, f.signed(4, PAST));
    let err = f.load(&[], Some(&net), None, refresh()).unwrap_err();
    assert_eq!(err.code(), "E_INDEX_EXPIRED");
}

#[test]
fn a_signature_can_be_mirrored_apart_from_its_file() {
    let mut f = Fixture::new();
    f.mirrors
        .insert("https://index.example.test/".into(), CORP.into());
    f.mirrors.insert(
        format!("{REMOTE_EXPANDED}.minisig"),
        "https://sig.test/demo.minisig".into(),
    );
    let (data, sig) = f.signed(3, FUTURE);
    let mut net = FakeNet::default();
    net.files.insert(format!("{CORP}demo-linux-x64.json"), data);
    net.files
        .insert("https://sig.test/demo.minisig".into(), sig);

    let loaded = f.load(&[], Some(&net), None, options()).unwrap();
    assert_eq!(loaded.index.sequence, 3);
    assert_eq!(
        *net.requests.borrow(),
        vec![
            format!("{CORP}demo-linux-x64.json"),
            "https://sig.test/demo.minisig".to_owned(),
        ]
    );
}

#[test]
fn a_file_mirror_serves_the_index_and_keys_file_offline() {
    let mut f = Fixture::new();
    let dir = f.dirs.data.join("mirror");
    f.mirrors
        .insert("https://index.example.test/".into(), file_url(&dir));
    let (root, idx) = (TestKey::generate(), TestKey::generate());
    f.write(&dir.join("keys.json"), keys_file(1, &[&idx], &[&root]));
    f.write(&dir.join("demo-linux-x64.json"), index_signed_by(&idx, 7));

    let offline = LoadOptions {
        offline: true,
        ..options()
    };
    let loader = f.loader(None, &[]);
    let keys = PluginKeys {
        plugin: "demo",
        signing_keys: &[root.public_str()],
        threshold: 1,
        keys_url: Some(KEYS_URL),
        origin: ManifestOrigin::Builtin,
    };
    let (keyring, warnings) = loader.keyring(&keys, &offline).unwrap();
    assert!(warnings.is_empty(), "{warnings:?}");
    let sources = IndexSources {
        plugin: "demo",
        platform: "linux-x64",
        remote_url: REMOTE,
        override_url: None,
    };
    let loaded = loader.load(&sources, &keyring, &offline).unwrap();
    assert_eq!(loaded.index.sequence, 7);
    assert_eq!(loaded.source, SourceKind::Mirror);
    assert_eq!(f.state().keys_file_newest("demo").unwrap().sequence, 1);
    // Both are kept for the next run, which may not see the mirror.
    assert!(f.cache().exists());
    assert!(keys_cache_path(&f.dirs, "demo").exists());
}

#[test]
fn a_tampered_file_mirror_index_fails_verification_and_is_not_cached() {
    let mut f = Fixture::new();
    let dir = f.dirs.data.join("mirror");
    f.mirrors
        .insert("https://index.example.test/".into(), file_url(&dir));
    let (mut data, sig) = f.signed(9, FUTURE);
    data.extend_from_slice(b" ");
    f.write(&dir.join("demo-linux-x64.json"), (data, sig));

    let net = FakeNet::default();
    let err = f.load(&[], Some(&net), None, options()).unwrap_err();
    assert_eq!(err.code(), "E_SIGNATURE_INVALID");
    assert!(!f.cache().exists());
    assert!(net.requests.borrow().is_empty());
}

#[test]
fn a_tampered_file_mirror_keys_file_delegates_nothing() {
    let mut f = Fixture::new();
    let dir = f.dirs.data.join("mirror");
    f.mirrors
        .insert("https://index.example.test/".into(), file_url(&dir));
    let (root, idx) = (TestKey::generate(), TestKey::generate());
    let (mut keys, sig) = keys_file(1, &[&idx], &[&root]);
    keys.extend_from_slice(b" ");
    f.write(&dir.join("keys.json"), (keys, sig));
    f.write(&dir.join("demo-linux-x64.json"), index_signed_by(&idx, 1));

    let offline = LoadOptions {
        offline: true,
        ..options()
    };
    let loader = f.loader(None, &[]);
    let keys = PluginKeys {
        plugin: "demo",
        signing_keys: &[root.public_str()],
        threshold: 1,
        keys_url: Some(KEYS_URL),
        origin: ManifestOrigin::Builtin,
    };
    let (keyring, warnings) = loader.keyring(&keys, &offline).unwrap();
    assert_eq!(warnings[0].code, W_KEYS_FILE_UNAVAILABLE);
    assert!(!keys_cache_path(&f.dirs, "demo").exists());
    let sources = IndexSources {
        plugin: "demo",
        platform: "linux-x64",
        remote_url: REMOTE,
        override_url: None,
    };
    // The index key was only delegated by the file that failed verification.
    let err = loader.load(&sources, &keyring, &offline).unwrap_err();
    assert_eq!(err.code(), "E_KEY_UNTRUSTED", "{err}");
}

#[test]
fn a_file_mirror_with_nothing_in_it_is_not_a_reason_to_hit_the_network() {
    let mut f = Fixture::new();
    let dir = f.dirs.data.join("empty-mirror");
    f.mirrors
        .insert("https://index.example.test/".into(), file_url(&dir));
    let mut net = FakeNet::default();
    net.serve(REMOTE_EXPANDED, f.signed(2, FUTURE));
    // The rewritten location is the only one that is asked, and it holds no index.
    assert!(f.load(&[], Some(&net), None, refresh()).is_err());
    assert!(net.requests.borrow().is_empty());
}
