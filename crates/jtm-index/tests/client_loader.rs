//! The done-when of T6.3: files the generator writes and signs are accepted by jtm's own index
//! loader, through the same chain a client follows (a keys file signed by the plugin's root
//! keys delegates to the index key), and every way of tampering with them is refused with the
//! code a client reports.
//!
//! Keys are generated here, in every test. Nothing touches the network: the loader fetches
//! from an in-memory map.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use jtm_core::indices::{
    EmbeddedKeysFile, Fetcher, IndexLoader, IndexSources, LoadOptions, ManifestOrigin, PluginIndex,
    PluginKeys, cache_path,
};
use jtm_core::{Dirs, JtmError, Os, Platform};
use jtm_index::candidate::Target;
use jtm_index::confirm::{ClaimRecord, Confirmation, Confirmed, ConfirmedEntry, Provenance};
use jtm_index::publish::{Request, publish};
use jtm_index::signing::Signer;
use jtm_index::writer::{Binding, Settings, Validity};
use jtm_security::{ArchiveKind, ExpiryPolicy, Timestamp};

/// 2026-10-19T03:00:00Z
const NOW: Timestamp = Timestamp::from_unix(1_792_378_800);
const DAY: i64 = 86_400;
const REMOTE: &str = "https://index.example.test/demo-{os}-{arch}.json";
const ANY_REMOTE: &str = "https://index.example.test/tool-any.json";
const KEYS_URL: &str = "https://index.example.test/keys.json";

fn at(days: i64) -> Timestamp {
    Timestamp::from_unix(NOW.unix() + days * DAY)
}

struct Key {
    secret_file: String,
    public: String,
}

fn key() -> Key {
    let pair = minisign::KeyPair::generate_unencrypted_keypair().unwrap();
    Key {
        secret_file: pair.sk.to_box(None).unwrap().into_string(),
        public: pair.pk.to_base64(),
    }
}

fn signer(key: &Key) -> Signer {
    Signer::from_secret_key(&key.secret_file, None).unwrap()
}

fn entry(variant: Option<&str>, version: &str, target: Target) -> ConfirmedEntry {
    ConfirmedEntry {
        variant: variant.map(str::to_owned),
        version: version.to_owned(),
        target,
        tags: vec!["ga".to_owned()],
        url: format!("https://vendor.test/{version}.zip"),
        archive: ArchiveKind::Zip,
        size: 3,
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_owned(),
        distribution_version: None,
        provenance: Provenance {
            confirmation: Confirmation::Independent,
            sources: vec!["src-a".to_owned(), "src-b".to_owned()],
            claims: vec![ClaimRecord {
                source: "src-a".to_owned(),
                algorithm: jtm_index::HashAlgorithm::Sha256,
                origin: "https://vendor.test/a.sha256".to_owned(),
            }],
            signatures: Vec::new(),
            fetched_at: "2026-10-19T02:00:00Z".to_owned(),
        },
    }
}

fn linux(version: &str) -> ConfirmedEntry {
    entry(Some("alpha"), version, Target::Platform(Platform::LinuxX64))
}

fn confirmed(entries: Vec<ConfirmedEntry>) -> Confirmed {
    Confirmed {
        entries,
        warnings: Vec::new(),
    }
}

fn binding() -> Binding {
    Binding {
        plugin: "demo".to_owned(),
        platform_independent: false,
        variants: vec!["alpha".to_owned()],
    }
}

fn independent() -> Binding {
    Binding {
        plugin: "tool".to_owned(),
        platform_independent: true,
        variants: Vec::new(),
    }
}

/// Publishes `confirmed` into `out`, reading the previous publish from `previous`.
fn generate(
    binding: &Binding,
    confirmed: &Confirmed,
    previous: Option<&Path>,
    out: &Path,
    key: &Key,
    now: Timestamp,
) {
    publish(&Request {
        binding,
        confirmed,
        previous_dir: previous,
        previous_keys: &[],
        out_dir: out,
        signer: Some(&signer(key)),
        settings: Settings {
            now,
            validity: Validity::days(30).unwrap(),
        },
        dry_run: false,
    })
    .unwrap();
}

/// A network of files held in memory.
#[derive(Default)]
struct Net {
    files: HashMap<String, Vec<u8>>,
}

impl Net {
    fn serve(&mut self, url: &str, dir: &Path, file: &str) {
        self.files
            .insert(url.to_owned(), fs::read(dir.join(file)).unwrap());
        self.files.insert(
            format!("{url}.minisig"),
            fs::read(dir.join(format!("{file}.minisig"))).unwrap_or_default(),
        );
    }

    fn serve_bytes(&mut self, url: &str, data: &[u8], signature: &[u8]) {
        self.files.insert(url.to_owned(), data.to_vec());
        self.files
            .insert(format!("{url}.minisig"), signature.to_vec());
    }
}

impl Fetcher for Net {
    fn fetch(&self, url: &str) -> jtm_core::Result<Option<Vec<u8>>> {
        Ok(self.files.get(url).cloned())
    }
}

/// jtm's trust setup for a plugin: root keys that sign a keys file, which delegates to the
/// index key the generator signs with.
struct World {
    _home: tempfile::TempDir,
    dirs: Dirs,
    root: Key,
    index_key: Key,
    keys_file: &'static EmbeddedKeysFile,
}

impl World {
    fn new() -> World {
        World::with_scope(&["demo", "other", "tool"])
    }

    fn with_scope(scope: &[&str]) -> World {
        let home = tempfile::tempdir().unwrap();
        let dirs = Dirs::resolve(Os::host().unwrap(), Some(home.path()), None, &|_| None).unwrap();
        let root = key();
        let index_key = key();
        let keys = serde_json::json!({
            "format": 1,
            "sequence": 1,
            "threshold": 1,
            "keys": [{
                "key": index_key.public,
                "scope": scope,
                "expires": at(90).to_string()
            }]
        });
        let data = serde_json::to_vec_pretty(&keys).unwrap();
        let signature = signer(&root).sign("keys.json", &data, NOW).unwrap();
        let keys_file = Box::leak(Box::new(EmbeddedKeysFile {
            url: KEYS_URL,
            data: Box::leak(data.into_boxed_slice()),
            signature: Box::leak(signature.into_boxed_slice()),
        }));
        World {
            _home: home,
            dirs,
            root,
            index_key,
            keys_file,
        }
    }

    fn load(
        &self,
        net: &Net,
        plugin: &str,
        platform: &str,
        remote_url: &str,
        now: Timestamp,
    ) -> Result<PluginIndex, JtmError> {
        let loader = IndexLoader {
            dirs: &self.dirs,
            embedded: &[],
            embedded_keys: std::slice::from_ref(self.keys_file),
            fetcher: Some(net),
            mirrors: &std::collections::BTreeMap::new(),
        };
        let signing_keys = [self.root.public.clone()];
        let options = LoadOptions {
            refresh: true,
            offline: false,
            policy: ExpiryPolicy::RemoteOnly,
            now,
        };
        let (keyring, _) = loader.keyring(
            &PluginKeys {
                plugin,
                signing_keys: &signing_keys,
                threshold: 1,
                keys_url: Some(KEYS_URL),
                origin: ManifestOrigin::Builtin,
            },
            &options,
        )?;
        loader.load(
            &IndexSources {
                plugin,
                platform,
                remote_url,
                override_url: None,
            },
            &keyring,
            &options,
        )
    }

    fn generate(&self, confirmed: &Confirmed, previous: Option<&Path>, out: &Path, now: Timestamp) {
        generate(&binding(), confirmed, previous, out, &self.index_key, now);
    }
}

fn code(result: Result<PluginIndex, JtmError>) -> &'static str {
    result.unwrap_err().code()
}

const FILE: &str = "demo-linux-x64.json";

// ---------------------------------------------------------------------------------------------
// Generated files are accepted
// ---------------------------------------------------------------------------------------------

#[test]
fn generated_files_verify_with_the_client_loader() {
    let world = World::new();
    let out = tempfile::tempdir().unwrap();
    world.generate(
        &confirmed(vec![linux("1.0.0"), linux("1.1.0")]),
        None,
        out.path(),
        NOW,
    );
    let mut net = Net::default();
    net.serve(
        "https://index.example.test/demo-linux-x64.json",
        out.path(),
        FILE,
    );

    let loaded = world
        .load(&net, "demo", "linux-x64", REMOTE, NOW)
        .expect("the loader accepts what the generator wrote");

    assert_eq!(loaded.index.plugin, "demo");
    assert_eq!(loaded.index.platform, "linux-x64");
    assert_eq!(loaded.index.sequence, 1);
    assert_eq!(loaded.index.generated, NOW);
    assert_eq!(loaded.index.expires, at(30));
    let versions: Vec<&str> = loaded
        .index
        .entries
        .iter()
        .map(|e| e.version.as_str())
        .collect();
    assert_eq!(versions, ["1.0.0", "1.1.0"]);
    assert_eq!(loaded.index.entries[0].provenance, ["src-a", "src-b"]);
    assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
}

#[test]
fn a_platform_independent_index_loads_as_any() {
    let world = World::new();
    let out = tempfile::tempdir().unwrap();
    let confirmed = confirmed(vec![entry(None, "3.9.9", Target::Any)]);
    generate(
        &independent(),
        &confirmed,
        None,
        out.path(),
        &world.index_key,
        NOW,
    );
    let mut net = Net::default();
    net.serve(ANY_REMOTE, out.path(), "tool-any.json");

    let loaded = world.load(&net, "tool", "any", ANY_REMOTE, NOW).unwrap();
    assert_eq!(loaded.index.platform, "any");
    assert_eq!(loaded.index.entries[0].variant, "default");
}

#[test]
fn a_later_publish_is_accepted_after_an_earlier_one_was_seen() {
    let world = World::new();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    world.generate(&confirmed(vec![linux("1.0.0")]), None, first.path(), NOW);
    world.generate(
        &confirmed(vec![linux("1.0.0"), linux("1.1.0")]),
        Some(first.path()),
        second.path(),
        at(1),
    );

    let mut net = Net::default();
    let url = "https://index.example.test/demo-linux-x64.json";
    net.serve(url, first.path(), FILE);
    assert_eq!(
        world
            .load(&net, "demo", "linux-x64", REMOTE, NOW)
            .unwrap()
            .index
            .sequence,
        1
    );
    net.serve(url, second.path(), FILE);
    let loaded = world
        .load(&net, "demo", "linux-x64", REMOTE, at(1))
        .unwrap();
    assert_eq!(loaded.index.sequence, 2);
    assert_eq!(loaded.index.entries.len(), 2);
}

#[test]
fn an_unchanged_republish_is_the_same_file_and_the_client_takes_it_again() {
    let world = World::new();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let input = confirmed(vec![linux("1.0.0")]);
    world.generate(&input, None, first.path(), NOW);
    world.generate(&input, Some(first.path()), second.path(), at(1));
    assert_eq!(
        fs::read(first.path().join(FILE)).unwrap(),
        fs::read(second.path().join(FILE)).unwrap()
    );

    let mut net = Net::default();
    net.serve(
        "https://index.example.test/demo-linux-x64.json",
        second.path(),
        FILE,
    );
    world.load(&net, "demo", "linux-x64", REMOTE, NOW).unwrap();
    // Equal sequence is accepted only for the same bytes (section 9); these are.
    world
        .load(&net, "demo", "linux-x64", REMOTE, at(1))
        .unwrap();
}

// ---------------------------------------------------------------------------------------------
// Everything else is refused, with the client's own codes
// ---------------------------------------------------------------------------------------------

fn published_file(world: &World) -> (tempfile::TempDir, Net) {
    let out = tempfile::tempdir().unwrap();
    world.generate(&confirmed(vec![linux("1.0.0")]), None, out.path(), NOW);
    let mut net = Net::default();
    net.serve(
        "https://index.example.test/demo-linux-x64.json",
        out.path(),
        FILE,
    );
    (out, net)
}

#[test]
fn tampered_bytes_fail_the_signature() {
    let world = World::new();
    let (out, mut net) = published_file(&world);
    let data = String::from_utf8(fs::read(out.path().join(FILE)).unwrap()).unwrap();
    // A mirror pointing an entry at its own download is the attack the signature stops.
    let tampered = data.replace("https://vendor.test/", "https://evil.test/");
    assert_ne!(tampered, data);
    let signature = fs::read(out.path().join(format!("{FILE}.minisig"))).unwrap();
    net.serve_bytes(
        "https://index.example.test/demo-linux-x64.json",
        tampered.as_bytes(),
        &signature,
    );
    assert_eq!(
        code(world.load(&net, "demo", "linux-x64", REMOTE, NOW)),
        "E_SIGNATURE_INVALID"
    );
}

#[test]
fn a_signature_from_another_file_fails_the_signature() {
    let world = World::new();
    let (out, mut net) = published_file(&world);
    let other = tempfile::tempdir().unwrap();
    world.generate(&confirmed(vec![linux("9.9.9")]), None, other.path(), NOW);
    net.serve_bytes(
        "https://index.example.test/demo-linux-x64.json",
        &fs::read(out.path().join(FILE)).unwrap(),
        &fs::read(other.path().join(format!("{FILE}.minisig"))).unwrap(),
    );
    assert_eq!(
        code(world.load(&net, "demo", "linux-x64", REMOTE, NOW)),
        "E_SIGNATURE_INVALID"
    );
}

#[test]
fn a_file_without_a_signature_fails_the_signature() {
    let world = World::new();
    let (out, mut net) = published_file(&world);
    net.serve_bytes(
        "https://index.example.test/demo-linux-x64.json",
        &fs::read(out.path().join(FILE)).unwrap(),
        b"",
    );
    assert_eq!(
        code(world.load(&net, "demo", "linux-x64", REMOTE, NOW)),
        "E_SIGNATURE_INVALID"
    );
}

#[test]
fn a_file_signed_by_a_key_nobody_listed_is_not_trusted() {
    let world = World::new();
    let out = tempfile::tempdir().unwrap();
    generate(
        &binding(),
        &confirmed(vec![linux("1.0.0")]),
        None,
        out.path(),
        &key(),
        NOW,
    );
    let mut net = Net::default();
    net.serve(
        "https://index.example.test/demo-linux-x64.json",
        out.path(),
        FILE,
    );
    assert_eq!(
        code(world.load(&net, "demo", "linux-x64", REMOTE, NOW)),
        "E_KEY_UNTRUSTED"
    );
}

#[test]
fn a_key_scoped_to_other_plugins_is_not_trusted_for_this_one() {
    let world = World::with_scope(&["other"]);
    let (_out, net) = published_file(&world);
    assert_eq!(
        code(world.load(&net, "demo", "linux-x64", REMOTE, NOW)),
        "E_KEY_UNTRUSTED"
    );
}

#[test]
fn an_expired_index_from_the_remote_is_refused() {
    let world = World::new();
    let (_out, net) = published_file(&world);
    // Thirty days of validity; load on day 31 with a key that is still good.
    assert_eq!(
        code(world.load(&net, "demo", "linux-x64", REMOTE, at(31))),
        "E_INDEX_EXPIRED"
    );
}

#[test]
fn an_index_that_has_not_yet_expired_is_accepted() {
    let world = World::new();
    let (_out, net) = published_file(&world);
    world
        .load(&net, "demo", "linux-x64", REMOTE, at(29))
        .unwrap();
}

#[test]
fn an_older_sequence_is_a_rollback() {
    let world = World::new();
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    world.generate(&confirmed(vec![linux("1.0.0")]), None, first.path(), NOW);
    world.generate(
        &confirmed(vec![linux("1.0.0"), linux("1.1.0")]),
        Some(first.path()),
        second.path(),
        at(1),
    );
    let url = "https://index.example.test/demo-linux-x64.json";

    let mut net = Net::default();
    net.serve(url, second.path(), FILE);
    world
        .load(&net, "demo", "linux-x64", REMOTE, at(1))
        .unwrap();

    // An attacker replays the older, still validly signed file to a client with no cache.
    fs::remove_file(cache_path(&world.dirs, "demo", "linux-x64")).unwrap();
    net.serve(url, first.path(), FILE);
    assert_eq!(
        code(world.load(&net, "demo", "linux-x64", REMOTE, at(2))),
        "E_INDEX_ROLLBACK"
    );
}

#[test]
fn a_file_for_another_plugin_is_refused_by_the_binding() {
    let world = World::new();
    let (out, mut net) = published_file(&world);
    // Served where `other` would be looked for; the key covers both plugins.
    net.serve_bytes(
        "https://index.example.test/other-linux-x64.json",
        &fs::read(out.path().join(FILE)).unwrap(),
        &fs::read(out.path().join(format!("{FILE}.minisig"))).unwrap(),
    );
    let remote = "https://index.example.test/other-{os}-{arch}.json";
    assert_eq!(
        code(world.load(&net, "other", "linux-x64", remote, NOW)),
        "E_INDEX_BINDING"
    );
}

#[test]
fn a_file_for_another_platform_is_refused_by_the_binding() {
    let world = World::new();
    let (out, mut net) = published_file(&world);
    net.serve_bytes(
        "https://index.example.test/demo-linux-aarch64.json",
        &fs::read(out.path().join(FILE)).unwrap(),
        &fs::read(out.path().join(format!("{FILE}.minisig"))).unwrap(),
    );
    assert_eq!(
        code(world.load(&net, "demo", "linux-aarch64", REMOTE, NOW)),
        "E_INDEX_BINDING"
    );
}

#[test]
fn an_any_index_is_not_a_platform_index() {
    let world = World::new();
    let out = tempfile::tempdir().unwrap();
    generate(
        &Binding {
            plugin: "demo".to_owned(),
            platform_independent: true,
            variants: Vec::new(),
        },
        &confirmed(vec![entry(None, "1.0.0", Target::Any)]),
        None,
        out.path(),
        &world.index_key,
        NOW,
    );
    let mut net = Net::default();
    net.serve(
        "https://index.example.test/demo-linux-x64.json",
        out.path(),
        "demo-any.json",
    );
    assert_eq!(
        code(world.load(&net, "demo", "linux-x64", REMOTE, NOW)),
        "E_INDEX_BINDING"
    );
}

#[test]
fn a_signed_file_the_loader_cannot_parse_is_invalid() {
    // The generator never writes this; the test shows the code a malformed signed file gets,
    // which is why the generator loads every file itself before publishing it.
    let world = World::new();
    let data = br#"{"format": 1, "plugin": "demo"}"#;
    let signature = signer(&world.index_key)
        .sign("demo-linux-x64.json", data, NOW)
        .unwrap();
    let mut net = Net::default();
    net.serve_bytes(
        "https://index.example.test/demo-linux-x64.json",
        data,
        &signature,
    );
    assert_eq!(
        code(world.load(&net, "demo", "linux-x64", REMOTE, NOW)),
        "E_INDEX_INVALID"
    );
}
