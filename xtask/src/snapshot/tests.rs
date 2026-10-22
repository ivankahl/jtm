//! A release is served by a local mock server or read from a directory, with root and index
//! keys generated here. The shipped first-party manifest is used with its root key swapped for
//! the test root and its URLs aimed at the mock server; nothing touches the real network.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use jtm_archive::testing::{exe, file, tar_gz};
use jtm_core::config::{Config, ConfigInputs};
use jtm_core::indices::{EmbeddedIndex, EmbeddedKeysFile, Snapshot, cache_path};
use jtm_core::install::Status;
use jtm_core::plugins::BuiltinManifest;
use jtm_core::session::{InstallOptions, Session};
use jtm_core::{Context, Dirs, GlobalFlags, Os, Platform, Terminal, ToolSpec};
use jtm_security::testing::TestKey;
use jtm_security::{SourceKind, Timestamp};
use serde_json::json;
use tokio::runtime::Runtime;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

const DAY: i64 = 86_400;
const PLUGIN: &str = "java";
const VERSION: &str = "21.0.5+11";
/// Where the test manifest says the release is. Manifests accept only `https`, so requests are
/// rewritten to the mock server by [`Rewrite`].
const RELEASE: &str = "https://index.example.test/download";

/// A release of the first-party index for one plugin, as `jtm-dev/index` publishes it.
struct Release {
    rt: Runtime,
    server: MockServer,
    root: TestKey,
    index_key: TestKey,
    /// The plugin directory, holding the test manifest.
    plugins: tempfile::TempDir,
    manifest: String,
    platform: Platform,
    archive: Vec<u8>,
}

impl Release {
    fn new() -> Release {
        let rt = Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        let root = TestKey::generate();
        let shipped = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../crates/jtm-cli/plugins")
            .join(PLUGIN)
            .join("plugin.toml");
        let mut manifest: toml::Table =
            toml::from_str(&fs::read_to_string(shipped).unwrap()).unwrap();
        let index = manifest["index"].as_table_mut().unwrap();
        index["signing_keys"] = vec![root.public_str()].into();
        index["url"] = format!("{RELEASE}/{PLUGIN}-{{os}}-{{arch}}.json").into();
        index["keys_url"] = format!("{RELEASE}/keys.json").into();
        let manifest = toml::to_string(&manifest).unwrap();
        let plugins = tempfile::tempdir().unwrap();
        fs::create_dir_all(plugins.path().join(PLUGIN)).unwrap();
        fs::write(plugins.path().join(PLUGIN).join("plugin.toml"), &manifest).unwrap();
        let top = format!("jdk-{VERSION}");
        let archive = tar_gz(&[
            exe(&format!("{top}/bin/java"), b"#!/bin/sh\necho java\n"),
            exe(&format!("{top}/bin/java.exe"), b"MZ"),
            file(&format!("{top}/release"), VERSION.as_bytes()),
        ]);
        Release {
            rt,
            server,
            root,
            index_key: TestKey::generate(),
            plugins,
            manifest,
            platform: Platform::detect().unwrap(),
            archive,
        }
    }

    fn index_name(&self) -> String {
        format!("{PLUGIN}-{}.json", self.platform.as_str())
    }

    /// `keys.json` delegating to the index key, signed by `signer`.
    fn keys(&self, signer: &TestKey) -> (Vec<u8>, Vec<u8>) {
        let data = serde_json::to_vec_pretty(&json!({
            "format": 1,
            "sequence": 1,
            "threshold": 1,
            "keys": [{
                "key": self.index_key.public_str(),
                "scope": [PLUGIN],
                "expires": days(60).to_string(),
            }]
        }))
        .unwrap();
        let signature = signer.sign(&data);
        (data, signature)
    }

    /// This platform's index, offering one version whose archive lives on a host that does not
    /// exist, signed by the index key.
    fn index(&self, expires: Timestamp) -> (Vec<u8>, Vec<u8>) {
        let data = serde_json::to_vec_pretty(&json!({
            "format": 1,
            "plugin": PLUGIN,
            "platform": self.platform.as_str(),
            "sequence": 7,
            "generated": days(-1).to_string(),
            "expires": expires.to_string(),
            "entries": [{
                "variant": "temurin",
                "version": VERSION,
                "tags": ["ga", "lts"],
                "url": "https://archives.invalid/jdk.tar.gz",
                "archive": "tar.gz",
                "size": self.archive.len(),
                "sha256": jtm_security::sha256_hex(&self.archive),
            }]
        }))
        .unwrap();
        let signature = self.index_key.sign(&data);
        (data, signature)
    }

    /// The release's files by name: `keys.json`, this platform's index and their signatures.
    fn files(&self) -> Vec<(String, Vec<u8>)> {
        let (keys, keys_sig) = self.keys(&self.root);
        let (index, index_sig) = self.index(days(30));
        vec![
            ("keys.json".to_owned(), keys),
            ("keys.json.minisig".to_owned(), keys_sig),
            (self.index_name(), index),
            (format!("{}.minisig", self.index_name()), index_sig),
        ]
    }

    fn serve(&self, files: &[(String, Vec<u8>)]) {
        for (name, bytes) in files {
            self.rt.block_on(
                Mock::given(method("GET"))
                    .and(path(format!("/download/{name}")))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes.clone()))
                    .mount(&self.server),
            );
        }
    }

    fn write_dir(&self, files: &[(String, Vec<u8>)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in files {
            fs::write(dir.path().join(name), bytes).unwrap();
        }
        dir
    }

    fn embed(&self, source: &dyn Fetcher, out: &Path) -> Result<Embedded, String> {
        embed(&Request {
            plugins: self.plugins.path(),
            source,
            out,
            now: Timestamp::now(),
        })
    }

    fn embed_from_server(&self, out: &Path) -> Result<Embedded, String> {
        let client = jtm_fetch::Client::new(jtm_fetch::ClientOptions {
            // The mock server speaks plain HTTP.
            allow_http: true,
            ..jtm_fetch::ClientOptions::new("0.0.0-test")
        })
        .unwrap();
        self.embed(
            &Rewrite {
                client,
                to: format!("{}/download", self.server.uri()),
            },
            out,
        )
    }

    fn expected_listing(&self) -> Listing {
        Listing {
            indices: vec![IndexFile {
                plugin: PLUGIN.to_owned(),
                platform: self.platform.as_str().to_owned(),
                file: self.index_name(),
            }],
            keys: vec![KeysFile {
                url: format!("{RELEASE}/keys.json"),
                file: "keys.json".to_owned(),
            }],
        }
    }
}

/// The HTTP client, with the release's `https` location rewritten to the mock server.
struct Rewrite {
    client: jtm_fetch::Client,
    to: String,
}

impl Fetcher for Rewrite {
    fn fetch(&self, url: &str) -> jtm_core::Result<Option<Vec<u8>>> {
        let rest = url.strip_prefix(RELEASE).unwrap();
        self.client.fetch(&format!("{}{rest}", self.to))
    }
}

fn days(n: i64) -> Timestamp {
    Timestamp::from_unix(Timestamp::now().unix() + n * DAY)
}

fn leak(bytes: Vec<u8>) -> &'static [u8] {
    Box::leak(bytes.into_boxed_slice())
}

fn leak_str(s: &str) -> &'static str {
    Box::leak(s.to_owned().into_boxed_str())
}

/// The snapshot `build.rs` would embed from `dir`: the same listing, read by the same code,
/// with the files' bytes in place of `include_bytes!`.
fn compiled(dir: &Path) -> Snapshot {
    let listing = Listing::read(dir).unwrap().expect("a listing");
    let read = |name: &str| leak(fs::read(dir.join(name)).unwrap());
    let indices: Vec<EmbeddedIndex> = listing
        .indices
        .iter()
        .map(|i| EmbeddedIndex {
            plugin: leak_str(&i.plugin),
            platform: leak_str(&i.platform),
            data: read(&i.file),
            signature: read(&signature_file(&i.file)),
        })
        .collect();
    let keys: Vec<EmbeddedKeysFile> = listing
        .keys
        .iter()
        .map(|k| EmbeddedKeysFile {
            url: leak_str(&k.url),
            data: read(&k.file),
            signature: read(&signature_file(&k.file)),
        })
        .collect();
    Snapshot {
        indices: Box::leak(indices.into_boxed_slice()),
        keys: Box::leak(keys.into_boxed_slice()),
    }
}

fn snapshot_files(out: &Path) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(String, Vec<u8>)> = fs::read_dir(out)
        .unwrap()
        .flatten()
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                fs::read(e.path()).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

#[test]
fn a_fresh_binary_installs_from_the_embedded_snapshot_with_the_network_disabled() {
    let release = Release::new();
    let files = release.files();
    release.serve(&files);
    let out = tempfile::tempdir().unwrap();
    let embedded = release.embed_from_server(out.path()).unwrap();
    assert_eq!(embedded.listing, release.expected_listing());
    for (name, bytes) in &files {
        assert_eq!(&fs::read(out.path().join(name)).unwrap(), bytes, "{name}");
    }

    // The release goes away: from here on nothing can be fetched, and the context is offline.
    let Release {
        server,
        manifest,
        archive,
        platform,
        ..
    } = release;
    drop(server);
    let home = tempfile::tempdir().unwrap();
    let ctx = Context {
        home: Some(home.path().to_path_buf()),
        // The test manifest as the binary would compile it in, so its root key is pre-approved.
        builtin: Box::leak(Box::new([BuiltinManifest {
            name: PLUGIN,
            text: leak_str(&manifest),
            script: None,
        }])),
        snapshot: compiled(out.path()),
        ..Context::resolve(
            &GlobalFlags {
                offline: true,
                ..GlobalFlags::default()
            },
            |_| None,
            Terminal::default(),
        )
        .unwrap()
    };
    let dirs = Dirs::resolve(Os::host().unwrap(), Some(home.path()), None, &|_| None).unwrap();
    // Archives are not embedded; a pre-seeded download cache stands in for one carried over.
    fs::create_dir_all(dirs.downloads()).unwrap();
    fs::write(
        dirs.downloads().join(jtm_security::sha256_hex(&archive)),
        &archive,
    )
    .unwrap();
    let settings = Config::load(&ConfigInputs {
        user: None,
        project: None,
        env: &|_| None,
        flags: &[],
    })
    .unwrap()
    .settings;
    let session = Session::new(&ctx, dirs.clone(), settings, platform).unwrap();

    let plugin = session.plugin(PLUGIN).unwrap();
    let index = session.index(&plugin, platform, false).unwrap();
    assert_eq!(index.source, SourceKind::Embedded);
    let spec = ToolSpec::parse(&format!("{PLUGIN}@temurin:21")).unwrap();
    let (item, _) = session
        .install(&spec, InstallOptions::default(), &mut |_| {})
        .unwrap();
    assert_eq!(item.status, Status::Installed);
    assert_eq!(item.version.id.version, VERSION);
    assert!(item.cached, "the archive came from the cache");
    let home_dir = Path::new(&item.version.path);
    assert!(home_dir.join("bin").join("java").is_file(), "{home_dir:?}");
    // An embedded copy is never written to the cache: the binary already holds it.
    assert!(!cache_path(&dirs, PLUGIN, platform.as_str()).exists());
}

#[test]
fn a_release_directory_embeds_the_same_files() {
    let release = Release::new();
    let files = release.files();
    let dir = release.write_dir(&files);
    let out = tempfile::tempdir().unwrap();
    let embedded = release.embed(&ReleaseDir(dir.path()), out.path()).unwrap();
    assert_eq!(embedded.listing, release.expected_listing());
    assert_eq!(
        Listing::read(out.path()).unwrap(),
        Some(release.expected_listing())
    );
    for (name, bytes) in &files {
        assert_eq!(&fs::read(out.path().join(name)).unwrap(), bytes, "{name}");
    }
}

#[test]
fn a_file_that_fails_the_check_leaves_the_previous_snapshot_untouched() {
    let release = Release::new();
    let out = tempfile::tempdir().unwrap();
    let good = release.write_dir(&release.files());
    release.embed(&ReleaseDir(good.path()), out.path()).unwrap();
    let before = snapshot_files(out.path());

    let tampered = |name: &str, bytes: Vec<u8>| {
        let mut files = release.files();
        for (n, b) in &mut files {
            if n == name {
                *b = bytes.clone();
            }
        }
        files
    };
    let mut flipped = release.files()[2].1.clone();
    flipped[10] ^= 1;
    let (expired, expired_sig) = release.index(days(-1));
    let (keys_by_index_key, sig_by_index_key) = release.keys(&release.index_key);
    let mut expired_files = tampered(&release.index_name(), expired);
    expired_files[3].1 = expired_sig;
    let mut keys_files = tampered("keys.json", keys_by_index_key);
    keys_files[1].1 = sig_by_index_key;
    let cases = [
        ("a changed index", tampered(&release.index_name(), flipped)),
        ("an expired index", expired_files),
        ("keys.json signed by an index key", keys_files),
    ];
    for (what, files) in cases {
        let dir = release.write_dir(&files);
        let err = release
            .embed(&ReleaseDir(dir.path()), out.path())
            .expect_err(what);
        assert!(err.contains("would not load"), "{what}: {err}");
        assert_eq!(snapshot_files(out.path()), before, "{what}");
    }
}

#[test]
fn a_missing_file_or_signature_is_refused() {
    let release = Release::new();
    let out = tempfile::tempdir().unwrap();
    let index = release.index_name();
    let index_sig = format!("{index}.minisig");
    let cases = [
        ("keys.json", "keys.json was not found"),
        ("keys.json.minisig", "keys.json.minisig was not found"),
        (index_sig.as_str(), "minisig was not found"),
        // No index for any platform: the release check names the plugin.
        (index.as_str(), "holds no index file"),
    ];
    for (missing, expected) in cases {
        let files: Vec<_> = release
            .files()
            .into_iter()
            .filter(|(name, _)| {
                name != missing
                    && !(missing.ends_with(".json") && *name == format!("{missing}.minisig"))
            })
            .collect();
        let dir = release.write_dir(&files);
        let err = release
            .embed(&ReleaseDir(dir.path()), out.path())
            .expect_err(missing);
        assert!(err.contains(expected), "{missing}: {err}");
        assert_eq!(Listing::read(out.path()).unwrap(), None, "{missing}");
    }
}

#[test]
fn clear_removes_the_snapshot_and_keeps_the_readme() {
    let release = Release::new();
    let out = tempfile::tempdir().unwrap();
    fs::write(out.path().join("README.md"), "docs").unwrap();
    fs::write(out.path().join(".gitignore"), "*").unwrap();
    let dir = release.write_dir(&release.files());
    release.embed(&ReleaseDir(dir.path()), out.path()).unwrap();

    clear(out.path()).unwrap();
    let names: Vec<String> = snapshot_files(out.path())
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(names, [".gitignore", "README.md"]);
    assert_eq!(Listing::read(out.path()).unwrap(), None);
    // Clearing an empty or absent snapshot is a no-op.
    clear(out.path()).unwrap();
    clear(&out.path().join("absent")).unwrap();
}

#[test]
fn a_release_dir_serves_only_plain_file_names() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("keys.json"), b"{}").unwrap();
    let release = ReleaseDir(dir.path());
    assert_eq!(
        release.fetch("https://example.test/a/keys.json").unwrap(),
        Some(b"{}".to_vec())
    );
    for url in [
        "https://example.test/missing.json",
        "https://example.test/..",
        "https://example.test/",
        "https://example.test/a\\keys.json",
    ] {
        assert_eq!(release.fetch(url).unwrap(), None, "{url}");
    }
}
