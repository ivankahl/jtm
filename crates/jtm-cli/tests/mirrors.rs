//! `[mirrors]` pointing at a directory (`file://` URL or plain path), end to end. A mirror
//! changes where bytes come from, never what is accepted: the signed index and its hashes
//! decide.

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::Path;

use common::{Fixture, exists};

/// `dir` as a `file://` URL ending in a slash, `file:///C:/x/` on Windows.
fn file_url(dir: &Path) -> String {
    let path = dir.display().to_string().replace('\\', "/");
    let slash = if path.starts_with('/') { "" } else { "/" };
    format!("file://{slash}{path}/")
}

fn path_target(dir: &Path) -> String {
    format!("{}/", dir.display().to_string().replace('\\', "/"))
}

fn requests_to_the_server(f: &Fixture) -> usize {
    f.rt.block_on(f.server.received_requests())
        .unwrap_or_default()
        .len()
}

#[test]
fn a_directory_mirror_serves_the_index_and_archive_offline() {
    for target in [file_url, path_target] {
        let f = Fixture::new(false);
        f.trust();
        let mirror = tempfile::tempdir().unwrap();
        f.use_directory_mirror(mirror.path(), &target(mirror.path()), false);

        let (code, value) = f.json(&["--offline", "install", "demo@1.0.0"]);
        assert_eq!(code, 0, "{value}");
        assert_eq!(value["changed"], true);
        assert_eq!(value["data"]["installed"][0]["status"], "installed");
        assert_eq!(
            std::fs::read(f.install_dir("1.0.0").join("VERSION")).unwrap(),
            b"1.0.0"
        );
        assert_eq!(requests_to_the_server(&f), 0, "the network is never used");

        let (code, again) = f.json(&["--offline", "install", "demo@1.0.0"]);
        assert_eq!(code, 0, "{again}");
        assert_eq!(again["changed"], false);
    }
}

#[test]
fn a_tampered_directory_mirror_copy_installs_nothing() {
    let f = Fixture::new(false);
    f.trust();
    let mirror = tempfile::tempdir().unwrap();
    f.use_directory_mirror(mirror.path(), &file_url(mirror.path()), true);

    let (code, value) = f.json(&["--offline", "install", "demo@1.0.0"]);
    assert_eq!(code, 5, "{value}");
    assert_eq!(value["error"]["code"], "E_HASH_MISMATCH");
    assert_ne!(
        value["error"]["details"]["expected"],
        value["error"]["details"]["actual"]
    );
    assert!(!exists(&f.install_dir("1.0.0")));
    let downloads = f.home.path().join("cache").join("downloads");
    let leftovers: Vec<_> = std::fs::read_dir(downloads)
        .map(|dir| {
            dir.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .filter(|n| !n.ends_with(".lock"))
                .collect()
        })
        .unwrap_or_default();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    // The untouched versions in the same mirror still install.
    let (code, value) = f.json(&["--offline", "install", "demo@1.1.0"]);
    assert_eq!(code, 0, "{value}");
}

#[test]
fn a_tampered_directory_mirror_index_is_refused() {
    let f = Fixture::new(false);
    f.trust();
    let mirror = tempfile::tempdir().unwrap();
    f.use_directory_mirror(mirror.path(), &file_url(mirror.path()), false);
    let index = mirror
        .path()
        .join("index")
        .join(format!("demo-{}.json", f.platform));
    let mut bytes = std::fs::read(&index).unwrap();
    bytes.push(b' ');
    std::fs::write(&index, bytes).unwrap();

    let (code, value) = f.json(&["--offline", "install", "demo@1.0.0"]);
    assert_ne!(code, 0, "{value}");
    assert_eq!(value["error"]["code"], "E_SIGNATURE_INVALID");
    assert!(!exists(&f.install_dir("1.0.0")));
}
