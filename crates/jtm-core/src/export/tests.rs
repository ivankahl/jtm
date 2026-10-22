use super::*;

fn entry(url: &str, bytes: &[u8]) -> IndexEntry {
    IndexEntry {
        variant: "default".to_owned(),
        version: "1.0.0".to_owned(),
        tags: Vec::new(),
        url: url.to_owned(),
        archive: jtm_security::ArchiveKind::TarGz,
        size: bytes.len() as u64,
        sha256: jtm_security::sha256_hex(bytes),
        provenance: Vec::new(),
    }
}

fn leftovers(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect()
}

#[test]
fn bytes_are_written_where_asked_and_recognised_afterwards() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("host").join("a").join("index.json");
    let content = Content::Bytes(b"signed".to_vec());
    assert!(!content.is_current(&dest).unwrap());

    write_bytes(&dest, b"signed").unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"signed");
    assert!(content.is_current(&dest).unwrap());
    assert_eq!(leftovers(dest.parent().unwrap()), ["index.json"]);

    // Different bytes of the same length are not current, and are replaced.
    assert!(
        !Content::Bytes(b"signeD".to_vec())
            .is_current(&dest)
            .unwrap()
    );
    write_bytes(&dest, b"signeD").unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"signeD");
}

#[test]
fn a_directory_in_the_way_is_not_current() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("x");
    fs::create_dir(&dest).unwrap();
    assert!(!Content::Bytes(Vec::new()).is_current(&dest).unwrap());
}

#[test]
fn a_verified_archive_is_copied_and_recognised_afterwards() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = vec![7u8; 200_000];
    let source = dir.path().join("cached");
    fs::write(&source, &bytes).unwrap();
    let entry = entry("https://dl.test/a.tar.gz", &bytes);
    let dest = dir.path().join("out").join("a.tar.gz");

    copy_verified(&source, &dest, &entry).unwrap();
    assert_eq!(fs::read(&dest).unwrap(), bytes);
    assert!(Content::Artifact(entry.clone()).is_current(&dest).unwrap());
    assert_eq!(leftovers(dest.parent().unwrap()), ["a.tar.gz"]);

    // A copy with a flipped byte is not current.
    let mut bad = bytes;
    bad[10] ^= 1;
    fs::write(&dest, bad).unwrap();
    assert!(!Content::Artifact(entry).is_current(&dest).unwrap());
}

#[test]
fn an_archive_that_does_not_match_its_hash_is_never_exported() {
    let dir = tempfile::tempdir().unwrap();
    let promised = vec![1u8; 4096];
    let entry = entry("https://dl.test/a.tar.gz", &promised);
    let source = dir.path().join("cached");
    let dest = dir.path().join("out").join("a.tar.gz");

    // Same length, one byte different.
    let mut tampered = promised.clone();
    tampered[100] ^= 0xff;
    fs::write(&source, &tampered).unwrap();
    let err = copy_verified(&source, &dest, &entry).unwrap_err();
    assert_eq!(err.code(), "E_HASH_MISMATCH", "{err}");
    assert!(!dest.exists());
    assert!(leftovers(dest.parent().unwrap()).is_empty());

    // Too short, and too long.
    for wrong in [
        &promised[..4000],
        &[promised.clone(), vec![0u8; 5]].concat()[..],
    ] {
        fs::write(&source, wrong).unwrap();
        let err = copy_verified(&source, &dest, &entry).unwrap_err();
        assert_eq!(err.code(), "E_HASH_MISMATCH", "{err}");
        assert!(!dest.exists());
        assert!(leftovers(dest.parent().unwrap()).is_empty());
    }
}

#[test]
fn a_failed_copy_keeps_the_file_that_was_already_there() {
    let dir = tempfile::tempdir().unwrap();
    let promised = vec![1u8; 64];
    let entry = entry("https://dl.test/a.tar.gz", &promised);
    let source = dir.path().join("cached");
    fs::write(&source, vec![2u8; 64]).unwrap();
    let dest = dir.path().join("a.tar.gz");
    fs::write(&dest, b"old").unwrap();

    assert!(copy_verified(&source, &dest, &entry).is_err());
    assert_eq!(fs::read(&dest).unwrap(), b"old");
}

fn item(kind: FileKind, plugin: &str, rel: &str, bytes: &[u8]) -> Item {
    Item {
        kind,
        plugin: plugin.to_owned(),
        platform: None,
        url: format!("https://{rel}"),
        rel: PathBuf::from(rel),
        content: Content::Bytes(bytes.to_vec()),
    }
}

#[test]
fn the_same_file_twice_is_one_file_and_two_contents_for_one_url_are_refused() {
    let mut plan = Plan::default();
    plan.add(item(FileKind::Index, "a", "h/x.json", b"1"))
        .unwrap();
    plan.add(item(FileKind::Index, "a", "h/x.json", b"1"))
        .unwrap();
    let err = plan
        .add(item(FileKind::Index, "b", "h/x.json", b"2"))
        .unwrap_err();
    assert_eq!(err.code(), "E_INDEX_INVALID", "{err}");
    assert_eq!(plan.ordered().len(), 1);
}

#[test]
fn indices_are_written_after_everything_they_advertise() {
    let mut plan = Plan::default();
    plan.add(item(FileKind::Index, "a", "h/a.json", b"i"))
        .unwrap();
    plan.add(item(FileKind::Signature, "a", "h/a.json.minisig", b"s"))
        .unwrap();
    plan.add(item(FileKind::Keys, "a", "h/keys.json", b"k"))
        .unwrap();
    plan.add(item(FileKind::Artifact, "a", "h/a.tar.gz", b"x"))
        .unwrap();
    let order: Vec<FileKind> = plan.ordered().iter().map(|i| i.kind).collect();
    assert_eq!(order.first(), Some(&FileKind::Artifact));
    assert_eq!(order.last(), Some(&FileKind::Index));
    assert!(
        order.iter().position(|k| *k == FileKind::Keys)
            < order.iter().position(|k| *k == FileKind::Signature)
    );
}

#[test]
fn a_host_prefix_ends_at_the_first_slash_after_the_scheme() {
    assert_eq!(
        host_prefix("https://github.com/adoptium/x.zip").as_deref(),
        Some("https://github.com/")
    );
    assert_eq!(
        host_prefix("http://mirror.test:8080/a").as_deref(),
        Some("http://mirror.test:8080/")
    );
    assert_eq!(host_prefix("https://nohost"), None);
}
