use super::*;

#[test]
fn digests_must_be_lowercase_hex() {
    let cache = DownloadCache::new("/cache");
    assert!(cache.path(&"a".repeat(64)).is_ok());
    assert!(cache.path(&"A".repeat(64)).is_err());
    assert!(cache.path(&"a".repeat(63)).is_err());
    assert!(cache.path("../../etc/passwd").is_err());
    assert!(cache.path(&format!("{}/x", "a".repeat(62))).is_err());
}

#[test]
fn hashes_readers() {
    let (hash, n) = hash_reader(&b"abc"[..], 10).unwrap();
    assert_eq!(n, 3);
    assert_eq!(
        hash,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
