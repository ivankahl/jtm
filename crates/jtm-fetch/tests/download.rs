//! Streaming downloads into the content-addressed cache.

mod common;

use std::fs;

use common::{Mock, client, sha256, unsized_server};
use jtm_fetch::{Artifact, DownloadCache, Error, Origin};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock as Route, ResponseTemplate};

fn body() -> Vec<u8> {
    (0..200_000u32).map(|i| (i % 251) as u8).collect()
}

fn serve(mock: &Mock, data: Vec<u8>) {
    mock.mount(
        Route::given(method("GET"))
            .and(path("/a.zip"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(data)),
    );
}

fn noop() -> impl FnMut(u64, u64) {
    |_, _| {}
}

#[test]
fn downloads_verifies_and_caches() {
    let mock = Mock::start();
    let data = body();
    serve(&mock, data.clone());
    let dir = tempfile::tempdir().unwrap();
    let cache = DownloadCache::new(dir.path().join("downloads"));
    let digest = sha256(&data);
    let url = mock.url("/a.zip");
    let artifact = Artifact {
        url: &url,
        sha256: &digest,
        size: data.len() as u64,
    };

    let mut last = (0, 0);
    let got = cache
        .fetch(&client(), &artifact, &mut |done, total| {
            last = (done, total)
        })
        .unwrap();
    assert_eq!(got.origin, Origin::Network);
    assert_eq!(got.path, dir.path().join("downloads").join(&digest));
    assert_eq!(fs::read(&got.path).unwrap(), data);
    assert_eq!(got.url, url);
    assert_eq!(last, (data.len() as u64, data.len() as u64));
    assert!(
        !dir.path()
            .join("downloads")
            .join(format!("{digest}.part"))
            .exists()
    );

    let again = cache.fetch(&client(), &artifact, &mut noop()).unwrap();
    assert_eq!(again.origin, Origin::Cache);
    assert_eq!(mock.requests().len(), 1);
}

#[test]
fn a_tampered_cached_file_is_rehashed_and_replaced() {
    let mock = Mock::start();
    let data = body();
    serve(&mock, data.clone());
    let dir = tempfile::tempdir().unwrap();
    let cache = DownloadCache::new(dir.path());
    let digest = sha256(&data);
    let url = mock.url("/a.zip");
    let artifact = Artifact {
        url: &url,
        sha256: &digest,
        size: data.len() as u64,
    };
    let mut tampered = data.clone();
    tampered[1000] ^= 0xff;
    fs::write(dir.path().join(&digest), &tampered).unwrap();

    assert_eq!(cache.lookup(&artifact).unwrap(), None);
    assert!(!dir.path().join(&digest).exists());

    fs::write(dir.path().join(&digest), &tampered).unwrap();
    let got = cache.fetch(&client(), &artifact, &mut noop()).unwrap();
    assert_eq!(got.origin, Origin::Network);
    assert_eq!(fs::read(&got.path).unwrap(), data);
}

#[test]
fn a_hash_mismatch_deletes_the_partial_file_and_is_not_retried() {
    let mock = Mock::start();
    let data = body();
    let mut served = data.clone();
    served[5] ^= 1;
    serve(&mock, served.clone());
    let dir = tempfile::tempdir().unwrap();
    let cache = DownloadCache::new(dir.path());
    let digest = sha256(&data);
    let url = mock.url("/a.zip");
    let artifact = Artifact {
        url: &url,
        sha256: &digest,
        size: data.len() as u64,
    };

    let err = cache.fetch(&client(), &artifact, &mut noop()).unwrap_err();
    match &err {
        Error::HashMismatch {
            url: got_url,
            expected,
            actual,
        } => {
            assert_eq!(got_url, &url);
            assert_eq!(expected, &digest);
            assert_eq!(actual, &sha256(&served));
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(!err.is_transient());
    assert_eq!(mock.requests().len(), 1);
    assert!(!dir.path().join(format!("{digest}.part")).exists());
    assert!(!dir.path().join(&digest).exists());
}

#[test]
fn a_short_body_is_a_hash_mismatch() {
    let mock = Mock::start();
    let data = body();
    serve(&mock, data[..1000].to_vec());
    let dir = tempfile::tempdir().unwrap();
    let digest = sha256(&data);
    let url = mock.url("/a.zip");
    let artifact = Artifact {
        url: &url,
        sha256: &digest,
        size: data.len() as u64,
    };
    let err = DownloadCache::new(dir.path())
        .fetch(&client(), &artifact, &mut noop())
        .unwrap_err();
    assert!(matches!(err, Error::HashMismatch { .. }), "{err:?}");
}

#[test]
fn an_announced_oversize_body_is_refused_before_reading() {
    let mock = Mock::start();
    let data = body();
    serve(&mock, data.clone());
    let dir = tempfile::tempdir().unwrap();
    let digest = sha256(&data[..100]);
    let url = mock.url("/a.zip");
    let artifact = Artifact {
        url: &url,
        sha256: &digest,
        size: 100,
    };
    let mut reported = Vec::new();
    let err = DownloadCache::new(dir.path())
        .fetch(&client(), &artifact, &mut |done, _| reported.push(done))
        .unwrap_err();
    assert!(matches!(err, Error::TooLarge { limit: 100, .. }), "{err:?}");
    assert!(reported.is_empty(), "nothing is read: {reported:?}");
    assert_eq!(mock.requests().len(), 1);
    assert!(!dir.path().join(format!("{digest}.part")).exists());
}

#[test]
fn an_unannounced_oversize_body_aborts_once_the_size_is_exceeded() {
    let data = vec![7u8; 4 * 1024 * 1024];
    let url = unsized_server(data.clone());
    let dir = tempfile::tempdir().unwrap();
    let digest = sha256(&data[..1000]);
    let artifact = Artifact {
        url: &url,
        sha256: &digest,
        size: 1000,
    };
    let mut most = 0;
    let err = DownloadCache::new(dir.path())
        .fetch(&client(), &artifact, &mut |done, _| most = most.max(done))
        .unwrap_err();
    assert!(
        matches!(err, Error::TooLarge { limit: 1000, .. }),
        "{err:?}"
    );
    assert!(most <= 1000, "verified bytes never pass the size: {most}");
    assert!(!dir.path().join(format!("{digest}.part")).exists());
}

#[test]
fn resumes_a_partial_file_after_rehashing_it() {
    let mock = Mock::start();
    let data = body();
    let half = data.len() / 2;
    mock.mount(
        Route::given(method("GET"))
            .and(header("range", format!("bytes={half}-").as_str()))
            .respond_with(
                ResponseTemplate::new(206)
                    .insert_header(
                        "content-range",
                        format!("bytes {half}-{}/{}", data.len() - 1, data.len()).as_str(),
                    )
                    .set_body_bytes(data[half..].to_vec()),
            ),
    );
    let dir = tempfile::tempdir().unwrap();
    let digest = sha256(&data);
    fs::write(dir.path().join(format!("{digest}.part")), &data[..half]).unwrap();
    let url = mock.url("/a.zip");
    let artifact = Artifact {
        url: &url,
        sha256: &digest,
        size: data.len() as u64,
    };
    let got = DownloadCache::new(dir.path())
        .fetch(&client(), &artifact, &mut noop())
        .unwrap();
    assert_eq!(fs::read(got.path).unwrap(), data);
}

#[test]
fn a_corrupt_partial_file_fails_the_hash_and_is_removed() {
    let mock = Mock::start();
    let data = body();
    let half = data.len() / 2;
    mock.mount(
        Route::given(method("GET"))
            .and(header("range", format!("bytes={half}-").as_str()))
            .respond_with(
                ResponseTemplate::new(206)
                    .insert_header(
                        "content-range",
                        format!("bytes {half}-{}/{}", data.len() - 1, data.len()).as_str(),
                    )
                    .set_body_bytes(data[half..].to_vec()),
            ),
    );
    let dir = tempfile::tempdir().unwrap();
    let digest = sha256(&data);
    let part = dir.path().join(format!("{digest}.part"));
    fs::write(&part, vec![0u8; half]).unwrap();
    let url = mock.url("/a.zip");
    let artifact = Artifact {
        url: &url,
        sha256: &digest,
        size: data.len() as u64,
    };
    let err = DownloadCache::new(dir.path())
        .fetch(&client(), &artifact, &mut noop())
        .unwrap_err();
    assert!(matches!(err, Error::HashMismatch { .. }), "{err:?}");
    assert!(!part.exists());
}

#[test]
fn starts_over_when_the_server_ignores_the_range() {
    let mock = Mock::start();
    let data = body();
    serve(&mock, data.clone());
    let dir = tempfile::tempdir().unwrap();
    let digest = sha256(&data);
    fs::write(dir.path().join(format!("{digest}.part")), b"junk").unwrap();
    let url = mock.url("/a.zip");
    let artifact = Artifact {
        url: &url,
        sha256: &digest,
        size: data.len() as u64,
    };
    let got = DownloadCache::new(dir.path())
        .fetch(&client(), &artifact, &mut noop())
        .unwrap();
    assert_eq!(fs::read(got.path).unwrap(), data);
}

#[test]
fn an_interrupted_transfer_resumes_where_it_stopped() {
    let data = body();
    let (url, ranges) = common::interrupting_server(data.clone(), 50_000);
    let dir = tempfile::tempdir().unwrap();
    let digest = sha256(&data);
    let artifact = Artifact {
        url: &url,
        sha256: &digest,
        size: data.len() as u64,
    };
    let got = DownloadCache::new(dir.path())
        .fetch(&client(), &artifact, &mut noop())
        .unwrap();
    assert_eq!(fs::read(got.path).unwrap(), data);
    assert_eq!(*ranges.lock().unwrap(), [None, Some("50000".to_owned())]);
}
