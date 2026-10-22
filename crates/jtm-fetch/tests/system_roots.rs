//! `network.extra_ca_file` adds to the platform verifier and never replaces it.
//!
//! The test makes one throwaway CA the "system" CA and another the extra one, then checks that
//! the client trusts both. On Linux the system store can be pointed at a file with
//! `SSL_CERT_FILE`, which must be set before the verifier loads it, so the check runs in a copy
//! of this test binary started with that variable. Other platforms have no such switch for a
//! test to use without touching the real certificate store.

#![cfg(target_os = "linux")]

mod common;

use std::process::Command;

use common::options;
use common::proxy::client_with_proxy;
use common::tls::tls_server;
use jtm_fetch::ClientOptions;

const CHILD: &str = "both_the_system_store_and_the_extra_file_are_trusted";

#[test]
fn the_extra_ca_file_is_added_to_the_system_store() {
    let (system, extra) = (tls_server(), tls_server());
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", CHILD, "--nocapture"])
        .env("SSL_CERT_FILE", &system.ca_file)
        .env_remove("SSL_CERT_DIR")
        .env("JTM_TEST_SYSTEM_URL", system.url("/file"))
        .env("JTM_TEST_EXTRA_URL", extra.url("/file"))
        .env("JTM_TEST_EXTRA_CA", &extra.ca_file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // A filter that matched nothing also exits successfully.
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "the child test did not run"
    );
}

/// Runs in the child process of the test above, with `SSL_CERT_FILE` set. Ignored so that a
/// plain test run does not start it without that setup.
#[test]
#[ignore = "started by the_extra_ca_file_is_added_to_the_system_store"]
fn both_the_system_store_and_the_extra_file_are_trusted() {
    let var = |name: &str| std::env::var(name).unwrap();
    let (system_url, extra_url) = (var("JTM_TEST_SYSTEM_URL"), var("JTM_TEST_EXTRA_URL"));

    // Without an extra file only the system store counts: its CA is trusted, the other is not.
    let plain = client_with_proxy(options(false), None, &[]);
    assert!(plain.get_bytes(&system_url, 1024).unwrap().is_some());
    assert!(plain.get_bytes(&extra_url, 1024).is_err());

    // With one, the extra CA is trusted and the system CA still is.
    let client = client_with_proxy(
        ClientOptions {
            extra_ca_file: Some(var("JTM_TEST_EXTRA_CA").into()),
            ..options(false)
        },
        None,
        &[],
    );
    assert!(client.get_bytes(&extra_url, 1024).unwrap().is_some());
    assert!(client.get_bytes(&system_url, 1024).unwrap().is_some());
}
