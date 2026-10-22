//! A throwaway CA, an HTTPS server it signs for, and a TLS-inspecting proxy. Nothing here
//! leaves the machine.

#![allow(dead_code, clippy::unwrap_used)]

use std::io::Write;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::proxy::read_head;

/// A throwaway certificate authority that signs server certificates for the TLS tests.
pub(crate) struct TestCa {
    cert_pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    not_before: time::OffsetDateTime,
    not_after: time::OffsetDateTime,
}

impl TestCa {
    pub(crate) fn new(common_name: &str) -> TestCa {
        use rcgen::{
            BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
            KeyUsagePurpose,
        };
        // Short lifetimes keep to the limits that macOS and Windows put on certificates.
        let now = time::OffsetDateTime::now_utc();
        let (not_before, not_after) = (
            now - time::Duration::days(1),
            now + time::Duration::days(30),
        );
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = not_before;
        params.not_after = not_after;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let key = KeyPair::generate().unwrap();
        let cert_pem = params.self_signed(&key).unwrap().pem();
        TestCa {
            cert_pem,
            issuer: Issuer::new(params, key),
            not_before,
            not_after,
        }
    }

    /// Writes the CA certificate as PEM to `<dir>/<name>` and returns that path.
    pub(crate) fn write_pem(&self, dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, &self.cert_pem).unwrap();
        path
    }

    /// A server configuration whose certificate this CA signed for `host`.
    pub(crate) fn server_config(&self, host: &str) -> Arc<rustls::ServerConfig> {
        use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair};
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![host.to_owned()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.not_before = self.not_before;
        params.not_after = self.not_after;
        let leaf = params.signed_by(&key, &self.issuer).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap();
        Arc::new(config)
    }
}

/// An HTTPS server with a certificate for `localhost` from a throwaway CA.
#[derive(Debug)]
pub(crate) struct TlsServer {
    pub(crate) addr: SocketAddr,
    /// The CA certificate as a PEM file, for `extra_ca_file`.
    pub(crate) ca_file: PathBuf,
    /// Every TCP connection accepted, whether or not the handshake succeeded.
    pub(crate) connections: Arc<AtomicUsize>,
    /// The request line of every request that got through the handshake.
    pub(crate) requests: Arc<Mutex<Vec<String>>>,
    _dir: tempfile::TempDir,
}

impl TlsServer {
    /// `https://localhost:<port><path>`.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.addr.port())
    }
}

/// Starts a [`TlsServer`]. `/redirect-to-http` answers `302` to a plain-http URL; every other
/// path answers `200` with the body `tls-ok`.
pub(crate) fn tls_server() -> TlsServer {
    tls_server_redirecting_to("http://127.0.0.1:9/downgraded")
}

/// Like [`tls_server`], but `/redirect-to-http` redirects to `location`.
pub(crate) fn tls_server_redirecting_to(location: &str) -> TlsServer {
    let ca = TestCa::new("jtm test CA");
    let config = ca.server_config("localhost");
    let dir = tempfile::tempdir().unwrap();
    let ca_file = ca.write_pem(dir.path(), "ca.pem");
    let redirect = format!(
        "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\n\
         Connection: close\r\n\r\n"
    );

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let (count, log) = (Arc::clone(&connections), Arc::clone(&requests));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut tcp) = stream else { return };
            count.fetch_add(1, Ordering::SeqCst);
            let (config, redirect, log) = (Arc::clone(&config), redirect.clone(), Arc::clone(&log));
            std::thread::spawn(move || {
                let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                    return;
                };
                let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
                let head = read_head(&mut tls);
                if head.is_empty() {
                    // The handshake failed, as it does for a client that distrusts the CA.
                    return;
                }
                let request = head.lines().next().unwrap_or_default().to_owned();
                log.lock().unwrap().push(request.clone());
                let response = if request.contains(" /redirect-to-http ") {
                    redirect.as_str()
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\ntls-ok"
                };
                let _ = tls.write_all(response.as_bytes());
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    TlsServer {
        addr,
        ca_file,
        connections,
        requests,
        _dir: dir,
    }
}

/// What an [`InterceptingProxy`] saw in one tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Intercepted {
    /// The `host:port` of the `CONNECT`.
    pub(crate) target: String,
    /// The request line read from inside the decrypted tunnel, if the handshake succeeded.
    pub(crate) request: Option<String>,
}

/// A TLS-inspecting proxy, as a corporate gateway runs one. It answers `CONNECT host:port`,
/// then ends the TLS session itself with a certificate for `host` that its own CA signed, and
/// answers every request with `200` and the body `intercepted`. It never contacts the real
/// server.
#[derive(Debug)]
pub(crate) struct InterceptingProxy {
    pub(crate) addr: SocketAddr,
    /// The proxy's CA certificate, which a client must trust to accept what it serves.
    pub(crate) ca_file: PathBuf,
    pub(crate) seen: Arc<Mutex<Vec<Intercepted>>>,
    _dir: tempfile::TempDir,
}

impl InterceptingProxy {
    /// The `network.proxy` value that points at this proxy.
    pub(crate) fn url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

/// Starts an [`InterceptingProxy`].
pub(crate) fn intercepting_proxy() -> InterceptingProxy {
    let ca = Arc::new(TestCa::new("Corp-Proxy-CA"));
    let dir = tempfile::tempdir().unwrap();
    let ca_file = ca.write_pem(dir.path(), "corp-ca.pem");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut tcp) = stream else { return };
            let (ca, log) = (Arc::clone(&ca), Arc::clone(&log));
            std::thread::spawn(move || {
                let head = read_head(&mut tcp);
                let Some(target) = head
                    .strip_prefix("CONNECT ")
                    .and_then(|rest| rest.split_whitespace().next())
                else {
                    let _ = tcp.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n");
                    return;
                };
                let host = target.rsplit_once(':').map_or(target, |(host, _)| host);
                let index = {
                    let mut log = log.lock().unwrap();
                    log.push(Intercepted {
                        target: target.to_owned(),
                        request: None,
                    });
                    log.len() - 1
                };
                let _ = tcp.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                let Ok(mut conn) = rustls::ServerConnection::new(ca.server_config(host)) else {
                    return;
                };
                let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
                let head = read_head(&mut tls);
                if head.is_empty() {
                    return;
                }
                log.lock().unwrap()[index].request =
                    Some(head.lines().next().unwrap_or_default().to_owned());
                let _ = tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n\
                      intercepted",
                );
                tls.conn.send_close_notify();
                let _ = tls.flush();
            });
        }
    });
    InterceptingProxy {
        addr,
        ca_file,
        seen,
        _dir: dir,
    }
}
