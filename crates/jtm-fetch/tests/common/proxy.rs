//! In-process proxies and a TLS server for the proxy tests. Nothing here leaves the machine.

#![allow(dead_code, clippy::unwrap_used, clippy::panic)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use jtm_fetch::proxy::ProxyConfig;
use jtm_fetch::{Client, ClientOptions};

/// A client whose proxy settings come from `explicit` (as `network.proxy`) and `env`, never
/// from the real environment, so the tests behave the same wherever they run.
pub(crate) fn client_with_proxy(
    options: ClientOptions,
    explicit: Option<&str>,
    env: &[(&str, &str)],
) -> Client {
    let env: HashMap<String, String> = env
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let proxies = ProxyConfig::resolve(explicit, &|name| env.get(name).cloned(), &|| None).unwrap();
    Client::with_proxies(options, proxies).unwrap()
}

/// Copies bytes between two streams until either side closes.
fn pipe(a: TcpStream, b: TcpStream) {
    let (mut a_read, mut b_write) = (a.try_clone().unwrap(), b.try_clone().unwrap());
    let forward = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a_read, &mut b_write);
        let _ = b_write.shutdown(Shutdown::Write);
    });
    let (mut b_read, mut a_write) = (b, a);
    let _ = std::io::copy(&mut b_read, &mut a_write);
    let _ = a_write.shutdown(Shutdown::Write);
    let _ = forward.join();
}

/// What a [`connect_proxy`] saw in one `CONNECT` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Connect {
    /// The `host:port` the client asked to tunnel to.
    pub(crate) target: String,
    /// The `Proxy-Authorization` header, if sent.
    pub(crate) authorization: Option<String>,
}

/// A local HTTP proxy that only tunnels: it answers `CONNECT host:port` by connecting to that
/// address and relaying bytes. With `require_auth`, a request whose `Proxy-Authorization` is
/// not exactly that value gets `407` instead. Returns its address and every `CONNECT` seen.
pub(crate) fn connect_proxy(
    require_auth: Option<&'static str>,
) -> (SocketAddr, Arc<Mutex<Vec<Connect>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut client) = stream else { return };
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let head = read_head(&mut client);
                let mut lines = head.lines();
                let request = lines.next().unwrap_or_default();
                let Some(target) = request
                    .strip_prefix("CONNECT ")
                    .and_then(|rest| rest.split_whitespace().next())
                else {
                    let _ = client.write_all(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n");
                    return;
                };
                let authorization = lines.find_map(|line| {
                    line.to_ascii_lowercase()
                        .starts_with("proxy-authorization:")
                        .then(|| line.split_once(':').unwrap().1.trim().to_owned())
                });
                log.lock().unwrap().push(Connect {
                    target: target.to_owned(),
                    authorization: authorization.clone(),
                });
                if require_auth.is_some_and(|want| authorization.as_deref() != Some(want)) {
                    let _ = client.write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=\"test\"\r\n\
                          Content-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                    return;
                }
                let Ok(upstream) = TcpStream::connect(target) else {
                    let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                    return;
                };
                let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                pipe(client, upstream);
            });
        }
    });
    (addr, seen)
}

/// Reads a request head, up to and including the blank line.
fn read_head(stream: &mut impl Read) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).is_ok_and(|n| n == 1) {
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

/// A SOCKS5 proxy without authentication that sends every connection to `backend`, whatever
/// address the client asks for. Returns its address and the host names clients asked for.
pub(crate) fn socks5_proxy(backend: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut client) = stream else { return };
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let mut greeting = [0u8; 2];
                client.read_exact(&mut greeting).unwrap();
                let mut methods = vec![0u8; greeting[1] as usize];
                client.read_exact(&mut methods).unwrap();
                client.write_all(&[5, 0]).unwrap();
                let mut head = [0u8; 4];
                client.read_exact(&mut head).unwrap();
                let name = match head[3] {
                    3 => {
                        let mut len = [0u8; 1];
                        client.read_exact(&mut len).unwrap();
                        let mut name = vec![0u8; len[0] as usize];
                        client.read_exact(&mut name).unwrap();
                        String::from_utf8(name).unwrap()
                    }
                    1 => {
                        let mut ip = [0u8; 4];
                        client.read_exact(&mut ip).unwrap();
                        Ipv4Addr::from(ip).to_string()
                    }
                    other => panic!("unexpected SOCKS address type {other}"),
                };
                let mut port = [0u8; 2];
                client.read_exact(&mut port).unwrap();
                log.lock().unwrap().push(name);
                client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
                pipe(client, TcpStream::connect(backend).unwrap());
            });
        }
    });
    (addr, seen)
}

/// An HTTPS server with a certificate for `localhost` from a throwaway CA.
#[derive(Debug)]
pub(crate) struct TlsServer {
    pub(crate) addr: SocketAddr,
    /// The CA certificate as a PEM file, for `extra_ca_file`.
    pub(crate) ca_file: PathBuf,
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
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    // Short lifetimes keep to the limits that macOS and Windows put on certificates.
    let now = time::OffsetDateTime::now_utc();
    let (not_before, not_after) = (
        now - time::Duration::days(1),
        now + time::Duration::days(30),
    );
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "jtm test CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.not_before = not_before;
    leaf_params.not_after = not_after;
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();
    let config = Arc::new(config);

    let dir = tempfile::tempdir().unwrap();
    let ca_file = dir.path().join("ca.pem");
    std::fs::write(&ca_file, ca_cert.pem()).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut tcp) = stream else { return };
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                let Ok(mut conn) = rustls::ServerConnection::new(config) else {
                    return;
                };
                let mut tls = rustls::Stream::new(&mut conn, &mut tcp);
                let head = read_head(&mut tls);
                let response = if head.contains(" /redirect-to-http ") {
                    "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/downgraded\r\n\
                     Content-Length: 0\r\nConnection: close\r\n\r\n"
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
        _dir: dir,
    }
}
