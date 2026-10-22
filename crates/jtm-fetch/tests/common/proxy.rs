//! In-process proxies for the proxy tests. Nothing here leaves the machine.

#![allow(dead_code, clippy::unwrap_used, clippy::panic)]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
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
pub(crate) fn read_head(stream: &mut impl Read) -> String {
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
