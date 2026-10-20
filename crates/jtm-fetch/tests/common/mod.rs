//! Helpers shared by the integration tests. Nothing here touches the real network.

#![allow(dead_code, clippy::unwrap_used)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use jtm_fetch::{Client, ClientOptions, RetryPolicy};
use tokio::runtime::Runtime;
use wiremock::MockServer;

/// A mock server and the runtime it runs on. The blocking client must be used outside the
/// runtime, so tests call it directly and only use the runtime to set up mocks.
pub(crate) struct Mock {
    pub(crate) rt: Runtime,
    pub(crate) server: MockServer,
}

impl Mock {
    pub(crate) fn start() -> Mock {
        let rt = Runtime::new().unwrap();
        let server = rt.block_on(MockServer::start());
        Mock { rt, server }
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{path}", self.server.uri())
    }

    pub(crate) fn mount(&self, mock: wiremock::Mock) {
        self.rt.block_on(mock.mount(&self.server));
    }

    pub(crate) fn requests(&self) -> Vec<wiremock::Request> {
        self.rt
            .block_on(self.server.received_requests())
            .unwrap_or_default()
    }
}

/// A client for plain-http mock servers, with no waits between retries.
pub(crate) fn client() -> Client {
    Client::new(options(true)).unwrap()
}

pub(crate) fn options(allow_http: bool) -> ClientOptions {
    ClientOptions {
        allow_http,
        retry: RetryPolicy {
            retries: 3,
            backoff: Duration::ZERO,
        },
        read_timeout: Duration::from_secs(5),
        ..ClientOptions::new("0.0.0-test")
    }
}

/// A server that drops the first `drops` connections without answering, then answers every
/// later one with `body`. Returns its URL and the number of connections accepted.
pub(crate) fn flaky_server(drops: usize, body: &'static [u8]) -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/file", listener.local_addr().unwrap());
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let n = seen.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            if n < drops {
                continue;
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(body);
        }
    });
    (url, count)
}
