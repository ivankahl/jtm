//! HTTP client, proxies, TLS, mirrors, streaming hash and download cache for jtm.

pub mod client;
pub mod download;
pub mod error;
pub mod mirrors;
pub mod proxy;
mod tls;

pub use client::{Client, ClientOptions, MAX_REDIRECTS, Response, RetryPolicy};
pub use download::{Artifact, DownloadCache, Downloaded, Origin};
pub use error::{Error, Result};
pub use proxy::{ProxyConfig, ProxyReport, ProxyRoute, ProxySource};
