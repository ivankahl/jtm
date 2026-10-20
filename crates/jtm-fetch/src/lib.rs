//! HTTP client, proxies, TLS, mirrors, streaming hash and download cache for jtm.

pub mod client;
pub mod error;

pub use client::{Client, ClientOptions, MAX_REDIRECTS, Response, RetryPolicy};
pub use error::{Error, Result};
