//! Extra trusted certificates for TLS-inspecting networks (SPEC.md section 13).
//!
//! `network.extra_ca_file` names a PEM bundle. Its certificates are added to what the platform
//! verifier already trusts; they never replace it, so a user who sets the option does not lose
//! the OS store. A file that cannot be trusted as given is refused whole, with an error that
//! names the setting and the path: a bundle that is half valid is never half trusted.

use std::path::Path;

use reqwest::Certificate;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

use crate::error::{Error, Result};

/// Reads the certificates in the PEM bundle at `path`.
///
/// Fails with [`Error::Io`] when the file cannot be read, and with [`Error::CaFile`] when it
/// holds no certificates or any certificate in it is malformed. PEM sections of other kinds,
/// such as a private key, are not certificates and are ignored.
pub(crate) fn load_extra_ca_file(path: &Path) -> Result<Vec<Certificate>> {
    let pem = std::fs::read(path).map_err(|e| Error::io(path, e))?;
    let reject = |reason: String| Error::CaFile {
        path: path.to_owned(),
        reason,
    };
    // Sections the PEM reader would skip as "not a certificate" but that are meant as one.
    if let Some(label) = unsupported_certificate_label(&pem) {
        return Err(reject(format!(
            "holds a `{label}` section, which jtm cannot read; convert it to a plain \
             `CERTIFICATE` section, for example with `openssl x509`"
        )));
    }
    let mut certs = Vec::new();
    for (n, item) in CertificateDer::pem_slice_iter(&pem).enumerate() {
        let n = n + 1;
        let der = item.map_err(|e| reject(format!("certificate {n} is not valid PEM: {e}")))?;
        // The same parsing the verifier will do, so a bad certificate fails here, by name,
        // and not later as an opaque error while the client starts.
        RootCertStore::empty()
            .add(der.clone())
            .map_err(|e| reject(format!("certificate {n} is not a valid certificate: {e}")))?;
        let cert = Certificate::from_der(&der)
            .map_err(|e| reject(format!("certificate {n} is not usable: {e}")))?;
        certs.push(cert);
    }
    // SPEC-QUESTION: section 13 wants "certificate ... is not trusted; add it with
    // `network.extra_ca_file`" for an untrusted certificate. `jtm doctor` gives that hint when
    // its TLS check fails; the client's own TLS error carries none.
    if certs.is_empty() {
        return Err(reject("holds no PEM certificates".to_owned()));
    }
    tracing::debug!(path = %path.display(), count = certs.len(), "loaded extra CA certificates");
    Ok(certs)
}

/// The label of the first PEM section that names a certificate in some form other than a plain
/// `CERTIFICATE`, such as OpenSSL's `TRUSTED CERTIFICATE`. Requests and keys are not meant as
/// certificates, so they do not count.
fn unsupported_certificate_label(pem: &[u8]) -> Option<String> {
    String::from_utf8_lossy(pem).lines().find_map(|line| {
        let label = line
            .trim()
            .strip_prefix("-----BEGIN ")?
            .strip_suffix("-----")?;
        (label.contains("CERTIFICATE") && label != "CERTIFICATE" && !label.contains("REQUEST"))
            .then(|| label.to_owned())
    })
}

/// Checks that the PEM bundle at `path`, as `network.extra_ca_file` names it, would be accepted
/// when a [`Client`](crate::Client) is built with it, and returns how many certificates it
/// holds. It fails exactly as building the client would.
pub fn check_ca_bundle(path: &Path) -> Result<usize> {
    load_extra_ca_file(path).map(|certs| certs.len())
}
