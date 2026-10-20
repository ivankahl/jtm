//! The install receipt, `.jtm-receipt.json` (SPEC.md section 10, step 11).

use std::fs;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::error::{JtmError, Result};

/// The receipt's file name inside an install dir.
pub const RECEIPT_FILE: &str = ".jtm-receipt.json";

/// What was installed, from where, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub plugin: String,
    pub manifest_sha256: String,
    pub variant: String,
    pub version: String,
    pub platform: String,
    /// The URL the archive came from, after mirrors and redirects.
    pub url: String,
    pub sha256: String,
    pub size: u64,
    pub index_sequence: u64,
    pub installed_at: String,
    pub jtm_version: String,
    /// The tool home relative to the install dir, with `/` separators; empty for the install
    /// dir itself.
    #[serde(default)]
    pub home: String,
}

impl Receipt {
    /// The receipt in `install_dir`, or `None` when it is missing or unreadable. A directory
    /// without a valid receipt is not an install.
    pub fn read(install_dir: &Path) -> Option<Receipt> {
        let bytes = fs::read(install_dir.join(RECEIPT_FILE)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Writes the receipt into `install_dir`.
    pub fn write(&self, install_dir: &Path) -> Result<()> {
        let path = install_dir.join(RECEIPT_FILE);
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| JtmError::internal(format!("cannot encode a receipt: {e}")))?;
        bytes.push(b'\n');
        fs::write(&path, bytes).map_err(|e| JtmError::io(&path, e))
    }
}

/// `home` as the receipt stores it.
pub(crate) fn home_string(home: &Path) -> String {
    home.components()
        .filter_map(|c| match c {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}
