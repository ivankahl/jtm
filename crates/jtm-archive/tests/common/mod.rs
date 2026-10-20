//! Builds archives in memory, including ones no well-behaved tool would write.

#![allow(dead_code, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

pub(crate) use jtm_archive::testing::*;
use jtm_archive::{Format, Options, Result, Summary};

/// A temporary directory holding an archive and an empty `dest` directory beside it.
pub(crate) struct Scratch {
    pub(crate) dir: tempfile::TempDir,
}

impl Scratch {
    pub(crate) fn new() -> Scratch {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("dest")).unwrap();
        Scratch { dir }
    }

    pub(crate) fn dest(&self) -> PathBuf {
        self.dir.path().join("dest")
    }

    pub(crate) fn extract(
        &self,
        bytes: &[u8],
        format: Format,
        options: &Options,
    ) -> Result<Summary> {
        let archive = self.dir.path().join("archive");
        std::fs::write(&archive, bytes).unwrap();
        let result = jtm_archive::extract(&archive, format, &self.dest(), options);
        std::fs::remove_file(&archive).unwrap();
        result
    }

    /// Every path in the scratch directory outside `dest`, relative to it.
    pub(crate) fn outside(&self) -> Vec<PathBuf> {
        walk(self.dir.path())
            .into_iter()
            .filter(|p| !p.starts_with(self.dest()))
            .map(|p| p.strip_prefix(self.dir.path()).unwrap().to_path_buf())
            .collect()
    }
}

/// Every path under `root`, not following links.
pub(crate) fn walk(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            out.push(path.clone());
            if std::fs::symlink_metadata(&path).unwrap().is_dir() {
                stack.push(path);
            }
        }
    }
    out
}
