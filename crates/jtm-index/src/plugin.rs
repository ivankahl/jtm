//! A plugin directory as the generator reads it: the manifest, which says what the plugin is
//! called and which files it publishes, and `sources.toml`, which says where to look
//! (SPEC.md sections 7, 8 and 15).

use std::collections::BTreeMap;
use std::path::Path;

use jtm_plugin::manifest::Manifest;

use crate::candidate::Discovery;
use crate::confirm::{Confirmed, Confirmer, Options};
use crate::context::Context;
use crate::error::{Error, Result};
use crate::signature::Keyring;
use crate::sources::SourcesFile;
use crate::writer::Binding;

/// The largest manifest read.
const MAX_MANIFEST: u64 = 256 * 1024;

/// Reads and validates the `plugin.toml` in `dir`.
pub fn read_manifest(dir: &Path) -> Result<Manifest> {
    let manifest_path = dir.join("plugin.toml");
    let label = manifest_path.display().to_string();
    let invalid = |message: String| Error::Sources {
        file: label.clone(),
        message,
    };
    let size = std::fs::metadata(&manifest_path)
        .map_err(|e| invalid(e.to_string()))?
        .len();
    if size > MAX_MANIFEST {
        return Err(invalid(format!("larger than {MAX_MANIFEST} bytes")));
    }
    let text = std::fs::read_to_string(&manifest_path).map_err(|e| invalid(e.to_string()))?;
    Manifest::parse(&text).map_err(|e| invalid(e.to_string()))
}

/// A plugin ready for a generator run.
#[derive(Debug)]
pub struct Plugin {
    /// What its index files must say, from the manifest.
    pub binding: Binding,
    pub sources: SourcesFile,
    /// The vendor keys pinned for each source, by source id.
    pub keyrings: BTreeMap<String, Keyring>,
}

impl Plugin {
    /// Reads `plugin.toml` and `sources.toml` (and the key files it names) from `dir`.
    pub fn load(dir: &Path) -> Result<Plugin> {
        let manifest = read_manifest(dir)?;

        let sources = SourcesFile::load(&dir.join("sources.toml"))?;
        let keyrings = Confirmer::load_keyrings(dir, &sources)?;
        Ok(Plugin {
            binding: Binding {
                plugin: manifest.name.clone(),
                platform_independent: manifest.index.platform_independent(),
                variants: manifest.versions.variants.clone(),
            },
            sources,
            keyrings,
        })
    }

    /// Asks every source what it knows. A source that fails fails the run, so a versions list
    /// is never built from some of the upstreams.
    pub fn discover(&self, ctx: &Context) -> Result<Discovery> {
        let mut all = Discovery::default();
        for source in &self.sources.sources {
            tracing::info!("querying {}", source.id);
            let found = source.discover(ctx)?;
            all.candidates.extend(found.candidates);
            all.warnings.extend(found.warnings);
        }
        Ok(all)
    }

    /// Confirms what `discovery` found. Notes from discovery come first among the warnings.
    pub fn confirm(
        &self,
        ctx: &Context,
        discovery: Discovery,
        options: Options,
    ) -> Result<Confirmed> {
        let confirmer = Confirmer::new(ctx, &self.sources, self.keyrings.clone(), options);
        let mut confirmed = confirmer.confirm(discovery.candidates)?;
        let mut warnings = discovery.warnings;
        warnings.append(&mut confirmed.warnings);
        confirmed.warnings = warnings;
        Ok(confirmed)
    }
}

#[cfg(test)]
mod tests;
