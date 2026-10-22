//! The yanked plugins check (SPEC.md section 16): a third-party plugin whose marketplace entry
//! was yanked is still installed and keeps working, so only doctor warns about it.
//!
//! The marketplace is never cached, and doctor never fetches it on its own; the caller passes
//! the signed listing when it could read it. Without one the check is skipped and says why.

use crate::error::Result;
use crate::indices::ManifestOrigin;

use super::{Check, Finding, Inputs, W_PLUGIN_YANKED, list};

/// What the signed marketplace says about one plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listing {
    /// The marketplace has no entry for the plugin, as for one added from a source URL.
    NotListed,
    Active,
    /// The entry is yanked, with the publisher's reason.
    Yanked {
        reason: String,
    },
}

/// The verified `marketplace.json`.
pub trait Marketplace {
    /// What the marketplace says about `plugin`.
    fn listing(&self, plugin: &str) -> Result<Listing>;
}

pub(super) fn check(inputs: &Inputs<'_>) -> Check {
    const ID: &str = "yanked_plugins";
    let mut external = Vec::new();
    let mut notes = Vec::new();
    for name in inputs.registry.names().unwrap_or_default() {
        match inputs.registry.find(&name) {
            Ok(plugin) if plugin.origin == ManifestOrigin::External => external.push(name),
            Ok(_) => {}
            Err(err) => notes.push(format!("plugin `{name}` was not checked: {err}")),
        }
    }
    let names: Vec<String> = external.iter().map(|n| format!("`{n}`")).collect();
    let mut check = if external.is_empty() {
        Check::pass(ID, "no third-party plugins are installed")
    } else if inputs.offline {
        Check::skipped(
            ID,
            format!(
                "not checked for {}: the signed marketplace.json can only be read online",
                list(&names)
            ),
        )
    } else if let Some(marketplace) = inputs.marketplace {
        listings(marketplace, &external)
    } else {
        Check::skipped(
            ID,
            format!(
                "not checked for {}: the signed marketplace.json is not available",
                list(&names)
            ),
        )
    };
    check.notes.extend(notes);
    check
}

fn listings(marketplace: &dyn Marketplace, plugins: &[String]) -> Check {
    const ID: &str = "yanked_plugins";
    let mut check = Check::pass(ID, "");
    let mut unlisted = Vec::new();
    for plugin in plugins {
        match marketplace.listing(plugin) {
            Ok(Listing::Active) => {}
            Ok(Listing::NotListed) => unlisted.push(plugin.clone()),
            Ok(Listing::Yanked { reason }) => check.push(
                Finding::warning(
                    W_PLUGIN_YANKED,
                    format!("plugin `{plugin}` is yanked in the marketplace: {reason}"),
                )
                .hint(format!(
                    "it still works, but its publisher withdrew it; move to a replacement \
                     named in the reason, or run `jtm plugin remove {plugin}`"
                ))
                .detail("plugin", plugin.as_str())
                .detail("reason", reason),
            ),
            Err(err) => {
                return Check::skipped(
                    ID,
                    format!("not checked: the marketplace could not be read: {err}"),
                );
            }
        }
    }
    check.summary = format!(
        "{} installed third-party plugin{} checked against the marketplace",
        plugins.len() - unlisted.len(),
        if plugins.len() - unlisted.len() == 1 {
            ""
        } else {
            "s"
        }
    );
    if !unlisted.is_empty() {
        let names: Vec<String> = unlisted.iter().map(|n| format!("`{n}`")).collect();
        check
            .notes
            .push(format!("{} not listed in the marketplace", list(&names)));
    }
    check
}
