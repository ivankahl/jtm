//! Alias resolution and version selection (SPEC.md sections 5 and 7).
//!
//! The core never interprets tags or aliases itself: an alias is resolved from the plugin's
//! `[aliases]` table against the entries of a version index.

use crate::manifest::{Alias, Manifest};
use crate::version::{MaybeVersion, Version, VersionScheme};

/// What the resolver needs from a version index entry.
pub trait Candidate {
    fn variant(&self) -> &str;
    fn version(&self) -> &str;
    fn tags(&self) -> &[String];

    /// The version parsed under `scheme`, or kept raw when it does not parse.
    fn parsed(&self, scheme: Option<VersionScheme>) -> MaybeVersion {
        MaybeVersion::parse(scheme, self.version())
    }
}

/// Why a version or alias could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("`{tool}` has no alias `{alias}`")]
    AliasUnknown { tool: String, alias: String },

    #[error("alias `{alias}` of `{tool}` matches no `{variant}` version")]
    AliasNoMatch {
        tool: String,
        alias: String,
        variant: String,
    },

    #[error("no `{variant}` version of `{tool}` matches `{value}`")]
    VersionNotFound {
        tool: String,
        variant: String,
        value: String,
    },

    /// Script aliases and script version schemes need the Luau engine, which is not available
    /// yet.
    #[error("resolving `{spec}` for `{tool}` needs a plugin script, which this jtm cannot run yet")]
    ScriptUnsupported { tool: String, spec: String },
}

/// Resolves the version or alias `value` to one `variant` entry in `candidates`, in this order:
///
/// 1. An entry whose version did not parse under the plugin's scheme and is exactly `value`.
///    Such entries cannot be ordered, so this is the only way to select them.
/// 2. An alias named `value`, as [`resolve_alias`] does.
/// 3. The highest entry whose version starts with the segments of `value`, as
///    [`select_highest`] does.
pub fn resolve_value<'c, C: Candidate>(
    manifest: &Manifest,
    value: &str,
    variant: &str,
    candidates: &'c [C],
) -> Result<&'c C, ResolveError> {
    let scheme = manifest.versions.scheme.builtin();
    let exact_raw = candidates.iter().find(|c| {
        c.variant() == variant && matches!(c.parsed(scheme), MaybeVersion::Raw(raw) if raw == value)
    });
    if let Some(found) = exact_raw {
        return Ok(found);
    }
    if manifest.aliases.contains_key(value) {
        return resolve_alias(manifest, value, variant, candidates);
    }
    let scheme = scheme.ok_or_else(|| ResolveError::ScriptUnsupported {
        tool: manifest.name.clone(),
        spec: value.to_owned(),
    })?;
    select_highest(
        scheme,
        candidates,
        variant,
        value,
        manifest.versions.include_prereleases,
    )
    .ok_or_else(|| ResolveError::VersionNotFound {
        tool: manifest.name.clone(),
        variant: variant.to_owned(),
        value: value.to_owned(),
    })
}

/// Resolves a spec without a version, such as a bare `maven`: the plugin's `default_alias`, or
/// without one the highest version, skipping pre-releases unless `include_prereleases` is set.
pub fn resolve_default<'c, C: Candidate>(
    manifest: &Manifest,
    variant: &str,
    candidates: &'c [C],
) -> Result<&'c C, ResolveError> {
    if let Some(alias) = &manifest.versions.default_alias {
        return resolve_alias(manifest, alias, variant, candidates);
    }
    let scheme =
        manifest
            .versions
            .scheme
            .builtin()
            .ok_or_else(|| ResolveError::ScriptUnsupported {
                tool: manifest.name.clone(),
                spec: manifest.name.clone(),
            })?;
    let include_prereleases = manifest.versions.include_prereleases;
    highest(scheme, candidates, variant, |_, version| {
        include_prereleases || !version.is_prerelease()
    })
    .ok_or_else(|| ResolveError::VersionNotFound {
        tool: manifest.name.clone(),
        variant: variant.to_owned(),
        value: "(default)".to_owned(),
    })
}

/// Resolves the alias `name` to the matching `variant` entry in `candidates`.
///
/// - `highest`: the highest version, skipping pre-releases unless the plugin sets
///   `include_prereleases`.
/// - `index-tag`: the highest version tagged `tag`, pre-releases included, since a tag such as
///   `rc` or `ea` exists to select them.
/// - `fixed`: the highest version matching the `target` prefix, as [`select_highest`] does.
/// - `script`: not supported yet.
///
/// Entries whose version does not parse are never ranked, so no alias selects them.
pub fn resolve_alias<'c, C: Candidate>(
    manifest: &Manifest,
    name: &str,
    variant: &str,
    candidates: &'c [C],
) -> Result<&'c C, ResolveError> {
    let alias = manifest
        .aliases
        .get(name)
        .ok_or_else(|| ResolveError::AliasUnknown {
            tool: manifest.name.clone(),
            alias: name.to_owned(),
        })?;
    let script = || ResolveError::ScriptUnsupported {
        tool: manifest.name.clone(),
        spec: name.to_owned(),
    };
    let scheme = manifest.versions.scheme.builtin().ok_or_else(script)?;
    let include_prereleases = manifest.versions.include_prereleases;

    let found = match alias {
        Alias::Highest {} => highest(scheme, candidates, variant, |_, version| {
            include_prereleases || !version.is_prerelease()
        }),
        Alias::IndexTag { tag } => highest(scheme, candidates, variant, |candidate, _| {
            candidate.tags().iter().any(|t| t == tag)
        }),
        Alias::Fixed { target } => {
            select_highest(scheme, candidates, variant, target, include_prereleases)
        }
        Alias::Script {} => return Err(script()),
    };
    found.ok_or_else(|| ResolveError::AliasNoMatch {
        tool: manifest.name.clone(),
        alias: name.to_owned(),
        variant: variant.to_owned(),
    })
}

/// Picks the highest `variant` entry whose version starts with the segments of `prefix`.
///
/// Pre-releases are eligible when `include_prereleases` is set or when `prefix` itself names a
/// pre-release, so `8.11` never picks `8.11-rc-1` by default but `8.11-rc` does.
pub fn select_highest<'c, C: Candidate>(
    scheme: VersionScheme,
    candidates: &'c [C],
    variant: &str,
    prefix: &str,
    include_prereleases: bool,
) -> Option<&'c C> {
    let wants_prerelease =
        include_prereleases || scheme.parse(prefix).is_ok_and(|p| p.is_prerelease());
    highest(scheme, candidates, variant, |_, version| {
        version.matches_prefix(prefix) && (wants_prerelease || !version.is_prerelease())
    })
}

/// Orders entries for display, such as in `jtm available`: parsed versions highest first, then
/// versions that did not parse, as written and in index order.
pub fn sorted_for_display<C: Candidate>(
    scheme: Option<VersionScheme>,
    candidates: &[C],
) -> Vec<&C> {
    let (mut parsed, raw): (Vec<_>, Vec<_>) = candidates
        .iter()
        .map(|c| (c, c.parsed(scheme)))
        .partition(|(_, v)| v.parsed().is_some());
    parsed.sort_by(|(_, a), (_, b)| b.parsed().cmp(&a.parsed()));
    parsed.into_iter().chain(raw).map(|(c, _)| c).collect()
}

/// The highest `variant` entry that `keep` accepts. Entries whose version does not parse under
/// `scheme` are never selected.
fn highest<'c, C: Candidate>(
    scheme: VersionScheme,
    candidates: &'c [C],
    variant: &str,
    keep: impl Fn(&C, &Version) -> bool,
) -> Option<&'c C> {
    candidates
        .iter()
        .filter(|c| c.variant() == variant)
        .filter_map(|c| match c.parsed(Some(scheme)) {
            MaybeVersion::Parsed(version) => Some((c, version)),
            MaybeVersion::Raw(_) => None,
        })
        .filter(|(c, version)| keep(c, version))
        .max_by(|(_, a), (_, b)| a.cmp(b))
        .map(|(c, _)| c)
}

#[cfg(test)]
mod tests;
