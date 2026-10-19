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
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    struct Entry {
        variant: &'static str,
        version: &'static str,
        tags: Vec<String>,
    }

    impl Candidate for Entry {
        fn variant(&self) -> &str {
            self.variant
        }
        fn version(&self) -> &str {
            self.version
        }
        fn tags(&self) -> &[String] {
            &self.tags
        }
    }

    fn entry(variant: &'static str, version: &'static str, tags: &[&str]) -> Entry {
        Entry {
            variant,
            version,
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
        }
    }

    const KEY: &str = "RWTB5jyFnNg68V0CwSpHcVuDAhAhJj5aYJboedszhloVwCP5cHSTI+PB";

    fn manifest(scheme: &str, variants: &str, aliases: &str, extra_versions: &str) -> Manifest {
        let text = format!(
            r#"
schema = 1
name = "demo"
display_name = "Demo"

[versions]
scheme = "{scheme}"
{variants}
default_alias = "latest"
{extra_versions}

[aliases]
{aliases}

[index]
url = "https://example.test/demo-{{os}}-{{arch}}.json"
signing_keys = ["{KEY}"]
format = 1

[layout]
strip_components = 1
bin_dirs = ["bin"]

[executables]
unix = ["demo"]

[hooks]
resolve_alias = "resolve"
"#
        );
        Manifest::parse(&text).unwrap_or_else(|e| panic!("{e}"))
    }

    /// An in-memory index for a JDK-like plugin with two variants.
    fn jdk_index() -> Vec<Entry> {
        vec![
            entry("temurin", "17.0.13+11", &["lts", "ga"]),
            entry("temurin", "21.0.4+7", &["lts", "ga"]),
            entry("temurin", "21.0.5+11", &["lts", "ga"]),
            entry("temurin", "23.0.1+11", &["ga"]),
            entry("temurin", "24-ea+20", &["ea"]),
            entry("corretto", "21.0.6+7", &["lts", "ga"]),
            entry("corretto", "23.0.2+7", &["ga"]),
            entry("temurin", "not a version", &["lts"]),
        ]
    }

    fn jdk() -> Manifest {
        manifest(
            "java",
            r#"variants = ["temurin", "corretto"]
default_variant = "temurin""#,
            r#"latest = { kind = "highest" }
lts = { kind = "index-tag", tag = "lts" }
ea = { kind = "index-tag", tag = "ea" }
"21" = { kind = "fixed", target = "21" }
custom = { kind = "script" }"#,
            "",
        )
    }

    #[test]
    fn highest_skips_prereleases_and_other_variants() {
        let index = jdk_index();
        let m = jdk();
        assert_eq!(
            resolve_alias(&m, "latest", "temurin", &index)
                .unwrap()
                .version,
            "23.0.1+11"
        );
        assert_eq!(
            resolve_alias(&m, "latest", "corretto", &index)
                .unwrap()
                .version,
            "23.0.2+7"
        );
    }

    #[test]
    fn index_tag_picks_highest_tagged_version() {
        let index = jdk_index();
        let m = jdk();
        assert_eq!(
            resolve_alias(&m, "lts", "temurin", &index).unwrap().version,
            "21.0.5+11"
        );
        assert_eq!(
            resolve_alias(&m, "lts", "corretto", &index)
                .unwrap()
                .version,
            "21.0.6+7"
        );
        assert_eq!(
            resolve_alias(&m, "ea", "temurin", &index).unwrap().version,
            "24-ea+20",
            "a tag selects pre-releases"
        );
    }

    #[test]
    fn fixed_picks_highest_matching_prefix() {
        let index = jdk_index();
        assert_eq!(
            resolve_alias(&jdk(), "21", "temurin", &index)
                .unwrap()
                .version,
            "21.0.5+11"
        );
    }

    #[test]
    fn unknown_alias_and_no_match() {
        let index = jdk_index();
        let m = jdk();
        assert_eq!(
            resolve_alias(&m, "stable", "temurin", &index).unwrap_err(),
            ResolveError::AliasUnknown {
                tool: "demo".into(),
                alias: "stable".into()
            }
        );
        assert_eq!(
            resolve_alias(&m, "ea", "corretto", &index).unwrap_err(),
            ResolveError::AliasNoMatch {
                tool: "demo".into(),
                alias: "ea".into(),
                variant: "corretto".into()
            }
        );
        assert!(matches!(
            resolve_alias(&m, "lts", "zulu", &index),
            Err(ResolveError::AliasNoMatch { .. })
        ));
    }

    #[test]
    fn script_aliases_are_stubbed() {
        let err = resolve_alias(&jdk(), "custom", "temurin", &jdk_index()).unwrap_err();
        assert!(matches!(err, ResolveError::ScriptUnsupported { .. }));
    }

    #[test]
    fn maven_like_fixed_aliases() {
        let index = vec![
            entry("default", "3.8.8", &[]),
            entry("default", "3.9.9", &[]),
            entry("default", "3.9.10", &[]),
            entry("default", "4.0.0-beta-5", &[]),
            entry("default", "4.0.0-rc-2", &[]),
        ];
        let m = manifest(
            "maven",
            "",
            r#"latest = { kind = "highest" }
"3" = { kind = "fixed", target = "3" }
"4" = { kind = "fixed", target = "4" }
"4rc" = { kind = "fixed", target = "4.0.0-rc" }"#,
            "",
        );
        assert_eq!(
            resolve_alias(&m, "latest", "default", &index)
                .unwrap()
                .version,
            "3.9.10"
        );
        assert_eq!(
            resolve_alias(&m, "3", "default", &index).unwrap().version,
            "3.9.10"
        );
        assert!(
            matches!(
                resolve_alias(&m, "4", "default", &index),
                Err(ResolveError::AliasNoMatch { .. })
            ),
            "4.x has only pre-releases"
        );
        assert_eq!(
            resolve_alias(&m, "4rc", "default", &index).unwrap().version,
            "4.0.0-rc-2",
            "a pre-release target selects pre-releases"
        );
    }

    #[test]
    fn include_prereleases_opts_in() {
        let index = vec![
            entry("default", "8.10.2", &[]),
            entry("default", "8.11-rc-1", &["rc"]),
            entry("default", "8.11-rc-2", &["rc"]),
        ];
        let aliases = r#"latest = { kind = "highest" }
rc = { kind = "index-tag", tag = "rc" }
"8.11" = { kind = "fixed", target = "8.11" }"#;
        let stable = manifest("semver-loose", "", aliases, "");
        assert_eq!(
            resolve_alias(&stable, "latest", "default", &index)
                .unwrap()
                .version,
            "8.10.2"
        );
        assert_eq!(
            resolve_alias(&stable, "rc", "default", &index)
                .unwrap()
                .version,
            "8.11-rc-2"
        );
        assert!(resolve_alias(&stable, "8.11", "default", &index).is_err());

        let eager = manifest("semver-loose", "", aliases, "include_prereleases = true");
        assert_eq!(
            resolve_alias(&eager, "latest", "default", &index)
                .unwrap()
                .version,
            "8.11-rc-2"
        );
        assert_eq!(
            resolve_alias(&eager, "8.11", "default", &index)
                .unwrap()
                .version,
            "8.11-rc-2"
        );
    }

    #[test]
    fn script_scheme_cannot_order_versions_yet() {
        let text = r#"
schema = 1
name = "demo"
display_name = "Demo"
[versions]
scheme = "script"
default_alias = "latest"
[aliases]
latest = { kind = "highest" }
[index]
url = "https://example.test/demo.json"
signing_keys = ["RWTB5jyFnNg68V0CwSpHcVuDAhAhJj5aYJboedszhloVwCP5cHSTI+PB"]
format = 1
[layout]
strip_components = 1
bin_dirs = ["bin"]
[executables]
unix = ["demo"]
[hooks]
compare_versions = "compare"
"#;
        let m = Manifest::parse(text).unwrap();
        let index = [entry("default", "1", &[])];
        let err = resolve_alias(&m, "latest", "default", &index);
        assert!(matches!(err, Err(ResolveError::ScriptUnsupported { .. })));
    }

    #[test]
    fn select_highest_matches_whole_segments() {
        let index = vec![
            entry("default", "21.0.5", &[]),
            entry("default", "210.1", &[]),
            entry("default", "2.1", &[]),
        ];
        let pick = |prefix| {
            select_highest(VersionScheme::SemverLoose, &index, "default", prefix, false)
                .map(|e| e.version)
        };
        assert_eq!(pick("21"), Some("21.0.5"));
        assert_eq!(pick("210"), Some("210.1"));
        assert_eq!(pick("2"), Some("2.1"));
        assert_eq!(pick("3"), None);
    }

    fn jdk_with_vendor_strings() -> Vec<Entry> {
        vec![
            entry("temurin", "8u412-b08", &["lts"]),
            entry("temurin", "1.8.0_422-b05", &["lts"]),
            entry("temurin", "21.0.5+11", &["lts"]),
            entry("temurin", "21.0.5_custom", &["lts"]),
            entry("temurin", "21.0.6+7_openj9-0.48.0", &["lts"]),
            entry("corretto", "21.0.5_custom", &[]),
        ]
    }

    #[test]
    fn legacy_and_vendor_versions_are_ranked() {
        let index = jdk_with_vendor_strings();
        let m = jdk();
        let pick = |value| resolve_value(&m, value, "temurin", &index).map(|e| e.version);
        assert_eq!(pick("8"), Ok("1.8.0_422-b05"));
        assert_eq!(pick("21"), Ok("21.0.6+7_openj9-0.48.0"));
        assert_eq!(pick("lts"), Ok("21.0.6+7_openj9-0.48.0"));
    }

    #[test]
    fn unparsed_versions_are_only_selected_by_exact_text() {
        let index = jdk_with_vendor_strings();
        let m = jdk();
        let pick = |value, variant| resolve_value(&m, value, variant, &index).map(|e| e.version);
        assert_eq!(pick("21.0.5_custom", "temurin"), Ok("21.0.5_custom"));
        assert_eq!(pick("21.0.5_custom", "corretto"), Ok("21.0.5_custom"));
        assert_eq!(
            pick("21.0.5", "temurin"),
            Ok("21.0.5+11"),
            "a prefix never picks raw"
        );
        assert_eq!(
            pick("21.0.5_cust", "temurin"),
            Err(ResolveError::VersionNotFound {
                tool: "demo".into(),
                variant: "temurin".into(),
                value: "21.0.5_cust".into(),
            })
        );
        assert!(matches!(
            pick("22", "corretto"),
            Err(ResolveError::VersionNotFound { .. })
        ));
    }

    #[test]
    fn resolve_value_prefers_aliases_over_prefixes() {
        let index = jdk_index();
        let m = jdk();
        // `21` is both an alias and a prefix; the alias wins, and here they agree.
        assert_eq!(
            resolve_value(&m, "21", "temurin", &index).unwrap().version,
            "21.0.5+11"
        );
        assert_eq!(
            resolve_value(&m, "ea", "temurin", &index).unwrap().version,
            "24-ea+20"
        );
        assert_eq!(
            resolve_value(&m, "23.0", "temurin", &index)
                .unwrap()
                .version,
            "23.0.1+11"
        );
    }

    #[test]
    fn script_schemes_still_select_exact_versions() {
        let text = r#"
schema = 1
name = "demo"
display_name = "Demo"
[versions]
scheme = "script"
default_alias = "latest"
[aliases]
latest = { kind = "highest" }
[index]
url = "https://example.test/demo.json"
signing_keys = ["RWTB5jyFnNg68V0CwSpHcVuDAhAhJj5aYJboedszhloVwCP5cHSTI+PB"]
format = 1
[layout]
strip_components = 1
bin_dirs = ["bin"]
[executables]
unix = ["demo"]
[hooks]
compare_versions = "compare"
"#;
        let m = Manifest::parse(text).unwrap();
        let index = [
            entry("default", "2024.1", &[]),
            entry("default", "2024.2", &[]),
        ];
        assert_eq!(
            resolve_value(&m, "2024.2", "default", &index)
                .unwrap()
                .version,
            "2024.2"
        );
        assert!(matches!(
            resolve_value(&m, "2024", "default", &index),
            Err(ResolveError::ScriptUnsupported { .. })
        ));
    }

    #[test]
    fn display_order_puts_raw_versions_last() {
        let index = jdk_with_vendor_strings();
        let order: Vec<&str> = sorted_for_display(Some(VersionScheme::Java), &index)
            .iter()
            .map(|e| e.version)
            .collect();
        assert_eq!(
            order,
            [
                "21.0.6+7_openj9-0.48.0",
                "21.0.5+11",
                "1.8.0_422-b05",
                "8u412-b08",
                "21.0.5_custom",
                "21.0.5_custom",
            ]
        );
    }
}
