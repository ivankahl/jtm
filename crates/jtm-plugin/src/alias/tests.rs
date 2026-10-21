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

[hooks]
resolve_alias = "resolve"
script_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
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
[hooks]
compare_versions = "compare"
script_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
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
[hooks]
compare_versions = "compare"
script_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
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

#[test]
fn bare_specs_use_the_default_alias_or_the_highest_version() {
    let index = jdk_index();
    let mut m = jdk();
    let pick = |m: &Manifest, variant| resolve_default(m, variant, &index).map(|e| e.version);
    assert_eq!(
        pick(&m, "temurin"),
        Ok("23.0.1+11"),
        "default_alias = latest"
    );

    m.versions.default_alias = Some("lts".into());
    assert_eq!(pick(&m, "temurin"), Ok("21.0.5+11"));

    m.versions.default_alias = None;
    assert_eq!(
        pick(&m, "temurin"),
        Ok("23.0.1+11"),
        "highest, skipping 24-ea"
    );
    assert_eq!(pick(&m, "corretto"), Ok("23.0.2+7"));
    m.versions.include_prereleases = true;
    assert_eq!(pick(&m, "temurin"), Ok("24-ea+20"));
    assert!(matches!(
        pick(&m, "zulu"),
        Err(ResolveError::VersionNotFound { .. })
    ));
}
