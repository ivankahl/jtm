use super::*;
use crate::testing::{Mock, fixture};

const FULL: &str = r#"
schema = 1

[[source]]
id = "adoptium-api"
adapter = "adoptium"
role = "primary"
variant = "temurin"
features = [17, 21]
platforms = ["linux-x64", "windows-x64"]
include_ea = true

[[source]]
id = "github-sidecar"
adapter = "github-releases"
role = "confirm"
variant = "temurin"
repo = "adoptium/temurin{feature}-binaries"
features = [17, 21]
tag_pattern = 'jdk-(?P<version>\d+(?:\.\d+)*)\+(?P<build>\d+)'
version = "{version}+{build}"
hash_from = "sidecar"
sidecar_suffix = ".sha256.txt"
[source.assets]
linux-x64 = "OpenJDK{feature}U-jdk_x64_linux_hotspot_{version}_{build}.tar.gz"

[[source]]
id = "foojay-zulu"
adapter = "foojay"
role = "primary"
variant = "zulu"
distro = "zulu"
features = [21]

[[source]]
id = "foojay-zulu-2"
adapter = "foojay"
role = "confirm"
variant = "zulu"
distro = "zulu"
features = [21]
"#;

fn parse(text: &str) -> Result<SourcesFile> {
    SourcesFile::parse("sources.toml", text)
}

fn error(text: &str) -> String {
    parse(text).unwrap_err().to_string()
}

#[test]
fn a_full_file_parses_into_typed_adapter_settings() {
    let file = parse(FULL).unwrap();
    assert_eq!(file.sources.len(), 4);
    let first = &file.sources[0];
    assert_eq!(first.id, "adoptium-api");
    assert_eq!(first.role, Role::Primary);
    assert_eq!(first.variant.as_deref(), Some("temurin"));
    let Adapter::Adoptium(adoptium) = &first.adapter else {
        panic!("expected the adoptium adapter, got {:?}", first.adapter);
    };
    assert_eq!(adoptium.features, Some(vec![17, 21]));
    assert!(adoptium.include_ea);
    // Settings that are not given take the documented defaults.
    assert_eq!(adoptium.api_url, "https://api.adoptium.net");
    assert_eq!(adoptium.vendor, "eclipse");

    let Adapter::GithubReleases(github) = &file.sources[1].adapter else {
        panic!("expected the github-releases adapter");
    };
    assert_eq!(github.hash_from, crate::adapters::HashFrom::Sidecar);
    assert_eq!(github.assets.len(), 1);
    assert_eq!(file.sources[1].adapter.name(), "github-releases");
    assert_eq!(file.sources[2].role, Role::Primary);
    assert_eq!(file.sources[3].role, Role::Confirm);
}

#[test]
fn every_adapter_can_be_selected_by_name() {
    let text = r#"
schema = 1
[[source]]
id = "a"
adapter = "gradle"
role = "primary"
"#;
    let file = parse(text).unwrap();
    assert_eq!(file.sources[0].adapter.name(), "gradle");

    for (adapter, extra, name) in [
        (
            "apache",
            "listings = [\"https://archive.apache.org/dist/x/\"]\nartifact = \"{version}/x-{version}.zip\"",
            "apache",
        ),
        (
            "maven-central",
            "group = \"g\"\nartifact = \"a\"\nextension = \"zip\"",
            "maven-central",
        ),
        ("foojay", "distro = \"zulu\"\nfeatures = [21]", "foojay"),
        ("adoptium", "", "adoptium"),
        (
            "github-releases",
            "repo = \"o/r\"\ntag_pattern = 'v(?P<version>.+)'\nhash_from = \"digest\"\nassets = { any = \"a-{version}.zip\" }",
            "github-releases",
        ),
    ] {
        let text = format!(
            "schema = 1\n[[source]]\nid = \"a\"\nadapter = \"{adapter}\"\nrole = \"primary\"\n{extra}\n"
        );
        let file = parse(&text).unwrap_or_else(|e| panic!("{adapter}: {e}"));
        assert_eq!(file.sources[0].adapter.name(), name);
    }
}

#[test]
fn the_schema_version_must_be_known() {
    let message =
        error("schema = 2\n[[source]]\nid = \"a\"\nadapter = \"gradle\"\nrole = \"primary\"");
    assert!(message.contains("schema 2"), "{message}");
    assert!(message.contains("sources.toml"), "{message}");
    // No schema at all.
    let message = error("[[source]]\nid = \"a\"\nadapter = \"gradle\"\nrole = \"primary\"");
    assert!(message.contains("schema"), "{message}");
}

#[test]
fn an_empty_file_is_refused() {
    assert!(error("schema = 1").contains("no `[[source]]`"));
}

#[test]
fn an_unknown_adapter_is_refused() {
    let message =
        error("schema = 1\n[[source]]\nid = \"a\"\nadapter = \"npm\"\nrole = \"primary\"");
    assert!(message.contains("npm"), "{message}");
}

#[test]
fn a_misspelt_setting_is_refused_rather_than_ignored() {
    let message = error(
        "schema = 1\n[[source]]\nid = \"a\"\nadapter = \"gradle\"\nrole = \"primary\"\ninclude_rcs = true",
    );
    assert!(message.contains("include_rcs"), "{message}");
    let message = error(
        "schema = 1\n[[source]]\nid = \"a\"\nadapter = \"gradle\"\nrole = \"primary\"\nvarient = \"x\"",
    );
    assert!(message.contains("varient"), "{message}");
    let message = error("schema = 1\nsource = []\nsources = 3");
    assert!(message.contains("sources"), "{message}");
}

#[test]
fn a_missing_role_or_id_is_refused() {
    assert!(error("schema = 1\n[[source]]\nid = \"a\"\nadapter = \"gradle\"").contains("role"));
    assert!(
        error("schema = 1\n[[source]]\nadapter = \"gradle\"\nrole = \"primary\"").contains("id")
    );
}

#[test]
fn ids_and_variants_follow_the_naming_rules() {
    let message = error(
        "schema = 1\n[[source]]\nid = \"Gradle API\"\nadapter = \"gradle\"\nrole = \"primary\"",
    );
    assert!(message.contains("source id"), "{message}");
    let message = error(
        "schema = 1\n[[source]]\nid = \"a\"\nvariant = \"Zulu\"\nadapter = \"gradle\"\nrole = \"primary\"",
    );
    assert!(message.contains("variant"), "{message}");
}

#[test]
fn ids_must_be_unique() {
    let text = "schema = 1\n\
        [[source]]\nid = \"a\"\nadapter = \"gradle\"\nrole = \"primary\"\n\
        [[source]]\nid = \"a\"\nadapter = \"gradle\"\nrole = \"confirm\"\nhash_from = \"checksum-url\"";
    assert!(error(text).contains("used twice"));
}

#[test]
fn each_variant_needs_exactly_one_primary() {
    let none = "schema = 1\n[[source]]\nid = \"a\"\nadapter = \"gradle\"\nrole = \"confirm\"";
    let message = error(none);
    assert!(message.contains("exactly one"), "{message}");
    assert!(message.contains("without a variant"), "{message}");

    let two = "schema = 1\n\
        [[source]]\nid = \"a\"\nvariant = \"zulu\"\nadapter = \"gradle\"\nrole = \"primary\"\n\
        [[source]]\nid = \"b\"\nvariant = \"zulu\"\nadapter = \"gradle\"\nrole = \"primary\"";
    let message = error(two);
    assert!(message.contains("variant `zulu`"), "{message}");
    assert!(message.contains("found 2"), "{message}");

    // A variant whose only source is a confirmation has nothing to confirm.
    let orphan = format!(
        "{FULL}\n[[source]]\nid = \"orphan\"\nvariant = \"liberica\"\nadapter = \"gradle\"\nrole = \"confirm\"\n"
    );
    assert!(error(&orphan).contains("variant `liberica`"));
}

#[test]
fn bad_adapter_settings_name_the_source() {
    let text = "schema = 1\n[[source]]\nid = \"vendor-api\"\nadapter = \"foojay\"\nrole = \"primary\"\n\
                distro = \"zulu\"\nfeatures = [21]\napi_url = \"http://api.foojay.io\"";
    let message = error(text);
    assert!(message.contains("vendor-api"), "{message}");
    assert!(message.contains("api_url"), "{message}");
}

#[test]
fn an_oversized_file_is_refused_before_parsing() {
    let text = format!("schema = 1\n# {}", "x".repeat(300 * 1024));
    assert!(error(&text).contains("larger than"));
}

#[test]
fn sources_are_found_by_variant() {
    let file = parse(FULL).unwrap();
    assert_eq!(file.variants(), [Some("temurin"), Some("zulu")]);
    let temurin: Vec<&str> = file
        .for_variant(Some("temurin"))
        .map(|s| s.id.as_str())
        .collect();
    assert_eq!(temurin, ["adoptium-api", "github-sidecar"]);
    assert_eq!(file.for_variant(None).count(), 0);
}

#[test]
fn load_reads_a_file_and_names_it_in_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sources.toml");
    std::fs::write(
        &path,
        "schema = 1\n[[source]]\nid = \"a\"\nadapter = \"gradle\"\nrole = \"primary\"",
    )
    .unwrap();
    assert_eq!(SourcesFile::load(&path).unwrap().sources.len(), 1);

    std::fs::write(&path, [0xff, 0xfe]).unwrap();
    let message = SourcesFile::load(&path).unwrap_err().to_string();
    assert!(message.contains("sources.toml"), "{message}");
    assert!(message.contains("UTF-8"), "{message}");

    let missing = SourcesFile::load(&dir.path().join("nope.toml")).unwrap_err();
    assert_eq!(missing.code().as_str(), "E_PLUGIN_INVALID");
}

#[test]
fn a_loaded_source_runs_its_adapter() {
    let file = parse(
        "schema = 1\n[[source]]\nid = \"gradle-api\"\nadapter = \"gradle\"\nrole = \"primary\"\n\
         include_rc = false",
    )
    .unwrap();
    let mock = Mock::start();
    mock.serve(
        "/services.gradle.org/versions/all",
        fixture("gradle/versions-all.json"),
    );
    let discovery = file.sources[0].discover(&mock.context()).unwrap();
    assert_eq!(discovery.candidates.len(), 4);
    assert!(
        discovery
            .candidates
            .iter()
            .all(|c| c.source == "gradle-api")
    );
}

const SOLE: &str = r#"
schema = 1

[[source]]
id = "foojay-zulu"
adapter = "foojay"
role = "primary"
variant = "zulu"
distro = "zulu"
features = [21]
sole_source = true
signing_keys = ["keys/zulu.asc", "keys/other.asc"]
"#;

#[test]
fn confirmation_settings_default_to_off() {
    let file = parse(FULL).unwrap();
    assert!(file.sources.iter().all(|s| !s.sole_source));
    assert!(file.sources.iter().all(|s| s.signing_keys.is_empty()));
}

#[test]
fn a_sole_source_and_its_signing_keys_are_read() {
    let file = parse(SOLE).unwrap();
    let source = &file.sources[0];
    assert!(source.sole_source);
    assert_eq!(source.signing_keys, ["keys/zulu.asc", "keys/other.asc"]);
}

#[test]
fn only_a_primary_can_be_the_sole_source_of_its_variant() {
    // A confirm source cannot be the sole source: it would not supply the entry.
    let as_confirm = format!(
        "{SOLE}\n[[source]]\nid = \"main\"\nadapter = \"foojay\"\nrole = \"primary\"\nvariant = \"zulu\"\n\
         distro = \"zulu\"\nfeatures = [21]\n"
    )
    .replacen(r#"role = "primary""#, r#"role = "confirm""#, 1);
    let message = error(&as_confirm);
    assert!(message.contains("sole_source"), "{message}");

    // A variant with a second source has a second opinion to use instead.
    let with_second = format!(
        "{SOLE}\n[[source]]\nid = \"second\"\nadapter = \"foojay\"\nrole = \"confirm\"\n\
         variant = \"zulu\"\ndistro = \"zulu\"\nfeatures = [21]\n"
    );
    let message = error(&with_second);
    assert!(message.contains("sole_source"), "{message}");
    assert!(message.contains("zulu"), "{message}");
}

#[test]
fn signing_key_paths_stay_inside_the_plugin_directory() {
    for bad in [
        "",
        "/etc/keys.asc",
        "../keys.asc",
        "a/../b.asc",
        "a//b.asc",
        "a\\b.asc",
        "C:keys.asc",
        ".hidden",
        "a b.asc",
        "keys/",
    ] {
        let text = SOLE.replace(
            r#"["keys/zulu.asc", "keys/other.asc"]"#,
            &format!("[{bad:?}]"),
        );
        let message = error(&text);
        assert!(message.contains("signing_keys"), "{bad}: {message}");
    }
}
