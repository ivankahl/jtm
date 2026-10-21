#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use jtm_plugin::manifest::{Alias, InteropParser, Manifest, Scheme, StripComponents};

fn fixtures(kind: &str) -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/manifests")
        .join(kind);
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    paths.sort();
    paths
}

#[test]
fn every_valid_fixture_parses() {
    let valid = fixtures("valid");
    assert!(valid.len() >= 3);
    for path in valid {
        let text = fs::read_to_string(&path).unwrap();
        if let Err(err) = Manifest::parse(&text) {
            panic!("{}: {err}", path.display());
        }
    }
}

#[test]
fn spec_maven_example_parses() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manifests/valid/maven.toml"),
    )
    .unwrap();
    let m = Manifest::parse(&text).unwrap();
    assert_eq!(m.name, "maven");
    assert_eq!(m.display_name, "Apache Maven");
    assert_eq!(m.min_jtm.as_deref(), Some("0.1.0"));
    assert_eq!(m.versions.scheme, Scheme::Maven);
    assert_eq!(m.versions.default_alias.as_deref(), Some("latest"));
    assert!(!m.versions.include_prereleases);
    assert_eq!(m.default_variant(), "default");
    assert!(m.has_variant("default"));
    assert_eq!(m.aliases["latest"], Alias::Highest {});
    assert_eq!(m.aliases["3"], Alias::Fixed { target: "3".into() });
    assert_eq!(m.index.format, 1);
    assert_eq!(m.index.threshold(), 1);
    assert_eq!(m.index.keys_url, None);
    assert_eq!(m.layout.strip_components, StripComponents::Count(1));
    assert_eq!(m.layout.bin_dirs, ["bin"]);
    assert_eq!(m.env["MAVEN_HOME"], "{home}");
    assert_eq!(m.requires["java"], ">=8");
    assert_eq!(m.interop[0].parser, InteropParser::Keyvalue);
    assert_eq!(m.interop[0].key.as_deref(), Some("maven"));
}

#[test]
fn java_style_manifest_uses_variants_and_per_os_layout() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manifests/valid/java.toml"),
    )
    .unwrap();
    let m = Manifest::parse(&text).unwrap();
    assert_eq!(m.default_variant(), "temurin");
    assert!(m.has_variant("graalvm-community"));
    assert!(!m.has_variant("default"));
    assert_eq!(m.aliases["lts"], Alias::IndexTag { tag: "lts".into() });
    assert_eq!(m.layout.strip_components, StripComponents::Auto);
    assert_eq!(m.layout.home_subdir_for("macos"), Some("Contents/Home"));
    assert_eq!(m.layout.home_subdir_for("linux"), None);
    // A variant without an override takes `[layout]` as it is.
    let temurin = m.layout.for_variant("temurin");
    assert_eq!(temurin.home_subdir_for("macos"), Some("Contents/Home"));
    assert_eq!(temurin.strip_components, StripComponents::Auto);
    // An override replaces only the fields it sets, each as a whole.
    let zulu = m.layout.for_variant("zulu");
    assert_eq!(zulu.home_subdir_for("macos"), None);
    assert_eq!(zulu.strip_components, StripComponents::Auto);
    assert_eq!(zulu.bin_dirs, ["bin"]);
    let liberica = m.layout.for_variant("liberica");
    assert_eq!(liberica.strip_components, StripComponents::Count(1));
    assert_eq!(liberica.home_subdir_for("macos"), None);
    assert_eq!(liberica.home_subdir_for("windows"), Some("jdk"));
    assert_eq!(m.interop[0].mapping["tem"], "temurin");
    assert_eq!(m.interop[2].parser, InteropParser::SingleLine);
    assert_eq!(m.hooks.post_extract.as_deref(), Some("fix_permissions"));
    assert_eq!(m.index.threshold(), 2);
    assert_eq!(
        m.index.keys_url.as_deref(),
        Some("https://github.com/jtm-dev/index/releases/latest/download/keys.json")
    );
}

/// Each invalid fixture starts with `# expect: <field path>` and has exactly one problem.
#[test]
fn every_invalid_fixture_is_rejected_with_its_field_path() {
    let invalid = fixtures("invalid");
    assert!(invalid.len() >= 20, "need at least 20 invalid fixtures");
    let mut failures = Vec::new();
    for path in invalid {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = fs::read_to_string(&path).unwrap();
        let expected = text
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("# expect:"))
            .unwrap_or_else(|| panic!("{name}: missing `# expect:` line"))
            .trim();
        match Manifest::parse(&text) {
            Ok(_) => failures.push(format!("{name}: parsed but should be rejected")),
            Err(err) => {
                let paths: Vec<&str> = err.problems.iter().map(|p| p.path.as_str()).collect();
                if paths != [expected] || err.problems[0].message.is_empty() {
                    failures.push(format!("{name}: expected [{expected}], got {err}"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn errors_are_readable() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/manifests/invalid/unknown-versions-field.toml"),
    )
    .unwrap();
    let err = Manifest::parse(&text).unwrap_err().to_string();
    assert!(
        err.starts_with("invalid plugin.toml: `versions.sceme` (line "),
        "{err}"
    );
    assert!(
        err.contains("unknown field `sceme`, expected one of"),
        "{err}"
    );

    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/manifests/invalid/schema-future.toml"),
    )
    .unwrap();
    let err = Manifest::parse(&text).unwrap_err().to_string();
    assert!(err.contains("may need a newer jtm"), "{err}");
}

#[test]
fn home_subdir_string_form_explains_the_table_form() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/manifests/invalid/layout-home-subdir-string.toml"),
    )
    .unwrap();
    let err = Manifest::parse(&text).unwrap_err().to_string();
    assert!(
        err.contains("home_subdir = { macos = \"Contents/Home\" }"),
        "{err}"
    );
}

/// A plugin is trusted once installed, so any variable outside `PATH` and `JTM_*` is allowed.
#[test]
fn env_allows_any_variable_jtm_does_not_own() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manifests/valid/demo.toml"),
    )
    .unwrap();
    let m = Manifest::parse(&text).unwrap();
    assert_eq!(m.env["JAVA_TOOL_OPTIONS"], "-Dfile.encoding=UTF-8");
    assert_eq!(m.env["LD_LIBRARY_PATH"], "{home}/lib");

    // Values may contain control characters; whatever prints them for a shell must quote them.
    let text = text.replace(
        "JAVA_TOOL_OPTIONS = \"-Dfile.encoding=UTF-8\"",
        "JAVA_TOOL_OPTIONS = \"-Dfile.encoding=UTF-8\\n-Xmx1g\"",
    );
    let m = Manifest::parse(&text).unwrap();
    assert_eq!(m.env["JAVA_TOOL_OPTIONS"], "-Dfile.encoding=UTF-8\n-Xmx1g");
}

#[test]
fn strip_components_and_default_alias_are_optional() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manifests/valid/demo.toml"),
    )
    .unwrap()
    // Drop whole lines rather than matching `\n`: Windows checkouts use CRLF line endings.
    .lines()
    .filter(|line| !line.starts_with("strip_components") && !line.starts_with("default_alias"))
    .collect::<Vec<_>>()
    .join("\n");
    let m = Manifest::parse(&text).unwrap();
    assert_eq!(m.layout.strip_components, StripComponents::Auto);
    assert_eq!(m.versions.default_alias, None);
}

#[test]
fn validation_reports_every_problem() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manifests/valid/demo.toml"),
    )
    .unwrap()
    .replace("name = \"demo\"", "name = \"Demo\"")
    .replace("format = 1", "format = 7")
    .replace("DEMO_HOME", "PATH");
    let err = Manifest::parse(&text).unwrap_err();
    let paths: Vec<&str> = err.problems.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(paths, ["name", "index.format", "env.PATH"]);
}

#[test]
fn wrapper_interop_reads_a_distribution_url_pattern() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manifests/valid/wrapped.toml"),
    )
    .unwrap();
    let m = Manifest::parse(&text).unwrap();
    let wrapper = &m.interop[1];
    assert_eq!(wrapper.parser, InteropParser::Wrapper);
    assert_eq!(wrapper.key.as_deref(), Some("distributionUrl"));
    assert_eq!(wrapper.pattern.as_deref(), Some("wrapped-{version}-*.zip"));
}

#[test]
fn ide_declares_build_tool_toolchains() {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manifests/valid/java.toml"),
    )
    .unwrap();
    let m = Manifest::parse(&text).unwrap();
    assert_eq!(m.ide.maven_toolchain.as_deref(), Some("jdk"));
    assert!(m.ide.gradle_installations);
    let demo = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/manifests/valid/demo.toml"),
    )
    .unwrap();
    let m = Manifest::parse(&demo).unwrap();
    assert_eq!(m.ide.maven_toolchain, None);
    assert!(!m.ide.gradle_installations);
}

/// The base of the `layout-variant-*` fixtures, with its `[layout.variants.*]` table cut off.
fn variant_base() -> String {
    let text = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/manifests/invalid/layout-variant-unknown.toml"),
    )
    .unwrap();
    text.lines()
        .take_while(|line| !line.starts_with("[layout.variants"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn an_unknown_variant_override_reports_every_problem_at_once() {
    let text = format!(
        "{}\n[layout.variants.gamma-build]\nhome_subdir = {{ macos = \"../x\", solaris = \"y\" }}\n",
        variant_base()
    );
    let err = Manifest::parse(&text).unwrap_err();
    let paths: Vec<&str> = err.problems.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "layout.variants.gamma-build",
            "layout.variants.gamma-build.home_subdir.macos",
            "layout.variants.gamma-build.home_subdir.solaris",
        ],
        "{err}"
    );
}

#[test]
fn only_a_home_subdir_table_gets_the_per_os_hint() {
    let hint = "home_subdir = { macos = \"Contents/Home\" }";
    let text = format!(
        "{}\n[layout.variants.beta-build]\nhome_subdir = \"x\"\n",
        variant_base()
    );
    let err = Manifest::parse(&text).unwrap_err().to_string();
    assert!(err.contains(hint), "{err}");

    // A variant named `home_subdir` is not a `home_subdir` table.
    let text = format!(
        "{}\n[layout.variants]\nhome_subdir = \"x\"\n",
        variant_base()
    );
    let err = Manifest::parse(&text).unwrap_err().to_string();
    assert!(!err.contains(hint), "{err}");
}
