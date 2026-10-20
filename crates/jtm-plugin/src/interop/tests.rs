use super::*;
use crate::manifest::Manifest;

const JAVA: &str = include_str!("../../tests/fixtures/manifests/valid/java.toml");
const WRAPPED: &str = include_str!("../../tests/fixtures/manifests/valid/wrapped.toml");

fn manifest(text: &str) -> Manifest {
    Manifest::parse(text).unwrap_or_else(|e| panic!("{e}"))
}

fn interop<'m>(m: &'m Manifest, file: &str) -> &'m Interop {
    m.interop
        .iter()
        .find(|i| i.file == file)
        .unwrap_or_else(|| panic!("no interop for {file}"))
}

fn value(variant: Option<&str>, value: &str) -> InteropValue {
    InteropValue {
        variant: variant.map(str::to_owned),
        value: value.to_owned(),
    }
}

#[test]
fn sdkman_vendor_suffixes_map_to_variants() {
    let m = manifest(JAVA);
    let rc = interop(&m, ".sdkmanrc");
    let cases = [
        ("java=21.0.5-tem\n", "temurin", "21.0.5"),
        (
            "# comment\nmaven=3.9.9\njava = 17.0.13-amzn\n",
            "corretto",
            "17.0.13",
        ),
        ("java=21.0.5-librca", "liberica", "21.0.5"),
        ("java=21-ms\r\n", "microsoft", "21"),
        ("java=21.0.2-graalce\n", "graalvm-community", "21.0.2"),
    ];
    for (text, variant, version) in cases {
        assert_eq!(
            read(&m, rc, text),
            Ok(Some(value(Some(variant), version))),
            "{text:?}"
        );
    }
}

#[test]
fn an_unknown_sdkman_suffix_is_an_error_not_a_guess() {
    let m = manifest(JAVA);
    let rc = interop(&m, ".sdkmanrc");
    for text in ["java=21.0.5-zulu\n", "java=21.0.5\n"] {
        match read(&m, rc, text) {
            Err(InteropError::Unmappable { value, message, .. }) => {
                assert!(text.contains(&value), "{value}");
                assert!(message.contains("tem"), "{message}");
            }
            other => panic!("{text:?}: {other:?}"),
        }
    }
}

#[test]
fn a_file_without_the_key_pins_nothing() {
    let m = manifest(JAVA);
    assert_eq!(
        read(&m, interop(&m, ".sdkmanrc"), "maven=3.9.9\n"),
        Ok(None)
    );
    assert_eq!(
        read(&m, interop(&m, ".tool-versions"), "nodejs 20.1.0\n"),
        Ok(None)
    );
    assert_eq!(
        read(&m, interop(&m, ".java-version"), "\n# none\n"),
        Ok(None)
    );
}

#[test]
fn tool_versions_and_single_line_take_an_optional_variant_prefix() {
    let m = manifest(JAVA);
    let tv = interop(&m, ".tool-versions");
    assert_eq!(
        read(
            &m,
            tv,
            "nodejs 20.1.0\njava temurin-21.0.5+11 corretto-21\n"
        ),
        Ok(Some(value(Some("temurin"), "21.0.5+11")))
    );
    let jv = interop(&m, ".java-version");
    assert_eq!(read(&m, jv, "21\n"), Ok(Some(value(None, "21"))));
    assert_eq!(
        read(&m, jv, "corretto-17\n"),
        Ok(Some(value(Some("corretto"), "17")))
    );
    assert!(matches!(
        read(&m, jv, "acme-17\n"),
        Err(InteropError::Unmappable { .. })
    ));
}

#[test]
fn a_plugin_without_variants_reads_the_value_as_is() {
    let m = manifest(WRAPPED);
    let rc = interop(&m, ".sdkmanrc");
    assert_eq!(
        read(&m, rc, "wrapped=3.9.9\n"),
        Ok(Some(value(None, "3.9.9")))
    );
}

#[test]
fn values_that_are_not_versions_are_rejected() {
    let m = manifest(JAVA);
    let jv = interop(&m, ".java-version");
    assert!(matches!(
        read(&m, jv, "$(rm -rf ~)\n"),
        Err(InteropError::Unmappable { .. })
    ));
}

#[test]
fn format_is_the_inverse_of_read() {
    let m = manifest(JAVA);
    let rc = interop(&m, ".sdkmanrc");
    assert_eq!(
        format(&m, rc, Some("corretto"), "21.0.5"),
        Ok("21.0.5-amzn".to_owned())
    );
    // No variant means the plugin's default.
    assert_eq!(format(&m, rc, None, "21"), Ok("21-tem".to_owned()));
    assert!(matches!(
        format(&m, rc, Some("zulu"), "21"),
        Err(InteropError::Unmappable { .. })
    ));
    let tv = interop(&m, ".tool-versions");
    assert_eq!(
        format(&m, tv, Some("temurin"), "21"),
        Ok("temurin-21".to_owned())
    );
    let jv = interop(&m, ".java-version");
    assert_eq!(format(&m, jv, None, "21"), Ok("temurin-21".to_owned()));

    let w = manifest(WRAPPED);
    assert_eq!(
        format(&w, interop(&w, ".sdkmanrc"), None, "3.9"),
        Ok("3.9".to_owned())
    );
}

#[test]
fn writing_replaces_the_line_and_keeps_the_rest() {
    let m = manifest(JAVA);
    let rc = interop(&m, ".sdkmanrc");
    assert_eq!(
        write(rc, Some("# env\nmaven=3.9.9\njava=17-tem\n"), "21-tem"),
        Ok("# env\nmaven=3.9.9\njava=21-tem\n".to_owned())
    );
    assert_eq!(
        write(rc, Some("maven=3.9.9"), "21-tem"),
        Ok("maven=3.9.9\njava=21-tem\n".to_owned())
    );
    assert_eq!(write(rc, None, "21-tem"), Ok("java=21-tem\n".to_owned()));
    let tv = interop(&m, ".tool-versions");
    assert_eq!(
        write(tv, Some("nodejs 20\njava corretto-17\r\n"), "temurin-21"),
        Ok("nodejs 20\njava temurin-21\r\n".to_owned())
    );
    let jv = interop(&m, ".java-version");
    assert_eq!(write(jv, Some("17\n"), "21"), Ok("21\n".to_owned()));
}

#[test]
fn removing_drops_only_the_tool() {
    let m = manifest(JAVA);
    let rc = interop(&m, ".sdkmanrc");
    assert_eq!(
        remove(rc, "maven=3.9.9\njava=17-tem\n"),
        Some("maven=3.9.9\n".to_owned())
    );
    assert_eq!(remove(rc, "maven=3.9.9\n"), None);
    let jv = interop(&m, ".java-version");
    assert_eq!(remove(jv, "21\n"), Some(String::new()));
}

#[test]
fn wrapper_files_give_the_version_url_and_hash() {
    let m = manifest(WRAPPED);
    let w = interop(&m, "wrapped/wrapper/wrapped-wrapper.properties");
    let text = "distributionBase=GRADLE_USER_HOME\n\
                distributionUrl=https\\://dl.example.test/wrapped-8.11-rc-1-bin.zip\n\
                distributionSha256Sum=abc123\n";
    assert_eq!(
        read_wrapper(w, text),
        Ok(Some(WrapperPin {
            version: "8.11-rc-1".to_owned(),
            url: "https://dl.example.test/wrapped-8.11-rc-1-bin.zip".to_owned(),
            file_name: "wrapped-8.11-rc-1-bin.zip".to_owned(),
            sha256: Some("abc123".to_owned()),
        }))
    );
    assert_eq!(read_wrapper(w, "zipStoreBase=x\n"), Ok(None));
    // Without a `sha256_key`, the wrapper's hash is not read.
    let mut plain = w.clone();
    plain.sha256_key = None;
    assert_eq!(read_wrapper(&plain, text).unwrap().unwrap().sha256, None);
    assert!(matches!(
        read_wrapper(w, "distributionUrl=https://dl.example.test/other-1.0.zip\n"),
        Err(InteropError::Unmappable { .. })
    ));
}

#[test]
fn wrapper_files_are_read_only_and_script_interop_needs_hooks() {
    let m = manifest(WRAPPED);
    let w = interop(&m, "wrapped/wrapper/wrapped-wrapper.properties");
    assert!(matches!(
        write(w, None, "1"),
        Err(InteropError::ReadOnly { .. })
    ));
    assert!(matches!(
        read(&m, w, ""),
        Err(InteropError::ReadOnly { .. })
    ));

    let mut scripted = manifest(JAVA);
    scripted.interop[0].script = true;
    scripted.interop[0].mapping.clear();
    assert!(matches!(
        read(&scripted, &scripted.interop[0], "java=21-tem"),
        Err(InteropError::ScriptUnsupported { .. })
    ));
}
