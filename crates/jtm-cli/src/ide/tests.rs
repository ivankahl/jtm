use std::path::PathBuf;

use super::*;

fn toolchain(variant: &str, version: &str, home: &str) -> Toolchain {
    Toolchain {
        id: format!("java@{variant}:{version}"),
        kind: "jdk".to_owned(),
        vendor: variant.to_owned(),
        version: version.to_owned(),
        home: PathBuf::from(home),
    }
}

fn toolchains() -> Vec<Toolchain> {
    vec![
        toolchain("temurin", "21.0.5+11", "/data/tools/java/temurin-21.0.5+11"),
        toolchain(
            "corretto",
            "17.0.13.11.1",
            "/data/tools/java/corretto-17 & <x>",
        ),
    ]
}

const USER_TOOLCHAINS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<toolchains>
  <!-- mine -->
  <toolchain>
    <type>jdk</type>
    <provides><version>11</version></provides>
    <configuration><jdkHome>/opt/jdk11</jdkHome></configuration>
  </toolchain>
</toolchains>
"#;

#[test]
fn a_new_toolchains_file_lists_every_jdk() {
    let text = update_toolchains(None, &toolchains()).unwrap().unwrap();
    insta::assert_snapshot!(text);
    assert_eq!(update_toolchains(Some(&text), &toolchains()).unwrap(), None);
}

#[test]
fn entries_jtm_did_not_write_are_untouched() {
    let text = update_toolchains(Some(USER_TOOLCHAINS), &toolchains())
        .unwrap()
        .unwrap();
    assert!(text.contains("<jdkHome>/opt/jdk11</jdkHome>"), "{text}");
    assert!(text.contains("<!-- mine -->"), "{text}");
    assert!(text.ends_with("</toolchains>\n"), "{text}");
    // Re-running is a no-op; a shorter list replaces jtm's block only.
    assert_eq!(update_toolchains(Some(&text), &toolchains()).unwrap(), None);
    let fewer = update_toolchains(Some(&text), &toolchains()[..1])
        .unwrap()
        .unwrap();
    assert!(!fewer.contains("corretto"), "{fewer}");
    assert!(fewer.contains("/opt/jdk11"), "{fewer}");
    let none = update_toolchains(Some(&fewer), &[]).unwrap().unwrap();
    assert_eq!(none, USER_TOOLCHAINS);
}

#[test]
fn a_toolchains_file_jtm_cannot_place_entries_in_is_refused() {
    let err = update_toolchains(Some("<settings/>"), &toolchains()).unwrap_err();
    assert_eq!(err.code(), "E_USAGE");
}

#[test]
fn gradle_paths_keep_user_entries_and_replace_jtm_ones() {
    let tools = Path::new("/data/tools");
    let homes: Vec<PathBuf> = toolchains().into_iter().map(|j| j.home).collect();
    let fresh = update_gradle(None, &homes, tools).unwrap();
    assert_eq!(
        fresh,
        "org.gradle.java.installations.paths=/data/tools/java/corretto-17 & <x>,/data/tools/java/temurin-21.0.5+11\n"
    );
    assert_eq!(update_gradle(Some(&fresh), &homes, tools), None);

    let existing = "org.gradle.daemon=true\n\
                    org.gradle.java.installations.paths=/opt/jdk11,/data/tools/java/old-1\n\
                    # end\n";
    let merged = update_gradle(Some(existing), &homes[..1], tools).unwrap();
    assert_eq!(
        merged,
        "org.gradle.daemon=true\n\
         org.gradle.java.installations.paths=/opt/jdk11,/data/tools/java/temurin-21.0.5+11\n\
         # end\n"
    );
    // With no jtm installs left, only the user's entry stays.
    let cleared = update_gradle(Some(&merged), &[], tools).unwrap();
    assert!(
        cleared.contains("org.gradle.java.installations.paths=/opt/jdk11\n"),
        "{cleared}"
    );
}

#[test]
fn gradle_values_are_escaped_as_properties() {
    let tools = Path::new(r"C:\jtm\tools");
    let homes = [PathBuf::from(r"C:\jtm\tools\java\temurin-21")];
    let text = update_gradle(None, &homes, tools).unwrap();
    assert_eq!(
        text,
        "org.gradle.java.installations.paths=C\\:\\\\jtm\\\\tools\\\\java\\\\temurin-21\n"
    );
    // Reading it back gives the same path, so a re-run changes nothing.
    assert_eq!(update_gradle(Some(&text), &homes, tools), None);
}

#[test]
fn entries_go_inside_a_root_element_on_one_line() {
    let one_line = "<?xml version=\"1.0\"?>\n<toolchains></toolchains>\n";
    let text = update_toolchains(Some(one_line), &toolchains())
        .unwrap()
        .unwrap();
    let open = text.find("<toolchains>").unwrap();
    let first = text.find("<toolchain>").unwrap();
    let close = text.rfind("</toolchains>").unwrap();
    assert!(open < first && first < close, "{text}");
    // A second run finds jtm's block and changes nothing.
    assert_eq!(update_toolchains(Some(&text), &toolchains()).unwrap(), None);
}

#[test]
fn non_ascii_gradle_paths_are_written_as_unicode_escapes() {
    let tools = Path::new("/home/josé/.jtm/tools");
    let homes = [PathBuf::from("/home/josé/.jtm/tools/java/temurin-21")];
    let text = update_gradle(None, &homes, tools).unwrap();
    assert!(text.is_ascii(), "{text}");
    assert!(text.contains("jos\\u00e9"), "{text}");
    assert_eq!(update_gradle(Some(&text), &homes, tools), None);
}

#[test]
fn a_continued_gradle_line_is_replaced_whole() {
    let tools = Path::new("/data/tools");
    let homes = [PathBuf::from("/data/tools/java/temurin-21")];
    let existing =
        "a=1\norg.gradle.java.installations.paths=/opt/jdk11,\\\n    /data/tools/java/old\nb=2\n";
    let text = update_gradle(Some(existing), &homes, tools).unwrap();
    assert_eq!(
        text,
        "a=1\norg.gradle.java.installations.paths=/opt/jdk11,/data/tools/java/temurin-21\nb=2\n"
    );
}
