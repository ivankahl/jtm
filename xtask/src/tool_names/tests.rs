use std::path::Path;

use super::*;

fn names() -> Vec<String> {
    ["java", "JAVA_HOME", "mvn", "spring-boot-cli"]
        .map(str::to_owned)
        .to_vec()
}

fn literals(source: &str) -> Vec<String> {
    string_literals(source)
        .into_iter()
        .map(|(_, s)| s)
        .collect()
}

#[test]
fn finds_plain_raw_and_byte_strings_with_their_lines() {
    let source = "let a = \"one\";\nlet b = r#\"two \"quoted\"\"#;\nlet c = b\"three\";\n\
                  let d = br\"four\";\nlet e = \"multi\nline\";\nlet f = \"after\";";
    assert_eq!(
        string_literals(source),
        [
            (1, "one".to_owned()),
            (2, "two \"quoted\"".to_owned()),
            (3, "three".to_owned()),
            (4, "four".to_owned()),
            (5, "multi\nline".to_owned()),
            (7, "after".to_owned()),
        ]
    );
}

#[test]
fn skips_comments_chars_and_lifetimes() {
    let source = "// \"java\" in a comment\n/// doc \"java\"\n/* block \"java\" /* nested */ */\n\
                  let q = '\"'; let e = '\\''; fn f<'a>(x: &'a str) {}\nlet s = \"kept\";";
    assert_eq!(literals(source), ["kept"]);
}

#[test]
fn keeps_escaped_quotes_inside_strings() {
    assert_eq!(
        literals(r#"let s = "a \" b"; let t = "c";"#),
        [r#"a \" b"#, "c"]
    );
}

#[test]
fn matches_whole_words_only() {
    assert!(contains_word("set JAVA_HOME now", "JAVA_HOME"));
    assert!(contains_word("java", "java"));
    assert!(contains_word("`java@21`", "java"));
    assert!(contains_word("temurin-21", "temurin"));
    assert!(!contains_word("javascript", "java"));
    assert!(!contains_word("my_java", "java"));
    assert!(!contains_word("JAVA_HOMES", "JAVA_HOME"));
}

#[test]
fn reports_tool_names_outside_comments_and_allowed_literals() {
    let source = "// java is fine here\nlet x = \"run `mvn`\";\nlet y = \"generic\";\n";
    let hits = check_source("crates/jtm-core/src/x.rs", source, &names());
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].line, 2);
    assert_eq!(hits[0].name, "mvn");
    assert!(check_source("crates/jtm-plugin/src/version/mod.rs", "\"java\"", &names()).is_empty());
    assert_eq!(
        check_source("crates/jtm-core/src/x.rs", "\"java\"", &names()).len(),
        1
    );
}

#[test]
fn reads_names_from_the_first_party_manifests() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join(PLUGINS);
    let names = tool_names(&dir).unwrap_or_else(|e| panic!("{e}"));
    for expected in ["java", "temurin", "JAVA_HOME", "gradle", "springboot"] {
        assert!(
            names.iter().any(|n| n == expected),
            "{expected} in {names:?}"
        );
    }
}

#[test]
fn the_core_crates_name_no_tools() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    assert_eq!(run(&root), ExitCode::SUCCESS);
}
