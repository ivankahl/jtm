use std::path::Path;

use super::*;

const COMMENTED: &str = r#"# .jtm.toml
[tools]
java = "temurin:21"      # variant:version, alias, or partial version
maven = "3.9"
# gradle is pinned by the wrapper

[plugins]
# optional: third-party plugins this project needs, pinned to a commit
acme-flyway = { source = "https://github.com/acme/jtm-flyway", rev = "3f9c2e1" }
"#;

fn parse(text: &str) -> ProjectFile {
    ProjectFile::parse(Path::new("/work/app/.jtm.toml"), text).unwrap_or_else(|e| panic!("{e}"))
}

fn selector(text: &str) -> Selector {
    Selector::parse(text).unwrap_or_else(|e| panic!("{e}"))
}

#[test]
fn changing_a_pin_keeps_comments_and_order() {
    let mut file = parse(COMMENTED);
    assert!(file.set_tool("maven", &selector("3.9.9")));
    insta::assert_snapshot!(file.render());
}

#[test]
fn pinning_in_an_empty_file_creates_the_tools_table() {
    let mut file = ProjectFile::empty(Path::new("/work/app/.jtm.toml"));
    assert!(file.set_tool("java", &selector("temurin:21")));
    assert!(file.set_tool("maven", &selector("3.9")));
    assert_eq!(
        file.render(),
        "[tools]\njava = \"temurin:21\"\nmaven = \"3.9\"\n"
    );
}

#[test]
fn a_new_pin_goes_into_tools_even_when_other_tables_come_first() {
    let mut file = parse("[settings.index]\nttl_hours = 1\n");
    file.set_tool("gradle", &selector("8.10.2"));
    insta::assert_snapshot!(file.render());
}

#[test]
fn setting_the_same_pin_again_changes_nothing() {
    let mut file = parse(COMMENTED);
    assert!(!file.set_tool("java", &selector("temurin:21")));
    assert_eq!(file.render(), COMMENTED);
}

#[test]
fn unpinning_removes_only_that_line() {
    let mut file = parse(COMMENTED);
    assert!(file.remove_tool("java"));
    assert!(!file.remove_tool("java"));
    insta::assert_snapshot!(file.render());
}

#[test]
fn reads_tools_plugins_and_lock_platforms() {
    let file = parse(&format!(
        "{COMMENTED}\n[lock]\nplatforms = [\"linux-x64\", \"windows-x64\"]\n"
    ));
    let tools: Vec<String> = file
        .tools()
        .iter()
        .map(|(t, s)| format!("{t}={s}"))
        .collect();
    assert_eq!(tools, ["java=temurin:21", "maven=3.9"]);
    assert_eq!(file.tool("maven"), Some(selector("3.9")));
    assert_eq!(
        file.plugins(),
        [ProjectPlugin {
            name: "acme-flyway".to_owned(),
            source: "https://github.com/acme/jtm-flyway".to_owned(),
            rev: "3f9c2e1".to_owned(),
        }]
    );
    assert_eq!(
        file.lock_platforms(),
        Some(vec![Platform::LinuxX64, Platform::WindowsX64])
    );
}

#[test]
fn invalid_files_are_usage_errors_naming_the_key() {
    let cases = [
        ("[tools\n", ""),
        ("[toolz]\n", "toolz"),
        ("tools = 1\n", "tools"),
        ("[tools]\njava = 21\n", "tools.java"),
        ("[tools]\njava = \"temurin:\"\n", "tools.java"),
        ("[tools]\n\"Bad Name\" = \"1\"\n", "tools.Bad Name"),
        ("[plugins]\nx = \"y\"\n", "plugins.x"),
        (
            "[plugins]\nx = { source = \"https://e.test/x\" }\n",
            "plugins.x.rev",
        ),
        (
            "[plugins]\nx = { source = \"https://e.test/x\", rev = \"a\", branch = \"main\" }\n",
            "plugins.x.branch",
        ),
        ("[lock]\nplatforms = [\"amiga\"]\n", "lock.platforms"),
        ("[lock]\nos = []\n", "lock.os"),
    ];
    for (text, key) in cases {
        let err = ProjectFile::parse(Path::new("/p/.jtm.toml"), text)
            .err()
            .unwrap_or_else(|| panic!("accepted {text:?}"));
        assert_eq!(err.code(), "E_USAGE", "{text:?}");
        match &err {
            JtmError::Config { key: got, .. } => assert_eq!(got, key, "{text:?}: {err}"),
            other => panic!("{text:?}: {other}"),
        }
    }
}

#[test]
fn reads_and_writes_the_file_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    assert!(ProjectFile::read(dir.path()).unwrap().is_none());
    let mut file = ProjectFile::empty(&dir.path().join(PROJECT_FILE));
    file.set_tool("java", &selector("21"));
    file.write().unwrap();
    let back = ProjectFile::read(dir.path()).unwrap().unwrap();
    assert_eq!(back.tool("java"), Some(selector("21")));
}
