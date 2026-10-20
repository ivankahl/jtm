//! `jtm ide sync` end to end.

#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::fs;
use std::path::Path;

use common::Fixture;
use serde_json::Value;

fn ide_sync(f: &Fixture, home: &Path, args: &[&str]) -> (i32, Value) {
    let output = f
        .jtm()
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env_remove("GRADLE_USER_HOME")
        .args(["--json", "ide", "sync"])
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    (
        output.status.code().unwrap(),
        serde_json::from_str(&stdout).unwrap_or_else(|_| panic!("{stdout}")),
    )
}

#[test]
fn ide_sync_lists_each_install_and_keeps_other_entries() {
    let f = Fixture::new(false);
    f.trust();
    let (code, value) = f.json(&["install", "demo@1.0.0", "demo@1.1.0"]);
    assert_eq!(code, 0, "{value}");
    let home = tempfile::tempdir().unwrap();
    let gradle = home.path().join(".gradle").join("gradle.properties");
    fs::create_dir_all(gradle.parent().unwrap()).unwrap();
    fs::write(
        &gradle,
        "org.gradle.daemon=true\norg.gradle.java.installations.paths=/opt/jdk11\n",
    )
    .unwrap();

    let (code, value) = ide_sync(&f, home.path(), &["--dry-run"]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["changed"], false);
    assert_eq!(value["data"]["maven"]["changed"], true);
    assert!(!home.path().join(".m2").exists());

    let (code, value) = ide_sync(&f, home.path(), &[]);
    assert_eq!(code, 0, "{value}");
    assert_eq!(value["command"], "ide sync");
    assert_eq!(value["changed"], true);
    assert_eq!(value["data"]["maven"]["entries"], 2);
    let toolchains = fs::read_to_string(home.path().join(".m2").join("toolchains.xml")).unwrap();
    for version in ["1.0.0", "1.1.0"] {
        let dir = f.install_dir(version).display().to_string();
        assert!(
            toolchains.contains(&format!("<jdkHome>{dir}</jdkHome>")),
            "{toolchains}"
        );
    }
    let props = fs::read_to_string(&gradle).unwrap();
    assert!(props.starts_with("org.gradle.daemon=true\n"), "{props}");
    assert!(props.contains("=/opt/jdk11,"), "{props}");

    let (code, again) = ide_sync(&f, home.path(), &[]);
    assert_eq!(code, 0);
    assert_eq!(again["changed"], false);

    // After an uninstall, only that entry goes.
    f.json(&["uninstall", "demo@1.0.0"]);
    let (_, value) = ide_sync(&f, home.path(), &["--maven-only"]);
    assert!(value["data"]["gradle"].is_null());
    let toolchains = fs::read_to_string(home.path().join(".m2").join("toolchains.xml")).unwrap();
    assert!(!toolchains.contains("1.0.0"), "{toolchains}");
    assert!(toolchains.contains("1.1.0"), "{toolchains}");
}
