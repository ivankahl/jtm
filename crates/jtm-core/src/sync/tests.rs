use std::path::PathBuf;

use super::*;

fn p(parts: &[&str]) -> PathBuf {
    let root = if cfg!(windows) { "C:\\" } else { "/" };
    parts
        .iter()
        .fold(PathBuf::from(root), |dir, part| dir.join(part))
}

#[test]
fn pin_sources_are_relative_with_forward_slashes() {
    let root = p(&["work", "app"]);
    assert_eq!(
        relative(&root, &p(&["work", "app", ".jtm.toml"])),
        ".jtm.toml"
    );
    assert_eq!(
        relative(&root, &p(&["work", "app", "svc", ".sdkmanrc"])),
        "svc/.sdkmanrc"
    );
    assert_eq!(
        relative(&root, &p(&["work", ".tool-versions"])),
        "../.tool-versions"
    );
}

#[test]
fn upgrade_names_which_tools_move() {
    assert!(!Upgrade::None.covers("java"));
    assert!(Upgrade::All.covers("java"));
    assert!(Upgrade::Tool("java".to_owned()).covers("java"));
    assert!(!Upgrade::Tool("java".to_owned()).covers("maven"));
}

#[test]
fn the_project_root_is_the_nearest_directory_with_any_pin_file() {
    let java = jtm_plugin::Manifest::parse(include_str!(
        "../../../jtm-plugin/tests/fixtures/manifests/valid/java.toml"
    ))
    .unwrap();
    let plugins = vec![Plugin {
        manifest: java,
        sha256: String::new(),
        origin: crate::indices::ManifestOrigin::External,
        location: "test".to_owned(),
    }];
    let repo = tempfile::tempdir().unwrap();
    let api = repo.path().join("services").join("api");
    std::fs::create_dir_all(&api).unwrap();
    std::fs::create_dir(repo.path().join(".git")).unwrap();
    std::fs::write(repo.path().join(".jtm.toml"), "[tools]\n").unwrap();
    std::fs::write(api.join(".java-version"), "corretto-17\n").unwrap();
    assert_eq!(project_root(&api, &plugins).unwrap(), api);
    let pins = project_pins(&api, &plugins).unwrap();
    assert_eq!(pins.pins["java"].selector.value, "17");

    // Pins above the repository root stay out of the lock.
    let outside = tempfile::tempdir().unwrap();
    let home_pin = outside.path().join(".java-version");
    std::fs::write(&home_pin, "temurin-21\n").unwrap();
    let project = outside.path().join("project");
    std::fs::create_dir_all(project.join(".git")).unwrap();
    std::fs::write(project.join(".jtm.toml"), "[tools]\n").unwrap();
    assert_eq!(project_root(&project, &plugins).unwrap(), project);
    assert!(project_pins(&project, &plugins).unwrap().pins.is_empty());
}
