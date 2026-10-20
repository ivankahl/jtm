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
