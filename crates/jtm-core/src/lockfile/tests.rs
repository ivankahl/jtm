use super::*;

fn artifact(platform: &str) -> LockedArtifact {
    LockedArtifact {
        platform: platform.to_owned(),
        url: format!("https://dl.example.test/demo-{platform}.tar.gz"),
        size: 1234,
        sha256: "ab".repeat(32),
    }
}

/// A lockfile built in a shuffled order.
fn sample() -> Lockfile {
    Lockfile {
        generated_by: "jtm 0.1.0".to_owned(),
        plugins: vec![
            LockedPlugin {
                name: "zeta".to_owned(),
                source: "builtin".to_owned(),
                rev: None,
                manifest_sha256: "cd".repeat(32),
                signing_keys: vec!["RWQb".to_owned(), "RWQa".to_owned()],
            },
            LockedPlugin {
                name: "acme/flyway".to_owned(),
                source: "https://github.com/acme/jtm-flyway".to_owned(),
                rev: Some("3f9c2e1a7b".to_owned()),
                manifest_sha256: "ef".repeat(32),
                signing_keys: vec!["RWQc".to_owned()],
            },
        ],
        tools: vec![
            LockedTool {
                name: "zeta".to_owned(),
                requested: "1".to_owned(),
                pin_source: ".jtm.toml".to_owned(),
                variant: "default".to_owned(),
                version: "1.2.3".to_owned(),
                artifacts: vec![artifact("windows-x64"), artifact("linux-x64")],
            },
            LockedTool {
                name: "acme/flyway".to_owned(),
                requested: "temurin:21".to_owned(),
                pin_source: "sub/.sdkmanrc".to_owned(),
                variant: "temurin".to_owned(),
                version: "21.0.5+11".to_owned(),
                artifacts: vec![artifact("macos-aarch64")],
            },
        ],
    }
}

#[test]
fn renders_deterministically_sorted_by_tool_then_platform() {
    let text = sample().render();
    insta::assert_snapshot!(text);
    let mut reversed = sample();
    reversed.plugins.reverse();
    reversed.tools.reverse();
    for tool in &mut reversed.tools {
        tool.artifacts.reverse();
    }
    assert_eq!(reversed.render(), text);
}

#[test]
fn parses_what_it_renders() {
    let text = sample().render();
    let parsed = Lockfile::parse(Path::new("/p/jtm.lock"), &text).unwrap();
    assert_eq!(parsed.render(), text);
    assert_eq!(parsed.tool("acme/flyway").unwrap().version, "21.0.5+11");
    assert_eq!(
        parsed
            .tool("zeta")
            .unwrap()
            .artifact("linux-x64")
            .unwrap()
            .size,
        1234
    );
}

#[test]
fn rejects_lockfiles_it_does_not_understand() {
    let good = sample().render();
    let cases = [
        good.replace("lock_version = 1", "lock_version = 2"),
        good.replace("lock_version = 1\n", ""),
        good.replace("size = 1234", "size = \"big\""),
        format!("{good}\nsurprise = true\n"),
        good.replacen(&"ab".repeat(32), "not-a-hash", 1),
        good.replacen("windows-x64", "amiga-68k", 1),
    ];
    for text in cases {
        let err = Lockfile::parse(Path::new("/p/jtm.lock"), &text).unwrap_err();
        assert_eq!(err.code(), "E_LOCK_OUTDATED", "{text}\n{err}");
        assert!(err.to_string().contains("jtm.lock"), "{err}");
    }
}
