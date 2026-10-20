use super::*;

#[test]
fn normal_names_split_into_components() {
    assert_eq!(
        entry_components(b"jdk/bin/java").unwrap(),
        ["jdk", "bin", "java"]
    );
    assert_eq!(entry_components(b"./bin//java").unwrap(), ["bin", "java"]);
    assert_eq!(entry_components(b"dir/").unwrap(), ["dir"]);
    assert!(entry_components(b"./").unwrap().is_empty());
    assert_eq!(entry_components(b"a/.../b").unwrap(), ["a", "...", "b"]);
}

#[test]
fn unsafe_names_are_refused() {
    for name in [
        &b"/etc/passwd"[..],
        b"../x",
        b"a/../../x",
        b"a/..",
        b"C:/Windows/x",
        b"C:x",
        b"\\\\server\\share\\x",
        b"a\\..\\..\\x",
        b"a\0b",
        b"a\nb",
        b"file.txt:stream",
        b"\xff\xfe",
    ] {
        assert!(
            entry_components(name).is_err(),
            "{:?} should be refused",
            String::from_utf8_lossy(name)
        );
    }
}

#[test]
fn link_targets_may_climb_but_not_start_at_the_root() {
    assert_eq!(
        link_steps(b"../lib/./libjli.dylib").unwrap(),
        [
            Step::Up,
            Step::Name("lib".into()),
            Step::Name("libjli.dylib".into())
        ]
    );
    assert!(link_steps(b"/etc/passwd").is_err());
    assert!(link_steps(b"").is_err());
    assert!(link_steps(b"C:/x").is_err());
    assert!(link_steps(b"..\\x").is_err());
}
