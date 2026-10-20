use super::*;

#[test]
fn valid_names() {
    for name in [
        "java",
        "spring-boot-cli",
        "graalvm-community",
        "a1",
        "acme/flyway",
    ] {
        assert_eq!(check_plugin_name(name), Ok(()), "{name}");
    }
}

#[test]
fn invalid_names_point_at_the_problem() {
    let cases = [
        ("", 0),
        ("Java", 0),
        ("jAva", 1),
        ("1java", 0),
        ("-java", 0),
        ("java-", 4),
        ("ja--va", 2),
        ("ja_va", 2),
        ("ja va", 2),
        ("/flyway", 0),
        ("acme/", 5),
        ("acme//flyway", 5),
        ("acme/fly/way", 8),
        ("jäva", 1),
    ];
    for (name, at) in cases {
        let err = check_plugin_name(name).unwrap_err();
        assert_eq!(err.0, at, "{name}: {}", err.1);
    }
    let long = "a".repeat(MAX_NAME_LEN + 1);
    assert!(check_plugin_name(&long).is_err());
}

#[test]
fn versions_and_aliases() {
    for ok in ["21", "lts", "21.0.5+11", "8.11-rc-1", "3", "temurin_x"] {
        assert_eq!(check_version_or_alias(ok), Ok(()), "{ok}");
    }
    for (bad, at) in [
        ("", 0),
        (".21", 0),
        ("-rc", 0),
        ("21 ", 2),
        ("21/0", 2),
        ("2:1", 1),
    ] {
        assert_eq!(check_version_or_alias(bad).unwrap_err().0, at, "{bad}");
    }
}
