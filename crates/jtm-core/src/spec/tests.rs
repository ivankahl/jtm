use super::*;

fn spec(tool: &str, variant: Option<&str>, value: Option<&str>) -> ToolSpec {
    ToolSpec {
        tool: tool.to_owned(),
        selector: value.map(|value| Selector {
            variant: variant.map(str::to_owned),
            value: value.to_owned(),
        }),
    }
}

#[test]
fn valid_specs() {
    let cases = [
        ("java", spec("java", None, None)),
        ("java@21", spec("java", None, Some("21"))),
        ("java@temurin:21", spec("java", Some("temurin"), Some("21"))),
        ("java@lts", spec("java", None, Some("lts"))),
        (
            "java@temurin:lts",
            spec("java", Some("temurin"), Some("lts")),
        ),
        (
            "java@temurin:21.0.5+11",
            spec("java", Some("temurin"), Some("21.0.5+11")),
        ),
        (
            "java@graalvm-community:21",
            spec("java", Some("graalvm-community"), Some("21")),
        ),
        ("maven@3.9.9", spec("maven", None, Some("3.9.9"))),
        ("gradle@8.11-rc-1", spec("gradle", None, Some("8.11-rc-1"))),
        (
            "spring-boot-cli@3",
            spec("spring-boot-cli", None, Some("3")),
        ),
        ("acme/flyway@10.1", spec("acme/flyway", None, Some("10.1"))),
    ];
    for (input, expected) in cases {
        let parsed = ToolSpec::parse(input).unwrap();
        assert_eq!(parsed, expected, "{input}");
        assert_eq!(parsed.to_string(), input, "round trip");
        assert_eq!(input.parse::<ToolSpec>().unwrap(), expected);
    }
}

/// Each case is the input, the 1-based column of the problem, and a message fragment.
#[test]
fn invalid_specs_report_usage_with_column() {
    let cases = [
        ("", 1, "expected a tool name"),
        ("@21", 1, "expected a tool name"),
        ("Java@21", 1, "lowercase letter"),
        ("jaVa", 3, "must be lowercase"),
        ("1java", 1, "start with a lowercase letter"),
        ("java_8", 5, "lowercase letters, digits and `-`"),
        ("java-@21", 5, "cannot end with `-`"),
        (" java", 1, "lowercase letter"),
        ("java ", 5, "lowercase letters, digits and `-`"),
        ("java@", 6, "expected a version or alias after `@`"),
        ("java@@21", 6, "start with a letter or digit"),
        ("java@:21", 6, "expected a variant before `:`"),
        ("java@temurin:", 14, "expected a version or alias after `:`"),
        ("java@Temurin:21", 6, "lowercase letter"),
        ("java@temurin:21:1", 16, "`:` is not allowed"),
        ("java@temurin::21", 14, "start with a letter or digit"),
        ("java@21@22", 8, "`@` is not allowed"),
        ("java@21 ", 8, "` ` is not allowed"),
        ("java@.21", 6, "start with a letter or digit"),
        ("java@21/../x", 8, "`/` is not allowed"),
        ("acme//flyway", 6, "start with a lowercase letter"),
        ("acme/", 6, "cannot be empty"),
        ("jäva@21", 2, "lowercase letters, digits and `-`"),
        ("jäva@2ü", 2, "lowercase letters, digits and `-`"),
        ("java@2ü", 7, "is not allowed"),
    ];
    for (input, column, fragment) in cases {
        let err = ToolSpec::parse(input).unwrap_err();
        assert_eq!(err.code(), "E_USAGE", "{input}");
        let JtmError::InvalidSpec {
            column: got,
            ref message,
            ..
        } = err
        else {
            panic!("{input}: expected InvalidSpec, got {err:?}");
        };
        assert_eq!(got, column, "{input}: {message}");
        assert!(
            message.contains(fragment),
            "{input}: `{message}` should contain `{fragment}`"
        );
        assert_eq!(err.details()["column"], column, "{input}");
        assert_eq!(err.details()["input"], input, "{input}");
    }
}

#[test]
fn overlong_values_are_rejected() {
    let long = format!("java@{}", "1".repeat(200));
    assert_eq!(ToolSpec::parse(&long).unwrap_err().code(), "E_USAGE");
    let long = format!("{}@1", "a".repeat(100));
    assert_eq!(ToolSpec::parse(&long).unwrap_err().code(), "E_USAGE");
}

#[test]
fn error_message_names_input_and_column() {
    let err = ToolSpec::parse("java@").unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid spec `java@` at column 6: expected a version or alias after `@`, \
             such as `21` or `lts`"
    );
}

#[test]
fn selectors_parse_on_their_own() {
    let selector = Selector::parse("temurin:21").unwrap();
    assert_eq!(selector.variant.as_deref(), Some("temurin"));
    assert_eq!(selector.value, "21");
    assert_eq!(selector.to_string(), "temurin:21");
    assert_eq!(Selector::parse("lts").unwrap().variant, None);

    let err = Selector::parse("").unwrap_err();
    assert_eq!(err.code(), "E_USAGE");
    let err = Selector::parse("temurin:").unwrap_err();
    assert_eq!(err.details()["column"], 9);
}
