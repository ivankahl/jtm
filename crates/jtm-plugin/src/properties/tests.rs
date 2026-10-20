use super::*;

#[test]
fn reads_separators_comments_and_escapes() {
    let text = "# comment\n! also\nurl=https\\://example.com/a\nkey: value\nspaced  v\\tx\nuni=jos\\u00e9\n";
    let found: Vec<(String, String)> = entries(text)
        .into_iter()
        .map(|e| (e.key, e.value))
        .collect();
    assert_eq!(
        found,
        [
            ("url".to_owned(), "https://example.com/a".to_owned()),
            ("key".to_owned(), "value".to_owned()),
            ("spaced".to_owned(), "v\tx".to_owned()),
            ("uni".to_owned(), "josé".to_owned()),
        ]
    );
}

#[test]
fn joins_continuation_lines_and_reports_their_span() {
    let text = "a=1\nlong=one,\\\n    two,\\\r\n  three\nb=2\n";
    let found = entries(text);
    assert_eq!(found.len(), 3);
    assert_eq!(found[1].key, "long");
    assert_eq!(found[1].value, "one,two,three");
    assert_eq!((found[1].first, found[1].end), (1, 4));
    assert_eq!(get(text, "b").as_deref(), Some("2"));
    // A comment ending in a backslash does not swallow the next line.
    assert_eq!(get("# c \\\nx=1\n", "x").as_deref(), Some("1"));
}

#[test]
fn the_last_repeated_key_wins() {
    assert_eq!(get("k=1\nk=2\n", "k").as_deref(), Some("2"));
    assert_eq!(get("k=1\n", "missing"), None);
}

#[test]
fn escaped_values_read_back_unchanged() {
    for value in [
        "C:\\Users\\Zoë\\jdk",
        "/home/josé/a,b",
        "a=b:c",
        "#x",
        " lead",
        "😀",
    ] {
        let line = format!("k={}\n", escape_value(value));
        assert!(line.is_ascii(), "{line}");
        assert_eq!(get(&line, "k").as_deref(), Some(value), "{line}");
    }
    assert_eq!(escape_value("é"), "\\u00e9");
}
