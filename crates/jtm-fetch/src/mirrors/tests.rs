use super::*;

#[test]
fn the_longest_prefix_wins() {
    let mirrors = BTreeMap::from([
        (
            "https://github.com/".to_owned(),
            "https://a.test/gh/".to_owned(),
        ),
        (
            "https://github.com/adoptium/".to_owned(),
            "https://a.test/adoptium/".to_owned(),
        ),
    ]);
    assert_eq!(
        rewrite("https://github.com/adoptium/x.zip", &mirrors),
        "https://a.test/adoptium/x.zip"
    );
    assert_eq!(
        rewrite("https://github.com/other/x.zip", &mirrors),
        "https://a.test/gh/other/x.zip"
    );
    assert_eq!(
        rewrite("https://example.test/x.zip", &mirrors),
        "https://example.test/x.zip"
    );
}
