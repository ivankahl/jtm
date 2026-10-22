use super::*;

#[test]
fn placeholders_are_checked_against_the_names_a_setting_allows() {
    assert_eq!(template::check("a-{version}.zip", &["version"]), Ok(()));
    assert_eq!(template::check("no placeholders", &[]), Ok(()));
    assert_eq!(template::check("{a}{b}", &["a", "b"]), Ok(()));

    let message = template::check("a-{versoin}.zip", &["version"]).unwrap_err();
    assert!(message.contains("versoin"), "{message}");
    assert!(message.contains("{version}"), "{message}");

    let message = template::check("a-{x}", &[]).unwrap_err();
    assert!(message.contains("none"), "{message}");

    assert!(template::check("a-{version", &["version"]).is_err());
    assert!(template::check("a-version}", &["version"]).is_err());
    assert!(template::check("a-{{version}}", &["version"]).is_err());
}

#[test]
fn placeholders_are_replaced_and_unknown_ones_left_alone() {
    let value = |name: &str| match name {
        "version" => Some("1.2".to_owned()),
        "n" => Some("7".to_owned()),
        _ => None,
    };
    assert_eq!(
        template::render("x-{version}-{n}-{version}.zip", value),
        "x-1.2-7-1.2.zip"
    );
    assert_eq!(template::render("x-{other}", value), "x-{other}");
    assert_eq!(template::render("plain", value), "plain");
    assert_eq!(template::render("open-{version", value), "open-{version");
}

#[test]
fn platform_lists_default_to_every_platform_and_are_ordered() {
    let all = Platforms::default();
    assert_eq!(all.validate(), Ok(()));
    assert_eq!(all.list(), Platform::ALL.to_vec());

    let some = Platforms(vec![
        "linux-x64".to_owned(),
        "windows-x64".to_owned(),
        "linux-x64".to_owned(),
    ]);
    assert_eq!(some.list(), [Platform::WindowsX64, Platform::LinuxX64]);
}

#[test]
fn platform_lists_reject_unknown_names_and_any() {
    for bad in ["linux-sparc", "any", "", "Linux-x64", "linux-musl-aarch64"] {
        let message = Platforms(vec![bad.to_owned()]).validate().unwrap_err();
        assert!(message.contains("linux-musl-x64"), "{bad}: {message}");
    }
}

#[test]
fn url_tokens_are_plain_words() {
    for good in ["zulu", "all_of_version", "21.0.5", "a-b"] {
        assert!(is_url_token(good), "{good}");
    }
    for bad in ["", "a b", "a&b=c", "a/b", "../x", "a%2Fb", "é"] {
        assert!(!is_url_token(bad), "{bad}");
    }
}

#[test]
fn urls_are_joined_with_one_slash() {
    assert_eq!(with_trailing_slash("https://a.test/x"), "https://a.test/x/");
    assert_eq!(
        with_trailing_slash("https://a.test/x//"),
        "https://a.test/x/"
    );
    assert_eq!(
        without_trailing_slash("https://a.test/x/"),
        "https://a.test/x"
    );
}

#[test]
fn candidates_start_with_what_the_origin_knows() {
    let origin = Origin {
        id: "vendor",
        variant: Some("zulu"),
    };
    let candidate = origin.candidate(
        "1.0".to_owned(),
        Target::Any,
        "https://a.test/a.zip".to_owned(),
        ArchiveKind::Zip,
    );
    assert_eq!(candidate.source, "vendor");
    assert_eq!(candidate.variant.as_deref(), Some("zulu"));
    assert_eq!(candidate.hash, None);
    assert_eq!(origin.to_string(), "vendor");
}
