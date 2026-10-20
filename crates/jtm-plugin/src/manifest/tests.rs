use super::*;

#[test]
fn requirements() {
    assert_eq!(
        parse_requirement(">=8").unwrap(),
        vec![(Comparator::Ge, "8".to_owned())]
    );
    assert_eq!(
        parse_requirement(">= 17, <22").unwrap(),
        vec![
            (Comparator::Ge, "17".to_owned()),
            (Comparator::Lt, "22".to_owned())
        ]
    );
    assert_eq!(
        parse_requirement("21").unwrap(),
        vec![(Comparator::Ge, "21".to_owned())]
    );
    for bad in ["", ">=", "=>8", ">=8,", "~8", ">=8 || 11"] {
        assert!(parse_requirement(bad).is_err(), "{bad}");
    }
}

#[test]
fn placeholders() {
    let mut p = Problems::default();
    check_placeholders(&mut p, "x", "a-{os}-{arch}.json", INDEX_URL_PLACEHOLDERS);
    assert!(p.0.is_empty());
    for bad in ["{os", "os}", "{platform}", "{}", "{{os}}"] {
        let mut p = Problems::default();
        check_placeholders(&mut p, "x", bad, INDEX_URL_PLACEHOLDERS);
        assert_eq!(p.0.len(), 1, "{bad}");
    }
}

#[test]
fn executables_fall_back_to_unix() {
    let exe = Executables {
        windows: vec!["mvn.cmd".into()],
        unix: vec!["mvn".into()],
        macos: vec!["mvn-mac".into()],
        linux: vec![],
    };
    assert_eq!(exe.for_os("windows"), ["mvn.cmd"]);
    assert_eq!(exe.for_os("macos"), ["mvn-mac"]);
    assert_eq!(exe.for_os("linux"), ["mvn"]);
    assert!(exe.for_os("plan9").is_empty());
}

#[test]
fn an_index_url_without_os_or_arch_is_platform_independent() {
    let mut index = Index {
        url: "https://example.test/tool-any.json".to_owned(),
        signing_keys: Vec::new(),
        threshold: None,
        keys_url: None,
        format: 1,
    };
    assert!(index.platform_independent());
    assert_eq!(index.index_platform("windows-x64"), ANY_PLATFORM);
    for url in [
        "https://example.test/tool-{os}-{arch}.json",
        "https://example.test/tool-{os}.json",
        "https://example.test/tool-{arch}.json",
    ] {
        index.url = url.to_owned();
        assert!(!index.platform_independent(), "{url}");
        assert_eq!(index.index_platform("windows-x64"), "windows-x64");
    }
}
