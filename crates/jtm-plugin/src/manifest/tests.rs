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
