use super::*;

#[test]
fn parses_and_formats_round_trip() {
    for (text, unix) in [
        ("1970-01-01T00:00:00Z", 0),
        ("2000-02-29T12:34:56Z", 951_827_696),
        ("2026-10-19T03:00:00Z", 1_792_378_800),
        ("2026-11-18T03:00:00Z", 1_794_970_800),
        ("1969-12-31T23:59:59Z", -1),
    ] {
        let ts = Timestamp::parse(text).unwrap();
        assert_eq!(ts.unix(), unix, "{text}");
        assert_eq!(ts.to_string(), text);
    }
}

#[test]
fn rejects_other_spellings() {
    for bad in [
        "",
        "2026-10-19",
        "2026-10-19T03:00:00",
        "2026-10-19T03:00:00+00:00",
        "2026-10-19T03:00:00.5Z",
        "2026-10-19t03:00:00z",
        "2026-13-01T00:00:00Z",
        "2026-02-29T00:00:00Z",
        "2026-04-31T00:00:00Z",
        "2026-10-19T24:00:00Z",
        "2026-10-19T03:60:00Z",
        "2026-10-19T03:00:60Z",
        "+026-10-19T03:00:00Z",
    ] {
        assert_eq!(Timestamp::parse(bad), None, "{bad}");
    }
}

#[test]
fn now_is_after_this_code_was_written() {
    assert!(Timestamp::now() > Timestamp::parse("2026-01-01T00:00:00Z").unwrap());
}
