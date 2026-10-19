use std::cmp::Ordering;

use proptest::prelude::*;

use super::*;

fn v(scheme: VersionScheme, s: &str) -> Version {
    scheme
        .parse(s)
        .unwrap_or_else(|e| panic!("{s} should parse: {e}"))
}

/// Asserts each version sorts strictly before the next under the scheme's rules.
fn assert_increasing(scheme: VersionScheme, versions: &[&str]) {
    for pair in versions.windows(2) {
        let (a, b) = (v(scheme, pair[0]), v(scheme, pair[1]));
        assert_eq!(
            a.cmp_precedence(&b),
            Ordering::Less,
            "{scheme}: expected {a} < {b}"
        );
        assert_eq!(
            b.cmp_precedence(&a),
            Ordering::Greater,
            "{scheme}: {b} > {a}"
        );
    }
}

fn assert_equivalent(scheme: VersionScheme, pairs: &[(&str, &str)]) {
    for (a, b) in pairs {
        assert_eq!(
            v(scheme, a).cmp_precedence(&v(scheme, b)),
            Ordering::Equal,
            "{scheme}: expected {a} == {b}"
        );
    }
}

fn assert_invalid(scheme: VersionScheme, inputs: &[&str]) {
    for input in inputs {
        let err = scheme
            .parse(input)
            .expect_err(&format!("{scheme}: `{input}` should be rejected"));
        assert_eq!(err.input, *input);
        assert_eq!(err.scheme, scheme);
    }
}

#[test]
fn java_ordering() {
    assert_increasing(
        VersionScheme::Java,
        &[
            "8.0.392+8",
            "11",
            "17-ea",
            "17",
            "17.0.1",
            "17.0.1+12",
            "17.0.2+8",
            "21-ea+3",
            "21-ea+35",
            "21",
            "21+35",
            "21.0.5+10",
            "21.0.5+11",
            "21.0.5+11-LTS",
            "21.0.10+7",
            "21.1",
            "22",
            "100",
        ],
    );
    assert_equivalent(
        VersionScheme::Java,
        &[("21", "21.0"), ("21", "21.0.0"), ("21.0.5", "21.0.5.0")],
    );
}

#[test]
fn java_rejects_malformed_versions() {
    assert_invalid(
        VersionScheme::Java,
        &[
            "",
            "21.",
            ".21",
            "21..0",
            "021",
            "21.0.5+",
            "21.0.5+abc",
            "21-",
            "21-e.a",
            "21-ea-x+3",
            "v21",
            "21 ",
            "1.8.0_392",
            "21/0",
        ],
    );
}

#[test]
fn java_prereleases() {
    assert!(v(VersionScheme::Java, "24-ea").is_prerelease());
    assert!(v(VersionScheme::Java, "24-ea+3").is_prerelease());
    assert!(!v(VersionScheme::Java, "21.0.5+11").is_prerelease());
    assert!(!v(VersionScheme::Java, "21.0.5+11-LTS").is_prerelease());
}

/// `VERSIONS_QUALIFIER` and `VERSIONS_NUMBER` from Maven's `ComparableVersionTest`.
#[test]
fn maven_ordering_matches_comparable_version() {
    assert_increasing(
        VersionScheme::Maven,
        &[
            "1-alpha2snapshot",
            "1-alpha2",
            "1-alpha-123",
            "1-beta-2",
            "1-beta123",
            "1-m2",
            "1-m11",
            "1-rc",
            "1-cr2",
            "1-rc123",
            "1-SNAPSHOT",
            "1",
            "1-sp",
            "1-sp2",
            "1-sp123",
            "1-abc",
            "1-def",
            "1-pom-1",
            "1-1-snapshot",
            "1-1",
            "1-2",
            "1-123",
        ],
    );
    assert_increasing(
        VersionScheme::Maven,
        &[
            "2.0", "2-1", "2.0.a", "2.0.0.a", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b",
            "2.1-c", "2.1-1", "2.1.0.1", "2.2", "2.123", "11.a2", "11.a11", "11.b2", "11.b11",
            "11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m",
        ],
    );
}

#[test]
fn maven_real_releases() {
    assert_increasing(
        VersionScheme::Maven,
        &[
            "3.8.8",
            "3.9.9",
            "3.9.10",
            "4.0.0-alpha-1",
            "4.0.0-alpha-13",
            "4.0.0-beta-5",
            "4.0.0-rc-2",
            "4.0.0",
        ],
    );
}

/// `testVersionsEqual` from Maven's `ComparableVersionTest`.
#[test]
fn maven_equivalences() {
    assert_equivalent(
        VersionScheme::Maven,
        &[
            ("1", "1"),
            ("1", "1.0"),
            ("1", "1.0.0"),
            ("1.0", "1.0.0"),
            ("1", "1-0"),
            ("1", "1.0-0"),
            ("1.0", "1.0-0"),
            ("1a", "1-a"),
            ("1a", "1.0-a"),
            ("1a", "1.0.0-a"),
            ("1.0a", "1-a"),
            ("1.0.0a", "1-a"),
            ("1x", "1-x"),
            ("1x", "1.0-x"),
            ("1x", "1.0.0-x"),
            ("1.0x", "1-x"),
            ("1.0.0x", "1-x"),
            ("1ga", "1"),
            ("1release", "1"),
            ("1final", "1"),
            ("1cr", "1rc"),
            ("1a1", "1-alpha-1"),
            ("1b2", "1-beta-2"),
            ("1m3", "1-milestone-3"),
            ("1X", "1x"),
            ("1A", "1a"),
            ("1GA", "1"),
            ("1RELeaSE", "1"),
            ("1FinaL", "1"),
            ("1cR", "1rC"),
            ("1m3", "1MILESTONE3"),
        ],
    );
}

#[test]
fn maven_prereleases() {
    for pre in [
        "4.0.0-rc-2",
        "4.0.0-alpha-13",
        "1.0-SNAPSHOT",
        "2.0b1",
        "1-m3",
    ] {
        assert!(v(VersionScheme::Maven, pre).is_prerelease(), "{pre}");
    }
    for release in ["3.9.9", "1-sp1", "1.0-ga", "1-abc"] {
        assert!(
            !v(VersionScheme::Maven, release).is_prerelease(),
            "{release}"
        );
    }
}

#[test]
fn maven_rejects_only_unsafe_text() {
    assert_invalid(VersionScheme::Maven, &["", "3.9 .9", "3.9/9", "../3"]);
    v(VersionScheme::Maven, "anything-goes_1+2");
}

#[test]
fn semver_loose_ordering() {
    assert_increasing(
        VersionScheme::SemverLoose,
        &[
            "8.9",
            "8.10",
            "8.10.1",
            "8.10.2",
            "8.11-milestone-1",
            "8.11-rc-1",
            "8.11-rc-2",
            "8.11-rc-10",
            "8.11",
            "8.11.1",
            "10.0",
        ],
    );
    assert_increasing(
        VersionScheme::SemverLoose,
        &[
            "2.1.0-Beta1",
            "2.1.0-Beta2",
            "2.1.0-Beta10",
            "2.1.0-RC",
            "2.1.0-RC2",
            "2.1.0",
            "2.1.20",
        ],
    );
    assert_increasing(
        VersionScheme::SemverLoose,
        &["1.0.0-1", "1.0.0-1.a", "1.0.0-a", "1.0.0"],
    );
    assert_equivalent(
        VersionScheme::SemverLoose,
        &[
            ("8.10", "8.10.0"),
            ("8.11-RC-1", "8.11-rc-1"),
            ("8.11-rc1", "8.11-rc-1"),
        ],
    );
}

#[test]
fn semver_loose_rejects_malformed_versions() {
    assert_invalid(
        VersionScheme::SemverLoose,
        &[
            "",
            "8.x",
            "8..1",
            ".8",
            "-rc",
            "8.11-",
            "8.11-rc..1",
            "8.11-rc--1",
            "8.11+",
            "8+a+b",
            "v8",
            "8 .1",
        ],
    );
}

#[test]
fn semver_loose_prereleases() {
    assert!(v(VersionScheme::SemverLoose, "8.11-rc-1").is_prerelease());
    assert!(!v(VersionScheme::SemverLoose, "8.10.2").is_prerelease());
    assert!(!v(VersionScheme::SemverLoose, "8.10.2+build.5").is_prerelease());
}

#[test]
fn parse_limits_length_and_reports_scheme() {
    let long = "1.".repeat(MAX_VERSION_LEN) + "1";
    let err = VersionScheme::Maven.parse(&long).unwrap_err();
    assert!(err.reason.contains("at most"));
    assert_eq!(
        VersionScheme::Java.parse("x").unwrap_err().to_string(),
        "`x` is not a valid java version: the version number must be dot-separated digits, \
         such as `21.0.5`"
    );
}

#[test]
fn prefix_matching_uses_whole_segments() {
    let cases: &[(VersionScheme, &str, &str, bool)] = &[
        (VersionScheme::Java, "21.0.5+11", "21", true),
        (VersionScheme::Java, "21.0.5+11", "21.0", true),
        (VersionScheme::Java, "21.0.5+11", "21.0.5", true),
        (VersionScheme::Java, "21.0.5+11", "21.0.5+11", true),
        (VersionScheme::Java, "21.0.5+11", "21.0.5+1", false),
        (VersionScheme::Java, "21.0.5+11", "21.0.5-11", false),
        (VersionScheme::Java, "21.0.5+11", "2", false),
        (VersionScheme::Java, "21.0.5+11", "21.0.5+11.1", false),
        (VersionScheme::Java, "210.1", "21", false),
        (VersionScheme::Java, "21.0.5", "", false),
        (VersionScheme::Maven, "3.9.9", "3", true),
        (VersionScheme::Maven, "3.9.9", "3.9", true),
        (VersionScheme::Maven, "3.9.9", "3.9.9", true),
        (VersionScheme::Maven, "30.1", "3", false),
        (VersionScheme::Maven, "3.9.10", "3.9.1", false),
        (VersionScheme::Maven, "4.0.0-rc-2", "4.0.0-rc", true),
        (VersionScheme::SemverLoose, "8.11-rc-1", "8.11", true),
        (VersionScheme::SemverLoose, "8.11-rc-1", "8.11-rc", true),
        (VersionScheme::SemverLoose, "8.11-rc-1", "8.11-RC", true),
        (VersionScheme::SemverLoose, "8.11-rc-1", "8.1", false),
        (VersionScheme::SemverLoose, "8.10", "8.10.0", false),
    ];
    for (scheme, version, prefix, expected) in cases {
        assert_eq!(
            v(*scheme, version).matches_prefix(prefix),
            *expected,
            "{scheme}: does `{prefix}` prefix `{version}`?"
        );
    }
}

fn numbers() -> impl Strategy<Value = String> {
    prop::collection::vec(prop_oneof![Just(0u32), 1u32..30, 100u32..1000], 1..5)
        .prop_map(|ns| ns.iter().map(u32::to_string).collect::<Vec<_>>().join("."))
}

fn word() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "ea",
        "rc",
        "RC",
        "alpha",
        "beta",
        "a",
        "b",
        "m",
        "milestone",
        "cr",
        "sp",
        "snapshot",
        "ga",
        "final",
        "x",
        "lts",
    ])
    .prop_map(str::to_owned)
}

fn token() -> impl Strategy<Value = String> {
    prop_oneof![
        word(),
        (0u32..40).prop_map(|n| n.to_string()),
        (word(), 0u32..20).prop_map(|(w, n)| format!("{w}{n}"))
    ]
}

/// Free-form version text: numbers followed by tokens joined by any separator.
fn version_text() -> impl Strategy<Value = String> {
    (
        numbers(),
        prop::collection::vec(
            (prop::sample::select(vec!["", ".", "-", "+", "_"]), token()),
            0..4,
        ),
    )
        .prop_map(|(head, tail)| {
            let mut s = head;
            for (sep, tok) in tail {
                s.push_str(sep);
                s.push_str(&tok);
            }
            s
        })
}

/// Text shaped like each scheme's grammar, so most samples parse.
fn shaped_text(scheme: VersionScheme) -> BoxedStrategy<String> {
    match scheme {
        VersionScheme::Java => (
            numbers(),
            prop::option::of(prop_oneof![Just("ea".to_owned()), token()]),
            prop::option::of(0u32..40),
        )
            .prop_map(|(n, pre, build)| {
                let mut s = n;
                if let Some(pre) = pre {
                    s = format!("{s}-{pre}");
                }
                if let Some(build) = build {
                    s = format!("{s}+{build}");
                }
                s
            })
            .boxed(),
        VersionScheme::SemverLoose => (
            numbers(),
            prop::option::of(prop::collection::vec(token(), 1..3)),
        )
            .prop_map(|(n, pre)| match pre {
                Some(ids) => format!("{n}-{}", ids.join("-")),
                None => n,
            })
            .boxed(),
        VersionScheme::Maven => version_text().boxed(),
    }
}

fn scheme_and_triple() -> impl Strategy<Value = (VersionScheme, String, String, String)> {
    prop::sample::select(VersionScheme::ALL.to_vec()).prop_flat_map(|scheme| {
        (
            Just(scheme),
            shaped_text(scheme),
            shaped_text(scheme),
            shaped_text(scheme),
        )
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn ordering_is_total((scheme, a, b, c) in scheme_and_triple()) {
        let (Ok(a), Ok(b), Ok(c)) = (scheme.parse(&a), scheme.parse(&b), scheme.parse(&c)) else {
            return Ok(());
        };
        for (x, y) in [(&a, &b), (&b, &c), (&a, &c)] {
            // Antisymmetric, for both the scheme order and the total order.
            prop_assert_eq!(x.cmp(y), y.cmp(x).reverse());
            prop_assert_eq!(x.cmp_precedence(y), y.cmp_precedence(x).reverse());
            // Equal only when the text is equal.
            prop_assert_eq!(x == y, x.as_str() == y.as_str());
        }
        prop_assert_eq!(a.cmp(&a), Ordering::Equal);
        // Transitive, for both orders.
        let mut sorted = [&a, &b, &c];
        sorted.sort();
        prop_assert!(sorted[0] <= sorted[2]);
        prop_assert!(sorted[0].cmp_precedence(sorted[1]).is_le());
        prop_assert!(sorted[1].cmp_precedence(sorted[2]).is_le());
        prop_assert!(sorted[0].cmp_precedence(sorted[2]).is_le());
    }

    #[test]
    fn transitivity_holds_for_free_form_maven_text(a in version_text(), b in version_text(), c in version_text()) {
        let parse = |s: &str| VersionScheme::Maven.parse(s).unwrap();
        let (a, b, c) = (parse(&a), parse(&b), parse(&c));
        if a.cmp_precedence(&b).is_le() && b.cmp_precedence(&c).is_le() {
            prop_assert!(a.cmp_precedence(&c).is_le(), "{} <= {} <= {}", a, b, c);
        }
        if a.cmp_precedence(&b).is_eq() {
            prop_assert_eq!(a.cmp_precedence(&c), b.cmp_precedence(&c));
        }
    }

    #[test]
    fn a_version_is_its_own_prefix(text in version_text()) {
        for scheme in VersionScheme::ALL {
            if let Ok(version) = scheme.parse(&text) {
                prop_assert!(version.matches_prefix(&text));
            }
        }
    }

    #[test]
    fn parsing_never_panics(text in "\\PC{0,40}") {
        for scheme in VersionScheme::ALL {
            let _ = scheme.parse(&text);
        }
    }
}
