use std::collections::HashMap;

use super::*;

/// A fake process environment.
fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |name| map.get(name).cloned()
}

fn resolve(explicit: Option<&str>, pairs: &[(&str, &str)]) -> Result<ProxyConfig> {
    ProxyConfig::resolve(explicit, &env(pairs), &|| None)
}

fn route(url: &str, source: ProxySource) -> Option<ProxyRoute> {
    Some(ProxyRoute {
        url: url.to_owned(),
        source,
    })
}

fn var(name: &str) -> ProxySource {
    ProxySource::Environment(name.to_owned())
}

#[test]
fn no_variables_and_no_config_mean_no_proxy() {
    let report = resolve(None, &[]).unwrap().report();
    assert_eq!(report, ProxyReport::default());
}

#[test]
fn https_proxy_serves_https_and_http_proxy_serves_http() {
    let report = resolve(
        None,
        &[
            ("HTTPS_PROXY", "http://secure.corp:8443"),
            ("HTTP_PROXY", "http://plain.corp:3128"),
        ],
    )
    .unwrap()
    .report();
    assert_eq!(
        report.https,
        route("http://secure.corp:8443/", var("HTTPS_PROXY"))
    );
    assert_eq!(
        report.http,
        route("http://plain.corp:3128/", var("HTTP_PROXY"))
    );
}

#[test]
fn lowercase_variables_work_and_uppercase_wins_when_both_are_set() {
    let report = resolve(None, &[("https_proxy", "http://lower.corp:1")])
        .unwrap()
        .report();
    assert_eq!(
        report.https,
        route("http://lower.corp:1/", var("https_proxy"))
    );
    assert_eq!(report.http, None);

    let both = resolve(
        None,
        &[
            ("https_proxy", "http://lower.corp:1"),
            ("HTTPS_PROXY", "http://upper.corp:2"),
        ],
    )
    .unwrap()
    .report();
    assert_eq!(
        both.https,
        route("http://upper.corp:2/", var("HTTPS_PROXY"))
    );
}

#[test]
fn all_proxy_fills_in_for_a_scheme_without_its_own_variable() {
    let report = resolve(
        None,
        &[
            ("ALL_PROXY", "http://all.corp:1"),
            ("HTTPS_PROXY", "http://secure.corp:2"),
        ],
    )
    .unwrap()
    .report();
    assert_eq!(
        report.https,
        route("http://secure.corp:2/", var("HTTPS_PROXY"))
    );
    assert_eq!(report.http, route("http://all.corp:1/", var("ALL_PROXY")));
}

#[test]
fn empty_variables_count_as_unset() {
    let report = resolve(None, &[("HTTPS_PROXY", ""), ("https_proxy", "  ")])
        .unwrap()
        .report();
    assert_eq!(report, ProxyReport::default());
}

#[test]
fn a_proxy_without_a_scheme_is_http() {
    let report = resolve(None, &[("HTTPS_PROXY", "proxy.corp:3128")])
        .unwrap()
        .report();
    assert_eq!(
        report.https,
        route("http://proxy.corp:3128/", var("HTTPS_PROXY"))
    );
}

#[test]
fn config_overrides_every_variable_for_both_schemes() {
    let report = resolve(
        Some("http://config.corp:9"),
        &[
            ("HTTPS_PROXY", "http://env.corp:1"),
            ("HTTP_PROXY", "http://env.corp:2"),
            ("ALL_PROXY", "http://env.corp:3"),
        ],
    )
    .unwrap()
    .report();
    let expected = route("http://config.corp:9/", ProxySource::Config);
    assert_eq!(report.https, expected);
    assert_eq!(report.http, expected);
}

#[test]
fn an_invalid_variable_is_ignored_when_config_names_a_proxy() {
    // The configured proxy replaces the variables, so a broken one cannot matter.
    let config = resolve(
        Some("http://config.corp:9"),
        &[("HTTPS_PROXY", "ftp://env.corp")],
    );
    assert!(config.is_ok());
}

#[test]
fn no_proxy_still_applies_to_the_config_proxy() {
    let report = resolve(
        Some("http://config.corp:9"),
        &[("NO_PROXY", "internal.corp,10.0.0.0/8")],
    )
    .unwrap()
    .report();
    assert_eq!(report.no_proxy.as_deref(), Some("internal.corp,10.0.0.0/8"));
}

#[test]
fn upper_case_no_proxy_wins_over_lowercase() {
    let report = resolve(
        None,
        &[
            ("HTTPS_PROXY", "http://p.corp:1"),
            ("no_proxy", "lower.corp"),
            ("NO_PROXY", "upper.corp"),
        ],
    )
    .unwrap()
    .report();
    assert_eq!(report.no_proxy.as_deref(), Some("upper.corp"));
}

#[test]
fn credentials_are_redacted_in_the_report_and_the_debug_output() {
    let config = resolve(
        None,
        &[("HTTPS_PROXY", "http://alice:s3cret@proxy.corp:8080")],
    )
    .unwrap();
    let report = config.report();
    assert_eq!(
        report.https,
        route("http://***@proxy.corp:8080/", var("HTTPS_PROXY"))
    );
    assert!(!format!("{config:?}").contains("s3cret"));
    assert!(!format!("{report:?}").contains("s3cret"));
}

#[test]
fn redact_url_hides_the_userinfo_only() {
    assert_eq!(redact_url("http://u:p@h:1/x"), "http://***@h:1/x");
    assert_eq!(redact_url("u:p@h:1"), "***@h:1");
    assert_eq!(redact_url("http://h:1/a@b"), "http://h:1/a@b");
    assert_eq!(redact_url("http://h:1"), "http://h:1");
}

fn assert_rejected(explicit: Option<&str>, vars: &[(&str, &str)], origin: &str) {
    let err = resolve(explicit, vars).unwrap_err();
    let text = format!("{err} {err:?}");
    assert!(matches!(err, Error::Proxy { .. }), "{text}");
    assert!(text.contains(origin), "{text}");
    assert!(!text.contains("s3cret"), "{text}");
}

#[test]
fn redact_proxy_url_hides_a_password_that_holds_url_delimiters() {
    // A proxy URL has no path, so everything before the last `@` is credentials.
    assert_eq!(
        redact_proxy_url("http://alice:p#ss@proxy:8080"),
        "http://***@proxy:8080"
    );
    assert_eq!(
        redact_proxy_url("http://alice:p/s?s@proxy:8080/"),
        "http://***@proxy:8080/"
    );
    assert_eq!(redact_proxy_url("alice:p@ss@proxy:1"), "***@proxy:1");
    assert_eq!(redact_proxy_url("http://proxy:8080"), "http://proxy:8080");
}

#[test]
fn an_invalid_proxy_names_its_origin_and_never_echoes_the_url() {
    assert_rejected(Some("ftp://u:s3cret@proxy.corp"), &[], "network.proxy");
    assert_rejected(
        None,
        &[("HTTPS_PROXY", "http://u:s3cret@[bad")],
        "HTTPS_PROXY",
    );
    assert_rejected(None, &[("ALL_PROXY", "http://u:s3cret@")], "ALL_PROXY");
}

#[test]
fn schemes_other_than_http_and_socks_are_refused() {
    assert!(resolve(Some("ftp://proxy.corp"), &[]).is_err());
    assert!(resolve(Some("socks4://proxy.corp"), &[]).is_err());
    assert!(resolve(Some("socks5://proxy.corp:1080"), &[]).is_ok());
    assert!(resolve(Some("socks5h://proxy.corp:1080"), &[]).is_ok());
    assert!(resolve(Some("https://proxy.corp"), &[]).is_ok());
}

fn windows(server: &str, bypass: Option<&str>) -> impl Fn() -> Option<wininet::WinInetSettings> {
    let settings = wininet::WinInetSettings {
        enabled: true,
        proxy_server: Some(server.to_owned()),
        proxy_override: bypass.map(str::to_owned),
        auto_config_url: None,
    };
    move || Some(settings.clone())
}

#[test]
fn the_windows_proxy_applies_when_no_variable_is_set() {
    let config = ProxyConfig::resolve(
        None,
        &env(&[]),
        &windows("u:s3cret@sys.corp:8080", Some("*.corp;10.*")),
    )
    .unwrap();
    let report = config.report();
    let expected = route("http://***@sys.corp:8080/", ProxySource::WindowsSystem);
    assert_eq!(report.https, expected);
    assert_eq!(report.http, expected);
    assert_eq!(report.no_proxy.as_deref(), Some(".corp,10.0.0.0/8"));
    assert!(!format!("{config:?}").contains("s3cret"));
}

#[test]
fn a_proxy_variable_beats_the_windows_proxy_for_both_schemes() {
    let report = ProxyConfig::resolve(
        None,
        &env(&[("HTTPS_PROXY", "http://env.corp:1")]),
        &windows("sys.corp:8080", None),
    )
    .unwrap()
    .report();
    assert_eq!(
        report.https,
        route("http://env.corp:1/", var("HTTPS_PROXY"))
    );
    // Setting any proxy variable switches the system proxy off, so `http` goes direct.
    assert_eq!(report.http, None);
}

#[test]
fn config_beats_the_windows_proxy() {
    let report = ProxyConfig::resolve(
        Some("http://config.corp:9"),
        &env(&[]),
        &windows("sys.corp:8080", None),
    )
    .unwrap()
    .report();
    assert_eq!(
        report.https,
        route("http://config.corp:9/", ProxySource::Config)
    );
}

#[test]
fn the_no_proxy_variable_beats_the_windows_bypass_list() {
    let report = ProxyConfig::resolve(
        None,
        &env(&[("NO_PROXY", "mine.corp")]),
        &windows("sys.corp:8080", Some("*.other")),
    )
    .unwrap()
    .report();
    assert_eq!(report.no_proxy.as_deref(), Some("mine.corp"));
    assert!(report.https.is_some());
}

#[test]
fn a_windows_pac_file_surfaces_as_a_note_and_no_proxy() {
    let pac = || {
        Some(wininet::WinInetSettings {
            enabled: false,
            auto_config_url: Some("http://wpad.corp/proxy.pac".to_owned()),
            ..wininet::WinInetSettings::default()
        })
    };
    let report = ProxyConfig::resolve(None, &env(&[]), &pac)
        .unwrap()
        .report();
    assert_eq!((report.http, report.https), (None, None));
    assert_eq!(report.notes.len(), 1);
}

#[test]
fn an_unusable_windows_proxy_is_an_error_naming_the_windows_settings() {
    let err = ProxyConfig::resolve(None, &env(&[]), &windows("ftp://u:s3cret@sys.corp", None))
        .unwrap_err();
    let text = format!("{err}");
    assert!(text.contains("Windows"), "{text}");
    assert!(!text.contains("s3cret"), "{text}");
}
