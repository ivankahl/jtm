use super::*;

fn settings(server: Option<&str>, bypass: Option<&str>) -> WinInetSettings {
    WinInetSettings {
        enabled: true,
        proxy_server: server.map(str::to_owned),
        proxy_override: bypass.map(str::to_owned),
        auto_config_url: None,
    }
}

#[test]
fn a_single_server_serves_both_schemes() {
    let proxy = settings(Some("proxy.corp:8080"), None).interpret();
    assert_eq!(proxy.http.as_deref(), Some("proxy.corp:8080"));
    assert_eq!(proxy.https.as_deref(), Some("proxy.corp:8080"));
    assert_eq!(proxy.bypass, None);
    assert!(proxy.notes.is_empty());
}

#[test]
fn per_scheme_servers_are_split_and_other_protocols_are_ignored() {
    let proxy = settings(
        Some("http=plain.corp:80;https=secure.corp:443;ftp=ftp.corp:21;socks=socks.corp:1080"),
        None,
    )
    .interpret();
    assert_eq!(proxy.http.as_deref(), Some("plain.corp:80"));
    assert_eq!(proxy.https.as_deref(), Some("secure.corp:443"));
}

#[test]
fn a_scheme_without_its_own_server_has_no_proxy() {
    let proxy = settings(Some("https=secure.corp:443"), None).interpret();
    assert_eq!(proxy.http, None);
    assert_eq!(proxy.https.as_deref(), Some("secure.corp:443"));
}

#[test]
fn a_bare_server_fills_the_schemes_that_have_no_entry() {
    let proxy = settings(Some("any.corp:1;https=secure.corp:2"), None).interpret();
    assert_eq!(proxy.http.as_deref(), Some("any.corp:1"));
    assert_eq!(proxy.https.as_deref(), Some("secure.corp:2"));
}

#[test]
fn space_separated_entries_are_accepted() {
    let proxy = settings(Some("http=plain.corp:80 https=secure.corp:443"), None).interpret();
    assert_eq!(proxy.http.as_deref(), Some("plain.corp:80"));
    assert_eq!(proxy.https.as_deref(), Some("secure.corp:443"));
}

#[test]
fn a_disabled_proxy_is_no_proxy() {
    let off = WinInetSettings {
        enabled: false,
        ..settings(Some("proxy.corp:8080"), Some("*.corp"))
    };
    assert_eq!(off.interpret(), SystemProxy::default());
}

#[test]
fn an_empty_server_is_no_proxy() {
    assert_eq!(
        settings(Some("  "), None).interpret(),
        SystemProxy::default()
    );
    assert_eq!(settings(None, None).interpret(), SystemProxy::default());
}

#[test]
fn a_pac_file_is_reported_and_never_followed() {
    let pac_only = WinInetSettings {
        auto_config_url: Some("http://wpad.corp/proxy.pac".to_owned()),
        ..settings(None, None)
    };
    let proxy = pac_only.interpret();
    assert_eq!(proxy.http, None);
    assert_eq!(proxy.https, None);
    assert_eq!(proxy.notes.len(), 1);
    assert!(proxy.notes[0].contains("PAC"), "{:?}", proxy.notes);
    assert!(
        proxy.notes[0].contains("network.proxy"),
        "{:?}",
        proxy.notes
    );
}

#[test]
fn a_static_server_next_to_a_pac_file_is_used_with_a_note() {
    let both = WinInetSettings {
        auto_config_url: Some("http://wpad.corp/proxy.pac".to_owned()),
        ..settings(Some("proxy.corp:8080"), None)
    };
    let proxy = both.interpret();
    assert_eq!(proxy.https.as_deref(), Some("proxy.corp:8080"));
    assert_eq!(proxy.notes.len(), 1);
}

#[test]
fn bypass_entries_become_no_proxy_entries() {
    let proxy = settings(
        Some("proxy.corp:8080"),
        Some("localhost;*.internal.corp;intranet.corp;192.168.1.5"),
    )
    .interpret();
    assert_eq!(
        proxy.bypass.as_deref(),
        Some("localhost,.internal.corp,intranet.corp,192.168.1.5")
    );
    assert!(proxy.notes.is_empty());
}

#[test]
fn ipv4_prefix_wildcards_become_cidr_ranges() {
    let proxy = settings(Some("p:1"), Some("10.*;192.168.*;172.16.5.*;127.*")).interpret();
    assert_eq!(
        proxy.bypass.as_deref(),
        Some("10.0.0.0/8,192.168.0.0/16,172.16.5.0/24,127.0.0.0/8")
    );
}

#[test]
fn local_bypasses_loopback_only_and_says_so() {
    let proxy = settings(Some("p:1"), Some("<local>")).interpret();
    assert_eq!(proxy.bypass.as_deref(), Some("localhost,127.0.0.1,::1"));
    assert_eq!(proxy.notes.len(), 1);
    assert!(proxy.notes[0].contains("<local>"), "{:?}", proxy.notes);
}

#[test]
fn bypass_patterns_that_cannot_be_matched_are_skipped_with_a_note() {
    let proxy = settings(Some("p:1"), Some("ww*.corp;ok.corp")).interpret();
    assert_eq!(proxy.bypass.as_deref(), Some("ok.corp"));
    assert_eq!(proxy.notes.len(), 1);
    assert!(proxy.notes[0].contains("ww*.corp"), "{:?}", proxy.notes);
}

#[test]
fn a_star_bypasses_everything() {
    let proxy = settings(Some("p:1"), Some("*")).interpret();
    assert_eq!(proxy.bypass.as_deref(), Some("*"));
}

#[test]
fn a_bypass_list_without_a_proxy_is_dropped() {
    let proxy = settings(None, Some("*.corp")).interpret();
    assert_eq!(proxy, SystemProxy::default());
}
