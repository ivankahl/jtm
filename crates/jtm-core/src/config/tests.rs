use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;

use super::*;

/// An absolute path that is absolute on the host OS.
fn abs(rest: &str) -> String {
    if cfg!(windows) {
        format!("C:\\{}", rest.replace('/', "\\"))
    } else {
        format!("/{rest}")
    }
}

#[derive(Default)]
struct Fixture {
    user: Option<String>,
    project: Option<String>,
    env: HashMap<String, String>,
    flags: Vec<(&'static str, &'static str)>,
}

impl Fixture {
    fn user(mut self, text: &str) -> Self {
        self.user = Some(text.to_owned());
        self
    }
    fn project(mut self, text: &str) -> Self {
        self.project = Some(text.to_owned());
        self
    }
    fn env(mut self, key: &str, value: &str) -> Self {
        self.env.insert(key.to_owned(), value.to_owned());
        self
    }
    fn flag(mut self, key: &'static str, value: &'static str) -> Self {
        self.flags.push((key, value));
        self
    }

    fn load(&self) -> Result<Config> {
        let env = |key: &str| self.env.get(key).map(OsString::from);
        fn file<'a>(path: &'static str, text: &'a Option<String>) -> Option<FileSource<'a>> {
            text.as_deref().map(|text| FileSource {
                path: Path::new(path),
                text,
            })
        }
        Config::load(&ConfigInputs {
            user: file("/home/u/.config/jtm/config.toml", &self.user),
            project: file("/work/app/.jtm.toml", &self.project),
            env: &env,
            flags: &self.flags,
        })
    }

    fn ok(&self) -> Config {
        self.load().unwrap_or_else(|e| panic!("{e}"))
    }

    fn err(&self) -> JtmError {
        self.load().expect_err("config should be rejected")
    }
}

fn key_of(err: &JtmError) -> String {
    err.details()["key"].as_str().unwrap().to_owned()
}

#[test]
fn defaults_match_the_spec() {
    let config = Fixture::default().ok();
    let s = &config.settings;
    assert_eq!(s.pin.default_format, "native");
    assert_eq!(s.index.auto_refresh, AutoRefresh::Tty);
    assert_eq!(s.index.ttl_hours, 24);
    assert_eq!(s.security.expiry, ExpiryPolicy::RemoteOnly);
    assert!(!s.security.allow_http_mirrors);
    assert_eq!(s.download.concurrency, 4);
    assert_eq!(s.download.cache_dir, None);
    assert_eq!(s.network.proxy, None);
    assert_eq!(s.network.extra_ca_file, None);
    assert_eq!(s.extract.max_bytes, 4 * 1024 * 1024 * 1024);
    assert!(s.mirrors.is_empty());
    assert!(s.plugins.is_empty());
    assert_eq!(
        config.origin("index.ttl_hours").unwrap().layer,
        Layer::Default
    );
    assert_eq!(config.origin("network.proxy"), None);
}

#[test]
fn later_layers_win_in_order() {
    let ttl = |f: &Fixture| {
        let config = f.ok();
        (
            config.settings.index.ttl_hours,
            config.origin("index.ttl_hours").unwrap().layer,
        )
    };
    let mut f = Fixture::default();
    assert_eq!(ttl(&f), (24, Layer::Default));
    f = f.user("[index]\nttl_hours = 2");
    assert_eq!(ttl(&f), (2, Layer::User));
    f = f.project("[settings.index]\nttl_hours = 3");
    assert_eq!(ttl(&f), (3, Layer::Project));
    f = f.env("JTM__INDEX__TTL_HOURS", "4");
    assert_eq!(ttl(&f), (4, Layer::Env));
    f = f.flag("index.ttl_hours", "5");
    assert_eq!(ttl(&f), (5, Layer::Flag));
}

#[test]
fn origins_name_the_file_variable_or_flag() {
    let config = Fixture::default()
        .user("[download]\nconcurrency = 8")
        .env("JTM__INDEX__AUTO_REFRESH", "never")
        .ok();
    assert_eq!(
        config.origin("download.concurrency").unwrap().to_string(),
        "user config /home/u/.config/jtm/config.toml"
    );
    assert_eq!(
        config.origin("index.auto_refresh").unwrap().to_string(),
        "environment variable JTM__INDEX__AUTO_REFRESH"
    );
    assert_eq!(config.settings.index.auto_refresh, AutoRefresh::Never);
    assert!(config.origins().any(|(key, _)| key == "pin.default_format"));
}

/// There is no system config, so nothing can be locked; the old locked form is just a value of
/// the wrong type.
#[test]
fn locked_values_are_not_supported() {
    let err = Fixture::default()
        .user("[index]\nttl_hours = { value = 1, locked = true }")
        .err();
    assert_eq!(err.code(), "E_USAGE");
    assert_eq!(key_of(&err), "index.ttl_hours");
}

/// The security invariant: a cloned repository cannot weaken verification or redirect
/// downloads through `.jtm.toml`.
#[test]
fn project_files_cannot_set_restricted_keys() {
    let https = "https://evil.example/x.json";
    let path = abs("tmp/evil");
    let cases = [
        (
            "[settings.security]\nexpiry = \"remote-only\"".to_owned(),
            "settings.security.expiry",
        ),
        (
            "[settings.security]\nallow_http_mirrors = true".to_owned(),
            "settings.security.allow_http_mirrors",
        ),
        (
            "[settings.network]\nproxy = \"http://evil.example:8080\"".to_owned(),
            "settings.network.proxy",
        ),
        (
            format!("[settings.network]\nextra_ca_file = {path:?}"),
            "settings.network.extra_ca_file",
        ),
        (
            format!("[settings.mirrors]\n\"https://github.com/\" = {https:?}"),
            "settings.mirrors.\"https://github.com/\"",
        ),
        (
            format!("[settings.plugins.example]\nindex_url = {https:?}"),
            "settings.plugins.example.index_url",
        ),
        (
            "[settings.extract]\nmax_bytes = 99999999999".to_owned(),
            "settings.extract.max_bytes",
        ),
        (
            format!("[settings.download]\ncache_dir = {path:?}"),
            "settings.download.cache_dir",
        ),
    ];
    for (text, key) in cases {
        let err = Fixture::default().project(&text).err();
        assert_eq!(err.code(), "E_USAGE", "{text}");
        assert_eq!(key_of(&err), key, "{text}");
        assert!(
            err.to_string()
                .starts_with("project file /work/app/.jtm.toml: "),
            "{err}"
        );
        assert!(
            err.to_string().contains("project files cannot set"),
            "{err}"
        );
    }
}

#[test]
fn project_restrictions_hold_even_when_the_value_is_the_default() {
    let err = Fixture::default()
        .project("[settings.security]\nexpiry = \"remote-only\"")
        .err();
    assert_eq!(key_of(&err), "settings.security.expiry");
}

#[test]
fn project_files_may_set_harmless_keys() {
    let config = Fixture::default()
        .project(
            r#"
[tools]
example = "1.2"

[settings.pin]
default_format = "sdkmanrc"

[settings.download]
concurrency = 2
"#,
        )
        .ok();
    assert_eq!(config.settings.pin.default_format, "sdkmanrc");
    assert_eq!(config.settings.download.concurrency, 2);
}

#[test]
fn project_file_without_settings_is_ignored() {
    let config = Fixture::default().project("[tools]\nexample = \"1\"").ok();
    assert_eq!(config.settings, Fixture::default().ok().settings);
    let err = Fixture::default().project("settings = 1").err();
    assert_eq!(key_of(&err), "settings");
}

#[test]
fn unknown_keys_are_errors() {
    for (text, key) in [
        ("[index]\nttl = 1", "index.ttl"),
        ("[indexes]\nttl_hours = 1", "indexes"),
        ("[security]\nverify = false", "security.verify"),
        (
            "[plugins.example]\nurl = \"https://x.example/\"",
            "plugins.example.url",
        ),
        (
            "[plugins.Example]\nindex_url = \"https://x.example/\"",
            "plugins.Example",
        ),
        ("ttl_hours = 1", "ttl_hours"),
    ] {
        let err = Fixture::default().user(text).err();
        assert_eq!(err.code(), "E_USAGE", "{text}");
        assert_eq!(key_of(&err), key, "{text}");
    }
    let err = Fixture::default().user("[index]\nttl = 1").err();
    assert!(
        err.to_string()
            .contains("known keys are pin.default_format"),
        "{err}"
    );
}

#[test]
fn values_are_type_checked() {
    for (text, key) in [
        ("[index]\nttl_hours = \"24\"", "index.ttl_hours"),
        ("[index]\nttl_hours = -1", "index.ttl_hours"),
        (
            "[index]\nauto_refresh = \"sometimes\"",
            "index.auto_refresh",
        ),
        ("[download]\nconcurrency = 0", "download.concurrency"),
        ("[download]\nconcurrency = 1000", "download.concurrency"),
        (
            "[download]\ncache_dir = \"relative/dir\"",
            "download.cache_dir",
        ),
        (
            "[security]\nallow_http_mirrors = \"yes\"",
            "security.allow_http_mirrors",
        ),
        ("[network]\nproxy = \"ftp://proxy\"", "network.proxy"),
        ("[extract]\nmax_bytes = 0", "extract.max_bytes"),
        ("[extract]\nmax_bytes = \"4 GB\"", "extract.max_bytes"),
        (
            "[pin]\ndefault_format = \"Not A Format\"",
            "pin.default_format",
        ),
        ("[pin]\ndefault_format = \"\"", "pin.default_format"),
    ] {
        let err = Fixture::default().user(text).err();
        assert_eq!(key_of(&err), key, "{text}");
    }
}

#[test]
fn sizes_accept_units() {
    for (text, bytes) in [
        ("max_bytes = 1024", 1024),
        ("max_bytes = \"4 GiB\"", 4 << 30),
        ("max_bytes = \"512MiB\"", 512 << 20),
        ("max_bytes = \"100 KiB\"", 100 << 10),
        ("max_bytes = \"7B\"", 7),
    ] {
        let config = Fixture::default().user(&format!("[extract]\n{text}")).ok();
        assert_eq!(config.settings.extract.max_bytes, bytes, "{text}");
    }
    let err = Fixture::default()
        .user("[extract]\nmax_bytes = \"99999999999 TiB\"")
        .err();
    assert_eq!(key_of(&err), "extract.max_bytes");
}

#[test]
fn mirrors_and_index_urls_require_safe_schemes() {
    let path = abs("srv/mirror/");
    let config = Fixture::default()
        .user(&format!(
            r#"
[mirrors]
"https://github.com/jtm-dev/index/releases/download/" = "https://artifactory.corp.example/jtm-index/"
"https://github.com/adoptium/" = "file:///opt/mirror/adoptium/"
"https://example.test/" = {path:?}

[plugins.example]
index_url = "file:///opt/jtm-mirror/index/example-{{os}}-{{arch}}.json"
"#
        ))
        .ok();
    assert_eq!(config.settings.mirrors.len(), 3);
    assert!(config.settings.plugins["example"].index_url.is_some());

    let http = "[mirrors]\n\"https://github.com/\" = \"http://mirror.corp.example/\"";
    let err = Fixture::default().user(http).err();
    assert_eq!(key_of(&err), "mirrors.\"https://github.com/\"");
    assert!(err.to_string().contains("allow_http_mirrors"), "{err}");
    let allowed = Fixture::default()
        .user(&format!("[security]\nallow_http_mirrors = true\n{http}"))
        .ok();
    assert_eq!(
        allowed.settings.mirrors["https://github.com/"],
        "http://mirror.corp.example/"
    );

    for bad in [
        "[mirrors]\n\"https://github.com/\" = \"ftp://mirror/\"",
        "[mirrors]\n\"https://github.com/\" = \"relative/dir\"",
        "[mirrors]\n\"http://github.com/\" = \"https://mirror/\"",
        "[plugins.example]\nindex_url = \"http://mirror/x.json\"",
    ] {
        assert_eq!(
            Fixture::default().user(bad).err().code(),
            "E_USAGE",
            "{bad}"
        );
    }
}

#[test]
fn env_variables_are_parsed_and_checked() {
    let config = Fixture::default()
        .env("JTM__SECURITY__ALLOW_HTTP_MIRRORS", "1")
        .env("JTM__EXTRACT__MAX_BYTES", "2 GiB")
        .env("JTM__DOWNLOAD__CONCURRENCY", "")
        .ok();
    assert!(config.settings.security.allow_http_mirrors);
    assert_eq!(config.settings.extract.max_bytes, 2 << 30);
    assert_eq!(config.settings.download.concurrency, 4, "empty means unset");

    // The old single-underscore spelling is not read.
    let config = Fixture::default().env("JTM_INDEX_TTL_HOURS", "1").ok();
    assert_eq!(config.settings.index.ttl_hours, 24);

    let err = Fixture::default()
        .env("JTM__DOWNLOAD__CONCURRENCY", "many")
        .err();
    assert_eq!(err.code(), "E_USAGE");
    assert!(
        err.to_string()
            .starts_with("environment variable JTM__DOWNLOAD__CONCURRENCY: "),
        "{err}"
    );
}

#[test]
fn flags_must_name_known_keys() {
    let err = Fixture::default().flag("index.nope", "1").err();
    assert_eq!(key_of(&err), "index.nope");
    let err = Fixture::default().flag("index.ttl_hours", "x").err();
    assert_eq!(key_of(&err), "index.ttl_hours");
}

#[test]
fn syntax_errors_name_the_file_and_line() {
    let err = Fixture::default().user("[index]\nttl_hours = = 1").err();
    assert_eq!(err.code(), "E_USAGE");
    let text = err.to_string();
    assert!(
        text.starts_with("user config /home/u/.config/jtm/config.toml: line 2:"),
        "{text}"
    );
}
