use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use jtm_security::testing::TestKey;
use serde_json::json;

use super::*;
use crate::config::{Config, ConfigInputs, FileSource};
use crate::links;
use crate::platform::Os;
use crate::plugins::BuiltinManifest;

/// A plugin manifest named `name` with the given extra `[index]` lines.
fn manifest(name: &str, key: &str, index_extra: &str) -> String {
    format!(
        r#"
schema = 1
name = "{name}"
display_name = "Demo"
[versions]
scheme = "semver-loose"
[index]
url = "https://index.example.test/{name}-{{os}}-{{arch}}.json"
signing_keys = ["{key}"]
format = 1
{index_extra}
[layout]
bin_dirs = ["bin"]
[env]
DEMO_HOME = "{{home}}"
"#
    )
}

fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

/// A jtm home with one first-party plugin `demo`, whose private key is `key`.
struct Home {
    _dir: tempfile::TempDir,
    dirs: Dirs,
    settings: Settings,
    builtin: &'static [BuiltinManifest],
    key: TestKey,
    env: BTreeMap<String, String>,
    offline: bool,
}

impl Home {
    fn new() -> Home {
        Home::with_index("")
    }

    fn with_index(index_extra: &str) -> Home {
        let dir = tempfile::tempdir().unwrap();
        let dirs = Dirs::resolve(Os::host().unwrap(), Some(dir.path()), None, &|_| None).unwrap();
        let key = TestKey::generate();
        let builtin: &'static [BuiltinManifest] = Box::leak(Box::new([BuiltinManifest {
            name: "demo",
            text: leak(manifest("demo", &key.public_str(), index_extra)),
            script: None,
        }]));
        Home {
            _dir: dir,
            dirs,
            settings: settings(""),
            builtin,
            key,
            env: BTreeMap::new(),
            offline: true,
        }
    }

    /// Sets the user config file to `toml`.
    fn config(mut self, toml: &str) -> Home {
        self.settings = settings(toml);
        self
    }

    fn online(mut self) -> Home {
        self.offline = false;
        self
    }

    fn with_env(mut self, key: &str, value: &str) -> Home {
        self.env.insert(key.to_owned(), value.to_owned());
        self
    }

    /// Installs `demo` at `version`, with its bin dir, and returns the install dir.
    fn install(&self, version: &str) -> PathBuf {
        let dir = self.dirs.install_dir("demo", "default", version);
        fs::create_dir_all(dir.join("bin")).unwrap();
        dir
    }

    fn set_default(&self, version: &str) {
        fs::create_dir_all(self.dirs.state()).unwrap();
        fs::write(
            self.dirs.defaults_file(),
            format!("[defaults]\ndemo = \"{version}\"\n"),
        )
        .unwrap();
    }

    fn link(&self) -> PathBuf {
        self.dirs.current().join("demo")
    }

    fn bin_on_path(&self) -> String {
        self.link().join("bin").display().to_string()
    }

    fn with_path(self, path: &str) -> Home {
        self.with_env("PATH", path)
    }

    /// An external plugin `acme/widget`, signed by `key`.
    fn add_external(&self, key: &TestKey, index_extra: &str) {
        let dir = self.dirs.plugins().join("acme--widget@abc123");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("plugin.toml"),
            manifest("acme/widget", &key.public_str(), index_extra),
        )
        .unwrap();
    }
}

fn settings(toml: &str) -> Settings {
    Config::load(&ConfigInputs {
        user: Some(FileSource {
            path: std::path::Path::new("config.toml"),
            text: toml,
        }),
        project: None,
        env: &|_| None,
        flags: &[],
    })
    .unwrap()
    .settings
}

/// Runs every check of `home` with its own environment.
fn report(
    home: &Home,
    prober: Option<&dyn Prober>,
    marketplace: Option<&dyn Marketplace>,
) -> Report {
    let lookup = |key: &str| home.env.get(key).cloned();
    run(
        &Inputs {
            dirs: &home.dirs,
            settings: &home.settings,
            registry: Registry {
                dirs: &home.dirs,
                builtin: home.builtin,
            },
            offline: home.offline,
            env: &lookup,
            now: Timestamp::parse("2026-10-22T00:00:00Z").unwrap(),
            prober,
            marketplace,
        },
        Check::pass("shell_hook", "loaded"),
    )
}

/// One check of `home`, offline unless `home` is [`Home::online`], with no marketplace.
fn check(home: &Home, id: &str) -> Check {
    check_with(home, id, None, None)
}

fn check_with(
    home: &Home,
    id: &str,
    prober: Option<&dyn Prober>,
    marketplace: Option<&dyn Marketplace>,
) -> Check {
    report(home, prober, marketplace)
        .checks
        .into_iter()
        .find(|c| c.id == id)
        .unwrap_or_else(|| panic!("no check {id}"))
}

fn codes(check: &Check) -> Vec<&'static str> {
    check.findings.iter().map(|f| f.code).collect()
}

#[test]
fn runs_every_check_in_a_fixed_order() {
    let report = report(&Home::new(), None, None);
    let ids: Vec<&str> = report.checks.iter().map(|c| c.id).collect();
    assert_eq!(
        ids,
        [
            "path",
            "current_links",
            "shell_hook",
            "proxy",
            "tls",
            "trust_store",
            "yanked_plugins"
        ]
    );
}

#[test]
fn a_report_without_failures_exits_zero_and_keeps_its_warnings() {
    let mut check = Check::pass("path", "fine");
    check.push(Finding::warning("W_PATH_MISSING", "not on PATH"));
    let report = Report {
        checks: vec![check, Check::pass("proxy", "direct")],
    };
    assert!(report.first_error().is_none());
    assert_eq!(report.exit_code(), ExitCode::Success);
    assert_eq!(report.checks[0].status, Status::Warning);
    assert_eq!(report.warnings().count(), 1);
}

#[test]
fn the_first_failure_in_check_order_decides_the_exit_code() {
    let mut warned = Check::pass("path", "");
    warned.push(Finding::warning("W_PATH_MISSING", "x"));
    let mut io = Check::pass("current_links", "");
    io.push(Finding::error(ErrorCode::Io, "dangling"));
    let mut net = Check::pass("tls", "");
    net.push(Finding::error(ErrorCode::IndexExpired, "expired"));
    let report = Report {
        checks: vec![warned, io, net],
    };
    let first = report.first_error().unwrap();
    assert_eq!(first.code, "E_IO");
    assert_eq!(report.exit_code(), ExitCode::Io);
    assert_eq!(report.checks[1].status, Status::Failed);
}

#[test]
fn a_finding_serializes_with_its_code_message_and_hint() {
    let finding = Finding::error(ErrorCode::Io, "the link is gone")
        .hint("run `jtm default`")
        .detail("tool", "demo");
    assert_eq!(
        serde_json::to_value(&finding).unwrap(),
        json!({
            "severity": "error",
            "code": "E_IO",
            "message": "the link is gone",
            "hint": "run `jtm default`",
            "details": { "tool": "demo" },
        })
    );
}

// PATH

#[test]
fn path_has_nothing_to_check_without_defaults() {
    let home = Home::new().with_path("/usr/bin");
    let path = check(&home, "path");
    assert_eq!(path.status, Status::Ok, "{path:?}");
    assert!(path.summary.contains("no defaults"), "{}", path.summary);
}

#[test]
fn path_warns_when_a_current_link_bin_dir_is_missing() {
    let home = Home::new().with_path("/usr/bin");
    let install = home.install("1.0.0");
    links::set(&home.link(), &install).unwrap();
    home.set_default("1.0.0");
    let path = check(&home, "path");
    assert_eq!(path.status, Status::Warning, "{path:?}");
    assert_eq!(codes(&path), ["W_PATH_MISSING"]);
    let finding = &path.findings[0];
    assert!(finding.message.contains(&home.bin_on_path()), "{finding:?}");
    assert!(finding.message.contains("`demo`"), "{finding:?}");
    assert!(
        finding.hint.as_deref().unwrap().contains("jtm self setup"),
        "{finding:?}"
    );
    assert_eq!(finding.details["tool"], "demo");
}

#[test]
fn path_is_fine_when_every_bin_dir_is_on_it() {
    let home = Home::new();
    let install = home.install("1.0.0");
    links::set(&home.link(), &install).unwrap();
    home.set_default("1.0.0");
    let sep = crate::session::PATH_SEPARATOR;
    let on_path = format!("/usr/bin{sep}{}/{sep}/bin", home.bin_on_path());
    let home = home.with_path(&on_path);
    let path = check(&home, "path");
    assert_eq!(path.status, Status::Ok, "{path:?}");
    assert!(path.summary.contains('1'), "{}", path.summary);
}

#[test]
fn path_warns_when_path_is_not_set_at_all() {
    let home = Home::new();
    let install = home.install("1.0.0");
    links::set(&home.link(), &install).unwrap();
    home.set_default("1.0.0");
    let path = check(&home, "path");
    assert_eq!(codes(&path), ["W_PATH_MISSING"]);
}

#[test]
fn an_unreadable_defaults_file_fails_the_path_check_with_its_own_code() {
    let home = Home::new();
    fs::create_dir_all(home.dirs.state()).unwrap();
    fs::write(home.dirs.defaults_file(), "[defaults\n").unwrap();
    let path = check(&home, "path");
    assert_eq!(path.status, Status::Failed, "{path:?}");
    assert_eq!(codes(&path), ["E_USAGE"]);
    assert!(
        path.findings[0].message.contains("defaults"),
        "{:?}",
        path.findings
    );
}

// Current links

#[test]
fn a_healthy_current_link_passes() {
    let home = Home::new();
    let install = home.install("1.0.0");
    links::set(&home.link(), &install).unwrap();
    home.set_default("1.0.0");
    let links = check(&home, "current_links");
    assert_eq!(links.status, Status::Ok, "{links:?}");
}

#[test]
fn a_default_without_a_link_names_the_command_that_recreates_it() {
    let home = Home::new();
    home.install("1.0.0");
    home.set_default("1.0.0");
    let links = check(&home, "current_links");
    assert_eq!(codes(&links), ["E_IO"]);
    let finding = &links.findings[0];
    assert!(finding.message.contains("missing"), "{finding:?}");
    assert_eq!(
        finding.hint.as_deref(),
        Some("run `jtm default demo@1.0.0` to point it at the install again")
    );
}

#[test]
fn a_dangling_current_link_says_where_it_points() {
    let home = Home::new();
    let install = home.install("1.0.0");
    links::set(&home.link(), &install).unwrap();
    home.set_default("1.0.0");
    fs::remove_dir_all(&install).unwrap();
    let links = check(&home, "current_links");
    assert_eq!(codes(&links), ["E_IO"]);
    let finding = &links.findings[0];
    assert!(finding.message.contains("does not exist"), "{finding:?}");
    assert!(
        finding.message.contains(&install.display().to_string()),
        "{finding:?}"
    );
    assert!(
        finding
            .hint
            .as_deref()
            .unwrap()
            .contains("jtm install demo@1.0.0"),
        "{finding:?}"
    );
}

#[test]
fn a_real_directory_where_the_link_belongs_is_reported() {
    let home = Home::new();
    fs::create_dir_all(home.link()).unwrap();
    home.set_default("1.0.0");
    let links = check(&home, "current_links");
    assert_eq!(codes(&links), ["E_IO"]);
    assert!(
        links.findings[0].message.contains("not a link"),
        "{:?}",
        links.findings
    );
}

#[test]
fn a_link_to_a_tool_home_without_its_bin_dir_is_reported() {
    let home = Home::new();
    let install = home.dirs.install_dir("demo", "default", "1.0.0");
    fs::create_dir_all(&install).unwrap();
    links::set(&home.link(), &install).unwrap();
    home.set_default("1.0.0");
    let links = check(&home, "current_links");
    assert_eq!(codes(&links), ["E_IO"]);
    assert!(
        links.findings[0].message.contains("bin"),
        "{:?}",
        links.findings
    );
}

#[test]
fn a_default_for_a_tool_without_a_plugin_is_reported_by_name() {
    let home = Home::new();
    fs::create_dir_all(home.dirs.state()).unwrap();
    fs::write(
        home.dirs.defaults_file(),
        "[defaults]\n\"acme/ghost\" = \"1.0.0\"\n",
    )
    .unwrap();
    let links = check(&home, "current_links");
    assert_eq!(codes(&links), ["E_TOOL_UNKNOWN"]);
    assert!(
        links.findings[0].message.contains("acme/ghost"),
        "{:?}",
        links.findings
    );
}

// Proxy

fn text(check: &Check) -> String {
    serde_json::to_string(check).unwrap()
}

#[test]
fn without_a_proxy_connections_are_direct() {
    let proxy = check(&Home::new(), "proxy");
    assert_eq!(proxy.status, Status::Ok, "{proxy:?}");
    assert!(proxy.summary.contains("direct"), "{}", proxy.summary);
}

#[test]
fn a_proxy_from_the_environment_is_shown_without_its_password() {
    let home = Home::new().with_env("HTTPS_PROXY", "http://alice:s3cret@proxy.corp:3128");
    let proxy = check(&home, "proxy");
    assert_eq!(proxy.status, Status::Ok, "{proxy:?}");
    assert!(
        proxy.summary.contains("proxy.corp:3128"),
        "{}",
        proxy.summary
    );
    assert!(proxy.summary.contains("HTTPS_PROXY"), "{}", proxy.summary);
    let everything = text(&proxy);
    assert!(!everything.contains("s3cret"), "{everything}");
    assert!(!everything.contains("alice"), "{everything}");
    assert_eq!(proxy.details["https"]["url"], "http://***@proxy.corp:3128/");
}

#[test]
fn the_configured_proxy_beats_the_environment() {
    let home = Home::new()
        .config("[network]\nproxy = \"http://cfg.corp:8080\"\n")
        .with_env("HTTPS_PROXY", "http://env.corp:3128");
    let proxy = check(&home, "proxy");
    assert!(proxy.summary.contains("cfg.corp:8080"), "{}", proxy.summary);
    assert!(proxy.summary.contains("network.proxy"), "{}", proxy.summary);
    assert!(!proxy.summary.contains("env.corp"), "{}", proxy.summary);
}

#[test]
fn an_invalid_proxy_names_the_setting_and_never_the_password() {
    let home = Home::new().with_env("HTTPS_PROXY", "http://alice:s3cret@[bad");
    let proxy = check(&home, "proxy");
    assert_eq!(proxy.status, Status::Failed, "{proxy:?}");
    assert_eq!(codes(&proxy), ["E_USAGE"]);
    assert!(
        proxy.findings[0].message.contains("HTTPS_PROXY"),
        "{:?}",
        proxy.findings
    );
    let everything = text(&proxy);
    assert!(!everything.contains("s3cret"), "{everything}");
    assert!(proxy.findings[0].hint.is_some());
}

#[test]
fn a_proxy_setting_jtm_cannot_honour_is_a_warning() {
    use jtm_fetch::ProxyConfig;
    use jtm_fetch::proxy::wininet::WinInetSettings;
    let config = ProxyConfig::resolve(None, &|_| None, &|| {
        Some(WinInetSettings {
            enabled: false,
            proxy_server: None,
            proxy_override: None,
            auto_config_url: Some("http://wpad.corp/proxy.pac".to_owned()),
        })
    });
    let proxy = network::proxy_check(config);
    assert_eq!(proxy.status, Status::Warning, "{proxy:?}");
    assert_eq!(codes(&proxy), ["W_PROXY_UNSUPPORTED"]);
    assert!(
        proxy.findings[0].message.contains("PAC"),
        "{:?}",
        proxy.findings
    );
    assert!(
        proxy.findings[0]
            .hint
            .as_deref()
            .unwrap()
            .contains("network.proxy"),
        "{:?}",
        proxy.findings
    );
}

// TLS

/// A prober that records what it was asked and answers `Ok`.
#[derive(Default)]
struct Recorder(std::sync::Mutex<Vec<String>>);

impl Recorder {
    /// The probed URLs, sorted: the hosts are probed on their own threads, so the order the
    /// probes arrive in is not the order of the hosts.
    fn urls(&self) -> Vec<String> {
        let mut urls = self.0.lock().unwrap().clone();
        urls.sort();
        urls
    }
}

impl Prober for Recorder {
    fn probe(&self, url: &str) -> jtm_fetch::Result<()> {
        self.0.lock().unwrap().push(url.to_owned());
        Ok(())
    }
}

/// A prober that fails every probe with the same message.
struct Failing(&'static str);

impl Prober for Failing {
    fn probe(&self, url: &str) -> jtm_fetch::Result<()> {
        Err(jtm_fetch::Error::Network {
            url: url.to_owned(),
            message: self.0.to_owned(),
            transient: false,
            source: None,
        })
    }
}

fn fixture_ca() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../jtm-fetch/tests/fixtures/extra-ca.pem")
}

/// A config file setting `network.extra_ca_file` to `path`.
fn ca_config(path: &std::path::Path) -> String {
    format!(
        "[network]\nextra_ca_file = {}\n",
        serde_json::to_string(&path.display().to_string()).unwrap()
    )
}

#[test]
fn offline_the_connection_test_is_skipped_with_a_note() {
    let recorder = Recorder::default();
    let tls = check_with(&Home::new(), "tls", Some(&recorder), None);
    assert_eq!(tls.status, Status::Ok, "{tls:?}");
    assert!(
        tls.notes.iter().any(|n| n.contains("offline")),
        "{:?}",
        tls.notes
    );
    assert!(recorder.urls().is_empty(), "no connection while offline");
}

#[test]
fn online_each_index_host_is_probed_once() {
    let recorder = Recorder::default();
    let home = Home::new().online();
    let tls = check_with(&home, "tls", Some(&recorder), None);
    assert_eq!(tls.status, Status::Ok, "{tls:?}");
    assert_eq!(recorder.urls(), ["https://index.example.test/"]);
    assert!(
        tls.summary.contains("index.example.test"),
        "{}",
        tls.summary
    );
}

#[test]
fn mirrors_and_index_overrides_decide_which_hosts_are_probed() {
    let recorder = Recorder::default();
    let home = Home::new()
        .online()
        .config("[mirrors]\n\"https://index.example.test/\" = \"https://mirror.corp.test/jtm/\"\n");
    check_with(&home, "tls", Some(&recorder), None);
    assert_eq!(recorder.urls(), ["https://mirror.corp.test/"]);

    let recorder = Recorder::default();
    let home = Home::new()
        .online()
        .config("[plugins.demo]\nindex_url = \"https://override.test:8443/x/demo.json\"\n");
    check_with(&home, "tls", Some(&recorder), None);
    assert_eq!(recorder.urls(), ["https://override.test:8443/"]);
}

#[test]
fn local_index_sources_are_not_probed() {
    let recorder = Recorder::default();
    let home = Home::new()
        .online()
        .config("[plugins.demo]\nindex_url = \"/srv/mirror/demo.json\"\n");
    let tls = check_with(&home, "tls", Some(&recorder), None);
    assert_eq!(tls.status, Status::Ok, "{tls:?}");
    assert!(recorder.urls().is_empty());
    assert!(tls.summary.contains("local"), "{}", tls.summary);
}

#[test]
fn an_unreachable_host_is_a_network_error_naming_the_host() {
    let home = Home::new().online();
    let tls = check_with(&home, "tls", Some(&Failing("connection refused")), None);
    assert_eq!(tls.status, Status::Failed, "{tls:?}");
    assert_eq!(codes(&tls), ["E_NETWORK"]);
    let finding = &tls.findings[0];
    assert!(
        finding.message.contains("index.example.test"),
        "{finding:?}"
    );
    assert!(
        finding.message.contains("connection refused"),
        "{finding:?}"
    );
    assert!(finding.hint.is_some());
    assert_eq!(finding.details["host"], "https://index.example.test/");
}

#[test]
fn a_probe_failure_never_shows_proxy_credentials() {
    let home = Home::new()
        .online()
        .with_env("HTTPS_PROXY", "http://alice:s3cret@proxy.corp:3128");
    let failing = Failing("tunnel via http://alice:s3cret@proxy.corp:3128 failed");
    let tls = check_with(&home, "tls", Some(&failing), None);
    let everything = text(&tls);
    assert!(!everything.contains("s3cret"), "{everything}");
    assert!(!everything.contains("alice"), "{everything}");
    assert_eq!(codes(&tls), ["E_NETWORK"]);
}

/// A server that answers every connection with bytes that are not TLS.
fn plain_server() -> u16 {
    use std::io::Write;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten().take(2) {
            let mut stream = stream;
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nnot tls");
        }
    });
    port
}

fn real_client() -> jtm_fetch::Client {
    jtm_fetch::Client::with_proxies(
        jtm_fetch::ClientOptions::new("0.0.0-test"),
        jtm_fetch::ProxyConfig::none(),
    )
    .unwrap()
}

#[test]
fn a_tls_failure_points_at_the_extra_ca_file() {
    let port = plain_server();
    let home = Home::new().online().config(&format!(
        "[plugins.demo]\nindex_url = \"https://127.0.0.1:{port}/demo.json\"\n"
    ));
    let client = real_client();
    let tls = check_with(&home, "tls", Some(&client), None);
    assert_eq!(tls.status, Status::Failed, "{tls:?}");
    assert_eq!(codes(&tls), ["E_NETWORK"]);
    let finding = &tls.findings[0];
    assert!(finding.message.contains("TLS"), "{finding:?}");
    assert!(finding.message.contains("127.0.0.1"), "{finding:?}");
    assert!(
        finding
            .hint
            .as_deref()
            .unwrap()
            .contains("network.extra_ca_file"),
        "{finding:?}"
    );
}

#[test]
fn a_closed_port_is_not_blamed_on_tls() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let home = Home::new().online().config(&format!(
        "[plugins.demo]\nindex_url = \"https://127.0.0.1:{port}/demo.json\"\n"
    ));
    let client = real_client();
    let tls = check_with(&home, "tls", Some(&client), None);
    assert_eq!(codes(&tls), ["E_NETWORK"]);
    assert!(
        !tls.findings[0]
            .hint
            .as_deref()
            .unwrap()
            .contains("extra_ca_file"),
        "{:?}",
        tls.findings
    );
}

#[test]
fn a_readable_extra_ca_file_is_counted() {
    let tls = check(&Home::new().config(&ca_config(&fixture_ca())), "tls");
    assert_eq!(tls.status, Status::Ok, "{tls:?}");
    assert!(tls.summary.contains("certificate"), "{}", tls.summary);
}

#[test]
fn a_missing_extra_ca_file_is_an_io_error_naming_the_setting() {
    let home = Home::new();
    let config = ca_config(&home.dirs.data.join("missing.pem"));
    let tls = check(&home.config(&config), "tls");
    assert_eq!(tls.status, Status::Failed, "{tls:?}");
    assert_eq!(codes(&tls), ["E_IO"]);
    let finding = &tls.findings[0];
    assert!(
        finding.message.contains("network.extra_ca_file"),
        "{finding:?}"
    );
    assert!(finding.message.contains("missing.pem"), "{finding:?}");
}

/// A `network.extra_ca_file` that holds no certificate.
fn broken_bundle(home: &Home) -> String {
    let bundle = home.dirs.data.join("bundle.pem");
    fs::create_dir_all(&home.dirs.data).unwrap();
    fs::write(&bundle, "not a certificate").unwrap();
    ca_config(&bundle)
}

#[test]
fn an_extra_ca_file_without_certificates_is_a_config_error() {
    let home = Home::new();
    let config = broken_bundle(&home);
    let tls = check(&home.config(&config), "tls");
    assert_eq!(codes(&tls), ["E_USAGE"]);
    assert!(
        tls.findings[0].message.contains("no PEM certificates"),
        "{:?}",
        tls.findings
    );
}

#[test]
fn a_client_that_cannot_start_skips_only_the_connection_test() {
    // No prober is given, so doctor builds the client, which refuses the broken bundle.
    let home = Home::new();
    let config = broken_bundle(&home);
    let tls = check(&home.online().config(&config), "tls");
    assert_eq!(codes(&tls), ["E_USAGE"], "only the bundle is reported");
    assert!(
        tls.notes.iter().any(|n| n.contains("not tested")),
        "{:?}",
        tls.notes
    );
}

// Trust store

const KEYS_URL: &str = "keys_url = \"https://index.example.test/keys.json\"";

/// Writes the cached keys file of `plugin`, signed by `signer`, listing `keys` as
/// `(key, expires)` pairs that all cover `plugin`.
fn cache_keys_file(home: &Home, plugin: &str, signer: &TestKey, keys: &[(&TestKey, &str)]) {
    cache_shared_keys_file(home, &[plugin], signer, keys);
}

/// Like [`cache_keys_file`], one file covering every plugin in `plugins` and cached for each.
fn cache_shared_keys_file(
    home: &Home,
    plugins: &[&str],
    signer: &TestKey,
    keys: &[(&TestKey, &str)],
) {
    let listed: Vec<_> = keys
        .iter()
        .map(|(key, expires)| {
            json!({ "key": key.public_str(), "scope": plugins, "expires": expires })
        })
        .collect();
    let data = serde_json::to_vec(&json!({
        "format": 1,
        "sequence": 1,
        "threshold": 1,
        "keys": listed,
    }))
    .unwrap();
    for plugin in plugins {
        let path = crate::indices::keys_cache_path(&home.dirs, plugin);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &data).unwrap();
        fs::write(path.with_file_name("keys.json.minisig"), signer.sign(&data)).unwrap();
    }
}

fn write_trust(home: &Home, text: &str) {
    fs::create_dir_all(home.dirs.state()).unwrap();
    fs::write(home.dirs.state().join("trust.json"), text).unwrap();
}

#[test]
fn an_empty_trust_store_is_fine() {
    let trust = check(&Home::new(), "trust_store");
    assert_eq!(trust.status, Status::Ok, "{trust:?}");
}

#[test]
fn the_trust_store_summary_counts_keys_and_tracked_indices() {
    let home = Home::new();
    let key = TestKey::generate();
    write_trust(
        &home,
        &json!({
            "format": 1,
            "keys": [{ "key": key.public_str(), "scope": ["acme/widget"], "added": "2026-10-19T03:00:00Z" }],
            "indices": { "demo": { "linux-x64": { "sequence": 3, "sha256": "ab", "source": "remote" } } },
        })
        .to_string(),
    );
    let trust = check(&home, "trust_store");
    assert_eq!(trust.status, Status::Ok, "{trust:?}");
    assert!(trust.summary.contains("1 trusted key"), "{}", trust.summary);
}

#[test]
fn a_corrupt_trust_file_says_which_file_and_what_removing_it_costs() {
    let home = Home::new();
    write_trust(&home, "{ not json");
    let trust = check(&home, "trust_store");
    assert_eq!(trust.status, Status::Failed, "{trust:?}");
    assert_eq!(codes(&trust), ["E_INTERNAL"]);
    let finding = &trust.findings[0];
    assert!(finding.message.contains("trust.json"), "{finding:?}");
    assert!(
        finding.hint.as_deref().unwrap().contains("trusted keys"),
        "{finding:?}"
    );
}

#[test]
fn an_unreadable_trust_file_is_an_io_error() {
    let home = Home::new();
    // A directory where the file belongs can be opened but not read as a file.
    fs::create_dir_all(home.dirs.state().join("trust.json")).unwrap();
    let trust = check(&home, "trust_store");
    assert!(
        matches!(codes(&trust).as_slice(), ["E_IO"] | ["E_PERMISSION"]),
        "{trust:?}"
    );
}

#[test]
fn an_untrusted_third_party_plugin_names_the_command_that_trusts_it() {
    let home = Home::new();
    let author = TestKey::generate();
    home.add_external(&author, "");
    let trust = check(&home, "trust_store");
    assert_eq!(trust.status, Status::Failed, "{trust:?}");
    assert_eq!(codes(&trust), ["E_KEY_UNTRUSTED"]);
    let finding = &trust.findings[0];
    assert!(finding.message.contains("acme/widget"), "{finding:?}");
    let expected = format!("jtm trust add {} --scope acme/widget", author.public_str());
    assert!(
        finding.hint.as_deref().unwrap().contains(&expected),
        "{finding:?}"
    );
}

#[test]
fn a_third_party_plugin_with_a_trusted_key_passes() {
    let home = Home::new();
    let author = TestKey::generate();
    home.add_external(&author, "");
    write_trust(
        &home,
        &json!({
            "format": 1,
            "keys": [{ "key": author.public_str(), "scope": ["acme/widget"], "added": "2026-10-19T03:00:00Z" }],
        })
        .to_string(),
    );
    let trust = check(&home, "trust_store");
    assert_eq!(trust.status, Status::Ok, "{trust:?}");
}

#[test]
fn a_current_keys_file_passes() {
    let home = Home::with_index(KEYS_URL);
    let delegated = TestKey::generate();
    cache_keys_file(
        &home,
        "demo",
        &home.key,
        &[(&delegated, "2027-01-01T00:00:00Z")],
    );
    let trust = check(&home, "trust_store");
    assert_eq!(trust.status, Status::Ok, "{trust:?}");
}

#[test]
fn a_plugin_whose_keys_file_is_not_cached_yet_is_a_note_not_a_problem() {
    let home = Home::with_index(KEYS_URL);
    let trust = check(&home, "trust_store");
    assert_eq!(trust.status, Status::Ok, "{trust:?}");
    assert!(
        trust.notes.iter().any(|n| n.contains("demo")),
        "{:?}",
        trust.notes
    );
}

#[test]
fn a_keys_file_whose_every_key_expired_is_an_expired_index_error() {
    let home = Home::with_index(KEYS_URL);
    let delegated = TestKey::generate();
    cache_keys_file(
        &home,
        "demo",
        &home.key,
        &[(&delegated, "2026-10-01T00:00:00Z")],
    );
    let trust = check(&home, "trust_store");
    assert_eq!(trust.status, Status::Failed, "{trust:?}");
    assert_eq!(codes(&trust), ["E_INDEX_EXPIRED"]);
    let finding = &trust.findings[0];
    assert!(finding.message.contains("demo"), "{finding:?}");
    assert!(
        finding.message.contains("2026-10-01T00:00:00Z"),
        "{finding:?}"
    );
    assert!(
        finding.hint.as_deref().unwrap().contains("jtm update"),
        "{finding:?}"
    );
}

#[test]
fn an_expired_key_beside_a_valid_one_is_only_a_warning() {
    let home = Home::with_index(KEYS_URL);
    let (old, new) = (TestKey::generate(), TestKey::generate());
    cache_keys_file(
        &home,
        "demo",
        &home.key,
        &[
            (&old, "2026-10-01T00:00:00Z"),
            (&new, "2027-01-01T00:00:00Z"),
        ],
    );
    let trust = check(&home, "trust_store");
    assert_eq!(trust.status, Status::Warning, "{trust:?}");
    assert_eq!(codes(&trust), ["W_INDEX_KEY_EXPIRED"]);
    assert!(
        trust.findings[0]
            .message
            .contains(&old.public().id().to_string()),
        "{:?}",
        trust.findings
    );
}

#[test]
fn a_keys_file_signed_by_a_stranger_is_an_untrusted_key_error() {
    let home = Home::with_index(KEYS_URL);
    let (stranger, delegated) = (TestKey::generate(), TestKey::generate());
    cache_keys_file(
        &home,
        "demo",
        &stranger,
        &[(&delegated, "2027-01-01T00:00:00Z")],
    );
    let trust = check(&home, "trust_store");
    assert_eq!(codes(&trust), ["E_KEY_UNTRUSTED"]);
    let hint = trust.findings[0].hint.as_deref().unwrap();
    assert!(hint.contains("jtm update"), "{hint}");
}

#[test]
fn a_keys_file_changed_after_signing_is_a_signature_error() {
    let home = Home::with_index(KEYS_URL);
    let delegated = TestKey::generate();
    cache_keys_file(
        &home,
        "demo",
        &home.key,
        &[(&delegated, "2027-01-01T00:00:00Z")],
    );
    let path = crate::indices::keys_cache_path(&home.dirs, "demo");
    let mut data = fs::read(&path).unwrap();
    data.extend_from_slice(b"\n");
    fs::write(&path, data).unwrap();
    let trust = check(&home, "trust_store");
    assert_eq!(codes(&trust), ["E_SIGNATURE_INVALID"]);
}

#[test]
fn a_correctly_signed_but_malformed_keys_file_is_an_invalid_index_error() {
    let home = Home::with_index(KEYS_URL);
    let data = br#"{"format":1,"sequence":1,"threshold":1,"keys":[]}"#;
    let path = crate::indices::keys_cache_path(&home.dirs, "demo");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, data).unwrap();
    fs::write(
        path.with_file_name("keys.json.minisig"),
        home.key.sign(data),
    )
    .unwrap();
    let trust = check(&home, "trust_store");
    assert_eq!(codes(&trust), ["E_INDEX_INVALID"]);
}

#[test]
fn first_party_plugins_sharing_a_keys_file_are_reported_together() {
    let key = TestKey::generate();
    let delegated = TestKey::generate();
    let dir = tempfile::tempdir().unwrap();
    let dirs = Dirs::resolve(Os::host().unwrap(), Some(dir.path()), None, &|_| None).unwrap();
    let builtin: &'static [BuiltinManifest] = Box::leak(Box::new([
        BuiltinManifest {
            name: "alpha",
            text: leak(manifest("alpha", &key.public_str(), KEYS_URL)),
            script: None,
        },
        BuiltinManifest {
            name: "beta",
            text: leak(manifest("beta", &key.public_str(), KEYS_URL)),
            script: None,
        },
    ]));
    let home = Home {
        _dir: dir,
        dirs,
        settings: settings(""),
        builtin,
        key,
        env: BTreeMap::new(),
        offline: true,
    };
    cache_shared_keys_file(
        &home,
        &["alpha", "beta"],
        &home.key,
        &[(&delegated, "2026-10-01T00:00:00Z")],
    );
    let trust = check(&home, "trust_store");
    assert_eq!(codes(&trust), ["E_INDEX_EXPIRED"], "one finding for both");
    assert_eq!(
        trust.findings[0].details["plugins"],
        json!(["alpha", "beta"])
    );
}

// Yanked plugins

/// A marketplace with fixed answers per plugin.
struct Listed(Vec<(&'static str, Result<Listing, &'static str>)>);

impl Marketplace for Listed {
    fn listing(&self, plugin: &str) -> crate::Result<Listing> {
        match self.0.iter().find(|(name, _)| *name == plugin) {
            Some((_, Ok(listing))) => Ok(listing.clone()),
            Some((_, Err(message))) => Err(JtmError::internal(*message)),
            None => Ok(Listing::NotListed),
        }
    }
}

fn home_with_widget() -> Home {
    let home = Home::new().online();
    home.add_external(&TestKey::generate(), "");
    home
}

#[test]
fn builtin_plugins_alone_have_nothing_to_check_even_offline() {
    let yanked = check(&Home::new(), "yanked_plugins");
    assert_eq!(yanked.status, Status::Ok, "{yanked:?}");
    assert!(
        yanked.summary.contains("no third-party"),
        "{}",
        yanked.summary
    );
}

#[test]
fn a_yanked_plugin_is_a_warning_with_its_reason() {
    let market = Listed(vec![(
        "acme/widget",
        Ok(Listing::Yanked {
            reason: "compromised key, use rev abc123".to_owned(),
        }),
    )]);
    let yanked = check_with(&home_with_widget(), "yanked_plugins", None, Some(&market));
    assert_eq!(yanked.status, Status::Warning, "{yanked:?}");
    assert_eq!(codes(&yanked), ["W_PLUGIN_YANKED"]);
    let finding = &yanked.findings[0];
    assert!(finding.message.contains("acme/widget"), "{finding:?}");
    assert!(finding.message.contains("compromised key"), "{finding:?}");
    assert!(finding.hint.is_some());
}

#[test]
fn a_plugin_that_is_not_yanked_passes() {
    let market = Listed(vec![("acme/widget", Ok(Listing::Active))]);
    let yanked = check_with(&home_with_widget(), "yanked_plugins", None, Some(&market));
    assert_eq!(yanked.status, Status::Ok, "{yanked:?}");
    assert!(yanked.findings.is_empty());
}

#[test]
fn a_plugin_the_marketplace_does_not_list_is_noted() {
    let market = Listed(vec![]);
    let yanked = check_with(&home_with_widget(), "yanked_plugins", None, Some(&market));
    assert_eq!(yanked.status, Status::Ok, "{yanked:?}");
    assert!(
        yanked.notes.iter().any(|n| n.contains("acme/widget")),
        "{:?}",
        yanked.notes
    );
}

#[test]
fn offline_the_check_is_skipped_and_says_why() {
    let home = Home {
        offline: true,
        ..home_with_widget()
    };
    let market = Listed(vec![("acme/widget", Ok(Listing::Active))]);
    let yanked = check_with(&home, "yanked_plugins", None, Some(&market));
    assert_eq!(yanked.status, Status::Skipped, "{yanked:?}");
    assert!(yanked.summary.contains("online"), "{}", yanked.summary);
    assert!(yanked.summary.contains("acme/widget"), "{}", yanked.summary);
}

#[test]
fn without_a_marketplace_listing_the_check_is_skipped() {
    let yanked = check(&home_with_widget(), "yanked_plugins");
    assert_eq!(yanked.status, Status::Skipped, "{yanked:?}");
    assert!(
        yanked.summary.contains("not available"),
        "{}",
        yanked.summary
    );
}

#[test]
fn a_marketplace_that_fails_skips_the_check_with_the_reason() {
    let market = Listed(vec![("acme/widget", Err("the listing is corrupt"))]);
    let yanked = check_with(&home_with_widget(), "yanked_plugins", None, Some(&market));
    assert_eq!(yanked.status, Status::Skipped, "{yanked:?}");
    assert!(
        yanked.summary.contains("the listing is corrupt"),
        "{}",
        yanked.summary
    );
}

#[test]
fn a_keys_file_is_probed_at_its_own_unmirrored_host() {
    let recorder = Recorder::default();
    let home = Home::with_index(KEYS_URL)
        .online()
        .config("[mirrors]\n\"https://index.example.test/\" = \"https://mirror.corp.test/jtm/\"\n");
    check_with(&home, "tls", Some(&recorder), None);
    assert_eq!(
        recorder.urls(),
        ["https://index.example.test/", "https://mirror.corp.test/"],
        "the loader fetches the keys file from keys_url as written"
    );

    let recorder = Recorder::default();
    let home = Home::with_index(KEYS_URL)
        .online()
        .config("[plugins.demo]\nindex_url = \"https://override.test/demo.json\"\n");
    check_with(&home, "tls", Some(&recorder), None);
    assert_eq!(
        recorder.urls(),
        ["https://index.example.test/", "https://override.test/"],
        "an index_url override does not move the keys file"
    );
}

#[test]
fn a_failing_lookup_keeps_the_yanked_plugins_found_before_it() {
    let home = Home::new().online();
    let author = TestKey::generate();
    home.add_external(&author, "");
    let other = home.dirs.plugins().join("acme--zeta@abc123");
    fs::create_dir_all(&other).unwrap();
    fs::write(
        other.join("plugin.toml"),
        manifest("acme/zeta", &author.public_str(), ""),
    )
    .unwrap();
    let market = Listed(vec![
        (
            "acme/widget",
            Ok(Listing::Yanked {
                reason: "withdrawn".to_owned(),
            }),
        ),
        ("acme/zeta", Err("the listing is corrupt")),
    ]);
    let yanked = check_with(&home, "yanked_plugins", None, Some(&market));
    assert_eq!(codes(&yanked), ["W_PLUGIN_YANKED"]);
    assert!(
        yanked.notes.iter().any(|n| n.contains("incomplete")),
        "{:?}",
        yanked.notes
    );
}
