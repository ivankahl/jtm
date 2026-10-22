use super::*;

fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
    let vars: Vec<(String, String)> = vars
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |key| {
        vars.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| OsString::from(v))
    }
}

fn resolve(os: Os, vars: &[(&str, &str)]) -> Result<Dirs> {
    Dirs::resolve(os, None, None, &env(vars))
}

fn p(base: &str, parts: &[&str]) -> PathBuf {
    parts
        .iter()
        .fold(PathBuf::from(base), |dir, part| dir.join(part))
}

const WINDOWS: &[(&str, &str)] = &[
    ("LOCALAPPDATA", r"C:\Users\u\AppData\Local"),
    ("APPDATA", r"C:\Users\u\AppData\Roaming"),
    ("USERPROFILE", r"C:\Users\u"),
];

#[test]
fn windows_paths() {
    let dirs = resolve(Os::Windows, WINDOWS).unwrap();
    assert_eq!(dirs.data, p(r"C:\Users\u\AppData\Local", &["jtm"]));
    assert_eq!(
        dirs.cache,
        p(r"C:\Users\u\AppData\Local", &["jtm", "cache"])
    );
    assert_eq!(
        dirs.config_file,
        p(r"C:\Users\u\AppData\Roaming", &["jtm", "config.toml"])
    );
}

#[test]
fn windows_falls_back_to_the_profile() {
    let dirs = resolve(Os::Windows, &[("USERPROFILE", r"C:\Users\u")]).unwrap();
    assert_eq!(dirs.data, p(r"C:\Users\u", &["AppData", "Local", "jtm"]));
    assert_eq!(
        dirs.config_file,
        p(r"C:\Users\u", &["AppData", "Roaming", "jtm", "config.toml"])
    );
    assert_eq!(resolve(Os::Windows, &[]).unwrap_err().code(), "E_USAGE");
}

#[test]
fn unix_paths_default_under_home() {
    for os in [Os::Macos, Os::Linux] {
        let dirs = resolve(os, &[("HOME", "/home/u")]).unwrap();
        assert_eq!(dirs.data, p("/home/u", &[".local", "share", "jtm"]), "{os}");
        assert_eq!(dirs.cache, p("/home/u", &[".cache", "jtm"]), "{os}");
        assert_eq!(
            dirs.config_file,
            p("/home/u", &[".config", "jtm", "config.toml"]),
            "{os}"
        );
    }
}

#[test]
fn unix_honours_absolute_xdg_variables() {
    let dirs = resolve(
        Os::Linux,
        &[
            ("HOME", "/home/u"),
            ("XDG_DATA_HOME", "/xdg/data"),
            ("XDG_CACHE_HOME", "/xdg/cache"),
            ("XDG_CONFIG_HOME", "/xdg/config"),
        ],
    )
    .unwrap();
    assert_eq!(dirs.data, p("/xdg/data", &["jtm"]));
    assert_eq!(dirs.cache, p("/xdg/cache", &["jtm"]));
    assert_eq!(dirs.config_file, p("/xdg/config", &["jtm", "config.toml"]));

    let dirs = resolve(
        Os::Macos,
        &[("HOME", "/Users/u"), ("XDG_DATA_HOME", "relative/data")],
    )
    .unwrap();
    assert_eq!(dirs.data, p("/Users/u", &[".local", "share", "jtm"]));
}

#[test]
fn unix_without_home_is_an_error_unless_xdg_covers_everything() {
    assert_eq!(resolve(Os::Linux, &[]).unwrap_err().code(), "E_USAGE");
    assert_eq!(
        resolve(Os::Linux, &[("HOME", "relative")])
            .unwrap_err()
            .code(),
        "E_USAGE"
    );
    let dirs = resolve(
        Os::Linux,
        &[
            ("XDG_DATA_HOME", "/d"),
            ("XDG_CACHE_HOME", "/c"),
            ("XDG_CONFIG_HOME", "/f"),
        ],
    )
    .unwrap();
    assert_eq!(dirs.data, p("/d", &["jtm"]));
}

#[test]
fn jtm_home_collapses_data_config_and_cache() {
    for (os, home, vars) in [
        (Os::Windows, r"E:\portable\jtm", WINDOWS),
        (Os::Linux, "/opt/jtm", &[("HOME", "/home/u")][..]),
        (Os::Macos, "/opt/jtm", &[][..]),
    ] {
        let dirs = Dirs::resolve(os, Some(Path::new(home)), None, &env(vars)).unwrap();
        assert_eq!(dirs.data, PathBuf::from(home), "{os}");
        assert_eq!(dirs.cache, p(home, &["cache"]), "{os}");
        assert_eq!(dirs.config_file, p(home, &["config.toml"]), "{os}");
        assert_eq!(dirs.index_cache(), p(home, &["cache", "index"]), "{os}");
        assert_eq!(dirs.tools(), p(home, &["tools"]), "{os}");
        assert_eq!(dirs.state(), p(home, &["state"]), "{os}");
    }
}

#[test]
fn jtm_home_must_be_absolute() {
    let err = Dirs::resolve(Os::Linux, Some(Path::new("jtm")), None, &env(&[])).unwrap_err();
    assert_eq!(err.code(), "E_USAGE");
    assert!(err.to_string().contains("JTM_HOME"));
    let err = Dirs::resolve(Os::Windows, Some(Path::new("/opt/jtm")), None, &env(&[])).unwrap_err();
    assert_eq!(
        err.code(),
        "E_USAGE",
        "a Unix path is not absolute on Windows"
    );
    Dirs::resolve(
        Os::Windows,
        Some(Path::new(r"\\server\share\jtm")),
        None,
        &env(&[]),
    )
    .unwrap();
}

#[test]
fn an_explicit_config_file_wins() {
    let dirs = Dirs::resolve(
        Os::Linux,
        Some(Path::new("/opt/jtm")),
        Some(Path::new("/srv/ci/jtm.toml")),
        &env(&[]),
    )
    .unwrap();
    assert_eq!(dirs.config_file, PathBuf::from("/srv/ci/jtm.toml"));
    assert_eq!(dirs.data, PathBuf::from("/opt/jtm"));
}

#[test]
fn data_layout_matches_section_14() {
    let dirs = resolve(Os::Linux, &[("HOME", "/h")]).unwrap();
    let data = p("/h", &[".local", "share", "jtm"]);
    let cache = p("/h", &[".cache", "jtm"]);
    assert_eq!(dirs.current(), data.join("current"));
    assert_eq!(
        dirs.install_dir("example", "default", "21.0.5+11"),
        data.join("tools").join("example").join("default-21.0.5+11")
    );
    assert_eq!(
        dirs.install_dir("acme/flyway", "default", "10.1"),
        data.join("tools").join("acme--flyway").join("default-10.1")
    );
    assert_eq!(dirs.tools_tmp(), data.join("tools").join(".tmp"));
    assert_eq!(dirs.tools_trash(), data.join("tools").join(".trash"));
    assert_eq!(dirs.builtin_plugins(), data.join("plugins").join("builtin"));
    assert_eq!(dirs.locks(), data.join("locks"));
    assert_eq!(dirs.downloads(), cache.join("downloads"));
}

#[test]
fn resolves_for_the_running_os() {
    let ctx = Context::resolve(
        &crate::context::GlobalFlags::default(),
        |_| None,
        crate::context::Terminal::default(),
        &[],
    )
    .unwrap();
    let host_home = if cfg!(windows) {
        r"C:\jtm-test"
    } else {
        "/jtm-test"
    };
    let ctx = Context {
        home: Some(PathBuf::from(host_home)),
        ..ctx
    };
    let dirs = Dirs::for_context(&ctx).unwrap();
    assert_eq!(dirs.data, PathBuf::from(host_home));
}
