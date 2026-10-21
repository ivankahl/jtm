use super::*;
use crate::context::{GlobalFlags, Terminal};
use crate::platform::Os;

/// Lists the installs of `demo` in a home where `prepare` set up `tools/demo`.
fn list_demo(prepare: impl FnOnce(&Path)) -> Result<Vec<InstalledItem>> {
    let home = tempfile::tempdir().unwrap();
    let mut ctx = Context::resolve(
        &GlobalFlags::default(),
        |_| None,
        Terminal {
            stdin: false,
            stderr: false,
        },
    )
    .unwrap();
    ctx.home = Some(home.path().to_path_buf());
    let dirs = Dirs::resolve(Os::host().unwrap(), Some(home.path()), None, &|_| None).unwrap();
    prepare(&dirs.tools().join("demo"));
    let settings = Config::load(&ConfigInputs {
        user: None,
        project: None,
        env: &|_| None,
        flags: &[],
    })
    .unwrap()
    .settings;
    let session = Session::new(&ctx, dirs, settings, Platform::detect().unwrap()).unwrap();
    session.list(Some("demo"))
}

#[test]
fn a_dir_without_a_receipt_is_not_an_install() {
    let found = list_demo(|tools| fs::create_dir_all(tools.join("demo-1")).unwrap()).unwrap();
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn a_receipt_that_cannot_be_read_fails_the_listing() {
    // A receipt path that is a directory exists but cannot be read as a file, on every OS.
    let err = list_demo(|tools| {
        fs::create_dir_all(
            tools
                .join("demo-1")
                .join(crate::install::receipt::RECEIPT_FILE),
        )
        .unwrap();
    })
    .unwrap_err();
    assert!(
        matches!(err.code(), "E_IO" | "E_PERMISSION"),
        "{}: {err}",
        err.code()
    );
}

#[test]
fn a_tool_dir_that_cannot_be_listed_fails_the_listing() {
    let err = list_demo(|tools| {
        fs::create_dir_all(tools.parent().unwrap()).unwrap();
        fs::write(tools, "not a directory").unwrap();
    })
    .unwrap_err();
    assert_eq!(err.code(), "E_IO", "{err}");
}

#[test]
fn network_settings_reach_the_http_client() {
    let mut settings = Config::load(&ConfigInputs {
        user: None,
        project: None,
        env: &|_| None,
        flags: &[],
    })
    .unwrap()
    .settings;
    settings.security.allow_http_mirrors = true;
    settings.network.proxy = Some("http://proxy.example:8080".to_owned());
    settings.network.extra_ca_file = Some(PathBuf::from("/etc/corp-ca.pem"));
    let options = client_options(&settings);
    assert!(options.allow_http);
    assert_eq!(options.proxy.as_deref(), Some("http://proxy.example:8080"));
    assert_eq!(
        options.extra_ca_file.as_deref(),
        Some(Path::new("/etc/corp-ca.pem"))
    );
}
