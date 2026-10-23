use std::fs;

use jtm_security::testing::TestKey;

use crate::context::{Context, GlobalFlags, Terminal};
use crate::error::ExitCode;
use crate::install::Receipt;
use crate::plugins::BuiltinManifest;
use crate::{Config, ConfigInputs, Dirs, Platform};

use super::*;

/// A temp dir holding `bin/tool` and, beside `bin`, a file `outside`.
fn setup() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::write(bin.join("tool"), "").unwrap();
    fs::write(root.path().join("outside"), "").unwrap();
    (root, bin)
}

#[test]
fn finds_a_bare_command_in_the_dirs() {
    let (_root, bin) = setup();
    assert_eq!(
        find_in_dirs("tool", std::slice::from_ref(&bin), Os::Linux),
        Some(bin.join("tool"))
    );
    assert_eq!(find_in_dirs("missing", &[bin], Os::Linux), None);
}

#[test]
fn never_resolves_a_path_against_the_dirs() {
    let (root, bin) = setup();
    let absolute = root.path().join("outside");
    let dirs = [bin];
    for command in [
        absolute.to_str().unwrap(),
        "../outside",
        "./tool",
        "sub/tool",
        "sub\\tool",
        "..",
        ".",
        "",
        "C:tool",
    ] {
        assert_eq!(find_in_dirs(command, &dirs, Os::Linux), None, "{command}");
        assert_eq!(find_in_dirs(command, &dirs, Os::Windows), None, "{command}");
    }
}

#[test]
fn a_bare_name_is_one_plain_file_name() {
    assert!(is_bare_name("java"));
    assert!(is_bare_name("mvn.cmd"));
    assert!(!is_bare_name("bin/java"));
    assert!(!is_bare_name("/usr/bin/java"));
    assert!(!is_bare_name("..\\java"));
    assert!(!is_bare_name("C:java"));
    assert!(!is_bare_name("ja\0va"));
    assert!(!is_bare_name(".."));
    assert!(!is_bare_name(""));
}

// --- installs that cannot be read ---

/// A test manifest for `name`, with `requires` as the body of its `[requires]` table.
fn manifest(name: &str, requires: &str) -> &'static str {
    let key = TestKey::generate().public_str();
    let text = format!(
        r#"
schema = 1
name = "{name}"
display_name = "Demo"
[versions]
scheme = "semver-loose"
[index]
url = "https://example.test/{name}-{{os}}-{{arch}}.json"
signing_keys = ["{key}"]
format = 1
[layout]
bin_dirs = ["bin"]
[requires]
{requires}
"#
    );
    Box::leak(text.into_boxed_str())
}

/// A home where `app` requires `base`, both are user defaults, and the installs of `broken`
/// cannot be listed, because `tools/<broken>` is a file.
struct Broken {
    home: tempfile::TempDir,
    cwd: tempfile::TempDir,
    ctx: Context,
}

impl Broken {
    fn new(broken: &str) -> Broken {
        let home = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let builtin: &'static [BuiltinManifest] = Box::leak(Box::new([
            BuiltinManifest {
                name: "app",
                text: manifest("app", "base = \">=2\""),
            },
            BuiltinManifest {
                name: "base",
                text: manifest("base", ""),
            },
        ]));
        let mut ctx = Context::resolve(
            &GlobalFlags::default(),
            |_| None,
            Terminal {
                stdin: false,
                stderr: false,
            },
            builtin,
        )
        .unwrap();
        ctx.home = Some(home.path().to_path_buf());
        let f = Broken { home, cwd, ctx };
        let dirs = f.dirs();
        fs::create_dir_all(dirs.defaults_file().parent().unwrap()).unwrap();
        fs::write(
            dirs.defaults_file(),
            "[defaults]\napp = \"1\"\nbase = \"1\"\n",
        )
        .unwrap();
        fs::create_dir_all(dirs.tools()).unwrap();
        fs::write(dirs.tools().join(broken), "not a directory").unwrap();
        f
    }

    /// Records `tool` 1.0 as installed, with a receipt and nothing else.
    fn install(&self, tool: &str) {
        let dir = self.dirs().tools().join(tool).join("default-1.0");
        fs::create_dir_all(&dir).unwrap();
        Receipt {
            plugin: tool.to_owned(),
            manifest_sha256: String::new(),
            variant: "default".to_owned(),
            version: "1.0".to_owned(),
            platform: Platform::detect().unwrap().as_str().to_owned(),
            url: String::new(),
            sha256: String::new(),
            size: 0,
            index_sequence: 0,
            installed_at: String::new(),
            jtm_version: String::new(),
            home: String::new(),
        }
        .write(&dir)
        .unwrap();
    }

    fn dirs(&self) -> Dirs {
        Dirs::resolve(Os::host().unwrap(), Some(self.home.path()), None, &|_| None).unwrap()
    }

    fn session(&self) -> Session<'_> {
        let settings = Config::load(&ConfigInputs {
            user: None,
            project: None,
            env: &|_| None,
            flags: &[],
        })
        .unwrap()
        .settings;
        Session::new(
            &self.ctx,
            self.dirs(),
            settings,
            Platform::detect().unwrap(),
        )
        .unwrap()
    }

    fn here<'s, 'c>(
        &self,
        session: &'s Session<'c>,
        env: &dyn Fn(&str) -> Option<OsString>,
    ) -> Here<'s, 'c> {
        Here::read(session, self.cwd.path(), env).unwrap()
    }
}

/// Asserts that `result` failed because installs cannot be read: `E_IO`, exit code 4.
fn assert_unreadable<T: std::fmt::Debug>(result: Result<T>) {
    let err = result.unwrap_err();
    assert_eq!(err.code(), "E_IO", "{err}");
    assert_eq!(err.exit_code(), ExitCode::Io, "{err}");
}

#[test]
fn current_fails_when_a_tool_set_here_cannot_be_read() {
    let f = Broken::new("base");
    let session = f.session();
    let here = f.here(&session, &|_| None);
    assert_unreadable(here.current(None));
    assert_unreadable(here.current(Some("base")));
    // A tool whose own installs can be read is still shown on its own.
    let items = here.current(Some("app")).unwrap();
    assert_eq!(items.len(), 1);
    assert!(!items[0].installed);
}

#[test]
fn the_requirements_check_fails_when_a_required_tool_cannot_be_read() {
    let f = Broken::new("base");
    f.install("app");
    let session = f.session();
    let here = f.here(&session, &|_| None);
    assert_unreadable(here.requirement_warnings(&[], &[]));
}

#[test]
fn the_requirements_check_fails_when_a_requiring_tool_cannot_be_read() {
    let f = Broken::new("app");
    let session = f.session();
    let here = f.here(&session, &|_| None);
    assert_unreadable(here.requirement_warnings(&[], &[]));
}

#[test]
fn installs_that_can_be_read_but_are_missing_are_not_an_error() {
    let f = Broken::new("unrelated");
    let session = f.session();
    let here = f.here(&session, &|_| None);
    let items = here.current(None).unwrap();
    assert!(items.iter().all(|i| !i.installed), "{items:?}");
    assert!(here.requirement_warnings(&[], &items).unwrap().is_empty());
}

#[test]
fn an_unmet_requirement_is_still_only_a_warning() {
    let f = Broken::new("unrelated");
    f.install("app");
    f.install("base");
    let session = f.session();
    let here = f.here(&session, &|_| None);
    let items = here.current(None).unwrap();
    assert!(items.iter().all(|i| i.installed), "{items:?}");
    let warnings = here.requirement_warnings(&[], &items).unwrap();
    let codes: Vec<&str> = warnings.iter().map(|w| w.code).collect();
    assert_eq!(codes, [W_REQUIRES_UNMET], "{warnings:?}");
}

#[test]
fn a_session_version_that_cannot_be_read_fails_env_and_use() {
    let f = Broken::new("base");
    let session = f.session();
    let env = |key: &str| (key == "JTM_SESSION_BASE").then(|| OsString::from("1"));
    let here = f.here(&session, &env);
    assert_unreadable(here.overrides(&[]));
}
