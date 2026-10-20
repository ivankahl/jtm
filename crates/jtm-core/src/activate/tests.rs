use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

use super::*;
use crate::pins::{Pin, PinKind, ProjectPins};

fn sel(text: &str) -> Selector {
    Selector::parse(text).unwrap_or_else(|e| panic!("{e}"))
}

fn project(value: &str) -> ProjectPins {
    let mut pins = ProjectPins::default();
    pins.pins.insert(
        "java".to_owned(),
        Pin {
            tool: "java".to_owned(),
            selector: sel(value),
            file: PathBuf::from("/work/app/.jtm.toml"),
            kind: PinKind::Native,
            wrapper: None,
        },
    );
    pins
}

/// Every combination of the four layers setting `java`: the highest layer present wins, and
/// with none jtm does not manage the tool.
#[test]
fn the_highest_layer_that_sets_a_tool_wins() {
    for mask in 0u8..16 {
        let (exec_on, session_on, project_on, default_on) =
            (mask & 8 != 0, mask & 4 != 0, mask & 2 != 0, mask & 1 != 0);
        let exec = if exec_on {
            vec![ToolSpec::parse("java@11").unwrap()]
        } else {
            Vec::new()
        };
        let mut session = BTreeMap::new();
        if session_on {
            session.insert("java".to_owned(), sel("corretto:17.0.13"));
        }
        let pins = if project_on {
            project("temurin:21")
        } else {
            ProjectPins::default()
        };
        let mut defaults = Defaults::empty(PathBuf::from("/data/state/defaults.toml"));
        if default_on {
            defaults.set("java", sel("temurin:8.0.432+6"));
        }
        let layers = Layers {
            exec: &exec,
            session: &session,
            project: &pins,
            defaults: &defaults,
        };
        let choice = layers.choose("java");
        let expected = if exec_on {
            Some((Layer::Exec, "11", "jtm exec"))
        } else if session_on {
            Some((Layer::Session, "corretto:17.0.13", "JTM_SESSION_JAVA"))
        } else if project_on {
            Some((Layer::Project, "temurin:21", "/work/app/.jtm.toml"))
        } else if default_on {
            Some((
                Layer::Default,
                "temurin:8.0.432+6",
                "/data/state/defaults.toml",
            ))
        } else {
            None
        };
        let got = choice.as_ref().map(|c| {
            (
                c.layer,
                c.selector
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                c.origin.as_str(),
            )
        });
        let got = got.as_ref().map(|(l, s, o)| (*l, s.as_str(), *o));
        assert_eq!(got, expected, "mask {mask:04b}");
    }
}

#[test]
fn a_bare_exec_spec_means_the_plugin_default() {
    let exec = vec![ToolSpec::parse("java").unwrap()];
    let defaults = Defaults::empty(PathBuf::from("/d.toml"));
    let layers = Layers {
        exec: &exec,
        session: &BTreeMap::new(),
        project: &ProjectPins::default(),
        defaults: &defaults,
    };
    let choice = layers.choose("java").unwrap();
    assert_eq!(choice.layer, Layer::Exec);
    assert_eq!(choice.selector, None);
}

#[test]
fn session_variables_have_one_name_per_tool() {
    assert_eq!(session_var("java"), "JTM_SESSION_JAVA");
    assert_eq!(
        session_var("spring-boot-cli"),
        "JTM_SESSION_SPRING_BOOT_CLI"
    );
    assert_eq!(session_var("acme/flyway"), "JTM_SESSION_ACME__FLYWAY");
    assert_ne!(session_var("acme/flyway"), session_var("acme-flyway"));
}

#[test]
fn session_values_are_read_from_the_environment() {
    let env = |key: &str| match key {
        "JTM_SESSION_JAVA" => Some(OsString::from("temurin:21.0.5+11")),
        "JTM_SESSION_MAVEN" => Some(OsString::from("")),
        _ => None,
    };
    let tools = ["java".to_owned(), "maven".to_owned(), "gradle".to_owned()];
    let (session, warnings) = session_from_env(&tools, &env);
    assert_eq!(session.len(), 1);
    assert_eq!(session["java"], sel("temurin:21.0.5+11"));
    assert!(warnings.is_empty());
}

#[test]
fn an_invalid_session_value_is_ignored_with_a_warning() {
    let bad = |_: &str| Some(OsString::from("not a spec!"));
    let (session, warnings) = session_from_env(&["java".to_owned()], &bad);
    assert!(session.is_empty());
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].code, W_SESSION_INVALID);
    assert!(
        warnings[0].message.contains("JTM_SESSION_JAVA"),
        "{warnings:?}"
    );
}

#[test]
fn defaults_round_trip_through_the_state_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state").join("defaults.toml");
    let mut defaults = Defaults::load(&path).unwrap();
    assert_eq!(defaults.get("java"), None);
    assert!(defaults.set("java", sel("temurin:21.0.5+11")));
    assert!(!defaults.set("java", sel("temurin:21.0.5+11")));
    defaults.set("maven", sel("3.9.9"));
    defaults.save().unwrap();
    let back = Defaults::load(&path).unwrap();
    assert_eq!(back.get("java"), Some(&sel("temurin:21.0.5+11")));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        "[defaults]\njava = \"temurin:21.0.5+11\"\nmaven = \"3.9.9\"\n"
    );
    let mut back = back;
    assert!(back.remove("maven"));
    assert!(!back.remove("maven"));
}

#[test]
fn a_corrupt_defaults_file_is_an_error_not_a_reset() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("defaults.toml");
    std::fs::write(&path, "[defaults]\njava = 21\n").unwrap();
    assert!(Defaults::load(&path).is_err());
}

const JAVA: &str = include_str!("../../../jtm-plugin/tests/fixtures/manifests/valid/java.toml");

fn installed(list: &[&str]) -> Vec<Installed> {
    list.iter()
        .map(|id| {
            let (variant, version) = id.split_once(':').unwrap();
            Installed {
                variant: variant.to_owned(),
                version: version.to_owned(),
                dir: PathBuf::from(format!("/data/tools/java/{variant}-{version}")),
                home: PathBuf::from(format!("/data/tools/java/{variant}-{version}")),
            }
        })
        .collect()
}

#[test]
fn an_installed_match_is_preferred_and_the_highest_one_wins() {
    let manifest = jtm_plugin::Manifest::parse(JAVA).unwrap();
    let have = installed(&[
        "temurin:21.0.3+9",
        "temurin:21.0.5+11",
        "temurin:17.0.13+11",
        "corretto:21.0.6.7.1",
    ]);
    let pick = |s: Option<&str>| {
        let selector = s.map(sel);
        pick_installed(&manifest, selector.as_ref(), &have)
            .map(|i| format!("{}:{}", i.variant, i.version))
    };
    assert_eq!(pick(Some("21")).as_deref(), Some("temurin:21.0.5+11"));
    assert_eq!(
        pick(Some("temurin:17")).as_deref(),
        Some("temurin:17.0.13+11")
    );
    assert_eq!(
        pick(Some("corretto:21")).as_deref(),
        Some("corretto:21.0.6.7.1")
    );
    assert_eq!(pick(Some("11")), None);
    assert_eq!(pick(Some("210")), None);
    // An alias that needs index tags cannot be answered from installs alone.
    assert_eq!(pick(Some("lts")), None);
}

#[test]
fn a_tool_environment_fills_home_and_bin_placeholders() {
    let text = JAVA.replace("[env]", "[env]\nJDK_BIN = \"{bin}\"");
    let manifest = jtm_plugin::Manifest::parse(&text).unwrap();
    let home = PathBuf::from("/data/tools/java/temurin-21");
    let env = tool_env(&manifest, &home);
    assert_eq!(env.path, [home.join("bin")]);
    let vars: BTreeMap<&str, &str> = env
        .vars
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    assert_eq!(vars["JAVA_HOME"], home.display().to_string());
    assert_eq!(vars["JDK_BIN"], home.join("bin").display().to_string());
}

mod plan {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    use super::super::*;

    const TOOLS: &str = "/data/tools";

    fn over(tool: &str, layer: Layer, version: &str) -> Override {
        let home = PathBuf::from(format!("{TOOLS}/{tool}/default-{version}"));
        Override {
            tool: tool.to_owned(),
            layer,
            selector: Selector::parse(&format!("default:{version}")).unwrap(),
            env: ToolEnv {
                vars: vec![(
                    format!("{}_HOME", tool.to_uppercase()),
                    home.display().to_string(),
                )],
                path: vec![home.join("bin")],
            },
        }
    }

    /// The bin directory of a demo install, joined as `tool_env` joins it on this OS.
    fn bin(version: &str) -> String {
        PathBuf::from(format!("{TOOLS}/demo/default-{version}"))
            .join("bin")
            .display()
            .to_string()
    }

    fn plan(env: &HashMap<String, String>, overrides: &[Override]) -> Vec<Change> {
        let tools = ["demo".to_owned(), "other".to_owned()];
        plan_env(
            &|k| env.get(k).cloned(),
            overrides,
            &tools,
            Path::new(TOOLS),
            ':',
        )
    }

    /// Applies changes to an environment, as a shell would.
    fn apply(env: &mut HashMap<String, String>, changes: &[Change]) {
        for change in changes {
            match change {
                Change::Set { name, value } => {
                    env.insert(name.clone(), value.clone());
                }
                Change::Unset { name } => {
                    env.remove(name);
                }
            }
        }
    }

    /// Plans against `env` and applies the plan to it.
    fn step(env: &mut HashMap<String, String>, overrides: &[Override]) {
        let changes = plan(env, overrides);
        apply(env, &changes);
    }

    fn base() -> HashMap<String, String> {
        HashMap::from([
            (
                "PATH".to_owned(),
                "/data/current/demo/bin:/usr/bin".to_owned(),
            ),
            ("DEMO_HOME".to_owned(), "/data/current/demo".to_owned()),
        ])
    }

    #[test]
    fn a_session_override_sets_variables_and_path_and_records_itself() {
        let mut env = base();
        let changes = plan(&env, &[over("demo", Layer::Session, "1.0.0")]);
        apply(&mut env, &changes);
        assert_eq!(env["DEMO_HOME"], "/data/tools/demo/default-1.0.0");
        assert_eq!(
            env["PATH"],
            format!("{}:/data/current/demo/bin:/usr/bin", bin("1.0.0"))
        );
        assert_eq!(env["JTM_SESSION_DEMO"], "default:1.0.0");
        assert!(!env.contains_key("JTM_PROJECT_DEMO"));
        assert!(env.contains_key("JTM_SAVED"));
        // Applying the same plan again changes nothing.
        assert_eq!(plan(&env, &[over("demo", Layer::Session, "1.0.0")]), []);
    }

    #[test]
    fn switching_versions_replaces_the_path_entry() {
        let mut env = base();
        step(&mut env, &[over("demo", Layer::Session, "1.0.0")]);
        step(&mut env, &[over("demo", Layer::Project, "1.1.0")]);
        assert_eq!(
            env["PATH"],
            format!("{}:/data/current/demo/bin:/usr/bin", bin("1.1.0"))
        );
        assert_eq!(env["DEMO_HOME"], "/data/tools/demo/default-1.1.0");
        assert_eq!(env["JTM_PROJECT_DEMO"], "default:1.1.0");
        assert!(!env.contains_key("JTM_SESSION_DEMO"));
    }

    #[test]
    fn dropping_every_override_restores_the_original_environment() {
        let original = base();
        let mut env = original.clone();
        step(
            &mut env,
            &[
                over("demo", Layer::Session, "1.0.0"),
                over("other", Layer::Project, "2.0"),
            ],
        );
        assert_eq!(env["OTHER_HOME"], "/data/tools/other/default-2.0");
        step(&mut env, &[]);
        assert_eq!(env, original);
    }

    #[test]
    fn a_variable_the_user_never_set_is_unset_again() {
        let mut env = HashMap::from([("PATH".to_owned(), "/usr/bin".to_owned())]);
        step(&mut env, &[over("demo", Layer::Session, "1.0.0")]);
        assert!(env.contains_key("DEMO_HOME"));
        step(&mut env, &[]);
        assert_eq!(
            env,
            HashMap::from([("PATH".to_owned(), "/usr/bin".to_owned())])
        );
    }

    #[test]
    fn nothing_to_change_plans_nothing() {
        assert_eq!(plan(&base(), &[]), []);
    }
}
