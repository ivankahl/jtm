use super::*;
use std::collections::HashMap;

const TTY: Terminal = Terminal {
    stdin: true,
    stderr: true,
};

fn resolve(flags: GlobalFlags, vars: &[(&str, &str)], terminal: Terminal) -> Result<Context> {
    let vars: HashMap<String, OsString> = vars
        .iter()
        .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
        .collect();
    Context::resolve(&flags, |key| vars.get(key).cloned(), terminal, &[])
}

fn ok(flags: GlobalFlags, vars: &[(&str, &str)]) -> Context {
    resolve(flags, vars, TTY).unwrap()
}

#[test]
fn defaults_in_a_terminal() {
    let ctx = ok(GlobalFlags::default(), &[]);
    assert!(!ctx.json);
    assert!(!ctx.offline);
    assert!(ctx.interactive);
    assert!(!ctx.assume_yes);
    assert!(ctx.color);
    assert_eq!(ctx.verbosity, Verbosity::Normal);
    assert_eq!(ctx.log_filter, "warn");
    assert_eq!(ctx.config_path, None);
    assert_eq!(ctx.home, None);
    assert!(ctx.use_lockfile);
    assert!(!ctx.ci);
}

#[test]
fn env_vars_apply_when_no_flag_is_given() {
    let ctx = ok(
        GlobalFlags::default(),
        &[
            ("JTM_OFFLINE", "1"),
            ("JTM_NO_INPUT", "true"),
            ("JTM_CONFIG", "/env/config.toml"),
            ("JTM_HOME", "/env/home"),
            ("JTM_LOG", "jtm_core=trace"),
        ],
    );
    assert!(ctx.offline);
    assert!(!ctx.interactive);
    assert_eq!(ctx.config_path, Some(PathBuf::from("/env/config.toml")));
    assert_eq!(ctx.home, Some(PathBuf::from("/env/home")));
    assert_eq!(ctx.log_filter, "jtm_core=trace");
}

#[test]
fn config_flag_beats_jtm_config() {
    let flags = GlobalFlags {
        config: Some(PathBuf::from("/flag/config.toml")),
        ..GlobalFlags::default()
    };
    let ctx = ok(flags, &[("JTM_CONFIG", "/env/config.toml")]);
    assert_eq!(ctx.config_path, Some(PathBuf::from("/flag/config.toml")));
}

#[test]
fn verbosity_flags_beat_jtm_log() {
    let vars = [("JTM_LOG", "trace")];
    let verbose = GlobalFlags {
        verbose: true,
        ..GlobalFlags::default()
    };
    assert_eq!(ok(verbose, &vars).log_filter, "debug");
    let quiet = GlobalFlags {
        quiet: true,
        ..GlobalFlags::default()
    };
    assert_eq!(ok(quiet, &vars).log_filter, "error");
}

#[test]
fn offline_flag_beats_jtm_offline_off() {
    let flags = GlobalFlags {
        offline: true,
        ..GlobalFlags::default()
    };
    assert!(ok(flags, &[("JTM_OFFLINE", "0")]).offline);
}

#[test]
fn no_input_flag_beats_jtm_no_input_off() {
    let flags = GlobalFlags {
        no_input: true,
        ..GlobalFlags::default()
    };
    assert!(!ok(flags, &[("JTM_NO_INPUT", "false")]).interactive);
}

#[test]
fn color_flag_beats_ci_and_no_color() {
    let always = GlobalFlags {
        color: Some(ColorChoice::Always),
        ..GlobalFlags::default()
    };
    assert!(ok(always, &[("CI", "true"), ("NO_COLOR", "1")]).color);
    let never = GlobalFlags {
        color: Some(ColorChoice::Never),
        ..GlobalFlags::default()
    };
    assert!(!ok(never, &[]).color);
}

#[test]
fn ci_implies_no_input_and_no_colour() {
    for value in ["true", "1", "github-actions"] {
        let ctx = ok(GlobalFlags::default(), &[("CI", value)]);
        assert!(ctx.ci, "CI={value}");
        assert!(!ctx.interactive, "CI={value}");
        assert!(!ctx.color, "CI={value}");
    }
    for value in ["false", "0", ""] {
        let ctx = ok(GlobalFlags::default(), &[("CI", value)]);
        assert!(!ctx.ci, "CI={value}");
        assert!(ctx.interactive, "CI={value}");
    }
}

#[test]
fn json_is_never_interactive() {
    let flags = GlobalFlags {
        json: true,
        ..GlobalFlags::default()
    };
    let ctx = ok(flags, &[]);
    assert!(!ctx.interactive);
    assert!(!ctx.color);
}

#[test]
fn no_terminal_is_never_interactive() {
    for terminal in [
        Terminal {
            stdin: false,
            stderr: true,
        },
        Terminal {
            stdin: true,
            stderr: false,
        },
    ] {
        let ctx = resolve(GlobalFlags::default(), &[], terminal).unwrap();
        assert!(!ctx.interactive, "{terminal:?}");
    }
}

#[test]
fn progress_only_applies_with_json() {
    let progress = GlobalFlags {
        progress: true,
        ..GlobalFlags::default()
    };
    assert!(!ok(progress.clone(), &[]).progress);
    let json = GlobalFlags {
        json: true,
        ..progress
    };
    assert!(ok(json, &[]).progress);
}

#[test]
fn yes_and_no_lock_flags_are_carried_through() {
    let flags = GlobalFlags {
        yes: true,
        no_lock: true,
        ..GlobalFlags::default()
    };
    let ctx = ok(flags, &[]);
    assert!(ctx.assume_yes);
    assert!(!ctx.use_lockfile);
}

#[test]
fn empty_env_values_count_as_unset() {
    let ctx = ok(
        GlobalFlags::default(),
        &[
            ("JTM_HOME", ""),
            ("JTM_CONFIG", ""),
            ("JTM_OFFLINE", ""),
            ("JTM_LOG", ""),
        ],
    );
    assert_eq!(ctx.home, None);
    assert_eq!(ctx.config_path, None);
    assert!(!ctx.offline);
    assert_eq!(ctx.log_filter, "warn");
}

#[test]
fn unrecognised_boolean_env_value_is_a_usage_error() {
    let err = resolve(GlobalFlags::default(), &[("JTM_OFFLINE", "maybe")], TTY).unwrap_err();
    assert_eq!(err.code(), "E_USAGE");
    assert!(err.to_string().contains("JTM_OFFLINE"));
}

#[test]
fn quiet_and_verbose_together_is_a_usage_error() {
    let flags = GlobalFlags {
        quiet: true,
        verbose: true,
        ..GlobalFlags::default()
    };
    let err = resolve(flags, &[], TTY).unwrap_err();
    assert_eq!(err.code(), "E_USAGE");
}
