use super::*;
use clap::CommandFactory;

#[test]
fn definition_is_valid() {
    Cli::command().debug_assert();
}

#[test]
fn global_flags_map_onto_core_flags() {
    let cli = Cli::try_parse_from([
        "jtm",
        "--version",
        "--json",
        "--progress",
        "--offline",
        "--verbose",
        "--no-input",
        "--yes",
        "--config",
        "c.toml",
        "--color",
        "never",
        "--no-lock",
    ])
    .unwrap();
    let flags = GlobalFlags::from(&cli.global);
    assert_eq!(
        flags,
        GlobalFlags {
            json: true,
            progress: true,
            offline: true,
            quiet: false,
            verbose: true,
            no_input: true,
            yes: true,
            config: Some(PathBuf::from("c.toml")),
            color: Some(ColorChoice::Never),
            no_lock: true,
        }
    );
}

#[test]
fn install_takes_several_specs_and_flags() {
    let cli = Cli::try_parse_from(["jtm", "install", "a@1", "b", "--dry-run", "--force"]).unwrap();
    match cli.command {
        Some(Command::Install {
            specs,
            dry_run,
            force,
            latest,
        }) => {
            assert_eq!(specs, ["a@1", "b"]);
            assert!(dry_run && force && !latest);
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(Cli::try_parse_from(["jtm", "install"]).is_err());
}

#[test]
fn available_variant_conflicts_with_all() {
    assert!(Cli::try_parse_from(["jtm", "available", "a", "--variant", "x", "--all"]).is_err());
}

#[test]
fn quiet_conflicts_with_verbose() {
    assert!(Cli::try_parse_from(["jtm", "--version", "-q", "-v"]).is_err());
}
