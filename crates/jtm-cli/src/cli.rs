//! Command-line definition.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use jtm_core::{ColorChoice, GlobalFlags};

/// Runtime manager for the JVM ecosystem.
#[derive(Debug, Parser)]
#[command(
    name = "jtm",
    disable_version_flag = true,
    arg_required_else_help = true
)]
pub(crate) struct Cli {
    /// Print the jtm version.
    #[arg(short = 'V', long)]
    pub(crate) version: bool,

    #[command(flatten)]
    pub(crate) global: GlobalArgs,

    #[command(subcommand)]
    pub(crate) command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Download, verify and extract versions. Never changes the default.
    Install {
        /// What to install, such as `java@temurin:21`, `maven@3.9.9` or `gradle`.
        #[arg(required = true, value_name = "SPEC")]
        specs: Vec<String>,
        /// Show what would be installed without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Reinstall even when the version is already installed.
        #[arg(long)]
        force: bool,
        /// Refresh the index first, so the newest versions are considered.
        #[arg(long)]
        latest: bool,
    },
    /// Remove an installed version and clear a current link that points at it.
    Uninstall {
        /// The version to remove, such as `java@temurin:21.0.5+11` or `maven@3.9.9`.
        #[arg(value_name = "TOOL@VERSION")]
        spec: String,
        /// Remove the version from every variant, not only the default one.
        #[arg(long)]
        all_variants: bool,
        /// Show what would be removed without changing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// List installed versions.
    List {
        /// Only list this tool.
        tool: Option<String>,
    },
    /// List versions the index offers for this platform.
    Available {
        tool: String,
        /// Show this variant instead of the default one.
        #[arg(long, conflicts_with = "all")]
        variant: Option<String>,
        /// Only show the version this alias resolves to.
        #[arg(long)]
        alias: Option<String>,
        /// Show every variant.
        #[arg(long)]
        all: bool,
    },
    /// Manage keys trusted to sign version indices.
    #[command(subcommand)]
    Trust(TrustCommand),
}

#[derive(Debug, Subcommand)]
pub(crate) enum TrustCommand {
    /// Trust a minisign public key to sign the indices of the named plugins.
    Add {
        /// The public key: the base64 line of a minisign.pub file, starting with `RW`.
        key: String,
        /// A plugin the key may sign indices for. Repeat for several plugins.
        #[arg(long, value_name = "PLUGIN", required = true)]
        scope: Vec<String>,
    },
    /// Stop trusting a key, for the named plugins or entirely.
    Remove {
        /// The public key, or its 16-digit key id.
        key: String,
        /// Only stop trusting it for this plugin. Repeatable; without it the key is removed.
        #[arg(long, value_name = "PLUGIN")]
        scope: Vec<String>,
    },
    /// List the keys you trust and their scopes.
    List,
}

/// Flags accepted by every command.
#[derive(Debug, Args)]
pub(crate) struct GlobalArgs {
    /// Write one JSON envelope to stdout; logs go to stderr.
    #[arg(long, global = true)]
    json: bool,

    /// With --json, stream newline-delimited progress events to stderr.
    #[arg(long, global = true)]
    progress: bool,

    /// Never use the network; use embedded and cached data only [env: JTM_OFFLINE].
    #[arg(long, global = true)]
    offline: bool,

    /// Only show errors.
    #[arg(short, long, global = true, conflicts_with = "verbose")]
    quiet: bool,

    /// Show debug logs; overrides JTM_LOG.
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Never prompt; fail with exit code 7 instead [env: JTM_NO_INPUT].
    #[arg(long, global = true)]
    no_input: bool,

    /// Accept routine confirmations. Never accepts trust changes.
    #[arg(short, long, global = true)]
    yes: bool,

    /// Use this config file instead of the user config [env: JTM_CONFIG].
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    /// When to use colour.
    #[arg(long, global = true, value_name = "WHEN")]
    color: Option<Color>,

    /// Ignore jtm.lock.
    #[arg(long, global = true)]
    no_lock: bool,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Color {
    Auto,
    Always,
    Never,
}

impl From<&GlobalArgs> for GlobalFlags {
    fn from(args: &GlobalArgs) -> Self {
        GlobalFlags {
            json: args.json,
            progress: args.progress,
            offline: args.offline,
            quiet: args.quiet,
            verbose: args.verbose,
            no_input: args.no_input,
            yes: args.yes,
            config: args.config.clone(),
            color: args.color.map(|c| match c {
                Color::Auto => ColorChoice::Auto,
                Color::Always => ColorChoice::Always,
                Color::Never => ColorChoice::Never,
            }),
            no_lock: args.no_lock,
        }
    }
}

#[cfg(test)]
mod tests {
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
    fn trust_add_requires_a_scope() {
        assert!(Cli::try_parse_from(["jtm", "trust", "add", "RWkey"]).is_err());
        let cli = Cli::try_parse_from([
            "jtm", "trust", "add", "RWkey", "--scope", "a", "--scope", "b",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Trust(TrustCommand::Add { key, scope })) => {
                assert_eq!(key, "RWkey");
                assert_eq!(scope, ["a", "b"]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn install_takes_several_specs_and_flags() {
        let cli =
            Cli::try_parse_from(["jtm", "install", "a@1", "b", "--dry-run", "--force"]).unwrap();
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
}
