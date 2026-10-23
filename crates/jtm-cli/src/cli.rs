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
    /// Set the persistent user-wide version of a tool.
    Default {
        /// The version to make the default, such as `java@temurin:21` or `maven@3.9`.
        #[arg(value_name = "SPEC")]
        spec: String,
        /// Install the version first when it is missing.
        #[arg(long)]
        install: bool,
        /// Refresh the index and use the newest match instead of an installed one.
        #[arg(long)]
        latest: bool,
    },
    /// Use a version in the current shell only. Needs the shell hook from `jtm shell-init`.
    Use {
        /// The version to use, such as `java@21`; with `--unset`, only the tool.
        #[arg(value_name = "SPEC")]
        spec: String,
        /// Stop using a session version, going back to the project pin or default.
        #[arg(long, conflicts_with_all = ["install", "latest"])]
        unset: bool,
        /// Install the version first when it is missing.
        #[arg(long)]
        install: bool,
        /// Refresh the index and use the newest match instead of an installed one.
        #[arg(long)]
        latest: bool,
        /// Print code for this shell; the shell hook passes it.
        #[arg(long, value_name = "SHELL")]
        shell: Option<String>,
    },
    /// Print the environment changes for the active versions.
    Env {
        /// bash, zsh, fish, pwsh or cmd; the default is bash, or pwsh on Windows.
        #[arg(long, value_name = "SHELL")]
        shell: Option<String>,
    },
    /// Print the shell hook for bash, zsh, fish or pwsh.
    ShellInit {
        #[arg(value_name = "SHELL")]
        shell: String,
    },
    /// Pin a version for the current project, in `.jtm.toml` or an interop file.
    Pin {
        /// The version to pin, such as `java@temurin:21` or `maven@3.9`.
        #[arg(value_name = "SPEC")]
        spec: String,
        /// The file to write: native (.jtm.toml) or an interop format such as sdkmanrc,
        /// tool-versions or java-version. The default is `pin.default_format`.
        #[arg(long)]
        format: Option<String>,
        /// Pin the exact version the spec resolves to.
        #[arg(long)]
        exact: bool,
        /// Show what would be written without changing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove a tool's project pin.
    Unpin {
        tool: String,
        /// Only remove it from files in this format.
        #[arg(long)]
        format: Option<String>,
    },
    /// Show the active version of each tool and the layer that set it.
    Current { tool: Option<String> },
    /// Show the executable a command runs here, and which layer chose it.
    Which { command: String },
    /// Run a command with specific versions, without changing any state.
    Exec {
        /// Versions to use, such as `java@17`.
        #[arg(value_name = "SPEC")]
        specs: Vec<String>,
        /// Install missing versions first.
        #[arg(long)]
        install: bool,
        /// Refresh the index and use the newest matches.
        #[arg(long)]
        latest: bool,
        /// The command to run, after `--`.
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<String>,
    },
    /// Install everything the project's pins need and update jtm.lock.
    Sync {
        /// Show what would be installed and locked without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Fail instead of changing jtm.lock. For CI.
        #[arg(long)]
        frozen: bool,
    },
    /// Resolve the project's pins and write jtm.lock without installing.
    Lock {
        /// Lock only this platform, such as `linux-x64`. Repeatable.
        #[arg(long, value_name = "PLATFORM")]
        platform: Vec<String>,
        /// Move locked versions forward: every tool, or only the one named.
        #[arg(long, value_name = "TOOL", num_args = 0..=1, default_missing_value = "")]
        upgrade: Option<String>,
        /// Show what would be locked without writing jtm.lock.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print the changes the shell hook applies at a prompt. Called by the hook itself.
    #[command(hide = true)]
    HookEnv {
        #[arg(long, value_name = "SHELL")]
        shell: String,
    },
    /// Offer installed JDKs to Maven and Gradle toolchains, which IDEs read.
    #[command(subcommand)]
    Ide(IdeCommand),
    /// Manage jtm itself.
    #[command(subcommand, name = "self")]
    SelfCmd(SelfCommand),
    /// Diagnose PATH, current links, the shell hook, proxy, TLS, the trust store and yanked
    /// plugins. Only reads; exits with the code of the first check that fails.
    Doctor,
    /// Copy signed indices and artifacts for a corporate or air-gapped mirror.
    #[command(subcommand)]
    Mirror(MirrorCommand),
}

#[derive(Debug, Subcommand)]
pub(crate) enum MirrorCommand {
    /// Copy verified indices, their signatures and, with --artifacts, every archive they list
    /// into a directory that `[mirrors]` or `plugins.<name>.index_url` can point at. Files are
    /// laid out as `<dir>/<host>/<path of the URL>`.
    Export {
        /// The directory to export into; created when missing.
        dir: PathBuf,
        /// Export only this plugin. Repeatable; the default is every plugin.
        #[arg(long, value_name = "NAME")]
        plugin: Vec<String>,
        /// Export only this platform, such as `linux-x64`. Repeatable; the default is every
        /// platform a plugin publishes an index for.
        #[arg(long, value_name = "PLATFORM")]
        platform: Vec<String>,
        /// Also copy every archive the indices list. Verified against the signed index.
        #[arg(long)]
        artifacts: bool,
        /// Show what would be exported without writing or downloading anything.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum IdeCommand {
    /// Write installed JDKs into ~/.m2/toolchains.xml and Gradle's
    /// org.gradle.java.installations.paths, leaving other entries alone.
    Sync {
        /// Show what would change without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Only update Maven's toolchains.xml.
        #[arg(long, conflicts_with = "gradle_only")]
        maven_only: bool,
        /// Only update Gradle's gradle.properties.
        #[arg(long)]
        gradle_only: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum SelfCommand {
    /// Put the default versions on the user PATH and set their variables, without admin
    /// rights, and load the shell hook so project pins apply on cd. Edits your shell's rc file
    /// (your PowerShell profile on Windows) after confirmation or with --yes.
    Setup {
        /// Show what would change without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Leave out the shell hook (`jtm shell-init`), so only the default versions are set
        /// up. Re-running without it adds the hook back.
        #[arg(long)]
        no_hook: bool,
    },
    /// Take jtm out of your environment: the rc-file and profile lines, the user PATH and
    /// variables `self setup` set, the current links and the defaults. Asks first, or --yes.
    /// Installed versions stay unless --purge; the config file and jtm itself always stay.
    Uninstall {
        /// Show what would be removed without removing anything.
        #[arg(long)]
        dry_run: bool,
        /// Also delete installed versions, plugins, trust and the download cache.
        #[arg(long)]
        purge: bool,
    },
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
mod tests;
