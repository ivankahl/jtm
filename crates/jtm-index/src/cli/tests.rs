use std::collections::HashMap;
use std::fs;
use std::path::Path;

use clap::Parser;
use jtm_core::Platform;
use serde_json::Value;

use super::*;
use crate::candidate::Target;
use crate::confirm::Confirmed;
use crate::testing::{confirmed_entry, minisign_key};

const MANIFEST: &str = r#"
schema = 1
name = "demo"
display_name = "Demo"

[versions]
scheme = "semver-loose"
variants = ["alpha"]
default_variant = "alpha"

[index]
url = "https://index.example.test/demo-{os}-{arch}.json"
signing_keys = ["RWRysDZolh28UjrMjL/6mCMDPnqfDtDj5Al+TxN8z6RkXGawmRo1ob7K"]
format = 1

[layout]
bin_dirs = ["bin"]
"#;

const SOURCES: &str = r#"
schema = 1

[[source]]
id = "only"
adapter = "gradle"
role = "primary"
variant = "alpha"
hash_from = "versions-api"
"#;

/// 2026-10-19T03:00:00Z
const NOW: &str = "2026-10-19T03:00:00Z";

struct Setup {
    plugin: tempfile::TempDir,
    out: tempfile::TempDir,
    scratch: tempfile::TempDir,
}

impl Setup {
    fn new() -> Setup {
        let plugin = tempfile::tempdir().unwrap();
        fs::write(plugin.path().join("plugin.toml"), MANIFEST).unwrap();
        fs::write(plugin.path().join("sources.toml"), SOURCES).unwrap();
        Setup {
            plugin,
            out: tempfile::tempdir().unwrap(),
            scratch: tempfile::tempdir().unwrap(),
        }
    }

    fn args(&self, extra: &[&str]) -> Vec<String> {
        let mut args = vec![
            "jtm-index".to_owned(),
            "generate".to_owned(),
            "--plugin-dir".to_owned(),
            self.plugin.path().display().to_string(),
            "--out".to_owned(),
            self.out.path().display().to_string(),
            "--now".to_owned(),
            NOW.to_owned(),
        ];
        args.extend(extra.iter().map(|s| (*s).to_owned()));
        args
    }

    fn secret_file(&self, text: &str) -> String {
        let path = self.scratch.path().join("minisign.key");
        fs::write(&path, text).unwrap();
        path.display().to_string()
    }
}

fn confirmed() -> Confirmed {
    Confirmed {
        entries: vec![
            confirmed_entry(Some("alpha"), "1.0.0", Target::Platform(Platform::LinuxX64)),
            confirmed_entry(
                Some("alpha"),
                "1.0.0",
                Target::Platform(Platform::WindowsX64),
            ),
        ],
        warnings: vec!["a vendor note".to_owned()],
    }
}

struct Outcome {
    code: u8,
    stdout: String,
    stderr: String,
}

impl Outcome {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("stdout is not one JSON document ({e}): {}", self.stdout))
    }
}

fn run_with(args: Vec<String>, env: &[(&str, &str)], entries: Confirmed) -> Outcome {
    let env: HashMap<String, String> = env
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let cli = Cli::try_parse_from(args).unwrap();
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let code = execute(
        &cli,
        &|name| env.get(name).cloned(),
        &|_plugin| Ok(entries.clone()),
        &mut stdout,
        &mut stderr,
    );
    Outcome {
        code,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

fn run(args: Vec<String>, env: &[(&str, &str)]) -> Outcome {
    run_with(args, env, confirmed())
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------------------------

#[test]
fn a_secret_key_cannot_come_from_a_file_and_the_environment_at_once() {
    let parsed = Cli::try_parse_from([
        "jtm-index",
        "generate",
        "--plugin-dir",
        "p",
        "--out",
        "o",
        "--secret-key",
        "k",
        "--secret-key-env",
        "K",
    ]);
    assert!(parsed.is_err());
}

#[test]
fn a_password_cannot_come_from_a_file_and_the_environment_at_once() {
    let parsed = Cli::try_parse_from([
        "jtm-index",
        "generate",
        "--plugin-dir",
        "p",
        "--out",
        "o",
        "--password-file",
        "k",
        "--password-env",
        "K",
    ]);
    assert!(parsed.is_err());
}

#[test]
fn there_is_no_flag_to_put_a_password_or_a_key_on_the_command_line() {
    for flag in ["--password", "--secret-key-text"] {
        let parsed = Cli::try_parse_from([
            "jtm-index",
            "generate",
            "--plugin-dir",
            "p",
            "--out",
            "o",
            flag,
            "value",
        ]);
        assert!(parsed.is_err(), "{flag} must not exist");
    }
}

#[test]
fn json_is_accepted_before_and_after_the_subcommand() {
    for position in [
        vec!["jtm-index", "--json", "generate"],
        vec!["jtm-index", "generate", "--json"],
    ] {
        let mut args = position;
        args.extend(["--plugin-dir", "p", "--out", "o"]);
        assert!(Cli::try_parse_from(args).unwrap().json);
    }
}

// ---------------------------------------------------------------------------------------------
// A run with a key
// ---------------------------------------------------------------------------------------------

#[test]
fn a_key_file_signs_and_json_reports_one_envelope() {
    let setup = Setup::new();
    let key = minisign_key();
    let secret = setup.secret_file(&key.secret_file);
    let outcome = run(setup.args(&["--json", "--secret-key", &secret]), &[]);

    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let json = outcome.json();
    assert_eq!(json["ok"], true);
    assert_eq!(json["command"], "generate");
    assert_eq!(json["changed"], true);
    assert_eq!(json["data"]["plugin"], "demo");
    assert_eq!(json["data"]["dry_run"], false);
    assert_eq!(json["data"]["public_key"], key.public.as_str());
    assert_eq!(json["data"]["files"].as_array().unwrap().len(), 2);
    assert_eq!(json["data"]["files"][0]["action"], "created");
    assert_eq!(json["jtm_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(json["warnings"][0]["code"], "W_SOURCE_NOTE");
    assert_eq!(json["warnings"][0]["message"], "a vendor note");
    assert!(json["warnings"][0]["details"].is_object());
    assert_eq!(
        names(setup.out.path()),
        [
            "demo-linux-x64.json",
            "demo-linux-x64.json.minisig",
            "demo-windows-x64.json",
            "demo-windows-x64.json.minisig"
        ]
    );
}

#[test]
fn logs_and_notes_stay_off_stdout_in_json_mode() {
    let setup = Setup::new();
    let secret = setup.secret_file(&minisign_key().secret_file);
    let outcome = run(setup.args(&["--json", "--secret-key", &secret]), &[]);
    // `json()` fails unless stdout is exactly one document.
    outcome.json();
    assert!(outcome.stderr.is_empty(), "{}", outcome.stderr);
}

#[test]
fn a_key_from_the_environment_signs() {
    let setup = Setup::new();
    let key = minisign_key();
    let outcome = run(
        setup.args(&["--json", "--secret-key-env", "INDEX_KEY"]),
        &[("INDEX_KEY", &key.secret_file)],
    );
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.json()["data"]["public_key"], key.public.as_str());
}

#[test]
fn a_password_from_the_environment_opens_an_encrypted_key() {
    let setup = Setup::new();
    let pair =
        minisign::KeyPair::generate_encrypted_keypair(Some("correct horse".to_owned())).unwrap();
    let secret = setup.secret_file(&pair.sk.to_box(None).unwrap().into_string());
    let outcome = run(
        setup.args(&[
            "--json",
            "--secret-key",
            &secret,
            "--password-env",
            "KEY_PASSWORD",
        ]),
        &[("KEY_PASSWORD", "correct horse")],
    );
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
}

#[test]
fn a_password_from_the_environment_loses_its_trailing_newline_too() {
    // A CI secret set with `echo` carries one.
    let setup = Setup::new();
    let pair =
        minisign::KeyPair::generate_encrypted_keypair(Some("correct horse".to_owned())).unwrap();
    let secret = setup.secret_file(&pair.sk.to_box(None).unwrap().into_string());
    let outcome = run(
        setup.args(&[
            "--json",
            "--secret-key",
            &secret,
            "--password-env",
            "KEY_PASSWORD",
        ]),
        &[("KEY_PASSWORD", "correct horse\r\n")],
    );
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
}

#[test]
fn a_password_from_a_file_loses_its_trailing_newline() {
    let setup = Setup::new();
    let pair =
        minisign::KeyPair::generate_encrypted_keypair(Some("correct horse".to_owned())).unwrap();
    let secret = setup.secret_file(&pair.sk.to_box(None).unwrap().into_string());
    let password = setup.scratch.path().join("password");
    fs::write(&password, "correct horse\n").unwrap();
    let outcome = run(
        setup.args(&[
            "--json",
            "--secret-key",
            &secret,
            "--password-file",
            &password.display().to_string(),
        ]),
        &[],
    );
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
}

#[test]
fn a_wrong_password_fails_without_echoing_the_password_or_the_key() {
    let setup = Setup::new();
    let pair =
        minisign::KeyPair::generate_encrypted_keypair(Some("correct horse".to_owned())).unwrap();
    let secret_text = pair.sk.to_box(None).unwrap().into_string();
    let secret = setup.secret_file(&secret_text);
    let outcome = run(
        setup.args(&[
            "--json",
            "--secret-key",
            &secret,
            "--password-env",
            "KEY_PASSWORD",
        ]),
        &[("KEY_PASSWORD", "battery staple")],
    );
    assert_eq!(outcome.code, 2);
    let json = outcome.json();
    assert_eq!(json["ok"], false);
    assert_eq!(json["error"]["code"], "E_USAGE");
    let all = format!("{}{}", outcome.stdout, outcome.stderr);
    assert!(!all.contains("battery staple"), "{all}");
    assert!(!all.contains("correct horse"), "{all}");
    assert!(!all.contains(secret_text.lines().nth(1).unwrap()), "{all}");
    assert!(names(setup.out.path()).is_empty());
}

#[test]
fn an_encrypted_key_without_a_password_fails_instead_of_asking() {
    let setup = Setup::new();
    let pair =
        minisign::KeyPair::generate_encrypted_keypair(Some("correct horse".to_owned())).unwrap();
    let secret = setup.secret_file(&pair.sk.to_box(None).unwrap().into_string());
    let outcome = run(setup.args(&["--json", "--secret-key", &secret]), &[]);
    assert_eq!(outcome.code, 2);
    assert_eq!(outcome.json()["error"]["code"], "E_USAGE");
}

#[test]
fn an_unset_environment_variable_is_named_but_nothing_else() {
    let setup = Setup::new();
    let outcome = run(
        setup.args(&["--json", "--secret-key-env", "INDEX_KEY"]),
        &[],
    );
    assert_eq!(outcome.code, 2);
    let message = outcome.json()["error"]["message"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(message.contains("INDEX_KEY"), "{message}");
}

#[test]
fn a_run_without_a_key_is_a_usage_error_that_names_the_flags() {
    let setup = Setup::new();
    let outcome = run(setup.args(&["--json"]), &[]);
    assert_eq!(outcome.code, 2);
    let json = outcome.json();
    assert_eq!(json["ok"], false);
    assert_eq!(json["error"]["code"], "E_USAGE");
    assert_eq!(json["error"]["retryable"], false);
    let message = json["error"]["message"].as_str().unwrap();
    assert!(message.contains("--secret-key"), "{message}");
    assert!(names(setup.out.path()).is_empty());
}

// ---------------------------------------------------------------------------------------------
// Dry runs
// ---------------------------------------------------------------------------------------------

#[test]
fn a_dry_run_needs_no_key_and_writes_nothing() {
    let setup = Setup::new();
    let outcome = run(setup.args(&["--json", "--dry-run"]), &[]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    let json = outcome.json();
    assert_eq!(json["data"]["dry_run"], true);
    // The envelope's `changed` says whether the run changed anything, which a dry run never
    // does; `data.changed` says what a real run would publish.
    assert_eq!(json["changed"], false);
    assert_eq!(json["data"]["changed"], true);
    assert_eq!(json["data"]["files"].as_array().unwrap().len(), 2);
    assert!(names(setup.out.path()).is_empty());
}

#[test]
fn a_dry_run_with_a_key_checks_it_and_still_writes_nothing() {
    let setup = Setup::new();
    let secret = setup.secret_file(&minisign_key().secret_file);
    let outcome = run(
        setup.args(&["--json", "--dry-run", "--secret-key", &secret]),
        &[],
    );
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(outcome.json()["data"]["public_key"].is_string());
    assert!(names(setup.out.path()).is_empty());
}

// ---------------------------------------------------------------------------------------------
// Later runs
// ---------------------------------------------------------------------------------------------

#[test]
fn a_second_run_reports_that_nothing_changed() {
    let setup = Setup::new();
    let secret = setup.secret_file(&minisign_key().secret_file);
    let first = run(setup.args(&["--json", "--secret-key", &secret]), &[]);
    assert_eq!(first.code, 0, "{}", first.stderr);

    let out = setup.out.path().display().to_string();
    let second = run(
        setup.args(&["--json", "--secret-key", &secret, "--previous", &out]),
        &[],
    );
    assert_eq!(second.code, 0, "{}", second.stderr);
    let json = second.json();
    assert_eq!(json["changed"], false);
    assert_eq!(json["data"]["files"][0]["action"], "unchanged");
    assert_eq!(json["data"]["files"][0]["sequence"], 1);
}

#[test]
fn the_previous_publish_can_be_checked_with_a_public_key_given_on_the_command_line() {
    let setup = Setup::new();
    let key = minisign_key();
    let secret = setup.secret_file(&key.secret_file);
    run(setup.args(&["--json", "--secret-key", &secret]), &[]);

    let out = setup.out.path().display().to_string();
    let outcome = run(
        setup.args(&[
            "--json",
            "--dry-run",
            "--previous",
            &out,
            "--previous-key",
            &key.public,
        ]),
        &[],
    );
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.json()["changed"], false);
}

#[test]
fn a_public_key_file_is_accepted_for_the_previous_publish() {
    let setup = Setup::new();
    let key = minisign_key();
    let secret = setup.secret_file(&key.secret_file);
    run(setup.args(&["--json", "--secret-key", &secret]), &[]);

    let public = setup.scratch.path().join("minisign.pub");
    fs::write(
        &public,
        format!("untrusted comment: minisign public key\n{}\n", key.public),
    )
    .unwrap();
    let out = setup.out.path().display().to_string();
    let outcome = run(
        setup.args(&[
            "--json",
            "--dry-run",
            "--previous",
            &out,
            "--previous-key",
            &public.display().to_string(),
        ]),
        &[],
    );
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
}

// ---------------------------------------------------------------------------------------------
// Failures
// ---------------------------------------------------------------------------------------------

#[test]
fn a_validity_outside_the_limits_is_a_usage_error() {
    let setup = Setup::new();
    let outcome = run(
        setup.args(&["--json", "--dry-run", "--validity-days", "91"]),
        &[],
    );
    assert_eq!(outcome.code, 2);
    assert_eq!(outcome.json()["error"]["code"], "E_USAGE");
}

#[test]
fn a_time_that_is_not_a_utc_timestamp_is_a_usage_error() {
    let setup = Setup::new();
    let mut args = setup.args(&["--json", "--dry-run"]);
    let at = args.iter().position(|a| a == NOW).unwrap();
    args[at] = "yesterday".to_owned();
    let outcome = run(args, &[]);
    assert_eq!(outcome.code, 2);
}

#[test]
fn a_plugin_directory_without_a_manifest_fails_with_the_plugin_code() {
    let setup = Setup::new();
    fs::remove_file(setup.plugin.path().join("plugin.toml")).unwrap();
    let outcome = run(setup.args(&["--json", "--dry-run"]), &[]);
    assert_eq!(outcome.code, 5);
    assert_eq!(outcome.json()["error"]["code"], "E_PLUGIN_INVALID");
}

#[test]
fn a_refused_entry_fails_with_its_code_and_lists_what_was_refused() {
    let setup = Setup::new();
    let setup_entries = |_: &Plugin| -> crate::error::Result<Confirmed> {
        Err(Error::Rejected {
            rejections: vec![crate::error::Rejection {
                variant: Some("alpha".to_owned()),
                version: "1.0.0".to_owned(),
                target: Target::Any,
                reason: crate::error::Reason::NotConfirmed {
                    message: "only one source".to_owned(),
                },
            }],
        })
    };
    let cli = Cli::try_parse_from(setup.args(&["--json", "--dry-run"])).unwrap();
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let code = execute(&cli, &|_| None, &setup_entries, &mut stdout, &mut stderr);
    assert_eq!(code, 5);
    let json: Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(json["error"]["code"], "E_INDEX_INVALID");
    assert!(
        json["error"]["details"]["rejections"][0]
            .as_str()
            .unwrap()
            .contains("only one source")
    );
}

#[test]
fn a_previous_publish_that_does_not_verify_fails_with_the_signature_code() {
    let setup = Setup::new();
    let secret = setup.secret_file(&minisign_key().secret_file);
    run(setup.args(&["--json", "--secret-key", &secret]), &[]);
    let file = setup.out.path().join("demo-linux-x64.json");
    let text = fs::read_to_string(&file).unwrap().replace("1.0.0", "6.6.6");
    fs::write(&file, text).unwrap();

    let out = setup.out.path().display().to_string();
    let outcome = run(
        setup.args(&["--json", "--secret-key", &secret, "--previous", &out]),
        &[],
    );
    assert_eq!(outcome.code, 5);
    assert_eq!(outcome.json()["error"]["code"], "E_SIGNATURE_INVALID");
}

// ---------------------------------------------------------------------------------------------
// Human output
// ---------------------------------------------------------------------------------------------

#[test]
fn human_output_lists_each_file_and_sends_warnings_to_stderr() {
    let setup = Setup::new();
    let secret = setup.secret_file(&minisign_key().secret_file);
    let outcome = run(setup.args(&["--secret-key", &secret]), &[]);
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(
        outcome.stdout.contains("created demo-linux-x64.json"),
        "{}",
        outcome.stdout
    );
    assert!(outcome.stdout.contains("sequence 1"), "{}", outcome.stdout);
    assert!(
        outcome.stderr.contains("W_SOURCE_NOTE"),
        "{}",
        outcome.stderr
    );
    assert!(
        outcome.stderr.contains("a vendor note"),
        "{}",
        outcome.stderr
    );
}

#[test]
fn human_output_says_when_there_is_nothing_to_publish() {
    let setup = Setup::new();
    let secret = setup.secret_file(&minisign_key().secret_file);
    run(setup.args(&["--secret-key", &secret]), &[]);
    let out = setup.out.path().display().to_string();
    let outcome = run(
        setup.args(&["--secret-key", &secret, "--previous", &out]),
        &[],
    );
    assert!(
        outcome.stdout.contains("nothing to publish"),
        "{}",
        outcome.stdout
    );
}

#[test]
fn human_errors_name_the_code_on_stderr() {
    let setup = Setup::new();
    let outcome = run(setup.args(&[]), &[]);
    assert_eq!(outcome.code, 2);
    assert!(outcome.stdout.is_empty());
    assert!(outcome.stderr.contains("E_USAGE"), "{}", outcome.stderr);
}

// ---------------------------------------------------------------------------------------------
// Confirmed files
// ---------------------------------------------------------------------------------------------

/// Runs with an acquirer that fails the test if the sources are asked for anything.
fn run_offline(args: Vec<String>, env: &[(&str, &str)]) -> Outcome {
    let env: HashMap<String, String> = env
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let cli = Cli::try_parse_from(args).unwrap();
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let code = execute(
        &cli,
        &|name| env.get(name).cloned(),
        &|_plugin| panic!("the sources must not be asked when a confirmed file is given"),
        &mut stdout,
        &mut stderr,
    );
    Outcome {
        code,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

#[test]
fn write_confirmed_saves_the_confirmed_entries_even_in_a_dry_run() {
    let setup = Setup::new();
    let file = setup.scratch.path().join("deep/confirmed/demo.json");
    let path = file.display().to_string();
    let outcome = run(
        setup.args(&["--json", "--dry-run", "--write-confirmed", &path]),
        &[],
    );
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert!(names(setup.out.path()).is_empty());
    let text = fs::read_to_string(&file).unwrap();
    assert_eq!(
        text,
        crate::confirmed_file::render("demo", &confirmed()).unwrap()
    );
}

#[test]
fn use_confirmed_signs_exactly_what_was_saved_without_asking_the_sources() {
    let setup = Setup::new();
    let secret = setup.secret_file(&minisign_key().secret_file);
    let file = setup.scratch.path().join("demo.json");
    let path = file.display().to_string();
    let first = run(
        setup.args(&["--json", "--dry-run", "--write-confirmed", &path]),
        &[],
    );
    assert_eq!(first.code, 0, "{}", first.stderr);

    let outcome = run_offline(
        setup.args(&["--json", "--secret-key", &secret, "--use-confirmed", &path]),
        &[],
    );
    assert_eq!(outcome.code, 0, "{}", outcome.stderr);
    assert_eq!(outcome.json()["data"]["files"].as_array().unwrap().len(), 2);
    // The run that read the file produced the same indices as one that went to the sources.
    let direct = Setup::new();
    let direct_secret = direct.secret_file(&minisign_key().secret_file);
    run(
        direct.args(&["--json", "--secret-key", &direct_secret]),
        &[],
    );
    assert_eq!(
        fs::read(setup.out.path().join("demo-linux-x64.json")).unwrap(),
        fs::read(direct.out.path().join("demo-linux-x64.json")).unwrap()
    );
}

#[test]
fn a_confirmed_file_cannot_be_both_read_and_written() {
    let setup = Setup::new();
    let args = setup.args(&["--use-confirmed", "a.json", "--write-confirmed", "b.json"]);
    assert!(Cli::try_parse_from(args).is_err());
}

#[test]
fn a_confirmed_file_for_another_plugin_or_a_missing_one_is_refused() {
    let setup = Setup::new();
    let file = setup.scratch.path().join("demo.json");
    let path = file.display().to_string();
    run(
        setup.args(&["--json", "--dry-run", "--write-confirmed", &path]),
        &[],
    );
    let text = fs::read_to_string(&file).unwrap();
    fs::write(&file, text.replace("\"demo\"", "\"other\"")).unwrap();
    let other = run_offline(
        setup.args(&["--json", "--dry-run", "--use-confirmed", &path]),
        &[],
    );
    assert_eq!(other.code, 5);
    assert_eq!(other.json()["error"]["code"], "E_INDEX_INVALID");

    let missing = setup.scratch.path().join("none.json").display().to_string();
    let outcome = run_offline(
        setup.args(&["--json", "--dry-run", "--use-confirmed", &missing]),
        &[],
    );
    assert_eq!(outcome.code, 2);
    assert_eq!(outcome.json()["error"]["code"], "E_USAGE");
}
