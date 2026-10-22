//! Embeds the first-party plugins in `plugins/` (SPEC.md section 15) and the signed index
//! snapshot in `snapshot/` (SPEC.md section 8).
//!
//! Each directory `plugins/<name>/` becomes one `BuiltinManifest` with its `plugin.toml` and
//! any `plugin.lua`, so adding a first-party plugin needs no code change and no tool name
//! appears in the source. The generated list is included by `src/builtin.rs`.
//!
//! The files `snapshot/snapshot.toml` lists become the `Snapshot` included by
//! `src/snapshot.rs`. `cargo xtask embed-snapshot` fills the directory; without a listing the
//! snapshot is empty and the build still works.

#[path = "build/snapshot.rs"]
mod snapshot;

use std::fmt::Write as _;
use std::path::Path;
use std::{env, fs};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    embed_snapshot(Path::new(&manifest_dir));
    let plugins = Path::new(&manifest_dir).join("plugins");
    println!("cargo::rerun-if-changed=plugins");

    let mut names: Vec<String> = match fs::read_dir(&plugins) {
        Ok(entries) => entries
            .flatten()
            .filter(|e| e.path().join("plugin.toml").is_file())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect(),
        Err(err) => fail(&format!("cannot read {}: {err}", plugins.display())),
    };
    names.sort();
    // A binary without its first-party plugins would build fine and be useless.
    if names.is_empty() {
        fail(&format!("no plugins found under {}", plugins.display()));
    }

    let mut code = String::from("&[\n");
    for name in &names {
        let dir = plugins.join(name);
        let toml = dir.join("plugin.toml");
        let lua = dir.join("plugin.lua");
        let script = if lua.is_file() {
            format!("Some(include_str!({:?}))", lua.display().to_string())
        } else {
            "None".to_owned()
        };
        let _ = writeln!(
            code,
            "    jtm_core::plugins::BuiltinManifest {{ name: {name:?}, text: include_str!({:?}), \
             script: {script} }},",
            toml.display().to_string()
        );
    }
    code.push(']');

    let out = Path::new(&env::var("OUT_DIR").unwrap_or_default()).join("builtin.rs");
    if let Err(err) = fs::write(&out, code) {
        fail(&format!("cannot write {}: {err}", out.display()));
    }
}

/// Generates `$OUT_DIR/snapshot.rs` from the files `snapshot/snapshot.toml` lists.
fn embed_snapshot(manifest_dir: &Path) {
    let dir = manifest_dir.join("snapshot");
    println!("cargo::rerun-if-changed=snapshot");
    let listing = match snapshot::Listing::read(&dir) {
        Ok(listing) => listing,
        Err(err) => fail(&format!("cannot embed the index snapshot: {err}")),
    };
    // A release without a snapshot works, but cannot install anything until it goes online.
    if listing.is_none() && env::var("PROFILE").as_deref() == Ok("release") {
        println!(
            "cargo::warning=no index snapshot is embedded; run `cargo xtask embed-snapshot` first"
        );
    }
    let code = snapshot::code(&dir, listing.as_ref());
    let out = Path::new(&env::var("OUT_DIR").unwrap_or_default()).join("snapshot.rs");
    if let Err(err) = fs::write(&out, code) {
        fail(&format!("cannot write {}: {err}", out.display()));
    }
}

/// Fails the build with `message` as a cargo error. Only the two-colon form is an error
/// instruction; `cargo:error=` is read as `links` metadata and never shown as one.
///
/// The script exits 0 on purpose: cargo fails the build on its own once `cargo::error` is
/// logged, and a non-zero exit would add "failed to run custom build command" plus a dump
/// of stdout that repeats the message.
fn fail(message: &str) -> ! {
    println!("cargo::error={message}");
    std::process::exit(0)
}
