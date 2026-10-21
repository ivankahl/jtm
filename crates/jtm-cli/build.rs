//! Embeds the first-party plugins in `plugins/` (SPEC.md section 15).
//!
//! Each directory `plugins/<name>/` becomes one `BuiltinManifest` with its `plugin.toml` and
//! any `plugin.lua`, so adding a first-party plugin needs no code change and no tool name
//! appears in the source. The generated list is included by `src/builtin.rs`.

use std::fmt::Write as _;
use std::path::Path;
use std::{env, fs};

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_default();
    let plugins = Path::new(&manifest_dir).join("plugins");
    println!("cargo:rerun-if-changed=plugins");

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

/// Fails the build with `message` as a cargo error. Only the two-colon form is an error
/// instruction; `cargo:error=` is read as `links` metadata and never shown as one.
fn fail(message: &str) -> ! {
    println!("cargo::error={message}");
    std::process::exit(1)
}
