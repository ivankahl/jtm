//! One hook call inside a fresh sandboxed Luau state, and the `jtm` host API it sees.
//!
//! - `jtm.plugin`, `jtm.platform` (`name`, `os`, `arch`) and `jtm.manifest`, the parsed
//!   manifest. All read-only.
//! - `jtm.version`: `parse`, `compare`, `matches_prefix` and `is_prerelease`. Each takes an
//!   optional scheme name as its last argument, defaulting to the plugin's own scheme.
//! - `jtm.json.decode(text)`; JSON `null` becomes `nil`.
//! - `jtm.regex`: `is_match(pattern, text)` and `match(pattern, text)`, which returns the
//!   whole match followed by each group (`false` for a group that did not take part), or `nil`.
//!   Patterns use Rust's `regex` syntax, which runs in linear time.
//! - `jtm.string`: `split(text, sep)` (plain text, not a pattern), `trim`, `starts_with` and
//!   `ends_with`.
//! - `jtm.fs`, during `post_extract` only (see [`super::fs`]).

use std::cmp::Ordering;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Instant;

use mlua::chunk::ChunkMode;
use mlua::{Function, Lua, LuaOptions, MultiValue, StdLib, Table, Value, VmState};
use serde_json::Value as Json;

use super::convert::{json_to_lua, lua_to_json};
use super::{Host, Limit, Limits, Shared, fs};
use crate::version::VersionScheme;

/// Globals the base library defines that a hook must not have: code loading, module loading,
/// writing to the terminal, environment tricks and garbage collector control.
const REMOVED_GLOBALS: &[&str] = &[
    "loadstring",
    "require",
    "print",
    "getfenv",
    "setfenv",
    "collectgarbage",
    "gcinfo",
];
/// The largest compiled regex a script may build.
const REGEX_SIZE_LIMIT: usize = 1024 * 1024;
const CHUNK_NAME: &str = "=plugin.lua";

/// Everything a hook's thread needs, owned so it can move there.
#[derive(Debug)]
pub(super) struct Job {
    pub(super) plugin: String,
    pub(super) source: Arc<str>,
    pub(super) manifest: Arc<Json>,
    pub(super) scheme: Option<VersionScheme>,
    pub(super) host: Host,
    pub(super) limits: Limits,
    pub(super) function: String,
    pub(super) args: Vec<Json>,
    pub(super) fs_root: Option<PathBuf>,
    pub(super) shared: Arc<Shared>,
}

/// How a hook call failed, before the host attaches the hook name.
#[derive(Debug)]
pub(super) enum Failure {
    Memory,
    Invalid(String),
    Runtime(String),
    /// Setting up the sandbox failed before any plugin code ran.
    Host(String),
}

/// A host function refused to act because the script broke a limit. The limit is recorded in
/// [`Shared`] before this is raised.
#[derive(Debug)]
struct Refused(String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// Checks that `source` compiles, without running it.
pub(super) fn check_syntax(source: &str) -> Result<(), String> {
    let lua = Lua::new_with(StdLib::NONE, LuaOptions::default()).map_err(|e| e.to_string())?;
    lua.load(source)
        .set_name(CHUNK_NAME)
        .set_mode(ChunkMode::Text)
        .into_function()
        .map(|_| ())
        .map_err(|e| message(&e))
}

/// Runs the job's hook and returns its first result as JSON.
pub(super) fn run(job: Job) -> Result<Json, Failure> {
    let runtime = |e: mlua::Error| classify(&e);
    let setup =
        |e: mlua::Error| Failure::Host(format!("cannot set up the sandbox: {}", message(&e)));
    let lua = Lua::new_with(
        StdLib::STRING | StdLib::TABLE | StdLib::MATH | StdLib::UTF8,
        LuaOptions::default(),
    )
    .map_err(setup)?;
    lua.set_memory_limit(job.limits.memory).map_err(setup)?;

    let deadline = Instant::now() + job.limits.time;
    let shared = Arc::clone(&job.shared);
    lua.set_interrupt(move |_| {
        if shared.cancelled() || Instant::now() >= deadline {
            shared.record(Limit::Time(shared.limits.time));
            return Err(mlua::Error::external(Refused("the time limit".to_owned())));
        }
        Ok(VmState::Continue)
    });

    let globals = lua.globals();
    for name in REMOVED_GLOBALS {
        globals.raw_set(*name, Value::Nil).map_err(setup)?;
    }
    install_protected_calls(&lua, &job.shared).map_err(setup)?;
    let api = host_api(&lua, &job).map_err(setup)?;
    globals.raw_set("jtm", api).map_err(setup)?;
    lua.sandbox(true).map_err(setup)?;

    lua.load(&*job.source)
        .set_name(CHUNK_NAME)
        .set_mode(ChunkMode::Text)
        .exec()
        .map_err(runtime)?;
    let function = match lua
        .globals()
        .get::<Value>(job.function.as_str())
        .map_err(runtime)?
    {
        Value::Function(function) => function,
        _ => {
            return Err(Failure::Invalid(format!(
                "plugin.lua defines no function `{}`",
                job.function
            )));
        }
    };
    let args = job
        .args
        .iter()
        .map(|arg| json_to_lua(&lua, arg, false))
        .collect::<mlua::Result<Vec<Value>>>()
        .map_err(runtime)?;
    let out: Value = function
        .call(mlua::MultiValue::from_iter(args))
        .map_err(runtime)?;
    lua_to_json(&out).map_err(Failure::Invalid)
}

/// Luau's error message for a failed allocation, which is what a protected call returns
/// when a hook runs out of memory in Lua code.
const MEMORY_ERROR: &str = "not enough memory";

/// Wraps `pcall` and `xpcall` so a memory breach is recorded before the script sees the
/// error, and catching it cannot hide it. Time and containment breaches are recorded where
/// they are raised. Luau's own functions still do the calling, so any callable value works and
/// an error value the script raised reaches it unchanged; an error from the host is seen as
/// its message. A script raising the memory error's message itself counts as a breach.
fn install_protected_calls(lua: &Lua, shared: &Arc<Shared>) -> mlua::Result<()> {
    let globals = lua.globals();
    let native_pcall: Function = globals.raw_get("pcall")?;
    let native_xpcall: Function = globals.raw_get("xpcall")?;

    let s = Arc::clone(shared);
    let pcall = lua.create_function(move |lua, args: MultiValue| {
        let mut out: MultiValue = native_pcall.call(args)?;
        if matches!(out.front(), Some(Value::Boolean(false))) {
            let error = out.get(1).cloned().unwrap_or(Value::Nil);
            let seen = caught(lua, &s, error)?;
            if let Some(slot) = out.get_mut(1) {
                *slot = seen;
            }
        }
        Ok(out)
    })?;

    let s = Arc::clone(shared);
    let xpcall = lua.create_function(move |lua, mut args: MultiValue| {
        // The handler runs inside the failed call, so the breach is recorded before it does.
        // Luau itself refuses a handler that is not a function. The flag is this call's own:
        // a limit recorded earlier must not stop a breach here from being raised again.
        let breached = Arc::new(AtomicBool::new(false));
        if let Some(Value::Function(handler)) = args.get(1).cloned() {
            let s = Arc::clone(&s);
            let flag = Arc::clone(&breached);
            let wrapped = lua.create_function(move |lua, error: Value| {
                let result =
                    caught(lua, &s, error).and_then(|error| handler.call::<MultiValue>(error));
                // Luau reports a failing handler as an ordinary error, so a breach in the
                // handler itself is recorded here.
                if let Err(e) = &result
                    && matches!(classify(e), Failure::Memory)
                {
                    s.record(Limit::Memory(s.limits.memory));
                    flag.store(true, AtomicOrdering::SeqCst);
                }
                result
            })?;
            if let Some(slot) = args.get_mut(1) {
                *slot = Value::Function(wrapped);
            }
        }
        let out: MultiValue = native_xpcall.call(args)?;
        // A handler that raised again replaced the error, but not the breach.
        if breached.load(AtomicOrdering::SeqCst) {
            return Err(mlua::Error::MemoryError(MEMORY_ERROR.to_owned()));
        }
        Ok(out)
    })?;
    globals.raw_set("pcall", pcall)?;
    globals.raw_set("xpcall", xpcall)
}

/// The error value a script's caller or handler sees for `error`: a memory breach is recorded
/// and raised again, a host error becomes its message, and any other value is unchanged.
fn caught(lua: &Lua, shared: &Shared, error: Value) -> mlua::Result<Value> {
    let memory = match &error {
        Value::Error(e) => matches!(classify(e), Failure::Memory),
        Value::String(text) => text.to_str().is_ok_and(|text| *text == *MEMORY_ERROR),
        _ => false,
    };
    if memory {
        shared.record(Limit::Memory(shared.limits.memory));
        return Err(mlua::Error::MemoryError(MEMORY_ERROR.to_owned()));
    }
    match error {
        Value::Error(e) => Ok(Value::String(lua.create_string(message(&e))?)),
        other => Ok(other),
    }
}

/// Builds the read-only `jtm` table.
fn host_api(lua: &Lua, job: &Job) -> mlua::Result<Table> {
    let api = lua.create_table()?;
    api.raw_set("plugin", job.plugin.as_str())?;
    let platform = lua.create_table()?;
    platform.raw_set("name", job.host.platform.as_str())?;
    platform.raw_set("os", job.host.os.as_str())?;
    platform.raw_set("arch", job.host.arch.as_str())?;
    platform.set_readonly(true);
    api.raw_set("platform", platform)?;
    api.raw_set("manifest", json_to_lua(lua, &job.manifest, true)?)?;
    api.raw_set("version", version_api(lua, job.scheme)?)?;
    api.raw_set("json", json_api(lua)?)?;
    api.raw_set("regex", regex_api(lua)?)?;
    api.raw_set("string", string_api(lua)?)?;
    if let Some(root) = &job.fs_root {
        api.raw_set("fs", fs::api(lua, root.clone(), Arc::clone(&job.shared))?)?;
    }
    api.set_readonly(true);
    Ok(api)
}

fn version_api(lua: &Lua, default: Option<VersionScheme>) -> mlua::Result<Table> {
    let scheme = move |name: Option<String>| -> mlua::Result<VersionScheme> {
        match name {
            Some(name) => VersionScheme::ALL
                .iter()
                .copied()
                .find(|s| s.as_str() == name)
                .ok_or_else(|| mlua::Error::runtime(format!("unknown version scheme `{name}`"))),
            None => default.ok_or_else(|| {
                mlua::Error::runtime("this plugin's scheme is `script`; name a version scheme")
            }),
        }
    };
    let parse = move |text: &str, name: Option<String>| -> mlua::Result<crate::Version> {
        scheme(name)?
            .parse(text)
            .map_err(|e| mlua::Error::runtime(e.to_string()))
    };
    let t = lua.create_table()?;
    t.raw_set(
        "parse",
        lua.create_function(move |_, (text, name): (String, Option<String>)| {
            Ok(match scheme(name)?.parse(&text) {
                Ok(version) => (Some(version.as_str().to_owned()), None),
                Err(e) => (None, Some(e.reason)),
            })
        })?,
    )?;
    t.raw_set(
        "compare",
        lua.create_function(move |_, (a, b, name): (String, String, Option<String>)| {
            let (a, b) = (parse(&a, name.clone())?, parse(&b, name)?);
            Ok(match a.cmp_precedence(&b) {
                Ordering::Less => -1,
                Ordering::Equal => 0,
                Ordering::Greater => 1,
            })
        })?,
    )?;
    t.raw_set(
        "matches_prefix",
        lua.create_function(
            move |_, (version, prefix, name): (String, String, Option<String>)| {
                Ok(parse(&version, name)?.matches_prefix(&prefix))
            },
        )?,
    )?;
    t.raw_set(
        "is_prerelease",
        lua.create_function(move |_, (version, name): (String, Option<String>)| {
            Ok(parse(&version, name)?.is_prerelease())
        })?,
    )?;
    t.set_readonly(true);
    Ok(t)
}

fn json_api(lua: &Lua) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    t.raw_set(
        "decode",
        lua.create_function(|lua, text: mlua::LuaString| {
            let value: Json = serde_json::from_slice(&text.as_bytes())
                .map_err(|e| mlua::Error::runtime(format!("invalid JSON: {e}")))?;
            json_to_lua(lua, &value, false)
        })?,
    )?;
    t.set_readonly(true);
    Ok(t)
}

fn regex_api(lua: &Lua) -> mlua::Result<Table> {
    fn compile(pattern: &str) -> mlua::Result<regex::Regex> {
        regex::RegexBuilder::new(pattern)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map_err(|e| mlua::Error::runtime(format!("invalid regex: {e}")))
    }
    let t = lua.create_table()?;
    t.raw_set(
        "is_match",
        lua.create_function(|_, (pattern, text): (String, String)| {
            Ok(compile(&pattern)?.is_match(&text))
        })?,
    )?;
    t.raw_set(
        "match",
        lua.create_function(|lua, (pattern, text): (String, String)| {
            let Some(caps) = compile(&pattern)?.captures(&text) else {
                return Ok(Value::Nil);
            };
            let out = lua.create_table()?;
            for (i, group) in caps.iter().enumerate() {
                match group {
                    Some(m) => out.raw_set(i + 1, m.as_str())?,
                    None => out.raw_set(i + 1, false)?,
                }
            }
            Ok(Value::Table(out))
        })?,
    )?;
    t.set_readonly(true);
    Ok(t)
}

fn string_api(lua: &Lua) -> mlua::Result<Table> {
    let t = lua.create_table()?;
    t.raw_set(
        "split",
        lua.create_function(|lua, (text, sep): (String, String)| {
            if sep.is_empty() {
                return Err(mlua::Error::runtime("the separator cannot be empty"));
            }
            lua.create_sequence_from(text.split(sep.as_str()))
        })?,
    )?;
    t.raw_set(
        "trim",
        lua.create_function(|_, text: String| Ok(text.trim().to_owned()))?,
    )?;
    t.raw_set(
        "starts_with",
        lua.create_function(|_, (text, prefix): (String, String)| Ok(text.starts_with(&prefix)))?,
    )?;
    t.raw_set(
        "ends_with",
        lua.create_function(|_, (text, suffix): (String, String)| Ok(text.ends_with(&suffix)))?,
    )?;
    t.set_readonly(true);
    Ok(t)
}

/// Raises `limit` in the script after recording it, so catching the error cannot hide it.
pub(super) fn refuse(shared: &Shared, limit: Limit) -> mlua::Error {
    let text = limit.to_string();
    shared.record(limit);
    mlua::Error::external(Refused(text))
}

fn classify(error: &mlua::Error) -> Failure {
    let mut current = error;
    loop {
        match current {
            mlua::Error::MemoryError(_) => return Failure::Memory,
            mlua::Error::SyntaxError { .. } => return Failure::Invalid(message(error)),
            mlua::Error::CallbackError { cause, .. } | mlua::Error::WithContext { cause, .. } => {
                current = cause;
            }
            _ => return Failure::Runtime(message(error)),
        }
    }
}

/// The error's message without mlua's stack traceback.
fn message(error: &mlua::Error) -> String {
    let text = error.to_string();
    let text = text.split("\nstack traceback:").next().unwrap_or_default();
    text.trim().to_owned()
}
