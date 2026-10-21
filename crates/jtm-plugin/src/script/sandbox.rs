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
use std::time::Instant;

use mlua::chunk::ChunkMode;
use mlua::ffi;
use mlua::{Lua, LuaOptions, MultiValue, StdLib, Table, Value, VmState};
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

    let deadline = job.shared.deadline;
    let shared = Arc::clone(&job.shared);
    lua.set_interrupt(move |_| {
        if shared.cancelled() || Instant::now() >= deadline {
            shared.record(Limit::Time(shared.limits.time));
        }
        // Any breach stops the script here too, whatever caught its error.
        match breach(&shared) {
            Some(error) => Err(error),
            None => Ok(VmState::Continue),
        }
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

/// The message of the error that stops a hook which ran out of memory.
const MEMORY_ERROR: &str = "not enough memory";
/// What Luau's `xpcall` returns when its handler fails too.
const HANDLER_ERROR: &str = "error in error handling";

/// How a protected call ended, when it did not run out of memory.
enum Outcome {
    Returned(MultiValue),
    Raised(Value),
}

/// Replaces `pcall` and `xpcall` with versions that make the call through Luau's
/// `lua_pcall`, whose status says whether an allocation was refused. A memory breach is
/// recorded there; time and containment breaches are recorded where they are raised. After
/// any breach the error is raised again, so catching it cannot hide it and no handler runs.
/// The error's text plays no part, so a script raising the same message raises an ordinary
/// error.
///
/// Otherwise they behave as Luau's own: any callable value works, an error value the script
/// raised reaches it unchanged, and an error from the host is seen as its message. `xpcall`
/// calls its handler once the failed call has unwound, which a script cannot tell apart
/// without the debug library.
fn install_protected_calls(lua: &Lua, shared: &Arc<Shared>) -> mlua::Result<()> {
    let s = Arc::clone(shared);
    let pcall =
        lua.create_function(move |lua, args: MultiValue| recorded(&s, pcall(lua, &s, args)))?;
    let s = Arc::clone(shared);
    let xpcall =
        lua.create_function(move |lua, args: MultiValue| recorded(&s, xpcall(lua, &s, args)))?;

    let globals = lua.globals();
    globals.raw_set("pcall", pcall)?;
    globals.raw_set("xpcall", xpcall)
}

/// Records a memory breach raised anywhere in a protected call, its own work included.
fn recorded<T>(shared: &Shared, result: mlua::Result<T>) -> mlua::Result<T> {
    if let Err(e) = &result
        && matches!(classify(e), Failure::Memory)
    {
        shared.record(Limit::Memory(shared.limits.memory));
    }
    result
}

fn pcall(lua: &Lua, s: &Shared, args: MultiValue) -> mlua::Result<MultiValue> {
    if args.is_empty() {
        return Err(mlua::Error::runtime("missing argument #1 to 'pcall'"));
    }
    Ok(match protected_call(lua, s, args)? {
        Outcome::Returned(mut values) => {
            values.push_front(Value::Boolean(true));
            values
        }
        Outcome::Raised(error) => MultiValue::from_iter([Value::Boolean(false), seen(lua, error)?]),
    })
}

fn xpcall(lua: &Lua, s: &Shared, mut args: MultiValue) -> mlua::Result<MultiValue> {
    if args.is_empty() {
        return Err(mlua::Error::runtime("missing argument #1 to 'xpcall'"));
    }
    let handler = match args.remove(1) {
        Some(Value::Function(handler)) => handler,
        Some(_) => {
            return Err(mlua::Error::runtime(
                "invalid argument #2 to 'xpcall' (function expected)",
            ));
        }
        None => {
            return Err(mlua::Error::runtime(
                "missing argument #2 to 'xpcall' (function expected)",
            ));
        }
    };
    let error = match protected_call(lua, s, args)? {
        Outcome::Returned(mut values) => {
            values.push_front(Value::Boolean(true));
            return Ok(values);
        }
        Outcome::Raised(error) => seen(lua, error)?,
    };
    let call = MultiValue::from_iter([Value::Function(handler), error]);
    let handled = match protected_call(lua, s, call)? {
        Outcome::Returned(values) => values.into_iter().next().unwrap_or(Value::Nil),
        Outcome::Raised(_) => Value::String(lua.create_string(HANDLER_ERROR)?),
    };
    Ok(MultiValue::from_iter([Value::Boolean(false), handled]))
}

/// Calls the first of `args` with the rest, protected. A refused allocation, in Lua code or
/// reported by a host function, is recorded. Once any limit has been broken, in this call or
/// before it, the breach is raised again rather than handed to the script.
fn protected_call(lua: &Lua, shared: &Shared, args: MultiValue) -> mlua::Result<Outcome> {
    if args.is_empty() {
        return Err(mlua::Error::runtime("nothing to call"));
    }
    let mut status = ffi::LUA_OK;
    // SAFETY: `args` holds at least the function. `exec_raw` pushes `args` and runs the
    // closure in a fresh C frame holding exactly those values. `lua_pcall` pops the function
    // and its arguments and leaves either all its results, for which Luau makes room under
    // `LUA_MULTRET`, or the single error value in the function's slot. Nothing escapes
    // `lua_pcall`, so the closure returns normally, and `exec_raw` reads what is left as the
    // frame's results.
    #[allow(unsafe_code)]
    let values: MultiValue = unsafe {
        lua.exec_raw(args, |state| {
            status = ffi::lua_pcall(state, ffi::lua_gettop(state) - 1, ffi::LUA_MULTRET, 0);
        })
    }?;
    let outcome = if status == ffi::LUA_OK {
        Outcome::Returned(values)
    } else {
        let error = values.into_iter().next().unwrap_or(Value::Nil);
        let out_of_memory = status == ffi::LUA_ERRMEM
            || matches!(&error, Value::Error(e) if matches!(classify(e), Failure::Memory));
        if out_of_memory {
            shared.record(Limit::Memory(shared.limits.memory));
        }
        Outcome::Raised(error)
    };
    // Fail closed: once any limit is broken, nothing the script wrote after the call runs,
    // neither the code following `pcall` nor an `xpcall` handler.
    match breach(shared) {
        None => Ok(outcome),
        Some(error) => Err(error),
    }
}

/// The error that stops the script once it has broken a limit, or `None` while it has not.
pub(super) fn breach(shared: &Shared) -> Option<mlua::Error> {
    if !shared.breached() {
        return None;
    }
    Some(match shared.violation()? {
        Limit::Memory(_) => mlua::Error::MemoryError(MEMORY_ERROR.to_owned()),
        limit => mlua::Error::external(Refused(limit.to_string())),
    })
}

/// The error value a script sees: a host error becomes its message, and any other value is
/// unchanged.
fn seen(lua: &Lua, error: Value) -> mlua::Result<Value> {
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
    // A host call that blocks without returning to Lua, as a stuck C function would.
    #[cfg(test)]
    api.raw_set(
        "sleep",
        lua.create_function(|_, ms: u64| {
            std::thread::sleep(std::time::Duration::from_millis(ms));
            Ok(())
        })?,
    )?;
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
