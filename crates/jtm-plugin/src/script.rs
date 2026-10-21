//! The Luau sandbox that runs `plugin.lua` hooks (SPEC.md section 7).
//!
//! Every hook call gets a fresh Luau state in Luau's sandbox mode, with only the `base`,
//! `string`, `table`, `math` and `utf8` libraries. `loadstring`, `require`, `print`,
//! `getfenv`, `setfenv`, `collectgarbage` and `gcinfo` are removed, and only source text is
//! loaded, never bytecode. The script sees a read-only `jtm` table (the host API in
//! [`sandbox`]); during `post_extract` it also gets `jtm.fs`, whose paths cannot leave the
//! temporary install dir.
//!
//! Limits: a memory cap through Luau's allocator, and a wall clock enforced twice. Luau's
//! interrupt callback stops Lua code once the deadline passes, and the hook runs on its own
//! thread, so a call stuck inside a C function, such as a slow pattern match, is abandoned
//! when the deadline passes. An abandoned hook is cancelled: a `jtm.fs` call already running
//! finishes before the host moves on, and every later one fails. A thread cannot be killed, so
//! an abandoned one keeps its memory until its C call returns; once [`MAX_STUCK`] of them are
//! still running, jtm refuses to start another hook. Hooks already running when the count is
//! reached are not refused, so hooks run in parallel, as `install_all` does, can leave up to
//! one fewer than their number behind on top of [`MAX_STUCK`].
//! Any limit breach or path escape fails the hook with [`ScriptError::Limit`], even when the
//! script catches the error with `pcall` or `xpcall`, which the sandbox replaces with versions
//! that record a memory breach before handing the error to the script.

mod convert;
mod fs;
mod sandbox;

use std::cmp::Ordering;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, mpsc};
use std::time::Duration;

use serde_json::{Value as Json, json};

use crate::alias::Candidate;
use crate::interop::InteropValue;
use crate::names::{check_name_segment, check_version_or_alias};
use crate::version::VersionScheme;

/// The memory one hook call may use.
pub const MEMORY_LIMIT: usize = 64 * 1024 * 1024;
/// The wall clock one hook call may use.
pub const TIME_LIMIT: Duration = Duration::from_secs(2);
/// How long past the deadline the host waits for a hook's thread before abandoning it. The
/// interrupt callback normally stops the hook well within this.
const ABANDON_GRACE: Duration = Duration::from_millis(250);
/// How many abandoned hooks may still be running, across the process, before jtm refuses to
/// start another. Each holds a thread and up to [`MEMORY_LIMIT`] until its C call returns.
pub const MAX_STUCK: usize = 4;
/// Abandoned hooks whose threads are still running.
static STUCK: AtomicUsize = AtomicUsize::new(0);

/// Resource limits for one hook call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Bytes Luau may allocate.
    pub memory: usize,
    /// Wall clock time, from creating the Luau state to the hook's return.
    pub time: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            memory: MEMORY_LIMIT,
            time: TIME_LIMIT,
        }
    }
}

/// What the host tells a script about where it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    /// The platform name, such as `linux-x64`.
    pub platform: String,
    /// `windows`, `macos` or `linux`.
    pub os: String,
    /// `x64` or `aarch64`.
    pub arch: String,
}

/// The limit a hook broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Limit {
    Memory(usize),
    Time(Duration),
    /// A `jtm.fs` path that resolves outside the install dir, or a link left pointing outside it.
    Path {
        path: String,
        reason: String,
    },
    /// The hook was not started because this many abandoned hooks are still running.
    Stuck(usize),
}

impl fmt::Display for Limit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Limit::Memory(bytes) => write!(f, "memory limit of {} MiB", bytes / (1024 * 1024)),
            Limit::Time(time) => write!(f, "time limit of {} ms", time.as_millis()),
            Limit::Path { path, reason } => {
                write!(f, "install dir containment: `{path}` {reason}")
            }
            Limit::Stuck(count) => write!(
                f,
                "{count} earlier hooks, of any plugin, are still running past their time limit"
            ),
        }
    }
}

/// Why a hook failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptError {
    /// The hook exceeded a limit or tried to leave the sandbox (`E_PLUGIN_SCRIPT_LIMIT`).
    Limit { hook: String, limit: Limit },
    /// The script does not compile, lacks the hook's function, or returned the wrong thing.
    Invalid { hook: String, message: String },
    /// The hook raised an error.
    Failed { hook: String, message: String },
    /// jtm could not reach a file the hook needs, such as the install dir; not the plugin's
    /// fault.
    Io {
        hook: String,
        path: PathBuf,
        kind: std::io::ErrorKind,
        message: String,
    },
    /// jtm could not run the hook at all, such as when its thread cannot start or dies; not the
    /// plugin's fault.
    Host { hook: String, message: String },
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptError::Limit { hook, limit } => {
                write!(f, "hook `{hook}` stopped at a sandbox limit: {limit}")
            }
            ScriptError::Invalid { hook, message } => {
                write!(f, "plugin.lua cannot run hook `{hook}`: {message}")
            }
            ScriptError::Failed { hook, message } => write!(f, "hook `{hook}` failed: {message}"),
            ScriptError::Io {
                hook,
                path,
                message,
                ..
            } => write!(
                f,
                "cannot run hook `{hook}`: cannot access {}: {message}",
                path.display()
            ),
            ScriptError::Host { hook, message } => {
                write!(f, "cannot run hook `{hook}`: {message}")
            }
        }
    }
}

impl std::error::Error for ScriptError {}

/// Extra facts `post_extract` receives about the version being installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostExtract<'a> {
    pub variant: &'a str,
    pub version: &'a str,
    /// The tool home relative to the install dir, `/`-separated; empty for the install dir.
    pub home: &'a str,
}

/// A plugin's `plugin.lua`, ready to run hooks.
#[derive(Debug, Clone)]
pub struct Script {
    plugin: String,
    source: Arc<str>,
    manifest: Arc<Json>,
    scheme: Option<VersionScheme>,
    host: Host,
    limits: Limits,
    /// The count of abandoned hooks still running: [`STUCK`], except in tests.
    stuck: &'static AtomicUsize,
}

impl Script {
    /// Prepares `source` for `plugin`, whose manifest text is `manifest_text`. Fails when the
    /// source does not compile.
    pub fn new(
        plugin: &str,
        source: &str,
        manifest_text: &str,
        scheme: Option<VersionScheme>,
        host: Host,
    ) -> Result<Script, ScriptError> {
        let invalid = |message: String| ScriptError::Invalid {
            hook: "(load)".to_owned(),
            message,
        };
        let manifest: toml::Table = toml::from_str(manifest_text)
            .map_err(|e| invalid(format!("the manifest is not TOML: {}", e.message())))?;
        let manifest = serde_json::to_value(manifest)
            .map_err(|e| invalid(format!("the manifest cannot be shown to the script: {e}")))?;
        sandbox::check_syntax(source).map_err(invalid)?;
        Ok(Script {
            plugin: plugin.to_owned(),
            source: Arc::from(source),
            manifest: Arc::new(manifest),
            scheme,
            host,
            limits: Limits::default(),
            stuck: &STUCK,
        })
    }

    /// The same script with other limits.
    #[must_use]
    pub fn with_limits(mut self, limits: Limits) -> Script {
        self.limits = limits;
        self
    }

    /// The same script counting its stuck hooks in `stuck`, so a test does not share the count.
    #[cfg(test)]
    fn with_stuck_counter(mut self, stuck: &'static AtomicUsize) -> Script {
        self.stuck = stuck;
        self
    }

    pub fn plugin(&self) -> &str {
        &self.plugin
    }

    /// `resolve_alias(alias, variant, candidates)`: returns the version `alias` selects among
    /// `candidates` (each `{ variant, version, tags }`), or `nil` when none matches.
    pub fn resolve_alias<C: Candidate>(
        &self,
        function: &str,
        alias: &str,
        variant: &str,
        candidates: &[C],
    ) -> Result<Option<String>, ScriptError> {
        const HOOK: &str = "resolve_alias";
        let list: Vec<Json> = candidates
            .iter()
            .map(|c| json!({ "variant": c.variant(), "version": c.version(), "tags": c.tags() }))
            .collect();
        let out = self.call(
            HOOK,
            function,
            vec![json!(alias), json!(variant), Json::Array(list)],
            None,
        )?;
        match out {
            Json::Null => Ok(None),
            Json::String(version) => check_version(HOOK, &version).map(|()| Some(version)),
            other => Err(wrong_return(HOOK, "a version string or nil", &other)),
        }
    }

    /// `compare_versions(a, b)`: returns a negative number, zero or a positive number.
    pub fn compare_versions(
        &self,
        function: &str,
        a: &str,
        b: &str,
    ) -> Result<Ordering, ScriptError> {
        const HOOK: &str = "compare_versions";
        let out = self.call(HOOK, function, vec![json!(a), json!(b)], None)?;
        match out.as_f64() {
            Some(n) if n < 0.0 => Ok(Ordering::Less),
            Some(n) if n > 0.0 => Ok(Ordering::Greater),
            Some(0.0) => Ok(Ordering::Equal),
            _ => Err(wrong_return(HOOK, "a number", &out)),
        }
    }

    /// `parse_interop(file, text)`: returns `nil` when the file does not set the tool, a
    /// version string, or `{ variant = ..., value = ... }`.
    pub fn parse_interop(
        &self,
        function: &str,
        file: &str,
        text: &str,
    ) -> Result<Option<InteropValue>, ScriptError> {
        const HOOK: &str = "parse_interop";
        let out = self.call(HOOK, function, vec![json!(file), json!(text)], None)?;
        let (variant, value) = match &out {
            Json::Null => return Ok(None),
            Json::String(value) => (None, value.clone()),
            Json::Object(map) => match (map.get("variant"), map.get("value")) {
                (None | Some(Json::Null), Some(Json::String(value))) => (None, value.clone()),
                (Some(Json::String(variant)), Some(Json::String(value))) => {
                    (Some(variant.clone()), value.clone())
                }
                _ => return Err(wrong_return(HOOK, "`{ variant = ..., value = ... }`", &out)),
            },
            other => return Err(wrong_return(HOOK, "a version, a table or nil", other)),
        };
        check_version(HOOK, &value)?;
        if let Some(variant) = &variant {
            check_name_segment(variant, "variant").map_err(|(_, message)| {
                ScriptError::Invalid {
                    hook: HOOK.to_owned(),
                    message: format!("returned variant `{variant}`: {message}"),
                }
            })?;
        }
        Ok(Some(InteropValue { variant, value }))
    }

    /// `format_interop(file, variant, value)`: returns the text the file holds for the value.
    pub fn format_interop(
        &self,
        function: &str,
        file: &str,
        variant: &str,
        value: &str,
    ) -> Result<String, ScriptError> {
        const HOOK: &str = "format_interop";
        let out = self.call(
            HOOK,
            function,
            vec![json!(file), json!(variant), json!(value)],
            None,
        )?;
        match out {
            Json::String(text) if !text.is_empty() && !text.contains(['\n', '\r', '\0']) => {
                Ok(text)
            }
            other => Err(wrong_return(HOOK, "one non-empty line of text", &other)),
        }
    }

    /// `post_extract(context)` with `jtm.fs` confined to `root`, the temporary install dir.
    /// `context` is `{ variant, version, home }`. Once the hook returns, every link in `root`
    /// must still point inside it.
    pub fn post_extract(
        &self,
        function: &str,
        root: &Path,
        context: &PostExtract<'_>,
    ) -> Result<(), ScriptError> {
        const HOOK: &str = "post_extract";
        let root = root.canonicalize().map_err(|e| ScriptError::Io {
            hook: HOOK.to_owned(),
            path: root.to_path_buf(),
            kind: e.kind(),
            message: e.to_string(),
        })?;
        let arg = json!({
            "variant": context.variant,
            "version": context.version,
            "home": context.home,
        });
        self.call(HOOK, function, vec![arg], Some(root.clone()))?;
        fs::check_links(&root).map_err(|limit| ScriptError::Limit {
            hook: HOOK.to_owned(),
            limit,
        })
    }

    /// Runs `function` on its own thread with a fresh sandboxed state and returns its first
    /// result.
    fn call(
        &self,
        hook: &str,
        function: &str,
        args: Vec<Json>,
        fs_root: Option<PathBuf>,
    ) -> Result<Json, ScriptError> {
        let shared = Arc::new(Shared::new(self.limits));
        let job = sandbox::Job {
            plugin: self.plugin.clone(),
            source: Arc::clone(&self.source),
            manifest: Arc::clone(&self.manifest),
            scheme: self.scheme,
            host: self.host.clone(),
            limits: self.limits,
            function: function.to_owned(),
            args,
            fs_root,
            shared: Arc::clone(&shared),
        };
        let host = |message: String| ScriptError::Host {
            hook: hook.to_owned(),
            message,
        };
        let stuck = self.stuck;
        let running = stuck.load(AtomicOrdering::SeqCst);
        if running >= MAX_STUCK {
            return Err(ScriptError::Limit {
                hook: hook.to_owned(),
                limit: Limit::Stuck(running),
            });
        }
        let (tx, rx) = mpsc::channel();
        let worker = Arc::clone(&shared);
        std::thread::Builder::new()
            .name(format!("jtm-luau-{hook}"))
            .spawn(move || {
                // Released on any exit, a panic included.
                let _finish = Finish {
                    shared: worker,
                    stuck,
                };
                let _ = tx.send(sandbox::run(job));
            })
            .map_err(|e| host(format!("cannot start the script engine: {e}")))?;
        let outcome = match rx.recv_timeout(self.limits.time + ABANDON_GRACE) {
            Ok(outcome) => Some(outcome),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // The thread is stuck outside Lua code; leave it, but cut off its file access.
                // Counting first keeps the thread's release from running ahead of the count.
                stuck.fetch_add(1, AtomicOrdering::SeqCst);
                if shared.abandon() {
                    shared.record(Limit::Time(self.limits.time));
                    None
                } else {
                    // The thread ended between the timeout and the abandon. An answer is sent
                    // before the thread ends, so none waiting means it panicked: a jtm bug.
                    stuck.fetch_sub(1, AtomicOrdering::SeqCst);
                    rx.try_recv().ok()
                }
            }
            // The thread ended without an answer, so it panicked: a jtm bug, not the plugin's.
            Err(mpsc::RecvTimeoutError::Disconnected) => None,
        };
        if let Some(limit) = shared.violation() {
            return Err(ScriptError::Limit {
                hook: hook.to_owned(),
                limit,
            });
        }
        let outcome =
            outcome.ok_or_else(|| host("the script engine stopped unexpectedly".to_owned()))?;
        outcome.map_err(|failure| match failure {
            sandbox::Failure::Memory => ScriptError::Limit {
                hook: hook.to_owned(),
                limit: Limit::Memory(self.limits.memory),
            },
            sandbox::Failure::Invalid(message) => ScriptError::Invalid {
                hook: hook.to_owned(),
                message,
            },
            sandbox::Failure::Runtime(message) => ScriptError::Failed {
                hook: hook.to_owned(),
                message,
            },
            sandbox::Failure::Host(message) => host(message),
        })
    }
}

/// Marks a hook's thread as ended when dropped, and releases the stuck count if the host had
/// abandoned it.
struct Finish {
    shared: Arc<Shared>,
    stuck: &'static AtomicUsize,
}

impl Drop for Finish {
    fn drop(&mut self) {
        if self.shared.finish() {
            self.stuck.fetch_sub(1, AtomicOrdering::SeqCst);
        }
    }
}

/// A hook's thread is still running.
const RUNNING: u8 = 0;
/// A hook's thread ended before the host gave up on it.
const FINISHED: u8 = 1;
/// The host gave up on a hook whose thread was still running.
const ABANDONED: u8 = 2;

/// State shared between the host and a hook's thread.
#[derive(Debug)]
struct Shared {
    limits: Limits,
    /// Set when the host abandons the hook; its file operations fail from then on.
    cancelled: AtomicBool,
    /// Held by each `jtm.fs` operation while it runs, so abandoning the hook waits for it.
    busy: Mutex<()>,
    /// [`RUNNING`], [`FINISHED`] or [`ABANDONED`]; whichever of the host and the thread moves
    /// it from running first decides who releases the stuck count.
    state: AtomicU8,
    /// The first limit the hook broke, kept even when the script catches the error.
    violation: Mutex<Option<Limit>>,
}

impl Shared {
    fn new(limits: Limits) -> Shared {
        Shared {
            limits,
            cancelled: AtomicBool::new(false),
            busy: Mutex::new(()),
            state: AtomicU8::new(RUNNING),
            violation: Mutex::new(None),
        }
    }

    /// Starts a file operation, which holds the guard until it is done; `None` once the hook
    /// is abandoned.
    fn enter(&self) -> Option<MutexGuard<'_, ()>> {
        let busy = self.busy.lock().unwrap_or_else(PoisonError::into_inner);
        (!self.cancelled()).then_some(busy)
    }

    /// Cuts the hook off: once this returns, no file operation is running and none can start.
    /// Returns whether the hook's thread was still running.
    fn abandon(&self) -> bool {
        self.cancelled.store(true, AtomicOrdering::SeqCst);
        drop(self.busy.lock().unwrap_or_else(PoisonError::into_inner));
        self.state
            .compare_exchange(
                RUNNING,
                ABANDONED,
                AtomicOrdering::SeqCst,
                AtomicOrdering::SeqCst,
            )
            .is_ok()
    }

    /// Marks the hook's thread as ended. Returns whether the host had abandoned it already.
    fn finish(&self) -> bool {
        self.state
            .compare_exchange(
                RUNNING,
                FINISHED,
                AtomicOrdering::SeqCst,
                AtomicOrdering::SeqCst,
            )
            .is_err()
    }

    fn record(&self, limit: Limit) {
        if let Ok(mut slot) = self.violation.lock() {
            slot.get_or_insert(limit);
        }
    }

    fn violation(&self) -> Option<Limit> {
        self.violation.lock().ok().and_then(|slot| slot.clone())
    }

    fn cancelled(&self) -> bool {
        self.cancelled.load(AtomicOrdering::SeqCst)
    }
}

fn check_version(hook: &str, version: &str) -> Result<(), ScriptError> {
    check_version_or_alias(version).map_err(|(_, message)| ScriptError::Invalid {
        hook: hook.to_owned(),
        message: format!("returned `{version}`, which is not a version: {message}"),
    })
}

fn wrong_return(hook: &str, expected: &str, got: &Json) -> ScriptError {
    let got = match got {
        Json::Null => "nil",
        Json::Bool(_) => "a boolean",
        Json::Number(_) => "a number",
        Json::String(_) => "a string",
        Json::Array(_) | Json::Object(_) => "a table",
    };
    ScriptError::Invalid {
        hook: hook.to_owned(),
        message: format!("must return {expected}, not {got}"),
    }
}

#[cfg(test)]
mod tests;
