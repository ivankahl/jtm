//! Errors with stable `E_` codes and their exit-code mapping (SPEC.md section 12).
//!
//! The strings returned by [`ErrorCode::as_str`] and the numbers in [`ExitCode`] are part of
//! jtm's public contract. Never rename or renumber them once released; add new ones instead.

use std::fmt;
use std::path::PathBuf;

use serde_json::{Map, Value};

/// Convenience alias for results that fail with a [`JtmError`].
pub type Result<T, E = JtmError> = std::result::Result<T, E>;

/// Process exit codes (SPEC.md section 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ExitCode {
    /// Success or nothing to do.
    Success = 0,
    /// Unexpected internal error.
    Internal = 1,
    /// Usage error, such as a bad flag or a bad spec.
    Usage = 2,
    /// Tool, version, alias or platform not found.
    NotFound = 3,
    /// Network or I/O error.
    Io = 4,
    /// Signature, hash, rollback, expiry or unsafe archive.
    Verification = 5,
    /// Lockfile or pin problem.
    LockOrPin = 6,
    /// An untrusted plugin or key, or a decision that needs a human.
    TrustRequired = 7,
    /// Partial success in a multi-tool command.
    Partial = 8,
}

impl ExitCode {
    /// Every exit code, in numeric order.
    pub const ALL: &[ExitCode] = &[
        ExitCode::Success,
        ExitCode::Internal,
        ExitCode::Usage,
        ExitCode::NotFound,
        ExitCode::Io,
        ExitCode::Verification,
        ExitCode::LockOrPin,
        ExitCode::TrustRequired,
        ExitCode::Partial,
    ];

    /// The numeric process exit status.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(code: ExitCode) -> Self {
        std::process::ExitCode::from(code.as_u8())
    }
}

/// Stable machine-readable error codes (SPEC.md section 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
#[non_exhaustive]
pub enum ErrorCode {
    Usage,
    ToolUnknown,
    VersionNotFound,
    AliasUnknown,
    PlatformUnsupported,
    Network,
    Offline,
    SignatureInvalid,
    KeyUntrusted,
    IndexExpired,
    IndexRollback,
    IndexBinding,
    IndexInvalid,
    HashMismatch,
    SizeExceeded,
    ArchiveUnsafe,
    LockOutdated,
    LockIndexMismatch,
    PluginUntrusted,
    KeyChanged,
    InputRequired,
    PluginScriptLimit,
    PluginInvalid,
    InUse,
    Permission,
    Io,
    Internal,
}

impl ErrorCode {
    /// Every error code, in declaration order.
    pub const ALL: &[ErrorCode] = &[
        ErrorCode::Usage,
        ErrorCode::ToolUnknown,
        ErrorCode::VersionNotFound,
        ErrorCode::AliasUnknown,
        ErrorCode::PlatformUnsupported,
        ErrorCode::Network,
        ErrorCode::Offline,
        ErrorCode::SignatureInvalid,
        ErrorCode::KeyUntrusted,
        ErrorCode::IndexExpired,
        ErrorCode::IndexRollback,
        ErrorCode::IndexBinding,
        ErrorCode::IndexInvalid,
        ErrorCode::HashMismatch,
        ErrorCode::SizeExceeded,
        ErrorCode::ArchiveUnsafe,
        ErrorCode::LockOutdated,
        ErrorCode::LockIndexMismatch,
        ErrorCode::PluginUntrusted,
        ErrorCode::KeyChanged,
        ErrorCode::InputRequired,
        ErrorCode::PluginScriptLimit,
        ErrorCode::PluginInvalid,
        ErrorCode::InUse,
        ErrorCode::Permission,
        ErrorCode::Io,
        ErrorCode::Internal,
    ];

    /// The stable `E_` string for this code.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::Usage => "E_USAGE",
            ErrorCode::ToolUnknown => "E_TOOL_UNKNOWN",
            ErrorCode::VersionNotFound => "E_VERSION_NOT_FOUND",
            ErrorCode::AliasUnknown => "E_ALIAS_UNKNOWN",
            ErrorCode::PlatformUnsupported => "E_PLATFORM_UNSUPPORTED",
            ErrorCode::Network => "E_NETWORK",
            ErrorCode::Offline => "E_OFFLINE",
            ErrorCode::SignatureInvalid => "E_SIGNATURE_INVALID",
            ErrorCode::KeyUntrusted => "E_KEY_UNTRUSTED",
            ErrorCode::IndexExpired => "E_INDEX_EXPIRED",
            ErrorCode::IndexRollback => "E_INDEX_ROLLBACK",
            ErrorCode::IndexBinding => "E_INDEX_BINDING",
            ErrorCode::IndexInvalid => "E_INDEX_INVALID",
            ErrorCode::HashMismatch => "E_HASH_MISMATCH",
            ErrorCode::SizeExceeded => "E_SIZE_EXCEEDED",
            ErrorCode::ArchiveUnsafe => "E_ARCHIVE_UNSAFE",
            ErrorCode::LockOutdated => "E_LOCK_OUTDATED",
            ErrorCode::LockIndexMismatch => "E_LOCK_INDEX_MISMATCH",
            ErrorCode::PluginUntrusted => "E_PLUGIN_UNTRUSTED",
            ErrorCode::KeyChanged => "E_KEY_CHANGED",
            ErrorCode::InputRequired => "E_INPUT_REQUIRED",
            ErrorCode::PluginScriptLimit => "E_PLUGIN_SCRIPT_LIMIT",
            ErrorCode::PluginInvalid => "E_PLUGIN_INVALID",
            ErrorCode::InUse => "E_IN_USE",
            ErrorCode::Permission => "E_PERMISSION",
            ErrorCode::Io => "E_IO",
            ErrorCode::Internal => "E_INTERNAL",
        }
    }

    /// The process exit code a failure with this code produces.
    pub const fn exit_code(self) -> ExitCode {
        match self {
            ErrorCode::Usage => ExitCode::Usage,
            ErrorCode::ToolUnknown
            | ErrorCode::VersionNotFound
            | ErrorCode::AliasUnknown
            | ErrorCode::PlatformUnsupported => ExitCode::NotFound,
            ErrorCode::Network
            | ErrorCode::Offline
            | ErrorCode::InUse
            | ErrorCode::Permission
            | ErrorCode::Io => ExitCode::Io,
            ErrorCode::SignatureInvalid
            | ErrorCode::IndexExpired
            | ErrorCode::IndexRollback
            | ErrorCode::IndexBinding
            | ErrorCode::IndexInvalid
            | ErrorCode::HashMismatch
            | ErrorCode::SizeExceeded
            | ErrorCode::ArchiveUnsafe
            | ErrorCode::PluginInvalid => ExitCode::Verification,
            ErrorCode::LockOutdated | ErrorCode::LockIndexMismatch => ExitCode::LockOrPin,
            ErrorCode::KeyUntrusted
            | ErrorCode::PluginUntrusted
            | ErrorCode::KeyChanged
            | ErrorCode::InputRequired => ExitCode::TrustRequired,
            // SPEC-QUESTION: section 12 gives no exit code for E_PLUGIN_SCRIPT_LIMIT; a plugin
            // script exceeding its limits is treated as an unexpected failure.
            ErrorCode::PluginScriptLimit | ErrorCode::Internal => ExitCode::Internal,
        }
    }

    /// Whether running the same command again might succeed without any other change.
    pub const fn retryable(self) -> bool {
        // SPEC-QUESTION: exit code 4 is marked retryable, but E_OFFLINE and E_PERMISSION will
        // fail again unchanged, so only transient failures are reported as retryable.
        matches!(self, ErrorCode::Network | ErrorCode::InUse)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A user-facing failure. Every variant maps to exactly one [`ErrorCode`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JtmError {
    #[error("{message}")]
    Usage { message: String },

    /// A `<tool>@<spec>` argument or pin value that does not parse. `column` is 1-based and
    /// counts characters.
    #[error("invalid spec `{input}` at column {column}: {message}")]
    InvalidSpec {
        input: String,
        column: usize,
        message: String,
    },

    /// A `plugin.toml` that does not validate. `origin` names where it came from, such as a
    /// plugin name or a path.
    #[error("{origin}: {error}")]
    InvalidManifest {
        origin: String,
        error: jtm_plugin::manifest::ManifestError,
    },

    /// A plugin manifest whose `[index] signing_keys` are not usable public keys.
    #[error("plugin `{plugin}` signing keys are not valid: {message}")]
    PluginSigningKeys { plugin: String, message: String },

    /// An extracted archive does not have the layout the plugin's manifest describes, such as
    /// a missing `home_subdir` or a bin dir with no files.
    #[error("the `{plugin}` archive does not match its manifest: {message}")]
    LayoutMismatch { plugin: String, message: String },

    /// A configuration value that is invalid or not allowed where it was set. `key` is the
    /// dotted key, or empty when the whole file is at fault.
    #[error("{origin}: {}{message}", key_prefix(.key))]
    Config {
        origin: String,
        key: String,
        message: String,
    },

    #[error("unknown tool `{tool}`")]
    ToolUnknown { tool: String },

    /// A pin file pins a tool no installed plugin provides.
    #[error(
        "{} pins `{tool}`, but no plugin `{tool}` is installed; add it with `jtm plugin add {tool}`",
        file.display()
    )]
    PinToolUnknown { tool: String, file: PathBuf },

    #[error("no version of `{tool}` matches `{spec}`")]
    VersionNotFound { tool: String, spec: String },

    #[error("`{tool}` has no alias `{alias}`")]
    AliasUnknown { tool: String, alias: String },

    #[error("`{tool}` is not available for platform `{platform}`")]
    PlatformUnsupported { tool: String, platform: String },

    /// The machine jtm runs on is not one of the v1 platforms.
    #[error("this machine ({host}) is not a supported platform")]
    HostUnsupported { host: String },

    #[error("network error fetching {url}: {message}")]
    Network {
        url: String,
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    #[error("{action} needs the network, but jtm is running offline")]
    Offline { action: String },

    #[error("invalid signature on {file}: {message}")]
    SignatureInvalid { file: String, message: String },

    #[error("{file} is signed by key `{key_id}`, which is not trusted; to trust it, run {resolve}")]
    KeyUntrusted {
        file: String,
        key_id: String,
        resolve: String,
    },

    #[error("index {index} expired at {expires}; run `jtm update` to fetch a current copy")]
    IndexExpired { index: String, expires: String },

    /// An index older than one already seen, or the same sequence with different content.
    #[error("index {index} has sequence {got}, {reason} (sequence {seen})")]
    IndexRollback {
        index: String,
        seen: u64,
        got: u64,
        reason: String,
    },

    #[error("index {index} is signed for {got}, not {expected}")]
    IndexBinding {
        index: String,
        expected: String,
        got: String,
    },

    /// `state/trust.json` cannot be read as jtm wrote it.
    #[error(
        "{}: {message}; fix or remove the file (removing it forgets trusted keys and \
         rollback history)",
        path.display()
    )]
    TrustStateCorrupt { path: PathBuf, message: String },

    /// A correctly signed index or `keys.json` that is malformed, in an unsupported format, or
    /// fails validation. Maps to `E_INDEX_INVALID`.
    #[error("{file} is signed but not valid: {message}")]
    SignedFileInvalid { file: String, message: String },

    #[error("hash mismatch for {url}: expected {expected}, got {actual}")]
    HashMismatch {
        url: String,
        expected: String,
        actual: String,
    },

    #[error("{what} exceeds the limit of {limit} bytes")]
    SizeExceeded { what: String, limit: u64 },

    #[error("unsafe archive entry `{entry}`: {reason}")]
    ArchiveUnsafe { entry: String, reason: String },

    #[error("jtm.lock is out of date: {message}")]
    LockOutdated { message: String },

    #[error("jtm.lock entry for `{tool}` does not match the signed index: {message}")]
    LockIndexMismatch { tool: String, message: String },

    /// A third-party plugin's manifest differs from the one `jtm.lock` recorded (SPEC.md
    /// section 11). Maps to `E_LOCK_INDEX_MISMATCH` and exits 6: it is a lock mismatch like a
    /// changed hash.
    #[error(
        "plugin `{tool}` changed since jtm.lock recorded it (manifest sha256 {locked}, now \
         {actual}); check the change, then run `jtm lock --upgrade {tool}`"
    )]
    LockPluginMismatch {
        tool: String,
        locked: String,
        actual: String,
    },

    #[error("plugin `{plugin}` is not trusted; to trust it, use {resolve}")]
    PluginUntrusted { plugin: String, resolve: String },

    /// A plugin's signing keys changed without a rotation signed by a current key. `--yes`
    /// never accepts this.
    #[error(
        "signing keys for plugin `{plugin}` changed without a signed rotation; \
         if the change is expected, run {resolve}"
    )]
    KeyChanged {
        plugin: String,
        old_keys: Vec<String>,
        new_keys: Vec<String>,
        resolve: String,
    },

    /// A step needed a confirmation or a choice while prompts were off.
    #[error("{action} needs confirmation, but prompts are off; rerun with {resolve}")]
    InputRequired { action: String, resolve: String },

    /// A `plugin.lua` hook broke a sandbox limit: memory, time or install dir containment.
    #[error("plugin `{plugin}` hook `{hook}` stopped at a sandbox limit: {limit}")]
    PluginScriptLimit {
        plugin: String,
        hook: String,
        limit: String,
    },

    /// A `plugin.lua` hook does not compile, is missing, raised an error or returned the wrong
    /// thing.
    #[error("plugin `{plugin}` hook `{hook}` failed: {message}")]
    PluginScript {
        plugin: String,
        hook: String,
        message: String,
    },

    #[error("{} is in use", path.display())]
    InUse { path: PathBuf },

    #[error("permission denied: {}", path.display())]
    Permission {
        path: PathBuf,
        #[source]
        source: Option<std::io::Error>,
    },

    /// Reading or writing a file failed for a reason other than permissions, such as a full
    /// disk.
    #[error("cannot access {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("internal error: {message}")]
    Internal { message: String },
}

impl JtmError {
    /// The [`ErrorCode`] for this error.
    pub const fn kind(&self) -> ErrorCode {
        match self {
            JtmError::Usage { .. } | JtmError::InvalidSpec { .. } | JtmError::Config { .. } => {
                ErrorCode::Usage
            }
            // SPEC-QUESTION: section 12 has no code for a plugin script that fails without
            // breaking a limit. The plugin is broken, so it is reported as an invalid plugin.
            JtmError::InvalidManifest { .. }
            | JtmError::PluginScript { .. }
            | JtmError::PluginSigningKeys { .. }
            | JtmError::LayoutMismatch { .. } => ErrorCode::PluginInvalid,
            JtmError::ToolUnknown { .. } | JtmError::PinToolUnknown { .. } => {
                ErrorCode::ToolUnknown
            }
            JtmError::VersionNotFound { .. } => ErrorCode::VersionNotFound,
            JtmError::AliasUnknown { .. } => ErrorCode::AliasUnknown,
            JtmError::PlatformUnsupported { .. } | JtmError::HostUnsupported { .. } => {
                ErrorCode::PlatformUnsupported
            }
            JtmError::Network { .. } => ErrorCode::Network,
            JtmError::Offline { .. } => ErrorCode::Offline,
            JtmError::SignatureInvalid { .. } => ErrorCode::SignatureInvalid,
            JtmError::KeyUntrusted { .. } => ErrorCode::KeyUntrusted,
            JtmError::IndexExpired { .. } => ErrorCode::IndexExpired,
            JtmError::IndexRollback { .. } => ErrorCode::IndexRollback,
            JtmError::IndexBinding { .. } => ErrorCode::IndexBinding,
            JtmError::SignedFileInvalid { .. } => ErrorCode::IndexInvalid,
            JtmError::HashMismatch { .. } => ErrorCode::HashMismatch,
            JtmError::SizeExceeded { .. } => ErrorCode::SizeExceeded,
            JtmError::ArchiveUnsafe { .. } => ErrorCode::ArchiveUnsafe,
            JtmError::LockOutdated { .. } => ErrorCode::LockOutdated,
            JtmError::LockIndexMismatch { .. } | JtmError::LockPluginMismatch { .. } => {
                ErrorCode::LockIndexMismatch
            }
            JtmError::PluginUntrusted { .. } => ErrorCode::PluginUntrusted,
            JtmError::KeyChanged { .. } => ErrorCode::KeyChanged,
            JtmError::InputRequired { .. } => ErrorCode::InputRequired,
            JtmError::PluginScriptLimit { .. } => ErrorCode::PluginScriptLimit,
            JtmError::InUse { .. } => ErrorCode::InUse,
            JtmError::Permission { .. } => ErrorCode::Permission,
            JtmError::Io { .. } => ErrorCode::Io,
            // SPEC-QUESTION: section 12 has no code for corrupt local state. It is not a
            // verification failure of anything downloaded, so it is reported as internal.
            JtmError::TrustStateCorrupt { .. } | JtmError::Internal { .. } => ErrorCode::Internal,
        }
    }

    /// The stable `E_` string for this error.
    pub const fn code(&self) -> &'static str {
        self.kind().as_str()
    }

    /// The process exit code this error produces.
    pub const fn exit_code(&self) -> ExitCode {
        self.kind().exit_code()
    }

    /// Whether running the same command again might succeed without any other change.
    pub const fn retryable(&self) -> bool {
        self.kind().retryable()
    }

    /// Structured context for machine output: the variant's fields, minus the message text.
    pub fn details(&self) -> Map<String, Value> {
        fn obj<const N: usize>(pairs: [(&str, Value); N]) -> Map<String, Value> {
            pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
        }
        let path = |p: &PathBuf| Value::from(p.display().to_string());
        match self {
            JtmError::Usage { .. } | JtmError::LockOutdated { .. } | JtmError::Internal { .. } => {
                Map::new()
            }
            JtmError::InvalidSpec { input, column, .. } => obj([
                ("input", input.as_str().into()),
                ("column", (*column).into()),
            ]),
            JtmError::InvalidManifest { origin, error } => obj([
                ("origin", origin.as_str().into()),
                (
                    "problems",
                    error
                        .problems
                        .iter()
                        .map(|p| {
                            serde_json::json!({
                                "path": p.path,
                                "message": p.message,
                                "line": p.line,
                            })
                        })
                        .collect::<Vec<_>>()
                        .into(),
                ),
            ]),
            JtmError::LayoutMismatch { plugin, message } => obj([
                ("plugin", plugin.as_str().into()),
                ("message", message.as_str().into()),
            ]),
            JtmError::PluginSigningKeys { plugin, message } => obj([
                ("plugin", plugin.as_str().into()),
                ("message", message.as_str().into()),
            ]),
            JtmError::Config { origin, key, .. } => obj([
                ("origin", origin.as_str().into()),
                ("key", key.as_str().into()),
            ]),
            JtmError::ToolUnknown { tool } => obj([("tool", tool.as_str().into())]),
            JtmError::PinToolUnknown { tool, file } => obj([
                ("tool", tool.as_str().into()),
                ("file", path(file)),
                ("resolve", format!("jtm plugin add {tool}").into()),
            ]),
            JtmError::VersionNotFound { tool, spec } => obj([
                ("tool", tool.as_str().into()),
                ("spec", spec.as_str().into()),
            ]),
            JtmError::AliasUnknown { tool, alias } => obj([
                ("tool", tool.as_str().into()),
                ("alias", alias.as_str().into()),
            ]),
            JtmError::PlatformUnsupported { tool, platform } => obj([
                ("tool", tool.as_str().into()),
                ("platform", platform.as_str().into()),
            ]),
            JtmError::HostUnsupported { host } => obj([("host", host.as_str().into())]),
            JtmError::Network { url, .. } => obj([("url", url.as_str().into())]),
            JtmError::Offline { action } => obj([("action", action.as_str().into())]),
            JtmError::SignatureInvalid { file, .. } | JtmError::SignedFileInvalid { file, .. } => {
                obj([("file", file.as_str().into())])
            }
            JtmError::KeyUntrusted {
                file,
                key_id,
                resolve,
            } => obj([
                ("file", file.as_str().into()),
                ("key_id", key_id.as_str().into()),
                ("resolve", resolve.as_str().into()),
            ]),
            JtmError::IndexExpired { index, expires } => obj([
                ("index", index.as_str().into()),
                ("expires", expires.as_str().into()),
            ]),
            JtmError::IndexRollback {
                index, seen, got, ..
            } => obj([
                ("index", index.as_str().into()),
                ("seen", (*seen).into()),
                ("got", (*got).into()),
            ]),
            JtmError::IndexBinding {
                index,
                expected,
                got,
            } => obj([
                ("index", index.as_str().into()),
                ("expected", expected.as_str().into()),
                ("got", got.as_str().into()),
            ]),
            JtmError::TrustStateCorrupt { path: p, .. } => obj([("path", path(p))]),
            JtmError::HashMismatch {
                url,
                expected,
                actual,
            } => obj([
                ("expected", expected.as_str().into()),
                ("actual", actual.as_str().into()),
                ("url", url.as_str().into()),
            ]),
            JtmError::SizeExceeded { what, limit } => {
                obj([("what", what.as_str().into()), ("limit", (*limit).into())])
            }
            JtmError::ArchiveUnsafe { entry, reason } => obj([
                ("entry", entry.as_str().into()),
                ("reason", reason.as_str().into()),
            ]),
            JtmError::LockIndexMismatch { tool, .. } => obj([("tool", tool.as_str().into())]),
            JtmError::LockPluginMismatch {
                tool,
                locked,
                actual,
            } => obj([
                ("tool", tool.as_str().into()),
                ("locked", locked.as_str().into()),
                ("actual", actual.as_str().into()),
            ]),
            JtmError::PluginUntrusted { plugin, resolve } => obj([
                ("plugin", plugin.as_str().into()),
                ("resolve", resolve.as_str().into()),
            ]),
            JtmError::KeyChanged {
                plugin,
                old_keys,
                new_keys,
                resolve,
            } => obj([
                ("plugin", plugin.as_str().into()),
                ("old_keys", old_keys.clone().into()),
                ("new_keys", new_keys.clone().into()),
                ("resolve", resolve.as_str().into()),
            ]),
            JtmError::InputRequired { action, resolve } => obj([
                ("action", action.as_str().into()),
                ("resolve", resolve.as_str().into()),
            ]),
            JtmError::PluginScriptLimit {
                plugin,
                hook,
                limit,
            } => obj([
                ("plugin", plugin.as_str().into()),
                ("hook", hook.as_str().into()),
                ("limit", limit.as_str().into()),
            ]),
            JtmError::PluginScript {
                plugin,
                hook,
                message,
            } => obj([
                ("plugin", plugin.as_str().into()),
                ("hook", hook.as_str().into()),
                ("message", message.as_str().into()),
            ]),
            JtmError::InUse { path: p }
            | JtmError::Permission { path: p, .. }
            | JtmError::Io { path: p, .. } => obj([("path", path(p))]),
        }
    }

    /// Shorthand for [`JtmError::Usage`].
    pub fn usage(message: impl Into<String>) -> Self {
        JtmError::Usage {
            message: message.into(),
        }
    }

    /// A failed file operation on `path`: `E_PERMISSION` when access was denied, otherwise
    /// `E_IO`.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        let path = path.into();
        if source.kind() == std::io::ErrorKind::PermissionDenied {
            JtmError::Permission {
                path,
                source: Some(source),
            }
        } else {
            JtmError::Io { path, source }
        }
    }

    /// Shorthand for [`JtmError::Internal`].
    pub fn internal(message: impl Into<String>) -> Self {
        JtmError::Internal {
            message: message.into(),
        }
    }
}

fn key_prefix(key: &str) -> String {
    if key.is_empty() {
        String::new()
    } else {
        format!("`{key}`: ")
    }
}

impl JtmError {
    /// The error for a failed hook of `plugin`.
    pub fn script(plugin: &str, err: jtm_plugin::script::ScriptError) -> JtmError {
        use jtm_plugin::script::ScriptError as S;
        match err {
            S::Limit { hook, limit } => JtmError::PluginScriptLimit {
                plugin: plugin.to_owned(),
                hook,
                limit: limit.to_string(),
            },
            S::Invalid { hook, message } | S::Failed { hook, message } => JtmError::PluginScript {
                plugin: plugin.to_owned(),
                hook,
                message,
            },
            S::Io {
                path,
                kind,
                message,
                ..
            } => JtmError::io(path, std::io::Error::new(kind, message)),
            S::Host { hook, message } => {
                JtmError::internal(format!("plugin `{plugin}` hook `{hook}`: {message}"))
            }
        }
    }
}

impl From<jtm_plugin::ResolveError> for JtmError {
    fn from(err: jtm_plugin::ResolveError) -> Self {
        use jtm_plugin::ResolveError as R;
        match err {
            R::AliasUnknown { tool, alias } => JtmError::AliasUnknown { tool, alias },
            R::AliasNoMatch {
                tool,
                alias: value,
                variant,
            }
            | R::VersionNotFound {
                tool,
                variant,
                value,
            } => JtmError::VersionNotFound {
                tool,
                spec: format!("{variant}:{value}"),
            },
            R::ScriptUnsupported { .. } => JtmError::internal(err.to_string()),
        }
    }
}

impl From<jtm_security::Error> for JtmError {
    fn from(err: jtm_security::Error) -> Self {
        use jtm_security::Error as S;
        match err {
            S::SignatureInvalid { file, message } => JtmError::SignatureInvalid { file, message },
            S::KeyUntrusted {
                file,
                key_id,
                resolve,
            } => JtmError::KeyUntrusted {
                file,
                key_id,
                resolve,
            },
            S::Invalid { file, message } => JtmError::SignedFileInvalid { file, message },
            S::SigningKeys { plugin, message } => JtmError::PluginSigningKeys { plugin, message },
            S::IndexBinding {
                file,
                expected,
                got,
            } => JtmError::IndexBinding {
                index: file,
                expected,
                got,
            },
            S::IndexRollback {
                file,
                seen,
                got,
                reason,
            } => JtmError::IndexRollback {
                index: file,
                seen,
                got,
                reason,
            },
            S::IndexExpired { file, expires } => JtmError::IndexExpired {
                index: file,
                expires,
            },
            S::State { path, message } => JtmError::TrustStateCorrupt { path, message },
            S::Io { path, source } => JtmError::io(path, source),
            other => JtmError::internal(other.to_string()),
        }
    }
}

impl From<jtm_archive::Error> for JtmError {
    fn from(err: jtm_archive::Error) -> Self {
        use jtm_archive::Error as A;
        match err {
            A::Unsafe { entry, reason } => JtmError::ArchiveUnsafe { entry, reason },
            A::Malformed { message } => JtmError::ArchiveUnsafe {
                entry: String::new(),
                reason: message,
            },
            A::Io { path, source } => JtmError::io(path, source),
            other => JtmError::internal(other.to_string()),
        }
    }
}

impl From<jtm_fetch::Error> for JtmError {
    fn from(err: jtm_fetch::Error) -> Self {
        use jtm_fetch::Error as F;
        match err {
            F::Scheme { url, reason } => {
                JtmError::usage(format!("refusing to fetch {url}: {reason}"))
            }
            // The message names the setting, never its value, which may hold credentials.
            F::Proxy { origin, message } => {
                JtmError::usage(format!("invalid proxy in {origin}: {message}"))
            }
            // The fetch error already names the setting and the path.
            // SPEC-QUESTION: section 12 has no configuration error code; a bad CA bundle is
            // E_USAGE, like other unusable settings, and never ignored.
            err @ F::CaFile { .. } => JtmError::usage(err.to_string()),
            F::Network {
                url,
                message,
                source,
                ..
            } => JtmError::Network {
                url,
                message,
                source,
            },
            F::Status { url, status } => JtmError::Network {
                message: format!("the server answered HTTP {status}"),
                url,
                source: None,
            },
            F::TooLarge { url, limit } => JtmError::SizeExceeded { what: url, limit },
            F::HashMismatch {
                url,
                expected,
                actual,
            } => JtmError::HashMismatch {
                url,
                expected,
                actual,
            },
            F::Io { path, source } => JtmError::io(path, source),
            other => JtmError::internal(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests;
