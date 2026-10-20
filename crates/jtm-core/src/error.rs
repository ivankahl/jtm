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
            ErrorCode::Network | ErrorCode::Offline | ErrorCode::InUse | ErrorCode::Permission => {
                ExitCode::Io
            }
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

    #[error("plugin `{plugin}` script exceeded its {limit} limit")]
    PluginScriptLimit { plugin: String, limit: String },

    #[error("{} is in use", path.display())]
    InUse { path: PathBuf },

    #[error("permission denied: {}", path.display())]
    Permission {
        path: PathBuf,
        #[source]
        source: Option<std::io::Error>,
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
            JtmError::InvalidManifest { .. } | JtmError::PluginSigningKeys { .. } => {
                ErrorCode::PluginInvalid
            }
            JtmError::ToolUnknown { .. } => ErrorCode::ToolUnknown,
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
            JtmError::LockIndexMismatch { .. } => ErrorCode::LockIndexMismatch,
            JtmError::PluginUntrusted { .. } => ErrorCode::PluginUntrusted,
            JtmError::KeyChanged { .. } => ErrorCode::KeyChanged,
            JtmError::InputRequired { .. } => ErrorCode::InputRequired,
            JtmError::PluginScriptLimit { .. } => ErrorCode::PluginScriptLimit,
            JtmError::InUse { .. } => ErrorCode::InUse,
            JtmError::Permission { .. } => ErrorCode::Permission,
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
            JtmError::PluginSigningKeys { plugin, message } => obj([
                ("plugin", plugin.as_str().into()),
                ("message", message.as_str().into()),
            ]),
            JtmError::Config { origin, key, .. } => obj([
                ("origin", origin.as_str().into()),
                ("key", key.as_str().into()),
            ]),
            JtmError::ToolUnknown { tool } => obj([("tool", tool.as_str().into())]),
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
            JtmError::PluginScriptLimit { plugin, limit } => obj([
                ("plugin", plugin.as_str().into()),
                ("limit", limit.as_str().into()),
            ]),
            JtmError::InUse { path: p } | JtmError::Permission { path: p, .. } => {
                obj([("path", path(p))])
            }
        }
    }

    /// Shorthand for [`JtmError::Usage`].
    pub fn usage(message: impl Into<String>) -> Self {
        JtmError::Usage {
            message: message.into(),
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
            S::Io { path, source } if source.kind() == std::io::ErrorKind::PermissionDenied => {
                JtmError::Permission {
                    path,
                    source: Some(source),
                }
            }
            S::Io { path, source } => {
                JtmError::internal(format!("cannot access {}: {source}", path.display()))
            }
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
            F::Io { path, source } if source.kind() == std::io::ErrorKind::PermissionDenied => {
                JtmError::Permission {
                    path,
                    source: Some(source),
                }
            }
            F::Io { path, source } => {
                JtmError::internal(format!("cannot access {}: {source}", path.display()))
            }
            other => JtmError::internal(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn all_lists_every_error_code_once_in_order() {
        for (index, code) in ErrorCode::ALL.iter().enumerate() {
            assert_eq!(
                *code as usize, index,
                "{code} is out of order in ErrorCode::ALL"
            );
        }
        assert_eq!(ErrorCode::ALL.len(), ErrorCode::Internal as usize + 1);
    }

    #[test]
    fn all_lists_every_exit_code() {
        for (index, code) in ExitCode::ALL.iter().enumerate() {
            assert_eq!(code.as_u8() as usize, index);
        }
        assert_eq!(ExitCode::ALL.len(), ExitCode::Partial as usize + 1);
    }

    #[test]
    fn codes_are_unique_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for code in ErrorCode::ALL {
            let s = code.as_str();
            assert!(seen.insert(s), "duplicate code {s}");
            assert!(s.starts_with("E_"), "{s} must start with E_");
            assert!(
                s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
                "{s} must be upper snake case"
            );
        }
    }

    /// Any change to this snapshot renames, renumbers or reclassifies a released code.
    #[test]
    fn error_code_table() {
        let mut table = String::new();
        for code in ErrorCode::ALL {
            let _ = writeln!(
                table,
                "{:<24} exit={} retryable={}",
                code.as_str(),
                code.exit_code().as_u8(),
                code.retryable()
            );
        }
        insta::assert_snapshot!(table);
    }

    #[test]
    fn exit_code_mapping_matches_spec() {
        use ErrorCode as E;
        let expected: &[(ErrorCode, u8)] = &[
            (E::Usage, 2),
            (E::ToolUnknown, 3),
            (E::VersionNotFound, 3),
            (E::AliasUnknown, 3),
            (E::PlatformUnsupported, 3),
            (E::Network, 4),
            (E::Offline, 4),
            (E::SignatureInvalid, 5),
            (E::KeyUntrusted, 7),
            (E::IndexExpired, 5),
            (E::IndexRollback, 5),
            (E::IndexBinding, 5),
            (E::IndexInvalid, 5),
            (E::HashMismatch, 5),
            (E::SizeExceeded, 5),
            (E::ArchiveUnsafe, 5),
            (E::LockOutdated, 6),
            (E::LockIndexMismatch, 6),
            (E::PluginUntrusted, 7),
            (E::KeyChanged, 7),
            (E::InputRequired, 7),
            (E::PluginScriptLimit, 1),
            (E::PluginInvalid, 5),
            (E::InUse, 4),
            (E::Permission, 4),
            (E::Internal, 1),
        ];
        assert_eq!(expected.len(), ErrorCode::ALL.len());
        for (code, exit) in expected {
            assert_eq!(code.exit_code().as_u8(), *exit, "{code}");
        }
    }

    #[test]
    fn error_exposes_code_exit_code_and_message() {
        let err = JtmError::HashMismatch {
            url: "https://example.test/a.zip".into(),
            expected: "aa".into(),
            actual: "bb".into(),
        };
        assert_eq!(err.code(), "E_HASH_MISMATCH");
        assert_eq!(err.exit_code(), ExitCode::Verification);
        assert!(!err.retryable());
        assert_eq!(
            err.to_string(),
            "hash mismatch for https://example.test/a.zip: expected aa, got bb"
        );

        let err = JtmError::usage("bad flag");
        assert_eq!(err.code(), "E_USAGE");
        assert_eq!(err.exit_code(), ExitCode::Usage);
        assert_eq!(err.to_string(), "bad flag");
    }

    #[test]
    fn details_carry_structured_context() {
        let err = JtmError::HashMismatch {
            url: "https://example.test/a.zip".into(),
            expected: "aa".into(),
            actual: "bb".into(),
        };
        assert_eq!(
            Value::Object(err.details()),
            serde_json::json!({
                "expected": "aa",
                "actual": "bb",
                "url": "https://example.test/a.zip"
            })
        );
        assert!(JtmError::usage("bad flag").details().is_empty());
    }

    #[test]
    fn exit_seven_errors_name_their_resolution() {
        let err = JtmError::InputRequired {
            action: "installing a missing version".into(),
            resolve: "--install".into(),
        };
        assert_eq!(err.code(), "E_INPUT_REQUIRED");
        assert_eq!(err.exit_code(), ExitCode::TrustRequired);
        assert_eq!(
            err.to_string(),
            "installing a missing version needs confirmation, but prompts are off; \
             rerun with --install"
        );

        let err = JtmError::KeyChanged {
            plugin: "example".into(),
            old_keys: vec!["RWOLD".into()],
            new_keys: vec!["RWNEW".into()],
            resolve: "jtm trust add RWNEW --scope example".into(),
        };
        assert_eq!(err.code(), "E_KEY_CHANGED");
        assert_eq!(
            Value::Object(err.details()),
            serde_json::json!({
                "plugin": "example",
                "old_keys": ["RWOLD"],
                "new_keys": ["RWNEW"],
                "resolve": "jtm trust add RWNEW --scope example"
            })
        );
        assert_eq!(err.exit_code(), ExitCode::TrustRequired);
        assert!(
            err.to_string()
                .ends_with("run jtm trust add RWNEW --scope example")
        );
    }

    #[test]
    fn invalid_manifest_is_plugin_invalid_listing_each_problem() {
        let error = jtm_plugin::Manifest::parse("schema = 1\nname = \"Bad\"").unwrap_err();
        let err = JtmError::InvalidManifest {
            origin: "plugins/bad/plugin.toml".into(),
            error,
        };
        assert_eq!(err.code(), "E_PLUGIN_INVALID");
        assert_eq!(err.exit_code(), ExitCode::Verification);
        assert!(
            err.to_string()
                .starts_with("plugins/bad/plugin.toml: invalid plugin.toml: ")
        );
        let details = Value::Object(err.details());
        assert_eq!(details["origin"], "plugins/bad/plugin.toml");
        assert_eq!(details["problems"][0]["path"], "display_name");
    }

    #[test]
    fn resolve_errors_map_to_not_found_codes() {
        use jtm_plugin::ResolveError as R;
        let unknown = JtmError::from(R::AliasUnknown {
            tool: "demo".into(),
            alias: "stable".into(),
        });
        assert_eq!(unknown.code(), "E_ALIAS_UNKNOWN");
        let no_match = JtmError::from(R::AliasNoMatch {
            tool: "demo".into(),
            alias: "lts".into(),
            variant: "zulu".into(),
        });
        assert_eq!(no_match.code(), "E_VERSION_NOT_FOUND");
        assert_eq!(no_match.details()["spec"], "zulu:lts");
        let not_found = JtmError::from(R::VersionNotFound {
            tool: "demo".into(),
            variant: "default".into(),
            value: "9.9".into(),
        });
        assert_eq!(not_found.code(), "E_VERSION_NOT_FOUND");
        assert_eq!(not_found.details()["spec"], "default:9.9");
        let script = JtmError::from(R::ScriptUnsupported {
            tool: "demo".into(),
            spec: "custom".into(),
        });
        assert_eq!(script.code(), "E_INTERNAL");
    }

    #[test]
    fn security_errors_map_to_verification_and_trust_codes() {
        let invalid = JtmError::from(jtm_security::Error::SignatureInvalid {
            file: "demo-linux-x64.json".into(),
            message: "bad".into(),
        });
        assert_eq!(invalid.code(), "E_SIGNATURE_INVALID");
        assert_eq!(invalid.exit_code(), ExitCode::Verification);
        let untrusted = JtmError::from(jtm_security::Error::KeyUntrusted {
            file: "demo-linux-x64.json".into(),
            key_id: "0123456789ABCDEF".into(),
            resolve: "jtm trust add <public key> --scope demo".into(),
        });
        assert_eq!(untrusted.code(), "E_KEY_UNTRUSTED");
        assert_eq!(untrusted.exit_code(), ExitCode::TrustRequired);
        assert_eq!(
            untrusted.details()["resolve"],
            "jtm trust add <public key> --scope demo"
        );
        assert_eq!(untrusted.details()["file"], "demo-linux-x64.json");
        assert!(
            untrusted.to_string().starts_with("demo-linux-x64.json"),
            "{untrusted}"
        );
        let invalid = JtmError::from(jtm_security::Error::Invalid {
            file: "keys.json".into(),
            message: "lists no keys".into(),
        });
        assert_eq!(invalid.code(), "E_INDEX_INVALID");
        assert_eq!(invalid.exit_code(), ExitCode::Verification);
        assert_eq!(invalid.details()["file"], "keys.json");
        let signing_keys = JtmError::from(jtm_security::Error::SigningKeys {
            plugin: "demo".into(),
            message: "not a public key".into(),
        });
        assert_eq!(signing_keys.code(), "E_PLUGIN_INVALID");
        assert_eq!(signing_keys.exit_code(), ExitCode::Verification);
        assert_eq!(signing_keys.details()["plugin"], "demo");
        assert_eq!(signing_keys.details()["message"], "not a public key");

        let binding = JtmError::from(jtm_security::Error::IndexBinding {
            file: "demo-linux-x64.json".into(),
            expected: "plugin `demo` on `linux-x64`".into(),
            got: "plugin `other` on `linux-x64`".into(),
        });
        assert_eq!(binding.code(), "E_INDEX_BINDING");
        assert_eq!(binding.details()["got"], "plugin `other` on `linux-x64`");
        let rollback = JtmError::from(jtm_security::Error::IndexRollback {
            file: "demo-linux-x64.json".into(),
            seen: 10,
            got: 9,
            reason: "older than the newest copy already seen".into(),
        });
        assert_eq!(rollback.code(), "E_INDEX_ROLLBACK");
        assert_eq!(rollback.details()["seen"], 10);
        let expired = JtmError::from(jtm_security::Error::IndexExpired {
            file: "demo-linux-x64.json".into(),
            expires: "2026-11-18T03:00:00Z".into(),
        });
        assert_eq!(expired.code(), "E_INDEX_EXPIRED");
        let corrupt = JtmError::from(jtm_security::Error::State {
            path: PathBuf::from("state/trust.json"),
            message: "bad".into(),
        });
        assert_eq!(corrupt.code(), "E_INTERNAL");
        let denied = JtmError::from(jtm_security::Error::Io {
            path: PathBuf::from("state/trust.json"),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        });
        assert_eq!(denied.code(), "E_PERMISSION");
    }

    #[test]
    fn fetch_errors_map_to_stable_codes() {
        use jtm_fetch::Error as F;
        let code = |err: F| JtmError::from(err).code();
        assert_eq!(
            code(F::Scheme {
                url: "http://a".into(),
                reason: "no".into()
            }),
            "E_USAGE"
        );
        assert_eq!(
            code(F::Status {
                url: "https://a".into(),
                status: 503
            }),
            "E_NETWORK"
        );
        assert_eq!(
            code(F::TooLarge {
                url: "https://a".into(),
                limit: 1
            }),
            "E_SIZE_EXCEEDED"
        );
        let mismatch = JtmError::from(F::HashMismatch {
            url: "https://a".into(),
            expected: "aa".into(),
            actual: "bb".into(),
        });
        assert_eq!(mismatch.code(), "E_HASH_MISMATCH");
        assert_eq!(mismatch.details()["url"], "https://a");
    }

    #[test]
    fn exit_code_converts_to_process_exit_code() {
        assert_eq!(
            std::process::ExitCode::from(ExitCode::TrustRequired),
            std::process::ExitCode::from(7)
        );
    }
}
