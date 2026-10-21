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
        (E::Io, 4),
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
fn archive_errors_are_unsafe_archives() {
    let unsafe_entry = JtmError::from(jtm_archive::Error::Unsafe {
        entry: "../x".into(),
        reason: "contains a `..` component".into(),
    });
    assert_eq!(unsafe_entry.code(), "E_ARCHIVE_UNSAFE");
    assert_eq!(unsafe_entry.details()["entry"], "../x");
    let malformed = JtmError::from(jtm_archive::Error::Malformed {
        message: "bad header".into(),
    });
    assert_eq!(malformed.code(), "E_ARCHIVE_UNSAFE");
}

#[test]
fn io_failures_are_e_io_unless_access_was_denied() {
    let full = JtmError::io("tools", std::io::Error::other("no space left on device"));
    assert_eq!(full.code(), "E_IO");
    assert_eq!(full.exit_code(), ExitCode::Io);
    assert!(!full.retryable());
    assert_eq!(full.details()["path"], "tools");
    let denied = JtmError::io(
        "tools",
        std::io::Error::from(std::io::ErrorKind::PermissionDenied),
    );
    assert_eq!(denied.code(), "E_PERMISSION");
    let from_fetch = JtmError::from(jtm_fetch::Error::Io {
        path: "cache".into(),
        source: std::io::Error::other("disk full"),
    });
    assert_eq!(from_fetch.code(), "E_IO");
}

#[test]
fn exit_code_converts_to_process_exit_code() {
    assert_eq!(
        std::process::ExitCode::from(ExitCode::TrustRequired),
        std::process::ExitCode::from(7)
    );
}

#[test]
fn script_errors_blame_the_plugin_only_for_what_it_did() {
    use jtm_plugin::script::ScriptError as S;
    let hook = || "post_extract".to_owned();
    let code = |err: S| JtmError::script("demo", err).code();
    assert_eq!(
        code(S::Invalid {
            hook: hook(),
            message: "no function".to_owned()
        }),
        "E_PLUGIN_INVALID"
    );
    assert_eq!(
        code(S::Failed {
            hook: hook(),
            message: "boom".to_owned()
        }),
        "E_PLUGIN_INVALID"
    );
    assert_eq!(
        code(S::Io {
            hook: hook(),
            path: PathBuf::from("/data/tools/.tmp/x"),
            kind: std::io::ErrorKind::NotFound,
            message: "gone".to_owned()
        }),
        "E_IO"
    );
    assert_eq!(
        code(S::Io {
            hook: hook(),
            path: PathBuf::from("/data/tools/.tmp/x"),
            kind: std::io::ErrorKind::PermissionDenied,
            message: "denied".to_owned()
        }),
        "E_PERMISSION"
    );
    let host = JtmError::script(
        "demo",
        S::Host {
            hook: hook(),
            message: "the script engine stopped".to_owned(),
        },
    );
    assert_eq!(host.code(), "E_INTERNAL");
    assert!(
        host.to_string().contains("the script engine stopped"),
        "{host}"
    );
}
