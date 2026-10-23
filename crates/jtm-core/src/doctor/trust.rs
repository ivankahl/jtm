//! The trust store check (SPEC.md sections 9 and 14): `state/trust.json`, the company keys in
//! the user config, the signing keys of third-party plugins, and the delegated index keys in
//! the cached keys files.
//!
//! A cached keys file is verified against the plugin's trust anchors before any of it is read,
//! exactly as loading an index does, so a file that was tampered with is reported rather than
//! believed.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;

use jtm_security::keys_json::MAX_KEYS_FILE;
use jtm_security::signature::MAX_SIGNATURE_FILE;
use jtm_security::{KeysFile, PublicKey, Timestamp, TrustAnchors, TrustState};

use crate::error::JtmError;
use crate::indices::{ManifestOrigin, keys_cache_path, trust_path};
use crate::plugins::Plugin;

use super::{Check, Finding, Inputs, W_INDEX_KEY_EXPIRED, list};
use crate::error::ErrorCode;

pub(super) fn check(inputs: &Inputs<'_>) -> Check {
    const ID: &str = "trust_store";
    let path = trust_path(inputs.dirs);
    let mut check = Check::pass(ID, "");
    let state = match TrustState::load(&path) {
        Ok(state) => Some(state),
        Err(err) => {
            let hint = format!(
                "fix {}, or remove it to start over; removing it forgets the rollback history",
                path.display()
            );
            check.summary = "the trust store cannot be read".to_owned();
            check.push(Finding::from_error(&JtmError::from(err)).hint(hint));
            None
        }
    };
    if let Some(state) = &state {
        let tracked: usize = state.indices.values().map(BTreeMap::len).sum();
        let company: Vec<String> = inputs
            .settings
            .plugins
            .iter()
            .filter(|(_, p)| !p.signing_keys.is_empty())
            .map(|(name, p)| {
                let ids: Vec<String> = p.signing_keys.iter().map(|k| k.id().to_string()).collect();
                format!("`{name}` ({})", ids.join(", "))
            })
            .collect();
        let company = if company.is_empty() {
            "no company keys configured".to_owned()
        } else {
            format!("company keys configured for {}", list(&company))
        };
        check.summary = format!(
            "{company}; rollback protection tracks {tracked} index{}",
            if tracked == 1 { "" } else { "es" },
        );
    }

    let mut missing = Vec::new();
    let mut files: BTreeMap<String, Vec<(String, KeysFile)>> = BTreeMap::new();
    for name in inputs.registry.names().unwrap_or_default() {
        let plugin = match inputs.registry.find(&name) {
            Ok(plugin) => plugin,
            Err(err) => {
                check
                    .notes
                    .push(format!("plugin `{name}` was not checked: {err}"));
                continue;
            }
        };
        let company_keys = inputs
            .settings
            .plugins
            .get(&name)
            .map_or(&[][..], |p| p.signing_keys.as_slice());
        let Some(anchors) = anchors(&plugin, company_keys, &mut check) else {
            continue;
        };
        if plugin.manifest.index.keys_url.is_none() {
            continue;
        }
        match cached_keys_file(inputs, &name, &anchors) {
            Ok(Some(file)) => files
                .entry(file.sha256.clone())
                .or_default()
                .push((name, file)),
            Ok(None) => missing.push(name),
            Err(finding) => check.push(*finding),
        }
    }
    if !missing.is_empty() {
        check.notes.push(format!(
            "no keys file is cached yet for {}; `jtm update` fetches it",
            list(&missing)
        ));
    }
    for group in files.into_values() {
        expiry(&group, inputs.now, &mut check);
    }
    check
}

/// The anchors of `plugin`, or `None` after reporting why they cannot be used. A third-party
/// plugin's anchors count only once `company_keys`, its keys in the user config, list them.
fn anchors(plugin: &Plugin, company_keys: &[PublicKey], check: &mut Check) -> Option<TrustAnchors> {
    let manifest = &plugin.manifest;
    let index = &manifest.index;
    let found = match plugin.origin {
        ManifestOrigin::Builtin => {
            TrustAnchors::preapproved(&manifest.name, &index.signing_keys, index.threshold())
        }
        ManifestOrigin::External => TrustAnchors::confirmed(
            &manifest.name,
            &index.signing_keys,
            index.threshold(),
            company_keys,
        ),
    };
    match found {
        Ok(anchors) => Some(anchors),
        Err(err) => {
            let err = JtmError::from(err);
            let hint = match &err {
                JtmError::KeyUntrusted { resolve, .. } => format!(
                    "if you trust the author of `{}`, add their key to `{resolve}` in the user \
                     config",
                    manifest.name
                ),
                _ => format!("fix or reinstall the plugin `{}`", manifest.name),
            };
            check.push(
                Finding::from_error(&err)
                    .hint(hint)
                    .detail("plugin", manifest.name.as_str()),
            );
            None
        }
    }
}

/// The verified cached keys file of `plugin`, `None` when there is none.
fn cached_keys_file(
    inputs: &Inputs<'_>,
    plugin: &str,
    anchors: &TrustAnchors,
) -> Result<Option<KeysFile>, Box<Finding>> {
    let path = keys_cache_path(inputs.dirs, plugin);
    let fail = |err: JtmError| {
        Box::new(
            Finding::from_error(&err)
                .hint(format!(
                    "remove {} and run `jtm update` to fetch a fresh copy",
                    path.display()
                ))
                .detail("plugin", plugin)
                .detail("path", path.display().to_string()),
        )
    };
    let Some(data) = read_capped(&path, MAX_KEYS_FILE).map_err(|e| fail(JtmError::io(&path, e)))?
    else {
        return Ok(None);
    };
    let sig_path = path.with_file_name("keys.json.minisig");
    // A missing signature is read as an empty one, which verification refuses as unsigned.
    let signature = read_capped(&sig_path, MAX_SIGNATURE_FILE)
        .map_err(|e| fail(JtmError::io(&sig_path, e)))?
        .unwrap_or_default();
    KeysFile::load(&data, &signature, anchors, inputs.now)
        .map(Some)
        .map_err(|e| fail(JtmError::from(e)))
}

/// The file at `path`, `None` when it does not exist. One over `limit` bytes is an error.
fn read_capped(path: &std::path::Path, limit: usize) -> std::io::Result<Option<Vec<u8>>> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("larger than the limit of {limit} bytes"),
        ));
    }
    Ok(Some(bytes))
}

/// Reports the expired keys of one keys file, for the plugins that share an identical view of
/// it, once for all of them.
fn expiry(group: &[(String, KeysFile)], now: Timestamp, check: &mut Check) {
    // Plugins whose scoped keys and expired keys are the same share one finding.
    type Key = (Vec<String>, Vec<(String, String)>);
    let mut shared: BTreeMap<Key, Vec<&str>> = BTreeMap::new();
    for (plugin, file) in group {
        let covering: Vec<_> = file
            .keys
            .iter()
            .filter(|k| k.scope.covers(plugin))
            .collect();
        let expired: Vec<(String, String)> = covering
            .iter()
            .filter(|k| now >= k.expires)
            .map(|k| (k.key.id().to_string(), k.expires.to_string()))
            .collect();
        if expired.is_empty() {
            continue;
        }
        let all: Vec<String> = covering.iter().map(|k| k.key.id().to_string()).collect();
        shared.entry((all, expired)).or_default().push(plugin);
    }
    for ((all, expired), plugins) in shared {
        let names: Vec<String> = plugins.iter().map(|p| format!("`{p}`")).collect();
        let keys: Vec<serde_json::Value> = expired
            .iter()
            .map(|(id, at)| serde_json::json!({ "key_id": id, "expires": at }))
            .collect();
        let finding = if expired.len() == all.len() {
            let last = expired
                .iter()
                .map(|(_, at)| at.as_str())
                .max()
                .unwrap_or_default();
            Finding::error(
                ErrorCode::IndexExpired,
                format!(
                    "every index key for {} in the cached keys file has expired, the last on \
                     {last}, so indices signed by those keys no longer verify",
                    list(&names)
                ),
            )
            .hint(
                "run `jtm update` to fetch the current keys file; if it still fails, the \
                 publisher has not rotated its keys",
            )
        } else {
            let (id, at) = &expired[0];
            Finding::warning(
                W_INDEX_KEY_EXPIRED,
                format!(
                    "index key {id} for {} expired at {at}; {} other key{} still sign{} for \
                     {}",
                    list(&names),
                    all.len() - expired.len(),
                    if all.len() - expired.len() == 1 {
                        ""
                    } else {
                        "s"
                    },
                    if all.len() - expired.len() == 1 {
                        "s"
                    } else {
                        ""
                    },
                    if plugins.len() == 1 { "it" } else { "them" },
                ),
            )
            .hint("no action is needed; `jtm update` fetches the current keys file")
        };
        check.push(
            finding
                .detail(
                    "plugins",
                    plugins.iter().map(|p| (*p).to_owned()).collect::<Vec<_>>(),
                )
                .detail("expired_keys", keys),
        );
    }
}
