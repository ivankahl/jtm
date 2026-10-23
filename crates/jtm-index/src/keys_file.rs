//! Assembling and checking the first-party `keys.json` (SPEC.md section 9; the offline signing
//! steps are in `docs/key-ceremony.md`).
//!
//! `build` writes the unsigned file the root key holders sign on the offline machine. `verify`
//! runs the signed file through the client's own loader, [`KeysFile::load`], once for every
//! first-party manifest, so a file that passes here is one every released jtm accepts.
//! Nothing here signs: the root keys never touch a machine that runs this tool.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use jtm_plugin::Manifest;
use jtm_security::{KeysFile, PublicKey, Timestamp, TrustAnchors};
use serde::Serialize;

/// Index keys are meant to be short-lived (SPEC.md section 9: 90 days).
pub(crate) const MAX_KEY_DAYS: i64 = 90;
const DAY: i64 = 86_400;

/// Why a command failed, with the stable code and exit code the client uses for the same
/// failure (SPEC.md section 12).
#[derive(Debug, thiserror::Error)]
pub(crate) enum Failure {
    /// A bad argument or input file: exit 2.
    #[error("{0}")]
    Usage(String),
    /// A file could not be read or written: exit 4.
    #[error("{0}")]
    Io(String),
    /// The signed file is not acceptable.
    #[error("{code}: {message}")]
    Verify {
        code: &'static str,
        exit: u8,
        message: String,
    },
}

impl Failure {
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            Failure::Usage(_) => 2,
            Failure::Io(_) => 4,
            Failure::Verify { exit, .. } => *exit,
        }
    }

    /// The stable `E_` code of the failure (SPEC.md section 12).
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Failure::Usage(_) => "E_USAGE",
            Failure::Io(_) => "E_IO",
            Failure::Verify { code, .. } => code,
        }
    }

    /// The message without the code, for `--json`, where the code has its own field.
    pub(crate) fn message(&self) -> String {
        match self {
            Failure::Verify { message, .. } => message.clone(),
            other => other.to_string(),
        }
    }

    fn verify(code: &'static str, message: String) -> Failure {
        Failure::Verify {
            code,
            exit: 5,
            message,
        }
    }

    fn from_security(plugin: &str, err: &jtm_security::Error) -> Failure {
        use jtm_security::Error;
        let message = format!("for plugin `{plugin}`: {err}");
        match err {
            Error::SignatureInvalid { .. } => Failure::verify("E_SIGNATURE_INVALID", message),
            Error::KeyUntrusted { .. } => Failure::Verify {
                code: "E_KEY_UNTRUSTED",
                exit: 7,
                message,
            },
            Error::Invalid { .. } => Failure::verify("E_INDEX_INVALID", message),
            Error::SigningKeys { .. } => Failure::verify("E_PLUGIN_INVALID", message),
            Error::IndexBinding { .. } => Failure::verify("E_INDEX_BINDING", message),
            Error::IndexRollback { .. } => Failure::verify("E_INDEX_ROLLBACK", message),
            Error::IndexExpired { .. } => Failure::verify("E_INDEX_EXPIRED", message),
            _ => Failure::Verify {
                code: "E_INTERNAL",
                exit: 1,
                message,
            },
        }
    }
}

/// What a first-party manifest says about its trust anchors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FirstParty {
    pub(crate) plugin: String,
    pub(crate) keys: Vec<String>,
    pub(crate) threshold: u32,
}

/// Reads every `<dir>/<plugin>/plugin.toml`, in plugin-name order.
pub(crate) fn load_first_party(dir: &Path) -> Result<Vec<FirstParty>, Failure> {
    let entries = fs::read_dir(dir).map_err(|e| {
        Failure::Io(format!(
            "cannot read plugin directory {}: {e}",
            dir.display()
        ))
    })?;
    let mut manifests = Vec::new();
    for entry in entries {
        let path = entry
            .map_err(|e| Failure::Io(format!("cannot read {}: {e}", dir.display())))?
            .path()
            .join("plugin.toml");
        if !path.is_file() {
            continue;
        }
        let text = fs::read_to_string(&path)
            .map_err(|e| Failure::Io(format!("cannot read {}: {e}", path.display())))?;
        let manifest = Manifest::parse(&text)
            .map_err(|e| Failure::Usage(format!("{}: {e}", path.display())))?;
        manifests.push(FirstParty {
            plugin: manifest.name.clone(),
            keys: manifest.index.signing_keys.clone(),
            threshold: manifest.index.threshold(),
        });
    }
    if manifests.is_empty() {
        return Err(Failure::Usage(format!(
            "no plugin.toml found under {}",
            dir.display()
        )));
    }
    manifests.sort_by(|a, b| a.plugin.cmp(&b.plugin));
    Ok(manifests)
}

/// The inputs of an unsigned `keys.json`.
#[derive(Debug, Clone)]
pub(crate) struct BuildSpec {
    pub(crate) sequence: u64,
    /// How many of the listed index keys must sign each index.
    pub(crate) threshold: u32,
    /// Each index key (the `RW...` line) and when it expires.
    pub(crate) keys: Vec<(String, Timestamp)>,
    /// Plugins every key may sign for. `None` means every first-party plugin.
    pub(crate) scope: Option<Vec<String>>,
    /// The sequence of the `keys.json` published now, which the new file must exceed.
    pub(crate) previous_sequence: Option<u64>,
}

fn usage(message: impl Into<String>) -> Failure {
    Failure::Usage(message.into())
}

fn root_keys(first_party: &[FirstParty]) -> BTreeSet<&str> {
    first_party
        .iter()
        .flat_map(|f| f.keys.iter().map(|k| k.trim()))
        .collect()
}

/// Writes the unsigned `keys.json` for `spec`. Everything the client would refuse, or that the
/// key policy forbids, is refused here instead of after the signing ceremony.
pub(crate) fn build(
    spec: &BuildSpec,
    first_party: &[FirstParty],
    now: Timestamp,
) -> Result<Vec<u8>, Failure> {
    if spec.sequence == 0 {
        return Err(usage("sequence must be at least 1"));
    }
    if let Some(previous) = spec.previous_sequence
        && spec.sequence <= previous
    {
        return Err(usage(format!(
            "sequence {} must be higher than the published sequence {previous}",
            spec.sequence
        )));
    }
    if spec.keys.is_empty() {
        return Err(usage("list at least one index key"));
    }
    let count = u32::try_from(spec.keys.len()).unwrap_or(u32::MAX);
    if spec.threshold == 0 || spec.threshold > count {
        return Err(usage(format!(
            "threshold {} must be between 1 and the {count} keys listed",
            spec.threshold
        )));
    }

    let plugins: BTreeSet<&str> = first_party.iter().map(|f| f.plugin.as_str()).collect();
    let scope: Vec<String> = match &spec.scope {
        None => plugins.iter().map(|p| (*p).to_owned()).collect(),
        Some(names) => {
            let names: BTreeSet<&String> = names.iter().collect();
            if names.is_empty() {
                return Err(usage("a scope must name at least one plugin"));
            }
            if let Some(unknown) = names.iter().find(|n| !plugins.contains(n.as_str())) {
                return Err(usage(format!(
                    "scope `{unknown}` is not a first-party plugin; this keys file is only for {}",
                    plugins.iter().copied().collect::<Vec<_>>().join(", ")
                )));
            }
            names.into_iter().cloned().collect()
        }
    };

    let roots = root_keys(first_party);
    let mut seen = BTreeSet::new();
    let mut keys = Vec::with_capacity(spec.keys.len());
    for (text, expires) in &spec.keys {
        let key = PublicKey::parse(text).map_err(|e| usage(e.to_string()))?;
        if roots.contains(key.as_str()) {
            return Err(usage(format!(
                "key {} is a root key; index keys must be separate keys held by CI",
                key.id()
            )));
        }
        if !seen.insert(key.id()) {
            return Err(usage(format!("key {} is listed twice", key.id())));
        }
        if *expires <= now {
            return Err(usage(format!(
                "key {} would expire at {expires}, which is not in the future",
                key.id()
            )));
        }
        if expires.unix() - now.unix() > MAX_KEY_DAYS * DAY {
            return Err(usage(format!(
                "key {} would expire at {expires}, more than {MAX_KEY_DAYS} days from now; \
                 index keys are short-lived",
                key.id()
            )));
        }
        keys.push(serde_json::json!({
            "key": key.as_str(),
            "scope": scope,
            "expires": expires.to_string(),
        }));
    }

    let file = serde_json::json!({
        "format": 1,
        "sequence": spec.sequence,
        "threshold": spec.threshold,
        "keys": keys,
    });
    let mut bytes =
        serde_json::to_vec_pretty(&file).map_err(|e| Failure::Io(format!("cannot encode: {e}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// What to check a signed `keys.json` against.
#[derive(Debug, Clone)]
pub(crate) struct VerifySpec {
    pub(crate) first_party: Vec<FirstParty>,
    /// Root keys and threshold to use instead of the manifests', to check a file against roots
    /// that are not embedded yet: the new roots of a rotation, or throwaway keys in a rehearsal.
    pub(crate) roots: Option<(Vec<String>, u32)>,
    /// The sequence of the `keys.json` published now, which this file must exceed.
    pub(crate) previous_sequence: Option<u64>,
}

impl VerifySpec {
    pub(crate) fn new(first_party: Vec<FirstParty>) -> VerifySpec {
        VerifySpec {
            first_party,
            roots: None,
            previous_sequence: None,
        }
    }
}

/// What a passing `keys.json` contains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Report {
    pub(crate) sequence: u64,
    pub(crate) threshold: u32,
    pub(crate) sha256: String,
    /// The first-party plugins the file was verified for.
    pub(crate) plugins: Vec<String>,
    /// Ids of the root keys whose signatures counted.
    pub(crate) signers: Vec<String>,
    pub(crate) keys: Vec<KeyReport>,
    pub(crate) warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct KeyReport {
    pub(crate) key: String,
    pub(crate) id: String,
    pub(crate) scope: Vec<String>,
    pub(crate) expires: String,
    pub(crate) days_left: i64,
}

/// Verifies `data` and its `signatures` (the `.minisig` file) with the client loader for every
/// first-party plugin, then applies the publishing checks the loader does not.
pub(crate) fn verify(
    data: &[u8],
    signatures: &[u8],
    spec: &VerifySpec,
    now: Timestamp,
) -> Result<Report, Failure> {
    let mut loaded: Option<KeysFile> = None;
    let mut roots: BTreeSet<String> = BTreeSet::new();
    let mut signers: BTreeSet<String> = BTreeSet::new();
    let targets = &spec.first_party;
    for fp in targets {
        let (keys, threshold) = match &spec.roots {
            Some((keys, threshold)) => (keys.as_slice(), *threshold),
            None => (fp.keys.as_slice(), fp.threshold),
        };
        let anchors = TrustAnchors::preapproved(&fp.plugin, keys, threshold)
            .map_err(|e| Failure::from_security(&fp.plugin, &e))?;
        let file = KeysFile::load(data, signatures, &anchors, now)
            .map_err(|e| Failure::from_security(&fp.plugin, &e))?;
        roots.extend(anchors.keys.iter().map(|k| k.as_str().to_owned()));
        signers.extend(file.verified.signers.iter().map(ToString::to_string));
        loaded.get_or_insert(file);
    }
    let file = loaded.ok_or_else(|| usage("no first-party plugins to verify against"))?;

    if let Some(previous) = spec.previous_sequence
        && file.sequence <= previous
    {
        return Err(Failure::verify(
            "E_INDEX_ROLLBACK",
            format!(
                "keys.json has sequence {}, not higher than the published sequence {previous}",
                file.sequence
            ),
        ));
    }
    if let Some(listed) = file.keys.iter().find(|k| roots.contains(k.key.as_str())) {
        return Err(Failure::verify(
            "E_INDEX_INVALID",
            format!(
                "key {} is a root key and must not also be an index key",
                listed.key.id()
            ),
        ));
    }
    if file.keys.iter().all(|k| k.expires <= now) {
        return Err(Failure::verify(
            "E_INDEX_EXPIRED",
            "every index key in keys.json has expired, so no index could be verified".to_owned(),
        ));
    }

    let plugins: BTreeSet<&str> = targets.iter().map(|f| f.plugin.as_str()).collect();
    let mut warnings = Vec::new();
    let mut covered: BTreeSet<&str> = BTreeSet::new();
    let mut keys = Vec::with_capacity(file.keys.len());
    for k in &file.keys {
        let days_left = (k.expires.unix() - now.unix()).div_euclid(DAY);
        if k.expires <= now {
            warnings.push(format!(
                "key {} has already expired at {}",
                k.key.id(),
                k.expires
            ));
        } else if k.expires.unix() - now.unix() > MAX_KEY_DAYS * DAY {
            warnings.push(format!(
                "key {} expires in {days_left} days; index keys are meant to expire within \
                 {MAX_KEY_DAYS} days",
                k.key.id()
            ));
        }
        for name in k.scope.names() {
            if plugins.contains(name.as_str()) {
                covered.insert(name.as_str());
            } else {
                warnings.push(format!(
                    "key {} is scoped to `{name}`, which is not a first-party plugin",
                    k.key.id()
                ));
            }
        }
        keys.push(KeyReport {
            key: k.key.as_str().to_owned(),
            id: k.key.id().to_string(),
            scope: k.scope.names().iter().cloned().collect(),
            expires: k.expires.to_string(),
            days_left,
        });
    }
    for plugin in plugins.difference(&covered) {
        warnings.push(format!(
            "no index key is scoped to first-party plugin `{plugin}`, so its indices cannot be \
             verified through this file"
        ));
    }

    Ok(Report {
        sequence: file.sequence,
        threshold: file.threshold,
        sha256: file.sha256.clone(),
        plugins: plugins.iter().map(|p| (*p).to_owned()).collect(),
        signers: signers.into_iter().collect(),
        keys,
        warnings,
    })
}

#[cfg(test)]
mod tests;
