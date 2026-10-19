//! Layered configuration (SPEC.md sections 6, 13 and 14).
//!
//! Layers merge in this order, later winning: built-in defaults, system config, user config,
//! project `.jtm.toml` `[settings]`, `JTM_<SECTION>_<KEY>` environment variables, and
//! command-line flags. A key the system config marks `locked` keeps its system value whatever
//! later layers say. A project file can never set a key that weakens verification or
//! redirects downloads.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use jtm_plugin::names::{check_name_segment, check_plugin_name};

use crate::error::{JtmError, Result};

/// The value of `index.auto_refresh`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoRefresh {
    Tty,
    Always,
    Never,
}

/// The value of `security.expiry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpiryPolicy {
    /// Expired indices are an error only from the canonical remote.
    RemoteOnly,
    /// Expired indices are an error from every source.
    Enforce,
}

/// The merged, validated configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub pin: PinSettings,
    pub index: IndexSettings,
    pub security: SecuritySettings,
    pub download: DownloadSettings,
    pub network: NetworkSettings,
    pub extract: ExtractSettings,
    /// URL prefix rewrites, from source prefix to replacement.
    pub mirrors: BTreeMap<String, String>,
    pub plugins: BTreeMap<String, PluginSettings>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinSettings {
    /// `native`, or the name of an interop format a plugin declares.
    pub default_format: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexSettings {
    pub auto_refresh: AutoRefresh,
    pub ttl_hours: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecuritySettings {
    pub expiry: ExpiryPolicy,
    pub allow_http_mirrors: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadSettings {
    pub concurrency: u32,
    /// `None` means the platform cache directory.
    pub cache_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSettings {
    /// `None` means the proxy from the environment.
    pub proxy: Option<String>,
    pub extra_ca_file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractSettings {
    pub max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PluginSettings {
    /// Replaces the index location in the plugin's manifest.
    pub index_url: Option<String>,
}

/// Where a configuration value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Layer {
    Default,
    System,
    User,
    Project,
    Env,
    Flag,
}

impl Layer {
    pub const fn as_str(self) -> &'static str {
        match self {
            Layer::Default => "default",
            Layer::System => "system",
            Layer::User => "user",
            Layer::Project => "project",
            Layer::Env => "env",
            Layer::Flag => "flag",
        }
    }
}

/// A layer and the file, variable or flag within it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub layer: Layer,
    /// The file path, variable name or flag; empty for built-in defaults.
    pub name: String,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.layer {
            Layer::Default => f.write_str("built-in default"),
            Layer::System => write!(f, "system config {}", self.name),
            Layer::User => write!(f, "user config {}", self.name),
            Layer::Project => write!(f, "project file {}", self.name),
            Layer::Env => write!(f, "environment variable {}", self.name),
            Layer::Flag => write!(f, "flag {}", self.name),
        }
    }
}

/// A non-fatal configuration problem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    pub code: &'static str,
    pub message: String,
    pub key: String,
    pub origin: Origin,
}

/// Warning code for a later layer trying to change a locked key.
pub const W_CONFIG_LOCKED: &str = "W_CONFIG_LOCKED";

/// A config file's location and contents.
#[derive(Debug, Clone, Copy)]
pub struct FileSource<'a> {
    pub path: &'a Path,
    pub text: &'a str,
}

/// Everything configuration is built from. Files are passed in already read, so loading is
/// pure and every layer can be tested without touching the disk.
pub struct ConfigInputs<'a> {
    pub system: Option<FileSource<'a>>,
    pub user: Option<FileSource<'a>>,
    /// The project's `.jtm.toml`; only its `[settings]` table is read.
    pub project: Option<FileSource<'a>>,
    /// Looks up one environment variable.
    pub env: &'a dyn Fn(&str) -> Option<OsString>,
    /// Settings from command-line flags, as dotted keys and text values.
    pub flags: &'a [(&'a str, &'a str)],
}

impl fmt::Debug for ConfigInputs<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigInputs")
            .field("system", &self.system)
            .field("user", &self.user)
            .field("project", &self.project)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

/// The result of loading configuration: settings, where each value came from, and warnings.
#[derive(Debug, Clone)]
pub struct Config {
    pub settings: Settings,
    pub warnings: Vec<ConfigWarning>,
    origins: BTreeMap<String, Origin>,
}

impl Config {
    /// Merges every layer, validates the result, and records where each value came from.
    pub fn load(inputs: &ConfigInputs<'_>) -> Result<Config> {
        let mut merged = Merged::defaults();
        if let Some(file) = inputs.system {
            merged.apply(read_file(Layer::System, file)?);
        }
        if let Some(file) = inputs.user {
            merged.apply(read_file(Layer::User, file)?);
        }
        if let Some(file) = inputs.project {
            merged.apply(read_file(Layer::Project, file)?);
        }
        merged.apply(read_env(inputs.env)?);
        merged.apply(read_flags(inputs.flags)?);
        let settings = merged.build()?;
        Ok(Config {
            settings,
            warnings: merged.warnings,
            origins: merged
                .entries
                .into_iter()
                .map(|(key, entry)| (key, entry.origin))
                .collect(),
        })
    }

    /// Where the value of a dotted key such as `index.ttl_hours` came from, if it is set.
    pub fn origin(&self, key: &str) -> Option<&Origin> {
        self.origins.get(key)
    }

    /// Every set key and its origin, in key order.
    pub fn origins(&self) -> impl Iterator<Item = (&str, &Origin)> {
        self.origins.iter().map(|(k, o)| (k.as_str(), o))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bool,
    Int {
        min: u64,
        max: u64,
    },
    Bytes,
    Text,
    Url,
    Path,
    Choice(&'static [&'static str]),
    /// `native` or a plugin interop format name.
    Format,
}

/// A scalar key in a fixed section.
#[derive(Debug)]
struct KeyDef {
    section: &'static str,
    name: &'static str,
    kind: Kind,
    default: Option<DefaultValue>,
    /// Whether a project file may set it.
    project: bool,
}

#[derive(Debug, Clone, Copy)]
enum DefaultValue {
    Bool(bool),
    Int(u64),
    Text(&'static str),
}

const GIB: u64 = 1 << 30;

const KEYS: &[KeyDef] = &[
    KeyDef {
        section: "pin",
        name: "default_format",
        kind: Kind::Format,
        default: Some(DefaultValue::Text("native")),
        project: true,
    },
    KeyDef {
        section: "index",
        name: "auto_refresh",
        kind: Kind::Choice(&["tty", "always", "never"]),
        default: Some(DefaultValue::Text("tty")),
        project: true,
    },
    KeyDef {
        section: "index",
        name: "ttl_hours",
        kind: Kind::Int {
            min: 0,
            max: 24 * 365,
        },
        default: Some(DefaultValue::Int(24)),
        project: true,
    },
    KeyDef {
        section: "security",
        name: "expiry",
        kind: Kind::Choice(&["remote-only", "enforce"]),
        default: Some(DefaultValue::Text("remote-only")),
        project: false,
    },
    KeyDef {
        section: "security",
        name: "allow_http_mirrors",
        kind: Kind::Bool,
        default: Some(DefaultValue::Bool(false)),
        project: false,
    },
    KeyDef {
        section: "download",
        name: "concurrency",
        kind: Kind::Int { min: 1, max: 64 },
        default: Some(DefaultValue::Int(4)),
        project: true,
    },
    // SPEC-QUESTION: section 14 does not list `download.cache_dir` among the keys a project
    // file cannot set. A cloned repository choosing where jtm writes downloads is refused here.
    KeyDef {
        section: "download",
        name: "cache_dir",
        kind: Kind::Path,
        default: None,
        project: false,
    },
    KeyDef {
        section: "network",
        name: "proxy",
        kind: Kind::Url,
        default: None,
        project: false,
    },
    KeyDef {
        section: "network",
        name: "extra_ca_file",
        kind: Kind::Path,
        default: None,
        project: false,
    },
    KeyDef {
        section: "extract",
        name: "max_bytes",
        kind: Kind::Bytes,
        default: Some(DefaultValue::Int(4 * GIB)),
        project: false,
    },
];

/// The identity of one configuration value.
#[derive(Debug, Clone)]
enum Key {
    Scalar(&'static KeyDef),
    Mirror(String),
    PluginIndexUrl(String),
}

impl Key {
    fn dotted(&self) -> String {
        match self {
            Key::Scalar(def) => format!("{}.{}", def.section, def.name),
            Key::Mirror(prefix) => format!("mirrors.{prefix:?}"),
            Key::PluginIndexUrl(plugin) => format!("plugins.{plugin}.index_url"),
        }
    }

    fn allowed_in_project(&self) -> bool {
        match self {
            Key::Scalar(def) => def.project,
            Key::Mirror(_) | Key::PluginIndexUrl(_) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Value {
    Bool(bool),
    Int(u64),
    Text(String),
}

#[derive(Debug, Clone)]
struct Entry {
    key: Key,
    value: Value,
    origin: Origin,
    locked: bool,
}

struct Merged {
    entries: BTreeMap<String, Entry>,
    warnings: Vec<ConfigWarning>,
}

impl Merged {
    fn defaults() -> Merged {
        let origin = Origin {
            layer: Layer::Default,
            name: String::new(),
        };
        let entries = KEYS
            .iter()
            .filter_map(|def| {
                let value = match def.default? {
                    DefaultValue::Bool(b) => Value::Bool(b),
                    DefaultValue::Int(n) => Value::Int(n),
                    DefaultValue::Text(t) => Value::Text(t.to_owned()),
                };
                let key = Key::Scalar(def);
                Some((
                    key.dotted(),
                    Entry {
                        key,
                        value,
                        origin: origin.clone(),
                        locked: false,
                    },
                ))
            })
            .collect();
        Merged {
            entries,
            warnings: Vec::new(),
        }
    }

    fn apply(&mut self, layer: Vec<Entry>) {
        for entry in layer {
            let dotted = entry.key.dotted();
            match self.entries.get(&dotted) {
                Some(current) if current.locked => {
                    if current.value != entry.value {
                        self.warnings.push(ConfigWarning {
                            code: W_CONFIG_LOCKED,
                            message: format!(
                                "`{dotted}` is locked by the {}; ignoring the value from the {}",
                                current.origin, entry.origin
                            ),
                            key: dotted,
                            origin: entry.origin,
                        });
                    }
                }
                _ => {
                    self.entries.insert(dotted, entry);
                }
            }
        }
    }

    fn scalar(&self, section: &str, name: &str) -> Option<&Value> {
        self.entries
            .get(&format!("{section}.{name}"))
            .map(|e| &e.value)
    }

    fn text(&self, section: &str, name: &str) -> Option<String> {
        match self.scalar(section, name)? {
            Value::Text(t) => Some(t.clone()),
            _ => None,
        }
    }

    fn int(&self, section: &str, name: &str) -> u64 {
        match self.scalar(section, name) {
            Some(Value::Int(n)) => *n,
            _ => 0,
        }
    }

    fn build(&self) -> Result<Settings> {
        let auto_refresh = match self.text("index", "auto_refresh").as_deref() {
            Some("always") => AutoRefresh::Always,
            Some("never") => AutoRefresh::Never,
            _ => AutoRefresh::Tty,
        };
        let expiry = match self.text("security", "expiry").as_deref() {
            Some("enforce") => ExpiryPolicy::Enforce,
            _ => ExpiryPolicy::RemoteOnly,
        };
        let allow_http_mirrors = matches!(
            self.scalar("security", "allow_http_mirrors"),
            Some(Value::Bool(true))
        );

        let mut mirrors = BTreeMap::new();
        let mut plugins: BTreeMap<String, PluginSettings> = BTreeMap::new();
        for entry in self.entries.values() {
            let Value::Text(url) = &entry.value else {
                continue;
            };
            match &entry.key {
                Key::Mirror(prefix) => {
                    check_location(entry, url, allow_http_mirrors)?;
                    mirrors.insert(prefix.clone(), url.clone());
                }
                Key::PluginIndexUrl(plugin) => {
                    check_location(entry, url, allow_http_mirrors)?;
                    plugins.entry(plugin.clone()).or_default().index_url = Some(url.clone());
                }
                Key::Scalar(_) => {}
            }
        }

        Ok(Settings {
            pin: PinSettings {
                default_format: self
                    .text("pin", "default_format")
                    .unwrap_or_else(|| "native".to_owned()),
            },
            index: IndexSettings {
                auto_refresh,
                ttl_hours: u32::try_from(self.int("index", "ttl_hours")).unwrap_or(u32::MAX),
            },
            security: SecuritySettings {
                expiry,
                allow_http_mirrors,
            },
            download: DownloadSettings {
                concurrency: u32::try_from(self.int("download", "concurrency")).unwrap_or(1),
                cache_dir: self.text("download", "cache_dir").map(PathBuf::from),
            },
            network: NetworkSettings {
                proxy: self.text("network", "proxy"),
                extra_ca_file: self.text("network", "extra_ca_file").map(PathBuf::from),
            },
            extract: ExtractSettings {
                max_bytes: self.int("extract", "max_bytes"),
            },
            mirrors,
            plugins,
        })
    }
}

fn config_error(origin: &Origin, key: &str, message: impl Into<String>) -> JtmError {
    JtmError::Config {
        origin: origin.to_string(),
        key: key.to_owned(),
        message: message.into(),
    }
}

/// Checks a mirror target or index URL: `https`, `file` or an absolute path, and `http` only
/// when `security.allow_http_mirrors` is set.
fn check_location(entry: &Entry, url: &str, allow_http: bool) -> Result<()> {
    let ok = url.starts_with("https://")
        || url.starts_with("file://")
        || (allow_http && url.starts_with("http://"))
        || (!url.contains("://") && Path::new(url).is_absolute());
    if ok {
        Ok(())
    } else if url.starts_with("http://") {
        Err(config_error(
            &entry.origin,
            &entry.key.dotted(),
            format!(
                "`{url}` uses plain http; set `security.allow_http_mirrors = true` to allow it \
                 (signatures and hashes are still checked)"
            ),
        ))
    } else {
        Err(config_error(
            &entry.origin,
            &entry.key.dotted(),
            format!("`{url}` must be an https or file URL, or an absolute path"),
        ))
    }
}

/// Reads one config file into entries. Only the system layer may lock keys, and the project
/// layer reads `[settings]` and refuses keys a project must not set.
fn read_file(layer: Layer, file: FileSource<'_>) -> Result<Vec<Entry>> {
    let origin = Origin {
        layer,
        name: file.path.display().to_string(),
    };
    let mut table: toml::Table = toml::from_str(file.text).map_err(|e| {
        let line = e.span().map(|s| {
            file.text[..s.start.min(file.text.len())]
                .matches('\n')
                .count()
                + 1
        });
        let message = match line {
            Some(line) => format!("line {line}: {}", e.message().trim()),
            None => e.message().trim().to_owned(),
        };
        config_error(&origin, "", message)
    })?;

    let prefix = if layer == Layer::Project {
        match table.remove("settings") {
            None => return Ok(Vec::new()),
            Some(toml::Value::Table(settings)) => {
                table = settings;
                "settings."
            }
            Some(_) => return Err(config_error(&origin, "settings", "must be a table")),
        }
    } else {
        ""
    };

    let mut entries = Vec::new();
    for (section, value) in table {
        let path = format!("{prefix}{section}");
        let toml::Value::Table(inner) = value else {
            return Err(config_error(
                &origin,
                &path,
                "expected a table such as `[index]`",
            ));
        };
        match section.as_str() {
            "mirrors" => {
                for (source, value) in inner {
                    if !source.starts_with("https://") {
                        return Err(config_error(
                            &origin,
                            &format!("{path}.{source:?}"),
                            "a mirror rewrites an `https://` URL prefix",
                        ));
                    }
                    let key = Key::Mirror(source);
                    entries.push(file_entry(&origin, prefix, key, value)?);
                }
            }
            "plugins" => {
                for (plugin, value) in inner {
                    let plugin_path = format!("{path}.{plugin}");
                    check_plugin_name(&plugin)
                        .map_err(|(_, message)| config_error(&origin, &plugin_path, message))?;
                    let toml::Value::Table(settings) = value else {
                        return Err(config_error(&origin, &plugin_path, "expected a table"));
                    };
                    for (name, value) in settings {
                        if name != "index_url" {
                            return Err(config_error(
                                &origin,
                                &format!("{plugin_path}.{name}"),
                                "unknown key; plugin settings support `index_url`",
                            ));
                        }
                        let key = Key::PluginIndexUrl(plugin.clone());
                        entries.push(file_entry(&origin, prefix, key, value)?);
                    }
                }
            }
            _ => {
                if !KEYS.iter().any(|def| def.section == section) {
                    return Err(config_error(&origin, &path, unknown_key_message()));
                }
                for (name, value) in inner {
                    let Some(def) = KEYS
                        .iter()
                        .find(|def| def.section == section && def.name == name)
                    else {
                        return Err(config_error(
                            &origin,
                            &format!("{path}.{name}"),
                            unknown_key_message(),
                        ));
                    };
                    entries.push(file_entry(&origin, prefix, Key::Scalar(def), value)?);
                }
            }
        }
    }
    Ok(entries)
}

fn unknown_key_message() -> String {
    let known: Vec<String> = KEYS
        .iter()
        .map(|def| format!("{}.{}", def.section, def.name))
        .chain(["mirrors".to_owned(), "plugins.<name>.index_url".to_owned()])
        .collect();
    format!("unknown key; known keys are {}", known.join(", "))
}

/// Converts one value from a config file, unwrapping the system layer's
/// `{ value = ..., locked = true }` form.
fn file_entry(origin: &Origin, prefix: &str, key: Key, value: toml::Value) -> Result<Entry> {
    let path = format!("{prefix}{}", key.dotted());
    if origin.layer == Layer::Project && !key.allowed_in_project() {
        return Err(config_error(
            origin,
            &path,
            "project files cannot set security, network, extract, mirror, plugin index or \
             download cache settings; set it in user or system config instead",
        ));
    }
    let (value, locked) = match value {
        toml::Value::Table(mut table) if table.contains_key("locked") => {
            if origin.layer != Layer::System {
                return Err(config_error(
                    origin,
                    &path,
                    "only the system config can lock a key",
                ));
            }
            let locked = match table.remove("locked") {
                Some(toml::Value::Boolean(b)) => b,
                _ => {
                    return Err(config_error(
                        origin,
                        &path,
                        "`locked` must be true or false",
                    ));
                }
            };
            let Some(value) = table.remove("value") else {
                return Err(config_error(
                    origin,
                    &path,
                    "a locked key is written `{ value = ..., locked = true }`",
                ));
            };
            if let Some(extra) = table.keys().next() {
                return Err(config_error(
                    origin,
                    &path,
                    format!("unexpected `{extra}`; use `{{ value = ..., locked = true }}`"),
                ));
            }
            (value, locked)
        }
        other => (other, false),
    };
    let value =
        convert_toml(&key, value).map_err(|message| config_error(origin, &path, message))?;
    Ok(Entry {
        key,
        value,
        origin: origin.clone(),
        locked,
    })
}

fn kind_of(key: &Key) -> Kind {
    match key {
        Key::Scalar(def) => def.kind,
        Key::Mirror(_) | Key::PluginIndexUrl(_) => Kind::Text,
    }
}

fn convert_toml(key: &Key, value: toml::Value) -> std::result::Result<Value, String> {
    match (kind_of(key), value) {
        (Kind::Bool, toml::Value::Boolean(b)) => Ok(Value::Bool(b)),
        (Kind::Int { min, max }, toml::Value::Integer(n)) => check_int(n, min, max),
        (Kind::Bytes, toml::Value::Integer(n)) if n > 0 => Ok(Value::Int(n.unsigned_abs())),
        (Kind::Bytes, toml::Value::String(s)) => parse_bytes(&s),
        (kind, toml::Value::String(s)) if !matches!(kind, Kind::Bool | Kind::Int { .. }) => {
            convert_text(kind, s)
        }
        (kind, _) => Err(format!("expected {}", describe(kind))),
    }
}

/// Converts text from an environment variable or flag.
fn convert_str(key: &Key, text: &str) -> std::result::Result<Value, String> {
    match kind_of(key) {
        Kind::Bool => match text.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(Value::Bool(true)),
            "0" | "false" | "no" | "off" => Ok(Value::Bool(false)),
            _ => Err(format!("expected {}", describe(Kind::Bool))),
        },
        Kind::Int { min, max } => text
            .trim()
            .parse::<i64>()
            .map_err(|_| format!("expected {}", describe(Kind::Int { min, max })))
            .and_then(|n| check_int(n, min, max)),
        Kind::Bytes => parse_bytes(text),
        kind => convert_text(kind, text.to_owned()),
    }
}

fn check_int(n: i64, min: u64, max: u64) -> std::result::Result<Value, String> {
    match u64::try_from(n) {
        Ok(n) if (min..=max).contains(&n) => Ok(Value::Int(n)),
        _ => Err(format!("expected {}", describe(Kind::Int { min, max }))),
    }
}

fn convert_text(kind: Kind, text: String) -> std::result::Result<Value, String> {
    if text.trim().is_empty() {
        return Err(format!("expected {}", describe(kind)));
    }
    match kind {
        Kind::Choice(choices) if !choices.contains(&text.as_str()) => {
            Err(format!("expected {}", describe(kind)))
        }
        Kind::Format if text != "native" && check_name_segment(&text, "format").is_err() => {
            Err(format!("expected {}", describe(kind)))
        }
        Kind::Path if !Path::new(&text).is_absolute() => {
            Err(format!("`{text}` must be an absolute path"))
        }
        Kind::Url
            if !["http://", "https://", "socks5://", "socks5h://"]
                .iter()
                .any(|scheme| text.starts_with(scheme)) =>
        {
            Err(format!(
                "`{text}` must be an http, https, socks5 or socks5h URL"
            ))
        }
        _ => Ok(Value::Text(text)),
    }
}

fn describe(kind: Kind) -> String {
    match kind {
        Kind::Bool => "true or false".to_owned(),
        Kind::Int { min, max } => format!("a whole number from {min} to {max}"),
        Kind::Bytes => "a positive size in bytes, or a size such as \"4 GiB\"".to_owned(),
        Kind::Text => "a non-empty string".to_owned(),
        Kind::Url => "a proxy URL".to_owned(),
        Kind::Path => "an absolute path".to_owned(),
        Kind::Choice(choices) => format!("one of {}", choices.join(", ")),
        Kind::Format => "`native` or the name of a plugin interop format".to_owned(),
    }
}

/// Parses `4294967296`, `4 GiB`, `512MiB` or `100 KiB`.
fn parse_bytes(text: &str) -> std::result::Result<Value, String> {
    let err = || format!("expected {}", describe(Kind::Bytes));
    let text = text.trim();
    let split = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: u64 = number.parse().map_err(|_| err())?;
    let multiplier: u64 = match unit.trim() {
        "" | "B" => 1,
        "KiB" => 1 << 10,
        "MiB" => 1 << 20,
        "GiB" => 1 << 30,
        "TiB" => 1 << 40,
        _ => return Err(err()),
    };
    match number.checked_mul(multiplier) {
        Some(n) if n > 0 => Ok(Value::Int(n)),
        _ => Err(err()),
    }
}

/// The environment variable for a scalar key, such as `JTM_INDEX_TTL_HOURS`.
fn env_name(def: &KeyDef) -> String {
    format!("JTM_{}_{}", def.section, def.name).to_ascii_uppercase()
}

// SPEC-QUESTION: section 14 names an environment layer without naming its variables. Each
// scalar key `<section>.<key>` is read from `JTM_<SECTION>_<KEY>`; mirrors and plugin index
// URLs have no variables. Locked system keys still win.
fn read_env(env: &dyn Fn(&str) -> Option<OsString>) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    for def in KEYS {
        let name = env_name(def);
        let Some(raw) = env(&name).filter(|v| !v.is_empty()) else {
            continue;
        };
        let origin = Origin {
            layer: Layer::Env,
            name,
        };
        let key = Key::Scalar(def);
        let text = raw
            .into_string()
            .map_err(|_| config_error(&origin, &key.dotted(), "is not valid UTF-8"))?;
        let value =
            convert_str(&key, &text).map_err(|m| config_error(&origin, &key.dotted(), m))?;
        entries.push(Entry {
            key,
            value,
            origin,
            locked: false,
        });
    }
    Ok(entries)
}

fn read_flags(flags: &[(&str, &str)]) -> Result<Vec<Entry>> {
    flags
        .iter()
        .map(|(dotted, text)| {
            let origin = Origin {
                layer: Layer::Flag,
                name: (*dotted).to_owned(),
            };
            let def = KEYS
                .iter()
                .find(|def| format!("{}.{}", def.section, def.name) == *dotted)
                .ok_or_else(|| config_error(&origin, dotted, unknown_key_message()))?;
            let key = Key::Scalar(def);
            let value = convert_str(&key, text).map_err(|m| config_error(&origin, dotted, m))?;
            Ok(Entry {
                key,
                value,
                origin,
                locked: false,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
