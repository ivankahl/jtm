//! The `plugin.toml` manifest (SPEC.md section 7): schema, parsing and validation.
//!
//! [`Manifest::parse`] rejects anything it does not understand. Every problem names the field
//! it is about, such as `aliases.lts.tag` or `interop[0].key`, and validation reports every
//! problem it finds rather than stopping at the first.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use base64::Engine as _;
use serde::Deserialize;

use crate::names::{check_name_segment, check_plugin_name, check_version_or_alias};
use crate::version::VersionScheme;

/// The only manifest schema version this build understands.
pub const SCHEMA_VERSION: i64 = 1;
/// The only index format this build understands.
pub const INDEX_FORMAT: i64 = 1;

/// Placeholders allowed in `[index] url`.
pub const INDEX_URL_PLACEHOLDERS: &[&str] = &["index_version", "os", "arch"];
/// Names no plugin may use. `marketplace` is the scope of the key that signs the marketplace.
pub const RESERVED_NAMES: &[&str] = &["marketplace"];
/// Placeholders allowed in `[env]` values.
pub const ENV_PLACEHOLDERS: &[&str] = &["home", "bin"];
/// OS names allowed as keys in per-OS tables.
pub const OS_NAMES: &[&str] = &["windows", "macos", "linux"];
/// The platform of an index whose artifacts run on every platform.
pub const ANY_PLATFORM: &str = "any";

/// A validated plugin manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: i64,
    pub name: String,
    pub display_name: String,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub license: Option<String>,
    pub min_jtm: Option<String>,
    pub versions: Versions,
    #[serde(default)]
    pub aliases: BTreeMap<String, Alias>,
    pub index: Index,
    pub layout: Layout,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Other tools this one needs at runtime, with a version requirement such as `>=8`.
    #[serde(default)]
    pub requires: BTreeMap<String, String>,
    #[serde(default)]
    pub interop: Vec<Interop>,
    #[serde(default)]
    pub hooks: Hooks,
    #[serde(default)]
    pub ide: Ide,
}

/// `[versions]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Versions {
    pub scheme: Scheme,
    pub default_variant: Option<String>,
    /// The alias a spec without a version resolves to, such as `latest` for a bare `maven`.
    /// Without one, a bare spec resolves to the highest version, as a `highest` alias would.
    pub default_alias: Option<String>,
    #[serde(default)]
    pub variants: Vec<String>,
    #[serde(default)]
    pub include_prereleases: bool,
}

/// How a plugin orders its versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scheme {
    Java,
    Maven,
    SemverLoose,
    /// Ordered by the plugin's `compare_versions` hook.
    Script,
}

impl Scheme {
    /// The built-in scheme, or `None` for `script`.
    pub fn builtin(self) -> Option<VersionScheme> {
        match self {
            Scheme::Java => Some(VersionScheme::Java),
            Scheme::Maven => Some(VersionScheme::Maven),
            Scheme::SemverLoose => Some(VersionScheme::SemverLoose),
            Scheme::Script => None,
        }
    }
}

/// One entry of `[aliases]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Alias {
    /// The highest version, skipping pre-releases unless `include_prereleases` is set.
    Highest {},
    /// The highest version whose index entry carries `tag`, pre-releases included.
    IndexTag { tag: String },
    /// The highest version matching the version prefix `target`.
    Fixed { target: String },
    /// Resolved by the plugin's `resolve_alias` hook.
    Script {},
}

/// `[index]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    /// An `https` URL template using the placeholders in [`INDEX_URL_PLACEHOLDERS`].
    pub url: String,
    /// The plugin's trust anchors: minisign public keys that sign its indices directly, or
    /// sign the keys file at `keys_url` that delegates to short-lived index keys.
    pub signing_keys: Vec<String>,
    /// How many distinct `signing_keys` must sign an index or the keys file. Defaults to 1.
    pub threshold: Option<u32>,
    /// An `https` URL of a keys file signed by `signing_keys`, listing delegated index keys.
    pub keys_url: Option<String>,
    pub format: i64,
}

impl Index {
    /// The number of `signing_keys` that must sign, 1 unless the manifest says otherwise.
    pub fn threshold(&self) -> u32 {
        self.threshold.unwrap_or(1)
    }

    /// Whether the plugin publishes one index for every platform: its URL has neither `{os}`
    /// nor `{arch}`, so it can only name one file. Such an index says `"platform": "any"`.
    pub fn platform_independent(&self) -> bool {
        !self.url.contains("{os}") && !self.url.contains("{arch}")
    }

    /// The platform to request this plugin's index for on `platform`: [`ANY_PLATFORM`] for a
    /// platform-independent plugin, else `platform` itself.
    pub fn index_platform<'a>(&self, platform: &'a str) -> &'a str {
        if self.platform_independent() {
            ANY_PLATFORM
        } else {
            platform
        }
    }
}

/// `[layout]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layout {
    #[serde(default)]
    pub strip_components: StripComponents,
    /// The tool home inside the archive per OS, keyed by the names in [`OS_NAMES`], such as
    /// `macos = "Contents/Home"`, or a list of candidates tried in order.
    #[serde(default)]
    pub home_subdir: BTreeMap<String, HomeCandidates>,
    pub bin_dirs: Vec<String>,
}

impl Layout {
    /// The candidate tool homes on `os`, in the order they are tried; empty when the home is
    /// the archive root.
    pub fn home_subdir_for(&self, os: &str) -> &[String] {
        self.home_subdir.get(os).map_or(&[], |c| c.0.as_slice())
    }
}

/// The tool home candidates for one OS, written as one path or a list of paths and tried in
/// order: the first that is a directory inside the archive wins, and the bin dirs are checked
/// after `post_extract`. `""` is the archive root, and a `*` segment matches any one directory
/// (never a link); a candidate with a `*` matches only when exactly one directory fits it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeCandidates(pub Vec<String>);

impl<'de> Deserialize<'de> for HomeCandidates {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = HomeCandidates;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a path or a list of paths")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(HomeCandidates(vec![v.to_owned()]))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut paths = Vec::new();
                while let Some(path) = seq.next_element::<String>()? {
                    paths.push(path);
                }
                Ok(HomeCandidates(paths))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

/// How many leading path components to remove from every archive entry, written
/// `strip_components = <n>` (0 to 16) or `strip_components = "auto"`, the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StripComponents {
    /// Strip a single top-level directory if the archive has exactly one.
    #[default]
    Auto,
    Count(u32),
}

/// One `[[interop]]` entry: a pin file this plugin reads and writes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interop {
    /// The file name, relative to the project directory, such as `.sdkmanrc`.
    pub file: String,
    pub parser: InteropParser,
    /// The key or tool name in the file; required by `keyvalue` and `tool-versions`.
    pub key: Option<String>,
    /// Maps text in the file to a variant, such as `tem = "temurin"`.
    #[serde(default)]
    pub mapping: BTreeMap<String, String>,
    /// Use the `parse_interop` and `format_interop` hooks instead of `mapping`.
    #[serde(default)]
    pub script: bool,
    /// For `wrapper`: the distribution file name, with `{version}` where the version is and
    /// `*` for any text, such as `gradle-{version}-*.zip`.
    pub pattern: Option<String>,
    /// For `wrapper`: the property holding the distribution's SHA-256, such as
    /// `distributionSha256Sum`. Without it the wrapper's hash is not compared.
    pub sha256_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InteropParser {
    /// `key=value` lines, as in `.sdkmanrc`.
    Keyvalue,
    /// `tool value` lines, as in `.tool-versions`.
    ToolVersions,
    /// The whole file is one value, as in `.java-version`.
    SingleLine,
    /// A build tool wrapper's properties file, such as `gradle-wrapper.properties`: the
    /// version comes from the file name in the URL under `key`. Read-only and lowest
    /// precedence (SPEC.md section 6, rule 5). A parser rather than core code, so the core
    /// stays free of tool names.
    Wrapper,
}

/// `[hooks]`: names of `plugin.lua` functions, and the script's hash.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hooks {
    pub resolve_alias: Option<String>,
    pub parse_interop: Option<String>,
    pub format_interop: Option<String>,
    pub compare_versions: Option<String>,
    pub post_extract: Option<String>,
    /// Lowercase hex SHA-256 of `plugin.lua`, required when any hook is named. The manifest's
    /// own hash is what receipts and `jtm.lock` record, so this pins the script too.
    pub script_sha256: Option<String>,
}

impl Hooks {
    /// Every hook as `(key, function)`, in manifest order.
    pub fn named(&self) -> [(&'static str, Option<&str>); 5] {
        [
            ("resolve_alias", self.resolve_alias.as_deref()),
            ("parse_interop", self.parse_interop.as_deref()),
            ("format_interop", self.format_interop.as_deref()),
            ("compare_versions", self.compare_versions.as_deref()),
            ("post_extract", self.post_extract.as_deref()),
        ]
    }
}

/// `[ide]`: how `jtm ide sync` offers this tool's installs to build tools (SPEC.md section 7).
/// The plugin declares which installs are JDKs, so the core never names a tool.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ide {
    /// The Maven toolchain `<type>` to list installs under in `~/.m2/toolchains.xml`, such as
    /// `jdk`.
    pub maven_toolchain: Option<String>,
    /// List installs in Gradle's `org.gradle.java.installations.paths`.
    #[serde(default)]
    pub gradle_installations: bool,
}

/// A rejected manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    pub problems: Vec<Problem>,
}

/// One problem with a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// The field, such as `versions.scheme` or `interop[0].key`; empty for the whole file.
    pub path: String,
    pub message: String,
    /// The 1-based line, when known.
    pub line: Option<usize>,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.line, self.path.is_empty()) {
            (Some(line), true) => write!(f, "line {line}: {}", self.message),
            (Some(line), false) => write!(f, "`{}` (line {line}): {}", self.path, self.message),
            (None, true) => f.write_str(&self.message),
            (None, false) => write!(f, "`{}`: {}", self.path, self.message),
        }
    }
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid plugin.toml")?;
        for (i, problem) in self.problems.iter().enumerate() {
            f.write_str(if i == 0 { ": " } else { "; " })?;
            write!(f, "{problem}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ManifestError {}

impl Manifest {
    /// Parses and validates a manifest.
    pub fn parse(text: &str) -> Result<Manifest, ManifestError> {
        check_schema(text)?;
        let deserializer = toml::Deserializer::parse(text).map_err(|e| toml_error(text, &e, ""))?;
        let manifest: Manifest = serde_path_to_error::deserialize(deserializer).map_err(|e| {
            let path = e.path().to_string();
            toml_error(text, e.inner(), &path)
        })?;
        let mut problems = Problems::default();
        manifest.validate(&mut problems);
        if problems.0.is_empty() {
            Ok(manifest)
        } else {
            Err(ManifestError {
                problems: problems.0,
            })
        }
    }

    /// The variant used when a spec names none: `default_variant`, or `default` for plugins
    /// without variants.
    pub fn default_variant(&self) -> &str {
        self.versions
            .default_variant
            .as_deref()
            .unwrap_or("default")
    }

    /// Whether `variant` is one this plugin publishes.
    pub fn has_variant(&self, variant: &str) -> bool {
        if self.versions.variants.is_empty() {
            variant == "default"
        } else {
            self.versions.variants.iter().any(|v| v == variant)
        }
    }

    fn validate(&self, p: &mut Problems) {
        self.validate_top_level(p);
        self.validate_versions(p);
        self.validate_aliases(p);
        self.validate_index(p);
        self.validate_layout(p);
        self.validate_env(p);
        self.validate_requires(p);
        self.validate_interop(p);
        self.validate_hooks(p);
        if let Some(kind) = &self.ide.maven_toolchain
            && let Err((_, message)) = check_name_segment(kind, "toolchain type")
        {
            p.push("ide.maven_toolchain", message);
        }
    }

    fn validate_top_level(&self, p: &mut Problems) {
        if let Err((_, message)) = check_plugin_name(&self.name) {
            p.push("name", message);
        }
        if RESERVED_NAMES.contains(&self.name.as_str()) {
            p.push(
                "name",
                format!("`{}` is reserved and cannot name a plugin", self.name),
            );
        }
        check_text(p, "display_name", Some(&self.display_name), 100);
        check_text(p, "description", self.description.as_deref(), 1000);
        check_text(p, "license", self.license.as_deref(), 100);
        if let Some(homepage) = &self.homepage {
            check_https_url(p, "homepage", homepage);
        }
        if let Some(min_jtm) = &self.min_jtm
            && VersionScheme::SemverLoose.parse(min_jtm).is_err()
        {
            p.push(
                "min_jtm",
                format!("`{min_jtm}` is not a version such as `0.1.0`"),
            );
        }
    }

    fn validate_versions(&self, p: &mut Problems) {
        let versions = &self.versions;
        let mut seen = BTreeSet::new();
        for (i, variant) in versions.variants.iter().enumerate() {
            let path = format!("versions.variants[{i}]");
            if let Err((_, message)) = check_name_segment(variant, "variant") {
                p.push(path, message);
            } else if !seen.insert(variant) {
                p.push(path, format!("variant `{variant}` is listed twice"));
            }
        }
        match (&versions.default_variant, versions.variants.is_empty()) {
            (Some(default), false) if !versions.variants.contains(default) => p.push(
                "versions.default_variant",
                format!("`{default}` is not one of `versions.variants`"),
            ),
            (Some(_), true) => p.push(
                "versions.default_variant",
                "a default variant needs a `versions.variants` list",
            ),
            (None, false) => p.push(
                "versions.default_variant",
                "plugins with variants must name a default variant",
            ),
            _ => {}
        }
        if let Some(alias) = &versions.default_alias
            && !self.aliases.contains_key(alias)
        {
            p.push(
                "versions.default_alias",
                format!("`{alias}` is not defined in `[aliases]`"),
            );
        }
        if versions.scheme == Scheme::Script && self.hooks.compare_versions.is_none() {
            p.push(
                "versions.scheme",
                "scheme `script` needs a `hooks.compare_versions` function",
            );
        }
    }

    fn validate_aliases(&self, p: &mut Problems) {
        for (name, alias) in &self.aliases {
            let path = format!("aliases.{}", quote_key(name));
            if let Err((_, message)) = check_version_or_alias(name) {
                p.push(path.clone(), format!("invalid alias name: {message}"));
            }
            match alias {
                Alias::Highest {} => {}
                Alias::IndexTag { tag } => {
                    if let Err((_, message)) = check_name_segment(tag, "tag") {
                        p.push(format!("{path}.tag"), message);
                    }
                }
                Alias::Fixed { target } => {
                    if let Err((_, message)) = check_version_or_alias(target) {
                        p.push(format!("{path}.target"), message);
                    } else if let Some(scheme) = self.versions.scheme.builtin()
                        && let Err(err) = scheme.parse(target)
                    {
                        // A target that is not a version, such as an alias name, could never
                        // match anything.
                        p.push(format!("{path}.target"), err.to_string());
                    }
                }
                Alias::Script {} => {
                    if self.hooks.resolve_alias.is_none() {
                        p.push(
                            format!("{path}.kind"),
                            "kind `script` needs a `hooks.resolve_alias` function",
                        );
                    }
                }
            }
        }
    }

    fn validate_index(&self, p: &mut Problems) {
        let index = &self.index;
        if index.format != INDEX_FORMAT {
            p.push(
                "index.format",
                format!(
                    "index format {} is not supported; this jtm reads format {INDEX_FORMAT}",
                    index.format
                ),
            );
        }
        if check_https_url(p, "index.url", &index.url) {
            check_placeholders(p, "index.url", &index.url, INDEX_URL_PLACEHOLDERS);
        }
        if index.signing_keys.is_empty() {
            p.push("index.signing_keys", "at least one signing key is required");
        }
        let mut seen = BTreeSet::new();
        for (i, key) in index.signing_keys.iter().enumerate() {
            let path = format!("index.signing_keys[{i}]");
            if !is_minisign_public_key(key) {
                p.push(
                    path,
                    "not a minisign public key; expected the base64 line starting with `RW`",
                );
            } else if !seen.insert(key) {
                p.push(path, "this key is listed twice");
            }
        }
        if let Some(threshold) = index.threshold {
            let keys = index.signing_keys.len();
            if threshold == 0 || usize::try_from(threshold).map_or(true, |t| t > keys) {
                p.push(
                    "index.threshold",
                    format!("must be between 1 and the {keys} signing keys listed"),
                );
            }
        }
        if let Some(url) = &index.keys_url
            && check_https_url(p, "index.keys_url", url)
        {
            check_placeholders(p, "index.keys_url", url, &[]);
        }
    }

    fn validate_layout(&self, p: &mut Problems) {
        let layout = &self.layout;
        check_home_subdir(p, "layout.home_subdir", &layout.home_subdir);
        if layout.bin_dirs.is_empty() {
            p.push("layout.bin_dirs", "at least one bin directory is required");
        }
        for (i, dir) in layout.bin_dirs.iter().enumerate() {
            check_relative_path(p, &format!("layout.bin_dirs[{i}]"), dir, true);
        }
    }

    fn validate_env(&self, p: &mut Problems) {
        // Windows compares variable names case-insensitively, so `JAVA_HOME` and `java_home`
        // would set the same variable.
        let mut seen: BTreeMap<String, &str> = BTreeMap::new();
        for (name, value) in &self.env {
            let path = format!("env.{}", quote_key(name));
            if !is_env_name(name) {
                p.push(
                    path,
                    "variable names use letters, digits and `_`, and cannot start with a digit",
                );
                continue;
            }
            if let Some(reason) = reserved_env(name) {
                p.push(path, reason);
                continue;
            }
            if let Some(first) = seen.insert(name.to_ascii_uppercase(), name) {
                p.push(
                    path,
                    format!("`{first}` and `{name}` differ only in case, and collide on Windows"),
                );
                continue;
            }
            check_placeholders(p, &path, value, ENV_PLACEHOLDERS);
        }
    }

    fn validate_requires(&self, p: &mut Problems) {
        for (tool, requirement) in &self.requires {
            let path = format!("requires.{}", quote_key(tool));
            if let Err((_, message)) = check_plugin_name(tool) {
                p.push(path, message);
            } else if tool == &self.name {
                p.push(path, "a plugin cannot require itself");
            } else if let Err(message) = parse_requirement(requirement) {
                p.push(path, message);
            }
        }
    }

    fn validate_interop(&self, p: &mut Problems) {
        let mut files = BTreeSet::new();
        for (i, interop) in self.interop.iter().enumerate() {
            let path = format!("interop[{i}]");
            check_relative_path(p, &format!("{path}.file"), &interop.file, false);
            if !files.insert(&interop.file) {
                p.push(
                    format!("{path}.file"),
                    format!("`{}` is listed twice", interop.file),
                );
            }
            match (interop.parser, &interop.key) {
                (InteropParser::SingleLine, Some(_)) => p.push(
                    format!("{path}.key"),
                    "parser `single-line` reads the whole file and takes no key",
                ),
                (
                    InteropParser::Keyvalue | InteropParser::ToolVersions | InteropParser::Wrapper,
                    None,
                ) => p.push(
                    format!("{path}.key"),
                    "parsers `keyvalue`, `tool-versions` and `wrapper` need the key to read",
                ),
                (_, Some(key)) if !is_interop_text(key) => p.push(
                    format!("{path}.key"),
                    "keys use letters, digits, `.`, `-` and `_`",
                ),
                _ => {}
            }
            match (interop.parser, &interop.pattern) {
                (InteropParser::Wrapper, None) => p.push(
                    format!("{path}.pattern"),
                    "parser `wrapper` needs the distribution file name pattern, such as \
                     `tool-{version}-*.zip`",
                ),
                (InteropParser::Wrapper, Some(pattern)) => {
                    if let Err(message) = check_wrapper_pattern(pattern) {
                        p.push(format!("{path}.pattern"), message);
                    }
                }
                (_, Some(_)) => p.push(
                    format!("{path}.pattern"),
                    "only parser `wrapper` takes a pattern",
                ),
                (_, None) => {}
            }
            match (interop.parser, &interop.sha256_key) {
                (InteropParser::Wrapper, Some(key)) if !is_interop_text(key) => p.push(
                    format!("{path}.sha256_key"),
                    "keys use letters, digits, `.`, `-` and `_`",
                ),
                (InteropParser::Wrapper, _) | (_, None) => {}
                (_, Some(_)) => p.push(
                    format!("{path}.sha256_key"),
                    "only parser `wrapper` takes a sha256_key",
                ),
            }
            if interop.parser == InteropParser::Wrapper && !interop.mapping.is_empty() {
                p.push(
                    format!("{path}.mapping"),
                    "parser `wrapper` reads a version only and takes no mapping",
                );
            }
            if interop.script {
                if !interop.mapping.is_empty() {
                    p.push(
                        format!("{path}.mapping"),
                        "use either `mapping` or `script = true`, not both",
                    );
                }
                if self.hooks.parse_interop.is_none() {
                    p.push(
                        format!("{path}.script"),
                        "`script = true` needs a `hooks.parse_interop` function",
                    );
                }
            }
            for (from, variant) in &interop.mapping {
                let entry = format!("{path}.mapping.{}", quote_key(from));
                if !is_interop_text(from) {
                    p.push(entry, "mapping keys use letters, digits, `.`, `-` and `_`");
                } else if !self.has_variant(variant) {
                    p.push(
                        entry,
                        format!("`{variant}` is not a variant of this plugin"),
                    );
                }
            }
        }
    }

    fn validate_hooks(&self, p: &mut Problems) {
        let named = self.hooks.named().iter().any(|(_, f)| f.is_some());
        match (&self.hooks.script_sha256, named) {
            (None, true) => p.push(
                "hooks.script_sha256",
                "hooks need the SHA-256 of plugin.lua, so a changed script is detected",
            ),
            (Some(_), false) => p.push(
                "hooks.script_sha256",
                "names no hooks, so there is no plugin.lua to check",
            ),
            (Some(hash), true) if !is_sha256_hex(hash) => {
                p.push("hooks.script_sha256", "must be 64 lowercase hex characters")
            }
            _ => {}
        }
        for (name, function) in self.hooks.named() {
            if let Some(function) = function
                && !is_lua_identifier(function)
            {
                p.push(
                    format!("hooks.{name}"),
                    format!("`{function}` is not a Lua function name"),
                );
            }
        }
    }
}

/// Checks a wrapper file name pattern: one `{version}`, `*` wildcards, and otherwise the
/// characters of a file name.
fn check_wrapper_pattern(pattern: &str) -> Result<(), String> {
    if pattern.matches("{version}").count() != 1 {
        return Err(format!(
            "`{pattern}` must contain `{{version}}` exactly once"
        ));
    }
    let rest = pattern.replace("{version}", "");
    if rest
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+' | b'*'))
    {
        Ok(())
    } else {
        Err(format!(
            "`{pattern}` is a file name: letters, digits, `.`, `-`, `_`, `+` and `*`"
        ))
    }
}

/// A comparison in a `[requires]` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparator {
    Eq,
    Gt,
    Ge,
    Lt,
    Le,
}

impl Comparator {
    /// Whether a version that compares as `order` against the requirement's version meets it.
    pub fn holds(self, order: std::cmp::Ordering) -> bool {
        use std::cmp::Ordering::{Equal, Greater, Less};
        match self {
            Comparator::Eq => order == Equal,
            Comparator::Gt => order == Greater,
            Comparator::Ge => order != Less,
            Comparator::Lt => order == Less,
            Comparator::Le => order != Greater,
        }
    }
}

/// Parses a requirement such as `>=8` or `>=17, <22` into comparisons that must all hold.
/// A bare version means `>=` that version.
pub fn parse_requirement(text: &str) -> Result<Vec<(Comparator, String)>, String> {
    let mut clauses = Vec::new();
    for clause in text.split(',') {
        let clause = clause.trim();
        let (op, rest) = [
            (">=", Comparator::Ge),
            ("<=", Comparator::Le),
            (">", Comparator::Gt),
            ("<", Comparator::Lt),
            ("=", Comparator::Eq),
        ]
        .iter()
        .find_map(|(prefix, op)| clause.strip_prefix(prefix).map(|rest| (*op, rest)))
        .unwrap_or((Comparator::Ge, clause));
        let version = rest.trim();
        if let Err((_, message)) = check_version_or_alias(version) {
            return Err(format!(
                "`{text}` is not a requirement such as `>=8` or `>=17, <22`: {message}"
            ));
        }
        clauses.push((op, version.to_owned()));
    }
    Ok(clauses)
}

#[derive(Default)]
struct Problems(Vec<Problem>);

impl Problems {
    fn push(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.0.push(Problem {
            path: path.into(),
            message: message.into(),
            line: None,
        });
    }
}

fn single(path: &str, message: String, line: Option<usize>) -> ManifestError {
    ManifestError {
        problems: vec![Problem {
            path: path.to_owned(),
            message,
            line,
        }],
    }
}

/// Reads `schema` before anything else, so a manifest written for a newer jtm says so instead
/// of failing on fields this version does not know.
fn check_schema(text: &str) -> Result<(), ManifestError> {
    let table: toml::Table = toml::from_str(text).map_err(|e| toml_error(text, &e, ""))?;
    match table.get("schema") {
        None => Err(single("schema", "missing field `schema`".to_owned(), None)),
        Some(toml::Value::Integer(SCHEMA_VERSION)) => Ok(()),
        Some(toml::Value::Integer(other)) => Err(single(
            "schema",
            format!(
                "manifest schema {other} is not supported; this jtm reads schema \
                 {SCHEMA_VERSION}, so the plugin may need a newer jtm"
            ),
            None,
        )),
        Some(_) => Err(single(
            "schema",
            "expected an integer such as `1`".to_owned(),
            None,
        )),
    }
}

fn toml_error(text: &str, error: &toml::de::Error, path: &str) -> ManifestError {
    let line = error
        .span()
        .map(|span| text[..span.start.min(text.len())].matches('\n').count() + 1);
    let message = error.message().trim().to_owned();
    let path = if path == "." { "" } else { path };
    // A missing field, and an unknown one outside `serde_path_to_error`, is reported against
    // its parent; name the field itself.
    let field = ["missing field `", "unknown field `"]
        .iter()
        .find_map(|prefix| message.strip_prefix(prefix)?.split_once('`'))
        .map(|(field, _)| field);
    let path = match field {
        Some(field) if path.is_empty() => field.to_owned(),
        Some(field) if !path.ends_with(&format!(".{field}")) && path != field => {
            format!("{path}.{field}")
        }
        _ => path.to_owned(),
    };
    let message = if path == "layout.home_subdir" {
        format!("{message}; set it per OS, such as `home_subdir = {{ macos = \"Contents/Home\" }}`")
    } else {
        message
    };
    single(&path, message, line)
}

/// Checks a per-OS `home_subdir` table at `path`.
fn check_home_subdir(p: &mut Problems, path: &str, home: &BTreeMap<String, HomeCandidates>) {
    for (os, candidates) in home {
        let path = format!("{path}.{}", quote_key(os));
        if !OS_NAMES.contains(&os.as_str()) {
            p.push(path, unknown_os(os));
            continue;
        }
        match candidates.0.as_slice() {
            [] => p.push(path, "list at least one candidate home"),
            [only] => check_home_candidate(p, &path, only),
            all => {
                for (i, candidate) in all.iter().enumerate() {
                    check_home_candidate(p, &format!("{path}[{i}]"), candidate);
                }
            }
        }
    }
}

/// Checks one candidate tool home: `""` for the archive root, or a relative path whose only
/// pattern is a `*` standing for a whole segment.
fn check_home_candidate(p: &mut Problems, path: &str, candidate: &str) {
    if candidate.is_empty() {
        return;
    }
    let before = p.0.len();
    check_relative_path(p, path, candidate, false);
    if p.0.len() == before
        && candidate
            .split('/')
            .any(|part| part.contains('*') && part != "*")
    {
        p.push(
            path,
            format!("`{candidate}`: `*` must be a whole path segment, such as `*/Contents/Home`"),
        );
    }
}

/// Quotes a table key for a field path when it is not a bare TOML key.
fn quote_key(key: &str) -> String {
    let bare = !key.is_empty()
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'));
    if bare {
        key.to_owned()
    } else {
        format!("{key:?}")
    }
}

fn unknown_os(os: &str) -> String {
    format!("`{os}` is not an OS; use one of {}", OS_NAMES.join(", "))
}

fn check_text(p: &mut Problems, path: &str, text: Option<&str>, max: usize) {
    let Some(text) = text else { return };
    if text.trim().is_empty() {
        p.push(path, "cannot be empty");
    } else if text.chars().count() > max {
        p.push(path, format!("is longer than {max} characters"));
    } else if text.chars().any(char::is_control) {
        p.push(path, "cannot contain control characters");
    }
}

/// Checks that `url` is an `https` URL with a host. Returns whether it passed.
fn check_https_url(p: &mut Problems, path: &str, url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        p.push(path, format!("`{url}` must be an `https://` URL"));
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.contains('@') || host.contains('{') {
        p.push(path, format!("`{url}` needs a literal host name"));
        return false;
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        p.push(path, "URLs cannot contain whitespace");
        return false;
    }
    true
}

/// Checks that every `{name}` in `template` is one of `allowed`, with balanced braces.
fn check_placeholders(p: &mut Problems, path: &str, template: &str, allowed: &[&str]) {
    let mut rest = template;
    while let Some(open) = rest.find(['{', '}']) {
        if rest.as_bytes()[open] == b'}' {
            p.push(path, "unmatched `}`");
            return;
        }
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            p.push(path, "unmatched `{`");
            return;
        };
        let name = &after[..close];
        if !allowed.contains(&name) {
            let known: Vec<String> = allowed.iter().map(|a| format!("{{{a}}}")).collect();
            p.push(
                path,
                format!("unknown placeholder `{{{name}}}`; use {}", known.join(", ")),
            );
            return;
        }
        rest = &after[close + 1..];
    }
}

/// Checks a `/`-separated path that must stay inside the directory it is relative to.
fn check_relative_path(p: &mut Problems, path: &str, value: &str, allow_dot: bool) {
    if allow_dot && value == "." {
        return;
    }
    let message = if value.is_empty() {
        Some("cannot be empty")
    } else if value.starts_with('/') || value.contains(':') {
        Some("must be a relative path")
    } else if value.contains('\\') {
        Some("use `/` as the separator")
    } else if value.chars().any(char::is_control) {
        Some("cannot contain control characters")
    } else if value
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        Some("cannot contain empty, `.` or `..` components")
    } else {
        None
    };
    if let Some(message) = message {
        p.push(path, format!("`{value}` {message}"));
    }
}

fn is_interop_text(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn is_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Names jtm sets itself: it builds `PATH` from `layout.bin_dirs`, and the shell hook records
/// its own changes in `JTM_*` variables to undo them. Refusing them keeps jtm correct; it is
/// not a security boundary. A plugin is trusted when it is installed, since it already picks
/// the keys that sign its archives, so any other variable is allowed. Names compare
/// case-insensitively because Windows does.
fn reserved_env(name: &str) -> Option<&'static str> {
    let upper = name.to_ascii_uppercase();
    if upper == "PATH" {
        Some("jtm manages `PATH` itself; list bin directories in `layout.bin_dirs`")
    } else if upper.starts_with("JTM_") {
        Some("`JTM_` variables are reserved for jtm")
    } else {
        None
    }
}

fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_lua_identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// A minisign public key: base64 of `Ed`, an 8-byte key id and a 32-byte Ed25519 key.
fn is_minisign_public_key(key: &str) -> bool {
    base64::engine::general_purpose::STANDARD
        .decode(key)
        .is_ok_and(|bytes| bytes.len() == 42 && bytes.starts_with(b"Ed"))
}

impl<'de> Deserialize<'de> for StripComponents {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = StripComponents;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a number of components from 0 to 16, or \"auto\"")
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                match u32::try_from(v) {
                    Ok(n) if n <= 16 => Ok(StripComponents::Count(n)),
                    _ => Err(E::invalid_value(serde::de::Unexpected::Signed(v), &self)),
                }
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                match u32::try_from(v) {
                    Ok(n) if n <= 16 => Ok(StripComponents::Count(n)),
                    _ => Err(E::invalid_value(serde::de::Unexpected::Unsigned(v), &self)),
                }
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v == "auto" {
                    Ok(StripComponents::Auto)
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Str(v), &self))
                }
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests;
